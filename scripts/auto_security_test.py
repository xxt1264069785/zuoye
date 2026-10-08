#!/usr/bin/env python3
"""pg-mcp SQL 安全验证器自动化测试脚本（测试岗作业：自动化脚本案例）。

针对 PostgreSQL MCP 服务器的核心安全组件 SQLValidator 进行自动化回归测试：

    自然语言 → LLM 生成 SQL → [SQLValidator 安全校验] → 数据库执行

覆盖 8 大类测试场景（60+ 用例）：
    1. 合法查询放行     —— 确保 SELECT 类查询不被误拦截
    2. 写操作拦截       —— INSERT/UPDATE/DELETE/DROP 等一律拒绝
    3. SQL 注入防护     —— 多语句堆叠注入等攻击载荷拦截
    4. 危险函数拦截     —— pg_sleep / pg_read_file / dblink 等黑名单
    5. 敏感表/列控制    —— blocked_tables / blocked_columns 访问控制
    6. EXPLAIN 策略     —— 受控放行 EXPLAIN，拒绝其他 Command
    7. 边界与畸形输入   —— 空 SQL、注释、残缺语句
    8. 子查询安全       —— 子查询内的函数/表访问同样受限

特性：
    - 无需 PostgreSQL / OpenAI 依赖，开箱即跑（仅依赖 sqlglot + pydantic）
    - 自动生成 HTML 可视化测试报告 + JSON 结果（CI 集成友好）
    - 任一用例失败时进程以非零码退出，可接入 GitHub Actions / Jenkins

用法：
    python scripts/auto_security_test.py                        # 全量运行
    python scripts/auto_security_test.py --category injection   # 按类别过滤
    python scripts/auto_security_test.py --no-html              # 不生成报告
    python scripts/auto_security_test.py --report-dir reports   # 指定报告目录
"""

from __future__ import annotations

import argparse
import html
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# Windows 控制台默认 GBK，强制 UTF-8 避免中文/符号输出崩溃
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# 静默 sqlglot 的 "unsupported syntax" 解析回退警告（属预期行为）
logging.getLogger("sqlglot").setLevel(logging.ERROR)

# 将项目 src 目录加入 sys.path，使脚本能直接导入 pg_mcp 包
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

import importlib.util

from pg_mcp.config.settings import SecurityConfig


def _load_sql_validator() -> type:
    """直接加载 sql_validator 模块。

    绕过 pg_mcp.services.__init__（其会连带导入 orchestrator -> asyncpg 等
    重量级运行时依赖），使本脚本仅需 sqlglot + pydantic 即可运行。
    """
    module_path = PROJECT_ROOT / "src" / "pg_mcp" / "services" / "sql_validator.py"
    spec = importlib.util.spec_from_file_location("_pg_mcp_sql_validator", module_path)
    assert spec and spec.loader, f"无法定位模块: {module_path}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.SQLValidator


SQLValidator = _load_sql_validator()

# ---------------------------------------------------------------------------
# 测试用例定义（数据驱动）
# ---------------------------------------------------------------------------

# 用例类别 -> 展示名
CATEGORIES: dict[str, str] = {
    "valid": "1. 合法查询放行",
    "write": "2. 写操作拦截",
    "injection": "3. SQL 注入防护",
    "function": "4. 危险函数拦截",
    "acl": "5. 敏感表/列控制",
    "explain": "6. EXPLAIN 策略",
    "edge": "7. 边界与畸形输入",
    "subquery": "8. 子查询安全",
}


@dataclass
class TestCase:
    """单条安全测试用例。

    Attributes:
        id: 用例编号，如 SEC-V-001。
        category: 类别 key，见 CATEGORIES。
        name: 用例名称（中文描述测试意图）。
        sql: 待校验的 SQL 语句。
        expect: 预期结果，"allow"（应放行）或 "block"（应拦截）。
        keyword: 拦截类用例期望错误消息中包含的关键字（可选，校验拦截理由）。
        blocked_tables: 该用例使用的表黑名单（可选）。
        blocked_columns: 该用例使用的列黑名单（可选）。
        allow_explain: 该用例是否允许 EXPLAIN（可选，默认 False）。
        blocked_functions: 额外自定义函数黑名单（可选）。
        note: 备注（可选，如已知限制说明）。
    """

    id: str
    category: str
    name: str
    sql: str
    expect: str  # "allow" | "block"
    keyword: str = ""
    blocked_tables: list[str] = field(default_factory=list)
    blocked_columns: list[str] = field(default_factory=list)
    allow_explain: bool = False
    blocked_functions: list[str] = field(default_factory=list)
    note: str = ""


def _cases() -> list[TestCase]:
    """构建全量测试用例集。"""
    cases: list[TestCase] = []

    def add(**kwargs) -> None:
        cases.append(TestCase(**kwargs))

    # --- 1. 合法查询放行：确保正常业务查询不被误伤 -----------------------
    valid_queries = [
        ("SELECT * FROM users", "简单全表查询"),
        ("SELECT id, name FROM users WHERE age > 18", "带 WHERE 条件"),
        (
            "SELECT u.name, o.total FROM users u "
            "INNER JOIN orders o ON u.id = o.user_id",
            "INNER JOIN 连接查询",
        ),
        (
            "SELECT name FROM users "
            "WHERE id IN (SELECT user_id FROM orders WHERE total > 100)",
            "WHERE 子查询",
        ),
        (
            "SELECT t.name, t.cnt FROM "
            "(SELECT name, COUNT(*) AS cnt FROM users GROUP BY name) t",
            "FROM 派生表",
        ),
        (
            "WITH stats AS (SELECT user_id, COUNT(*) AS c FROM orders GROUP BY user_id) "
            "SELECT u.name, s.c FROM users u JOIN stats s ON u.id = s.user_id",
            "CTE 公共表表达式",
        ),
        (
            "SELECT category, COUNT(*), AVG(price) FROM products "
            "GROUP BY category HAVING COUNT(*) > 5 ORDER BY 2 DESC",
            "聚合 + HAVING",
        ),
        (
            "SELECT name, ROW_NUMBER() OVER (ORDER BY salary DESC) "
            "FROM employees",
            "窗口函数",
        ),
        ("SELECT id FROM users UNION SELECT id FROM orders", "UNION 集合查询"),
        (
            "SELECT name, CASE WHEN age < 18 THEN 'minor' ELSE 'adult' END "
            "FROM users",
            "CASE 表达式",
        ),
        (
            "SELECT * FROM orders WHERE created_at > NOW() - INTERVAL '30 days'",
            "时间区间过滤",
        ),
        (
            "SELECT * FROM users WHERE first_name ILIKE '%john%'",
            "ILIKE 模糊搜索",
        ),
        (
            "SELECT COALESCE(nickname, name, 'unknown'), EXTRACT(YEAR FROM created_at) "
            "FROM users",
            "安全内置函数",
        ),
        ("SELECT 1", "常量查询"),
        ("SELECT * FROM users;", "结尾分号（单语句）"),
        (
            "-- 查询活跃用户\nSELECT id FROM users WHERE active = true -- 行内注释",
            "含注释的查询",
        ),
    ]
    for i, (sql, name) in enumerate(valid_queries, 1):
        add(id=f"SEC-V-{i:03d}", category="valid", name=name, sql=sql, expect="allow")

    # --- 2. 写操作拦截：只读红线 ----------------------------------------
    write_ops = [
        ("INSERT INTO users (name) VALUES ('hacker')", "INSERT 插入", "INSERT"),
        ("UPDATE users SET name = 'x' WHERE id = 1", "UPDATE 更新", "UPDATE"),
        ("DELETE FROM users WHERE id = 1", "DELETE 删除", "DELETE"),
        ("DROP TABLE users", "DROP TABLE 删表", "DROP"),
        ("DROP DATABASE prod", "DROP DATABASE 删库", "DROP"),
        ("CREATE TABLE t (id INT)", "CREATE 建表", "CREATE"),
        ("ALTER TABLE users ADD COLUMN age INT", "ALTER 改表", "ALTER"),
        ("GRANT SELECT ON users TO public", "GRANT 授权", "GRANT"),
        ("REVOKE SELECT ON users FROM public", "REVOKE 收权", "REVOKE"),
        ("MERGE INTO users USING src ON users.id = src.id WHEN MATCHED THEN UPDATE SET name = src.name", "MERGE 合并", "MERGE"),
        ("TRUNCATE TABLE users", "TRUNCATE 清表", "TRUNCATE"),
        ("VACUUM users", "VACUUM 维护命令", "VACUUM"),
        ("COPY users TO '/tmp/leak.csv'", "COPY 导出文件", "COPY"),
        ("SET search_path = evil_schema", "SET 会话变量", "SET"),
        ("LISTEN channel", "LISTEN 监听", "not allowed"),
    ]
    for i, (sql, name, kw) in enumerate(write_ops, 1):
        add(
            id=f"SEC-W-{i:03d}", category="write", name=name,
            sql=sql, expect="block", keyword=kw,
        )

    # --- 3. SQL 注入防护：堆叠语句攻击 -----------------------------------
    injections = [
        (
            "SELECT * FROM users; DROP TABLE users;--",
            "堆叠注入 + DROP", "multiple",
        ),
        (
            "SELECT * FROM users WHERE id = 1; DELETE FROM users;--",
            "堆叠注入 + DELETE", "multiple",
        ),
        (
            "SELECT * FROM users; INSERT INTO logs VALUES (1, 'hacked');",
            "堆叠注入 + INSERT", "multiple",
        ),
        ("SELECT 1; SELECT 2", "多语句 SELECT", "multiple"),
        (
            "UPDATE users SET name = 'x' WHERE id = 1; SELECT 1",
            "UPDATE 与 SELECT 混合", "multiple",
        ),
    ]
    for i, (sql, name, kw) in enumerate(injections, 1):
        add(
            id=f"SEC-I-{i:03d}", category="injection", name=name,
            sql=sql, expect="block", keyword=kw,
        )
    # 已知限制：恒真条件属于语义层攻击，结构校验无法识别，
    # 由只读事务 + 只读数据库账号在执行层兜底。
    add(
        id="SEC-I-006", category="injection",
        name="恒真条件 OR 1=1（已知限制，执行层兜底）",
        sql="SELECT * FROM users WHERE id = 1 OR 1=1",
        expect="allow",
        note="结构校验不识别语义注入，由只读事务兜底",
    )

    # --- 4. 危险函数拦截：内置黑名单 + 自定义黑名单 -----------------------
    dangerous_funcs = [
        ("SELECT pg_sleep(10)", "pg_sleep 拖垮连接", "pg_sleep"),
        ("SELECT pg_read_file('/etc/passwd')", "pg_read_file 读文件", "pg_read_file"),
        ("SELECT pg_read_binary_file('/etc/shadow')", "pg_read_binary_file", "pg_read_binary_file"),
        ("SELECT * FROM pg_ls_dir('/tmp')", "pg_ls_dir 列目录", "pg_ls_dir"),
        ("SELECT lo_import('/tmp/f.txt')", "lo_import 大对象导入", "lo_import"),
        ("SELECT lo_export(1, '/tmp/f.txt')", "lo_export 大对象导出", "lo_export"),
        (
            "SELECT * FROM dblink('host=remote', 'SELECT 1') AS t(id INT)",
            "dblink 跨库攻击", "dblink",
        ),
        ("SELECT pg_terminate_backend(12345)", "pg_terminate_backend", "pg_terminate_backend"),
        ("SELECT pg_cancel_backend(12345)", "pg_cancel_backend", "pg_cancel_backend"),
        ("SELECT pg_reload_conf()", "pg_reload_conf", "pg_reload_conf"),
        ("SELECT PG_SLEEP(10)", "大写绕过尝试 PG_SLEEP", "pg_sleep"),
        (
            "SELECT * FROM users WHERE id IN (SELECT 1 WHERE pg_sleep(1) IS NULL)",
            "子查询中调用危险函数", "pg_sleep",
        ),
        (
            "WITH t AS (SELECT pg_read_file('/etc/passwd') AS f) SELECT * FROM t",
            "CTE 中调用危险函数", "pg_read_file",
        ),
    ]
    for i, (sql, name, kw) in enumerate(dangerous_funcs, 1):
        add(
            id=f"SEC-F-{i:03d}", category="function", name=name,
            sql=sql, expect="block", keyword=kw,
        )
    add(
        id="SEC-F-014", category="function", name="自定义黑名单函数",
        sql="SELECT my_custom_func(123)", expect="block",
        blocked_functions=["my_custom_func"], keyword="my_custom_func",
    )
    add(
        id="SEC-F-015", category="function", name="未列入黑名单的安全函数放行",
        sql="SELECT COUNT(*), UPPER(name) FROM users", expect="allow",
    )

    # --- 5. 敏感表/列访问控制（blocked_tables / blocked_columns）---------
    acl_cases = [
        (
            "SELECT * FROM passwords", ["passwords"], [],
            "block", "passwords", "黑名单表直查",
        ),
        (
            "SELECT u.name FROM users u JOIN secrets s ON u.id = s.user_id",
            ["secrets"], [], "block", "secrets", "黑名单表 JOIN",
        ),
        (
            "SELECT * FROM users WHERE id IN (SELECT id FROM api_keys)",
            ["api_keys"], [], "block", "api_keys", "黑名单表出现在子查询",
        ),
        (
            "SELECT * FROM PASSWORDS", ["passwords"], [],
            "block", "passwords", "黑名单表大写绕过尝试",
        ),
        (
            "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders)",
            ["passwords"], [], "allow", "", "非黑名单表正常放行",
        ),
        (
            "SELECT id, name, password FROM users", [], ["password"],
            "block", "password", "黑名单列查询",
        ),
        (
            "SELECT id FROM users WHERE password = 'x'", [], ["password"],
            "block", "password", "黑名单列出现在 WHERE",
        ),
        (
            "SELECT id, SECRET_KEY FROM users", [], ["secret_key"],
            "block", "secret_key", "黑名单列大小写归一",
        ),
        (
            "SELECT users.id, users.ssn FROM users", [], ["users.ssn"],
            "block", "users.ssn", "限定名 table.column 黑名单",
        ),
        (
            "SELECT id, password_hash FROM users", [], ["password"],
            "allow", "", "列名部分匹配不误伤（精确匹配策略）",
        ),
    ]
    for i, (sql, bt, bc, expect, kw, name) in enumerate(acl_cases, 1):
        add(
            id=f"SEC-A-{i:03d}", category="acl", name=name, sql=sql,
            expect=expect, keyword=kw, blocked_tables=bt, blocked_columns=bc,
        )

    # --- 6. EXPLAIN 策略 --------------------------------------------------
    add(
        id="SEC-E-001", category="explain", name="默认拒绝 EXPLAIN",
        sql="EXPLAIN SELECT * FROM users", expect="block", keyword="explain",
    )
    add(
        id="SEC-E-002", category="explain", name="开启后放行 EXPLAIN",
        sql="EXPLAIN SELECT * FROM users", expect="allow", allow_explain=True,
    )
    add(
        id="SEC-E-003", category="explain", name="开启后放行 EXPLAIN ANALYZE",
        sql="EXPLAIN ANALYZE SELECT * FROM users WHERE id > 100",
        expect="allow", allow_explain=True,
    )
    add(
        id="SEC-E-004", category="explain", name="EXPLAIN DELETE 安全（只看计划不执行）",
        sql="EXPLAIN DELETE FROM users", expect="allow", allow_explain=True,
        note="EXPLAIN 不真正执行，PLAN 无副作用",
    )
    add(
        id="SEC-E-005", category="explain", name="其他 Command 拒绝（CHECKPOINT）",
        sql="CHECKPOINT", expect="block", keyword="not allowed",
    )

    # --- 7. 边界与畸形输入 ------------------------------------------------
    edge_cases = [
        ("", "空字符串", "empty"),
        ("   \n\t  ", "纯空白字符", "empty"),
        ("-- 只有一行注释", "纯注释", ""),
        ("/* 块注释 */", "纯块注释", ""),
        ("SELECT * FROM", "残缺语句", ""),
        ("SELECT * FROM WHERE", "语法错误", ""),
        ("INVALID SQL QUERY", "非 SQL 文本", ""),
    ]
    for i, (sql, name, kw) in enumerate(edge_cases, 1):
        add(
            id=f"SEC-G-{i:03d}", category="edge", name=name,
            sql=sql, expect="block", keyword=kw,
        )

    # --- 8. 子查询安全 ------------------------------------------------------
    subquery_cases = [
        (
            "SELECT name FROM users WHERE EXISTS "
            "(SELECT 1 FROM orders WHERE orders.user_id = users.id)",
            "allow", "", "EXISTS 子查询放行",
        ),
        (
            "SELECT name FROM users WHERE id IN (SELECT user_id FROM orders "
            "WHERE product_id IN (SELECT id FROM products WHERE category = 'electronics'))",
            "allow", "", "多层嵌套 SELECT 放行",
        ),
        (
            "WITH recent AS (SELECT user_id, total FROM orders "
            "WHERE created_at > NOW() - INTERVAL '30 days') "
            "SELECT u.name, (SELECT SUM(total) FROM recent WHERE user_id = u.id) "
            "FROM users u",
            "allow", "", "CTE + 标量子查询组合放行",
        ),
    ]
    for i, (sql, expect, kw, name) in enumerate(subquery_cases, 1):
        add(
            id=f"SEC-S-{i:03d}", category="subquery", name=name,
            sql=sql, expect=expect, keyword=kw,
        )

    return cases


# ---------------------------------------------------------------------------
# 执行引擎
# ---------------------------------------------------------------------------


@dataclass
class TestResult:
    """单条用例的执行结果。"""

    case: TestCase
    passed: bool
    duration_ms: float
    detail: str = ""  # 失败原因或拦截消息


def build_validator(case: TestCase) -> SQLValidator:
    """按用例配置构建 SQLValidator 实例。"""
    config = SecurityConfig(
        allow_write_operations=False,
        blocked_functions=case.blocked_functions or SecurityConfig().blocked_functions,
    )
    return SQLValidator(
        config=config,
        blocked_tables=case.blocked_tables or None,
        blocked_columns=case.blocked_columns or None,
        allow_explain=case.allow_explain,
    )


def run_case(case: TestCase) -> TestResult:
    """执行单条用例并判定结果。"""
    validator = build_validator(case)
    start = time.perf_counter()
    detail = ""
    try:
        is_valid, error = validator.validate(case.sql)
        duration = (time.perf_counter() - start) * 1000

        if case.expect == "allow":
            passed = is_valid
            if not passed:
                detail = f"预期放行，实际被拦截: {error}"
        else:  # block
            if is_valid:
                passed = False
                detail = "预期拦截，实际被放行（安全漏洞！）"
            elif case.keyword and case.keyword.lower() not in (error or "").lower():
                passed = False
                detail = f"拦截理由不符: 期望含 '{case.keyword}'，实际: {error}"
            else:
                passed = True
                detail = error or ""
    except Exception as e:  # noqa: BLE001 - 任何未预期异常都算用例失败
        duration = (time.perf_counter() - start) * 1000
        passed = False
        detail = f"未预期异常 {type(e).__name__}: {e}"

    return TestResult(case=case, passed=passed, duration_ms=duration, detail=detail)


def run_suite(cases: list[TestCase]) -> list[TestResult]:
    """顺序执行全部用例，实时打印进度。"""
    results: list[TestResult] = []
    total = len(cases)
    for i, case in enumerate(cases, 1):
        result = run_case(case)
        results.append(result)
        mark = _green("PASS") if result.passed else _red("FAIL")
        print(f"  [{i:>{len(str(total))}}/{total}] {mark}  {case.id}  {case.name}")
        if not result.passed:
            print(f"         {_red('-> ' + result.detail)}")
    return results


# ---------------------------------------------------------------------------
# 报告生成
# ---------------------------------------------------------------------------

RESET, GREEN, RED, YELLOW, CYAN, BOLD = "", "", "", "", "", ""


def _init_colors() -> None:
    """初始化 ANSI 颜色（Windows 终端兼容）。"""
    global RESET, GREEN, RED, YELLOW, CYAN, BOLD
    if os.name == "nt":
        os.system("")  # 触发 Windows 终端启用 ANSI 转义
    if sys.stdout.isatty():
        RESET, GREEN, RED = "\033[0m", "\033[32m", "\033[31m"
        YELLOW, CYAN, BOLD = "\033[33m", "\033[36m", "\033[1m"


def _green(s: str) -> str:
    return f"{GREEN}{s}{RESET}"


def _red(s: str) -> str:
    return f"{RED}{s}{RESET}"


def print_summary(results: list[TestResult], total_duration: float) -> bool:
    """打印终端摘要，返回整体是否通过。"""
    print(f"\n{BOLD}{'=' * 72}{RESET}")
    print(f"{BOLD}测试结果汇总{RESET}")
    print(f"{'=' * 72}")

    all_passed = True
    for key, title in CATEGORIES.items():
        group = [r for r in results if r.case.category == key]
        if not group:
            continue
        passed = sum(1 for r in group if r.passed)
        total = len(group)
        all_passed &= passed == total
        rate = passed / total * 100
        status = _green("OK") if passed == total else _red("FAIL")
        print(f"  {status}  {title:<24} {passed:>3}/{total:<3} ({rate:5.1f}%)")

    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed
    rate = passed / total * 100
    print("-" * 72)
    verdict = _green("全部通过 ✓") if failed == 0 else _red(f"存在 {failed} 个失败 ✗")
    print(f"  总计: {passed}/{total} 通过 ({rate:.1f}%)   耗时: {total_duration:.0f}ms   {verdict}")
    print(f"{'=' * 72}\n")
    return failed == 0


def generate_html_report(results: list[TestResult], total_duration: float, out_dir: Path) -> Path:
    """生成自包含的 HTML 测试报告。"""
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 分类统计行
    cat_rows = ""
    for key, title in CATEGORIES.items():
        group = [r for r in results if r.case.category == key]
        if not group:
            continue
        p = sum(1 for r in group if r.passed)
        rate = p / len(group) * 100
        cls = "pass" if p == len(group) else "fail"
        bar_width = rate / 100 * 120
        cat_rows += (
            f"<tr><td>{html.escape(title)}</td>"
            f"<td>{p} / {len(group)}</td>"
            f'<td><div class="bar"><div class="bar-fill {cls}" style="width:{bar_width}px"></div></div></td>'
            f'<td class="num {cls}">{rate:.1f}%</td></tr>'
        )

    # 明细行
    detail_rows = ""
    for r in results:
        c = r.case
        cls = "pass" if r.passed else "fail"
        expect_label = "放行" if c.expect == "allow" else "拦截"
        sql_preview = html.escape(c.sql.strip()[:120]) or "<空>"
        msg = (
            html.escape(r.detail[:200])
            if not r.passed
            else (html.escape(r.detail[:100]) if r.detail else "—")
        )
        detail_rows += (
            f'<tr class="{cls}">'
            f"<td>{c.id}</td>"
            f"<td>{html.escape(CATEGORIES[c.category])}</td>"
            f"<td class='name'>{html.escape(c.name)}"
            + (f"<div class='note'>{html.escape(c.note)}</div>" if c.note else "")
            + "</td>"
            f"<td><code>{sql_preview}</code></td>"
            f"<td>{expect_label}</td>"
            f"<td class='center'>{'✓' if r.passed else '✗'}</td>"
            f"<td>{r.duration_ms:.1f}</td>"
            f"<td class='msg'>{msg}</td>"
            f"</tr>"
        )

    rate = passed / total * 100 if total else 0
    verdict = "ALL PASSED" if failed == 0 else f"{failed} FAILED"

    page = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>pg-mcp 安全自动化测试报告 - {now}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: "Segoe UI", "Microsoft YaHei", sans-serif;
         background: #f4f6f9; color: #24292f; padding: 32px; }}
  .container {{ max-width: 1280px; margin: 0 auto; }}
  h1 {{ font-size: 22px; margin-bottom: 4px; }}
  .meta {{ color: #57606a; font-size: 13px; margin-bottom: 24px; }}
  .cards {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
  .card {{ flex: 1; min-width: 160px; background: #fff; border-radius: 10px;
          padding: 18px 20px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  .card .label {{ font-size: 12px; color: #57606a; margin-bottom: 6px; }}
  .card .value {{ font-size: 28px; font-weight: 700; }}
  .card .value.ok {{ color: #1a7f37; }}
  .card .value.bad {{ color: #cf222e; }}
  h2 {{ font-size: 16px; margin: 28px 0 12px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
          border-radius: 10px; overflow: hidden;
          box-shadow: 0 1px 3px rgba(0,0,0,.08); font-size: 13px; }}
  th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #eaeef2;
           vertical-align: top; }}
  th {{ background: #f6f8fa; font-weight: 600; white-space: nowrap; }}
  tr:last-child td {{ border-bottom: none; }}
  .num, .center {{ text-align: center; }}
  .pass {{ color: #1a7f37; }}
  .fail {{ color: #cf222e; }}
  code {{ font-family: Consolas, "Courier New", monospace; font-size: 12px;
         background: #f6f8fa; padding: 2px 5px; border-radius: 4px;
         word-break: break-all; }}
  .bar {{ background: #eaeef2; height: 12px; border-radius: 6px;
         width: 120px; overflow: hidden; }}
  .bar-fill {{ height: 100%; border-radius: 6px; }}
  .bar-fill.pass {{ background: #2da44e; }}
  .bar-fill.fail {{ background: #cf222e; }}
  .name {{ min-width: 180px; }}
  .msg {{ max-width: 320px; color: #57606a; word-break: break-all; }}
  .note {{ font-size: 11px; color: #9a6700; margin-top: 4px; }}
  tr.fail td {{ background: #fff5f5; }}
  .footer {{ margin-top: 24px; font-size: 12px; color: #57606a; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <h1>pg-mcp SQL 安全验证器 · 自动化测试报告</h1>
  <div class="meta">执行时间: {now} &nbsp;|&nbsp; 目标: SQLValidator (sqlglot) &nbsp;|&nbsp; 总耗时: {total_duration:.0f} ms</div>

  <div class="cards">
    <div class="card"><div class="label">总用例数</div><div class="value">{total}</div></div>
    <div class="card"><div class="label">通过</div><div class="value ok">{passed}</div></div>
    <div class="card"><div class="label">失败</div><div class="value {"bad" if failed else "ok"}">{failed}</div></div>
    <div class="card"><div class="label">通过率</div><div class="value {"ok" if failed == 0 else "bad"}">{rate:.1f}%</div></div>
    <div class="card"><div class="label">结论</div><div class="value {"ok" if failed == 0 else "bad"}" style="font-size:20px">{verdict}</div></div>
  </div>

  <h2>分类统计</h2>
  <table>
    <tr><th>类别</th><th>通过 / 总数</th><th>通过率</th><th class="num">%</th></tr>
    {cat_rows}
  </table>

  <h2>用例明细</h2>
  <table>
    <tr>
      <th>编号</th><th>类别</th><th>用例名称</th><th>SQL</th>
      <th>预期</th><th class="center">结果</th><th>耗时(ms)</th><th>消息</th>
    </tr>
    {detail_rows}
  </table>

  <div class="footer">Generated by scripts/auto_security_test.py · pg-mcp 测试岗自动化脚本案例</div>
</div>
</body>
</html>"""

    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = out_dir / f"security_report_{stamp}.html"
    report_path.write_text(page, encoding="utf-8")
    # 同步输出一份 latest.html 便于持续集成读取
    (out_dir / "security_report_latest.html").write_text(page, encoding="utf-8")
    return report_path


def generate_json_report(results: list[TestResult], total_duration: float, out_dir: Path) -> Path:
    """生成机器可读的 JSON 结果（供 CI 断言/看板使用）。"""
    payload = {
        "project": "pg-mcp",
        "target": "pg_mcp.services.sql_validator.SQLValidator",
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "duration_ms": round(total_duration, 1),
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if r.passed),
            "failed": sum(1 for r in results if not r.passed),
        },
        "categories": {
            key: {
                "title": title,
                "total": sum(1 for r in results if r.case.category == key),
                "passed": sum(1 for r in results if r.case.category == key and r.passed),
            }
            for key, title in CATEGORIES.items()
        },
        "cases": [
            {
                "id": r.case.id,
                "category": r.case.category,
                "name": r.case.name,
                "sql": r.case.sql,
                "expect": r.case.expect,
                "passed": r.passed,
                "duration_ms": round(r.duration_ms, 2),
                "message": r.detail,
            }
            for r in results
        ],
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "security_report.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="pg-mcp SQL 安全验证器自动化测试脚本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--category",
        choices=list(CATEGORIES),
        help="仅运行指定类别的用例",
    )
    parser.add_argument(
        "--report-dir", type=Path, default=PROJECT_ROOT / "reports",
        help="报告输出目录（默认: reports/）",
    )
    parser.add_argument("--no-html", action="store_true", help="不生成 HTML 报告")
    parser.add_argument("--no-json", action="store_true", help="不生成 JSON 报告")
    args = parser.parse_args()

    _init_colors()
    cases = _cases()
    if args.category:
        cases = [c for c in cases if c.category == args.category]

    print(f"{BOLD}{CYAN}pg-mcp SQL 安全自动化测试{RESET}")
    print(f"目标: SQLValidator (sqlglot)   用例数: {len(cases)}   开始时间: {datetime.now():%H:%M:%S}\n")

    start = time.perf_counter()
    results = run_suite(cases)
    total_duration = (time.perf_counter() - start) * 1000

    all_passed = print_summary(results, total_duration)

    if not args.no_html:
        path = generate_html_report(results, total_duration, args.report_dir)
        print(f"  HTML 报告: {path}")
    if not args.no_json:
        path = generate_json_report(results, total_duration, args.report_dir)
        print(f"  JSON  结果: {path}")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
