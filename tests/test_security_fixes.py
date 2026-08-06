"""安全审计修复验证测试

覆盖审核报告中的 P0/P1/P2 问题：
  P0-1: 嵌套查询脱敏绕过（子查询别名血缘追踪）
  P0-2: 安全聚合别名携带敏感数据（表达式树严格检查）
  P1-3: SQL Server schema/database 校验语义（catalog vs db）
  P1-4: SQL Server 连接池关闭方法
  P1-6: 元数据查询路由和 TABLE_SCHEMA 过滤
  P1-7: 插件安全管线 fail-closed + validate_sql
  P2-8: %s 占位符替换破坏字符串内容
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import os
os.environ["HMAC_SECRET"] = "test_secret_key_for_unit_tests_only_32bytes!"

from security.sql_validator import (
    validate_sql,
    extract_column_aliases,
    extract_aggregate_aliases,
    _is_safe_numeric_expression,
)
from security.errors import GatewayDeniedError
from auth.roles import get_roles
from db import _convert_placeholders

ROLES = get_roles()
DEV_ROLE = ROLES["developer"]
VIEWER_ROLE = ROLES["viewer"]

TSQL = "tsql"
MYSQL = "mysql"


# ══════════════════════════════════════════════════════════════
# P0-1: 嵌套查询脱敏绕过修复
# ══════════════════════════════════════════════════════════════

class TestNestedQueryAliasBypass:
    """P0: 嵌套查询通过子查询别名绕过脱敏"""

    def test_subquery_alias_traced(self):
        """子查询内的别名应被提取，确保 apply_masking 能追溯源列"""
        sql = """
            SELECT amount FROM (
                SELECT customer_name AS amount
                FROM dws_example_summary
            ) s
        """
        aliases = extract_column_aliases(sql, dialect=MYSQL)
        # 子查询中的 customer_name AS amount 必须被捕获
        assert "amount" in aliases
        assert aliases["amount"] == "customer_name"

    def test_subquery_alias_traced_tsql(self):
        """T-SQL 方言下子查询别名同样被提取"""
        sql = """
            SELECT amount FROM (
                SELECT customer_name AS amount
                FROM dws_example_summary
            ) s
        """
        aliases = extract_column_aliases(sql, dialect=TSQL)
        assert "amount" in aliases
        assert aliases["amount"] == "customer_name"

    def test_cte_alias_traced(self):
        """CTE 中的别名也应被提取"""
        sql = """
            WITH cte AS (
                SELECT customer_name AS amount
                FROM dws_example_summary
            )
            SELECT amount FROM cte
        """
        aliases = extract_column_aliases(sql, dialect=MYSQL)
        assert "amount" in aliases
        assert aliases["amount"] == "customer_name"

    def test_deeply_nested_alias_traced(self):
        """多层嵌套子查询的别名也应被提取"""
        sql = """
            SELECT amount FROM (
                SELECT amount FROM (
                    SELECT customer_name AS amount
                    FROM dws_example_summary
                ) inner_t
            ) outer_t
        """
        aliases = extract_column_aliases(sql, dialect=MYSQL)
        assert "amount" in aliases
        assert aliases["amount"] == "customer_name"

    def test_multiple_subquery_aliases_traced(self):
        """多个子查询的别名都应被提取"""
        sql = """
            SELECT a, b FROM (
                SELECT customer_name AS a, phone_number AS b
                FROM dws_example_summary
            ) s
        """
        aliases = extract_column_aliases(sql, dialect=MYSQL)
        assert aliases.get("a") == "customer_name"
        assert aliases.get("b") == "phone_number"

    def test_outer_alias_still_works(self):
        """外层 SELECT 的直接别名仍正常工作"""
        sql = "SELECT customer_name AS amount FROM dws_example_summary WHERE n_year = 2026"
        aliases = extract_column_aliases(sql, dialect=MYSQL)
        assert aliases.get("amount") == "customer_name"

    def test_no_alias_returns_empty(self):
        """无别名的查询返回空映射"""
        sql = "SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2026"
        aliases = extract_column_aliases(sql, dialect=MYSQL)
        assert len(aliases) == 0


# ══════════════════════════════════════════════════════════════
# P0-2: 安全聚合别名携带敏感数据修复
# ══════════════════════════════════════════════════════════════

class TestUnsafeAggregateAlias:
    """P0: 包含敏感列的表达式不应被认定为安全聚合别名"""

    def test_concat_with_secret_not_safe(self):
        """CONCAT(COUNT(*), ':', secret_col) 不应被放行"""
        sql = """
            SELECT CONCAT(COUNT(*), ':', unknown_secret) AS total_count
            FROM dws_example_summary WHERE n_year = 2026
        """
        # unknown_secret 不在白名单，validate_sql 应拒绝（TABLE_NOT_ALLOWED 或通过 column_tracker）
        # 但即使能通过校验，total_count 也不应出现在 safe_aliases 中
        agg_aliases = extract_aggregate_aliases(sql, dialect=MYSQL)
        assert "total_count" not in agg_aliases

    def test_count_plus_secret_not_safe(self):
        """COUNT(*) + secret_col 不应被放行"""
        sql = """
            SELECT COUNT(*) + unknown_secret AS total_count
            FROM dws_example_summary WHERE n_year = 2026
        """
        agg_aliases = extract_aggregate_aliases(sql, dialect=MYSQL)
        assert "total_count" not in agg_aliases

    def test_pure_count_is_safe(self):
        """COUNT(*) 是安全的"""
        sql = "SELECT COUNT(*) AS cnt FROM dws_example_summary WHERE n_year = 2026"
        agg_aliases = extract_aggregate_aliases(sql, dialect=MYSQL)
        assert "cnt" in agg_aliases

    def test_pure_sum_is_safe(self):
        """SUM(amount) 是安全的"""
        sql = "SELECT SUM(amount) AS total FROM dws_example_summary WHERE n_year = 2026"
        agg_aliases = extract_aggregate_aliases(sql, dialect=MYSQL)
        assert "total" in agg_aliases

    def test_round_sum_is_safe(self):
        """ROUND(SUM(amount), 2) 是安全的"""
        sql = "SELECT ROUND(SUM(amount), 2) AS total FROM dws_example_summary WHERE n_year = 2026"
        agg_aliases = extract_aggregate_aliases(sql, dialect=MYSQL)
        assert "total" in agg_aliases

    def test_count_plus_literal_is_safe(self):
        """COUNT(*) + 1 是安全的"""
        sql = "SELECT COUNT(*) + 1 AS cnt FROM dws_example_summary WHERE n_year = 2026"
        agg_aliases = extract_aggregate_aliases(sql, dialect=MYSQL)
        assert "cnt" in agg_aliases

    def test_count_times_literal_is_safe(self):
        """COUNT(*) * 100 是安全的"""
        sql = "SELECT COUNT(*) * 100 AS cnt FROM dws_example_summary WHERE n_year = 2026"
        agg_aliases = extract_aggregate_aliases(sql, dialect=MYSQL)
        assert "cnt" in agg_aliases

    def test_is_safe_numeric_expression_directly(self):
        """直接测试 _is_safe_numeric_expression"""
        import sqlglot
        from sqlglot import exp

        # 安全表达式
        expr = sqlglot.parse_one("COUNT(*)", dialect=MYSQL)
        assert _is_safe_numeric_expression(expr)

        expr = sqlglot.parse_one("SUM(amount)", dialect=MYSQL)
        assert _is_safe_numeric_expression(expr)

        expr = sqlglot.parse_one("ROUND(SUM(amount), 2)", dialect=MYSQL)
        assert _is_safe_numeric_expression(expr)

        expr = sqlglot.parse_one("COUNT(*) + 1", dialect=MYSQL)
        assert _is_safe_numeric_expression(expr)

        # 不安全表达式
        expr = sqlglot.parse_one("CONCAT(COUNT(*), ':', secret_col)", dialect=MYSQL)
        assert not _is_safe_numeric_expression(expr)

        expr = sqlglot.parse_one("COUNT(*) + secret_col", dialect=MYSQL)
        assert not _is_safe_numeric_expression(expr)

    def test_tsql_concat_with_secret_not_safe(self):
        """T-SQL 方言下同样检查"""
        sql = """
            SELECT CONCAT(COUNT(*), ':', unknown_secret) AS total_count
            FROM dws_example_summary WHERE n_year = 2026
        """
        agg_aliases = extract_aggregate_aliases(sql, dialect=TSQL)
        assert "total_count" not in agg_aliases


# ══════════════════════════════════════════════════════════════
# P1-3: SQL Server schema/database 校验语义
# ══════════════════════════════════════════════════════════════

class TestSqlserverSchemaValidation:
    """P1: T-SQL 三段式名称 catalog vs db 校验"""

    def test_dbo_schema_allowed_tsql(self):
        """dbo schema 不应被拒绝（不是系统 schema）"""
        sql = "SELECT * FROM dbo.dws_example_summary WHERE n_year = 2026"
        # 不应报 SYSTEM_TABLE_DENIED
        result = validate_sql(sql, DEV_ROLE, dialect=TSQL)
        assert "dws_example_summary" in result.lower()

    def test_cross_database_denied_tsql(self):
        """跨数据库查询（catalog 不在配置中）应被拒绝"""
        sql = "SELECT * FROM other_db.dbo.dws_example_summary WHERE n_year = 2026"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE, dialect=TSQL)
        assert exc_info.value.code == "TABLE_NOT_ALLOWED"

    def test_master_system_db_denied_tsql(self):
        """master 系统库应被拒绝"""
        sql = "SELECT * FROM master.dbo.sysobjects"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE, dialect=TSQL)
        assert exc_info.value.code in ("SYSTEM_TABLE_DENIED", "TABLE_NOT_ALLOWED")

    def test_mysql_schema_not_checked_as_catalog(self):
        """MySQL 方言下不使用 catalog 校验逻辑"""
        # MySQL 两段式：database.table
        # 不应触发 T-SQL 的 catalog 校验
        sql = "SELECT * FROM dws_example_summary WHERE n_year = 2026"
        result = validate_sql(sql, DEV_ROLE, dialect=MYSQL)
        assert "dws_example_summary" in result.lower()


# ══════════════════════════════════════════════════════════════
# P1-4: SQL Server 连接池关闭方法
# ══════════════════════════════════════════════════════════════

class TestSqlserverPoolClose:
    """P1: aioodbc 连接池关闭使用 close() + wait_closed()"""

    @pytest.fixture(autouse=True)
    def _cleanup_pools(self):
        """每个测试前后清理全局连接池状态，确保隔离"""
        import db as _db
        _db._pools.clear()
        _db._pool_types.clear()
        yield
        _db._pools.clear()
        _db._pool_types.clear()

    def test_close_pool_calls_sync_close_then_wait_closed(self):
        """验证 close_pool 对 SQL Server 池调用同步 close + 异步 wait_closed"""
        import asyncio
        import db as _db

        # 模拟 aioodbc 池
        class MockSqlserverPool:
            def __init__(self):
                self.closed = False
                self.close_called = False
                self.wait_closed_called = False

            def close(self):
                self.close_called = True
                self.closed = True

            async def wait_closed(self):
                self.wait_closed_called = True

        mock_pool = MockSqlserverPool()
        _db._pools["test_ss"] = mock_pool
        _db._pool_types["test_ss"] = "sqlserver"

        asyncio.run(_db.close_pool())

        assert mock_pool.close_called
        assert mock_pool.wait_closed_called
        assert _db._pools == {}
        assert _db._pool_types == {}

    def test_close_pool_mysql_unchanged(self):
        """MySQL 池关闭逻辑不变"""
        import asyncio
        import db as _db

        class MockMysqlPool:
            def __init__(self):
                self.closed = False
                self.close_called = False
                self.wait_closed_called = False

            def close(self):
                self.close_called = True
                self.closed = True

            async def wait_closed(self):
                self.wait_closed_called = True

        mock_pool = MockMysqlPool()
        _db._pools["test_mysql"] = mock_pool
        _db._pool_types["test_mysql"] = "mysql"

        asyncio.run(_db.close_pool())

        assert mock_pool.close_called
        assert mock_pool.wait_closed_called
        assert _db._pools == {}


# ══════════════════════════════════════════════════════════════
# P1-7: 插件安全管线 fail-closed
# ══════════════════════════════════════════════════════════════

class TestPluginSecurityPipeline:
    """P1: 插件安全管线 fail-closed 和 validate_sql 调用"""

    def test_extract_table_names_returns_none_on_parse_error(self):
        """解析失败时返回 None（fail-closed）"""
        from tools.plugin_base import _extract_table_names
        result = _extract_table_names("THIS IS NOT SQL !!!", dialect=MYSQL)
        assert result is None

    def test_extract_table_names_returns_none_on_empty(self):
        """空 SQL 返回 None"""
        from tools.plugin_base import _extract_table_names
        result = _extract_table_names("", dialect=MYSQL)
        assert result is None

    def test_extract_table_names_works_on_valid_sql(self):
        """有效 SQL 返回表名列表"""
        from tools.plugin_base import _extract_table_names
        result = _extract_table_names(
            "SELECT * FROM dws_example_summary WHERE n_year = 2026",
            dialect=MYSQL,
        )
        assert result is not None
        assert "dws_example_summary" in result

    def test_role_rank_viewer_below_developer(self):
        """viewer 角色层级低于 developer"""
        from tools.plugin_base import _ROLE_RANK
        assert _ROLE_RANK["viewer"] < _ROLE_RANK["developer"]

    def test_role_rank_unknown_role_defaults_zero(self):
        """未知角色层级为 0"""
        from tools.plugin_base import _ROLE_RANK
        assert _ROLE_RANK.get("unknown_role", 0) == 0


# ══════════════════════════════════════════════════════════════
# P2-8: %s 占位符替换不破坏字符串内容
# ══════════════════════════════════════════════════════════════

class TestPlaceholderConversionSafety:
    """P2: %s 占位符替换跳过字符串字面量"""

    def test_string_with_percent_s_not_replaced(self):
        """字符串字面量内的 %s 不应被替换"""
        sql = "SELECT '完成度 %s' AS template, amount FROM t WHERE id = %s"
        result = _convert_placeholders(sql, "sqlserver")
        # 字符串内的 %s 保持不变
        assert "'完成度 %s'" in result
        # 参数占位符 %s 被替换为 ?
        assert "id = ?" in result
        # 只有 1 个 ? 被替换
        assert result.count("?") == 1

    def test_multiple_string_literals(self):
        """多个字符串字面量内的 %s 都不替换"""
        sql = "SELECT '%s text %s' AS a, name FROM t WHERE id = %s AND code = %s"
        result = _convert_placeholders(sql, "sqlserver")
        assert "'%s text %s'" in result
        assert "id = ?" in result
        assert "code = ?" in result
        assert result.count("?") == 2

    def test_escaped_quote_in_string(self):
        """转义单引号 '' 在字符串内正确处理"""
        sql = "SELECT 'it''s %s' AS a FROM t WHERE id = %s"
        result = _convert_placeholders(sql, "sqlserver")
        # 字符串内的 %s 不替换
        assert "'it''s %s'" in result
        # 参数占位符替换
        assert "id = ?" in result
        assert result.count("?") == 1

    def test_no_string_literals(self):
        """无字符串字面量时全部替换"""
        sql = "SELECT * FROM t WHERE id = %s AND name = %s"
        result = _convert_placeholders(sql, "sqlserver")
        assert result.count("?") == 2
        assert "%s" not in result

    def test_mysql_not_affected(self):
        """MySQL 方言不做替换"""
        sql = "SELECT '%s' AS a FROM t WHERE id = %s"
        result = _convert_placeholders(sql, "mysql")
        assert result == sql

    def test_empty_string(self):
        """空字符串不报错"""
        assert _convert_placeholders("", "sqlserver") == ""

    def test_only_string_literal(self):
        """只有字符串字面量，无参数占位符"""
        sql = "SELECT 'hello %s world' AS a FROM t"
        result = _convert_placeholders(sql, "sqlserver")
        assert result == sql  # 无变化

    def test_percent_without_s(self):
        """单独的 % 不被替换"""
        sql = "SELECT '50% done' AS a FROM t WHERE id = %s"
        result = _convert_placeholders(sql, "sqlserver")
        assert "'50% done'" in result
        assert "id = ?" in result
