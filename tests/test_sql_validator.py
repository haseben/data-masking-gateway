"""SQL 安全校验引擎测试"""
import pytest
import sys
from pathlib import Path

# 确保项目根目录在 path 中
sys.path.insert(0, str(Path(__file__).parent.parent))

from security.sql_validator import validate_sql, normalize_sql_for_audit
from security.errors import GatewayDeniedError
from auth.roles import get_roles

ROLES = get_roles()
DEV_ROLE = ROLES["developer"]
VIEWER_ROLE = ROLES["viewer"]


class TestStatementType:
    """语句类型检查"""

    def test_select_allowed(self):
        sql = "SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2026"
        result = validate_sql(sql, DEV_ROLE)
        assert "n_year" in result

    def test_insert_denied(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql("INSERT INTO dws_example_summary VALUES (1)", DEV_ROLE)
        assert exc_info.value.code == "STATEMENT_DENIED"

    def test_update_denied(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql("UPDATE dws_example_summary SET amount = 0 WHERE n_year = 2026", DEV_ROLE)
        assert exc_info.value.code == "STATEMENT_DENIED"

    def test_delete_denied(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql("DELETE FROM dws_example_summary WHERE n_year = 2026", DEV_ROLE)
        assert exc_info.value.code == "STATEMENT_DENIED"

    def test_drop_denied(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql("DROP TABLE dws_example_summary", DEV_ROLE)
        assert exc_info.value.code == "STATEMENT_DENIED"

    def test_create_denied(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql("CREATE TABLE hack (id INT)", DEV_ROLE)
        assert exc_info.value.code == "STATEMENT_DENIED"


class TestMultiStatement:
    """多语句检查"""

    def test_single_statement_ok(self):
        sql = "SELECT n_year FROM dws_example_summary WHERE n_year = 2026"
        validate_sql(sql, DEV_ROLE)

    def test_multi_statement_denied(self):
        sql = "SELECT n_year FROM dws_example_summary WHERE n_year = 2026; DROP TABLE dws_example_summary"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE)
        assert exc_info.value.code in ("MULTI_STATEMENT", "STATEMENT_DENIED", "SYNTAX_ERROR")


class TestTableWhitelist:
    """表名白名单校验"""

    def test_allowed_table(self):
        sql = "SELECT amount FROM dws_example_summary WHERE n_year = 2026"
        validate_sql(sql, DEV_ROLE)

    def test_disallowed_table(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql("SELECT * FROM some_random_table WHERE n_year = 2026", DEV_ROLE)
        assert exc_info.value.code == "TABLE_NOT_ALLOWED"

    def test_mysql_system_table_denied(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql("SELECT user FROM mysql.user", DEV_ROLE)
        assert exc_info.value.code in ("SYSTEM_TABLE_DENIED", "TABLE_NOT_ALLOWED")

    def test_viewer_cannot_access_dwd(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql("SELECT amount FROM dwd_example_detail WHERE n_year = 2026", VIEWER_ROLE)
        assert exc_info.value.code == "TABLE_NOT_ALLOWED"

    def test_viewer_can_access_view(self):
        sql = "SELECT n_year, amount FROM v_example_view WHERE n_year = 2026"
        validate_sql(sql, VIEWER_ROLE)


class TestDangerousFunctions:
    """危险函数检查"""

    def test_sleep_denied(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql("SELECT SLEEP(10) FROM dws_example_summary WHERE n_year = 2026", DEV_ROLE)
        assert exc_info.value.code == "DANGEROUS_FUNCTION"

    def test_benchmark_denied(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql("SELECT BENCHMARK(1000000, SHA1('test')) FROM dws_example_summary WHERE n_year = 2026", DEV_ROLE)
        assert exc_info.value.code == "DANGEROUS_FUNCTION"

    def test_load_file_denied(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql("SELECT LOAD_FILE('/etc/passwd') FROM dws_example_summary WHERE n_year = 2026", DEV_ROLE)
        assert exc_info.value.code == "DANGEROUS_FUNCTION"


class TestUnion:
    """UNION 检查（developer 允许，viewer 禁止，深度限制）"""

    def test_union_allowed_for_developer(self):
        sql = """SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2026
                 UNION ALL
                 SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2025"""
        result = validate_sql(sql, DEV_ROLE)
        assert "UNION" in result.upper()

    def test_union_denied_for_viewer(self):
        sql = """SELECT n_year FROM v_example_view WHERE n_year = 2026
                 UNION
                 SELECT n_year FROM v_example_view WHERE n_year = 2025"""
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, VIEWER_ROLE)
        assert exc_info.value.code == "UNION_DENIED"

    def test_union_depth_exceeded(self):
        sql = """SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2026
                 UNION ALL
                 SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2025
                 UNION ALL
                 SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2024
                 UNION ALL
                 SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2023"""
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE)
        assert exc_info.value.code == "UNION_DENIED"

    def test_union_table_whitelist_still_enforced(self):
        """UNION 中每段子 SELECT 的表名仍受白名单约束"""
        sql = """SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2026
                 UNION ALL
                 SELECT id, amount FROM unauthorized_table WHERE n_year = 2026"""
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE)
        assert exc_info.value.code == "TABLE_NOT_ALLOWED"


class TestUserVariables:
    """用户变量检查"""

    def test_user_variable_denied(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql("SELECT @myvar := amount FROM dws_example_summary WHERE n_year = 2026", DEV_ROLE)
        assert exc_info.value.code == "USER_VARIABLE_DENIED"


class TestLimitEnforcement:
    """LIMIT 强制覆盖"""

    def test_no_limit_injected(self):
        sql = "SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2026"
        result = validate_sql(sql, DEV_ROLE)
        assert "5000" in result  # developer max_rows

    def test_excessive_limit_capped(self):
        sql = "SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2026 LIMIT 99999"
        result = validate_sql(sql, DEV_ROLE)
        assert "5000" in result
        assert "99999" not in result

    def test_small_limit_preserved(self):
        sql = "SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2026 LIMIT 100"
        result = validate_sql(sql, DEV_ROLE)
        assert "100" in result

    def test_viewer_limit_capped(self):
        sql = "SELECT n_year FROM v_example_view WHERE n_year = 2026 LIMIT 5000"
        result = validate_sql(sql, VIEWER_ROLE)
        assert "1000" in result  # viewer max_rows


class TestLargeTableFilter:
    """大表必要过滤条件"""

    def test_bill_detail_without_filter_denied(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql("SELECT amount FROM dws_example_bill_detail", DEV_ROLE)
        assert exc_info.value.code == "FILTER_REQUIRED"

    def test_bill_detail_with_year_filter_ok(self):
        sql = "SELECT amount FROM dws_example_bill_detail WHERE n_year = 2026"
        validate_sql(sql, DEV_ROLE)

    def test_bill_detail_with_period_filter_ok(self):
        sql = "SELECT amount FROM dws_example_bill_detail WHERE n_period = 6"
        validate_sql(sql, DEV_ROLE)

    def test_small_table_no_filter_ok(self):
        sql = "SELECT level_1 FROM dim_example_dimension"
        validate_sql(sql, DEV_ROLE)


class TestNormalizeSql:
    """规范化 SQL（审计用）"""

    def test_literals_replaced(self):
        import sqlglot
        sql = "SELECT amount FROM dws_example_summary WHERE n_year = 2026 AND n_period = 6"
        tree = sqlglot.parse(sql, dialect="mysql")[0]
        normalized = normalize_sql_for_audit(tree)
        assert "2026" not in normalized
        assert "?" in normalized
