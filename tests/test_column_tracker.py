"""敏感列血缘追踪测试"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import sqlglot
from security.column_tracker import check_sensitive_columns
from security.errors import GatewayDeniedError


def _parse(sql: str):
    return sqlglot.parse(sql, dialect="mysql")[0]


class TestAllowedUsage:
    """敏感列允许的使用方式"""

    def test_select_direct_column(self):
        tree = _parse("SELECT customer_name, amount FROM dws_example_summary WHERE n_year = 2026")
        check_sensitive_columns(tree)  # 不应抛异常

    def test_group_by_sensitive_column(self):
        tree = _parse("SELECT customer_name, SUM(amount) FROM dws_example_summary WHERE n_year = 2026 GROUP BY customer_name")
        check_sensitive_columns(tree)

    def test_where_equality(self):
        tree = _parse("SELECT amount FROM dws_example_summary WHERE customer_name = '某公司' AND n_year = 2026")
        check_sensitive_columns(tree)

    def test_non_sensitive_in_function_ok(self):
        tree = _parse("SELECT UPPER(level_1) FROM dws_example_summary WHERE n_year = 2026")
        check_sensitive_columns(tree)


class TestFunctionDenied:
    """敏感列禁止在函数中使用"""

    def test_upper_on_sensitive_denied(self):
        tree = _parse("SELECT UPPER(customer_name) FROM dws_example_summary WHERE n_year = 2026")
        with pytest.raises(GatewayDeniedError) as exc_info:
            check_sensitive_columns(tree)
        assert exc_info.value.code == "FUNCTION_DENIED"

    def test_substring_on_sensitive_denied(self):
        tree = _parse("SELECT SUBSTRING(customer_name, 1, 3) FROM dws_example_summary WHERE n_year = 2026")
        with pytest.raises(GatewayDeniedError) as exc_info:
            check_sensitive_columns(tree)
        assert exc_info.value.code == "FUNCTION_DENIED"


class TestOrderByDenied:
    """敏感列禁止在 ORDER BY 中使用"""

    def test_order_by_sensitive_denied(self):
        tree = _parse("SELECT customer_name FROM dws_example_summary WHERE n_year = 2026 ORDER BY customer_name")
        with pytest.raises(GatewayDeniedError) as exc_info:
            check_sensitive_columns(tree)
        assert exc_info.value.code == "COLUMN_DENIED"


class TestCaseExpressionDenied:
    """敏感列禁止在 CASE 表达式中使用"""

    def test_case_with_sensitive_denied(self):
        tree = _parse("""
            SELECT CASE WHEN customer_name = 'A' THEN 1 ELSE 0 END
            FROM dws_example_summary WHERE n_year = 2026
        """)
        with pytest.raises(GatewayDeniedError) as exc_info:
            check_sensitive_columns(tree)
        assert exc_info.value.code == "COLUMN_DENIED"


class TestArithmeticDenied:
    """敏感列禁止在算术表达式中使用"""

    def test_concat_sensitive_denied(self):
        tree = _parse("SELECT CONCAT(customer_name, '_suffix') FROM dws_example_summary WHERE n_year = 2026")
        with pytest.raises(GatewayDeniedError) as exc_info:
            check_sensitive_columns(tree)
        assert exc_info.value.code == "FUNCTION_DENIED"

    def test_add_sensitive_denied(self):
        tree = _parse("SELECT customer_name + 1 FROM dws_example_summary WHERE n_year = 2026")
        with pytest.raises(GatewayDeniedError) as exc_info:
            check_sensitive_columns(tree)
        assert exc_info.value.code == "COLUMN_DENIED"


class TestHavingDenied:
    """HAVING 中敏感列非聚合引用"""

    def test_having_raw_sensitive_denied(self):
        tree = _parse("""
            SELECT customer_name, SUM(amount)
            FROM dws_example_summary
            WHERE n_year = 2026
            GROUP BY customer_name
            HAVING customer_name = 'A'
        """)
        with pytest.raises(GatewayDeniedError) as exc_info:
            check_sensitive_columns(tree)
        assert exc_info.value.code == "COLUMN_DENIED"

    def test_having_aggregate_ok(self):
        tree = _parse("""
            SELECT customer_name, SUM(amount)
            FROM dws_example_summary
            WHERE n_year = 2026
            GROUP BY customer_name
            HAVING SUM(amount) > 100
        """)
        check_sensitive_columns(tree)
