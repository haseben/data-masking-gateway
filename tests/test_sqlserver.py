"""SQL Server (T-SQL) 支持测试

覆盖：
  1. config.py 方言映射
  2. db.py 占位符转换、数据源类型解析
  3. sql_validator.py SQL Server 专属安全规则
     - 系统库拒绝 (master/tempdb/model/msdb)
     - 危险存储过程/函数 (xp_cmdshell/sp_oacreate/openrowset...)
     - 锁提示拒绝 (WITH (NOLOCK) 等)
     - BULK INSERT 拒绝
  4. LIMIT → TOP 自动转换
  5. 列别名血缘追踪 (tsql 方言)
  6. 跨方言兼容性 (MySQL 测试不受 tsql 影响)
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# 设置测试用 HMAC 密钥
import os
os.environ["HMAC_SECRET"] = "test_secret_key_for_unit_tests_only_32bytes!"

from config import (
    get_dialect_for_datasource,
    get_datasource_type,
    get_datasource_config,
    _load_yaml,
)
from db import _convert_placeholders, get_pool_type, resolve_datasource
from security.sql_validator import (
    validate_sql,
    normalize_sql_for_audit,
    extract_column_aliases,
    extract_aggregate_aliases,
    _get_forbidden_schemas,
    _get_dangerous_functions,
)
from security.errors import GatewayDeniedError
from auth.roles import get_roles

ROLES = get_roles()
DEV_ROLE = ROLES["developer"]
VIEWER_ROLE = ROLES["viewer"]

# SQL Server dialect 常量
TSQL = "tsql"
MYSQL = "mysql"


# ══════════════════════════════════════════════════════════════
# 1. config.py 方言映射
# ══════════════════════════════════════════════════════════════

class TestDialectMapping:
    """config.py 方言映射测试"""

    def test_mysql_maps_to_mysql(self):
        assert get_dialect_for_datasource("default") == "mysql"

    def test_get_datasource_type_mysql(self):
        assert get_datasource_type("default") == "mysql"

    def test_unknown_datasource_defaults_mysql(self):
        assert get_dialect_for_datasource("nonexistent") == "mysql"
        assert get_datasource_type("nonexistent") == "mysql"

    def test_dialect_map_covers_sqlserver(self):
        """验证 _DIALECT_MAP 包含 sqlserver → tsql 映射"""
        from config import _DIALECT_MAP
        assert _DIALECT_MAP.get("sqlserver") == "tsql"
        assert _DIALECT_MAP.get("mssql") == "tsql"
        assert _DIALECT_MAP.get("mysql") == "mysql"
        assert _DIALECT_MAP.get("mariadb") == "mysql"


class TestDialectMappingWithSqlserverConfig:
    """使用模拟 SQL Server 数据源配置测试方言映射"""

    _MOCK_YAML = """# 模拟数据源配置（测试用）
datasources:
  - name: default
    type: mysql
    host: 127.0.0.1
    port: 3306
    user: readonly_user
    password: "${DB_PASSWORD}"
    database: your_database
    charset: utf8mb4
    minsize: 2
    maxsize: 10
  - name: sqlserver_ds
    type: sqlserver
    host: 127.0.0.1
    port: 1433
    user: sa
    password: "${DB_PASSWORD}"
    database: testdb
    driver: "ODBC Driver 18 for SQL Server"

table_routing:
  - pattern: "*"
    datasource: default
"""

    def setup_method(self):
        """清除 lru_cache，使后续读取使用修改后的配置"""
        _load_yaml.cache_clear()
        get_datasource_config.cache_clear()
        ds_path = Path(__file__).parent.parent / "config" / "datasource.yaml"
        self._original_content = None
        if ds_path.exists():
            self._original_content = ds_path.read_text(encoding="utf-8")
        ds_path.write_text(self._MOCK_YAML, encoding="utf-8")

    def teardown_method(self):
        """恢复原始配置文件"""
        ds_path = Path(__file__).parent.parent / "config" / "datasource.yaml"
        if self._original_content is not None:
            ds_path.write_text(self._original_content, encoding="utf-8")
        _load_yaml.cache_clear()
        get_datasource_config.cache_clear()

    def test_sqlserver_datasource_type(self):
        assert get_datasource_type("sqlserver_ds") == "sqlserver"

    def test_sqlserver_dialect_is_tsql(self):
        assert get_dialect_for_datasource("sqlserver_ds") == "tsql"

    def test_pool_type_from_config(self):
        """get_pool_type 在连接池未创建时从配置读取"""
        assert get_pool_type("sqlserver_ds") == "sqlserver"
        assert get_pool_type("default") == "mysql"


# ══════════════════════════════════════════════════════════════
# 2. db.py 占位符转换
# ══════════════════════════════════════════════════════════════

class TestPlaceholderConversion:
    """db.py %s → ? 占位符转换"""

    def test_mysql_placeholders_unchanged(self):
        sql = "SELECT * FROM t WHERE id = %s AND name = %s"
        assert _convert_placeholders(sql, "mysql") == sql

    def test_mariadb_placeholders_unchanged(self):
        sql = "SELECT * FROM t WHERE id = %s"
        assert _convert_placeholders(sql, "mariadb") == sql

    def test_sqlserver_placeholders_converted(self):
        sql = "SELECT * FROM t WHERE id = %s AND name = %s"
        expected = "SELECT * FROM t WHERE id = ? AND name = ?"
        assert _convert_placeholders(sql, "sqlserver") == expected

    def test_mssql_placeholders_converted(self):
        sql = "SELECT * FROM t WHERE id = %s"
        expected = "SELECT * FROM t WHERE id = ?"
        assert _convert_placeholders(sql, "mssql") == expected

    def test_no_placeholders_unchanged(self):
        sql = "SELECT 1"
        assert _convert_placeholders(sql, "sqlserver") == sql

    def test_multiple_placeholders_all_converted(self):
        sql = "INSERT INTO t VALUES (%s, %s, %s, %s)"
        result = _convert_placeholders(sql, "sqlserver")
        assert result.count("?") == 4
        assert "%s" not in result


# ══════════════════════════════════════════════════════════════
# 3. sql_validator.py SQL Server 安全规则
# ══════════════════════════════════════════════════════════════

class TestSqlserverSystemSchemas:
    """SQL Server 系统库拒绝"""

    def test_master_db_denied(self):
        sql = "SELECT * FROM dws_example_summary WHERE n_year = 2026"
        # 模拟跨库查询 master
        sql_cross = "SELECT * FROM master..sysobjects"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql_cross, DEV_ROLE, dialect=TSQL)
        assert exc_info.value.code in ("SYSTEM_TABLE_DENIED", "TABLE_NOT_ALLOWED")

    def test_tempdb_denied(self):
        sql = "SELECT * FROM tempdb..sysobjects"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE, dialect=TSQL)
        assert exc_info.value.code in ("SYSTEM_TABLE_DENIED", "TABLE_NOT_ALLOWED")

    def test_model_db_denied(self):
        sql = "SELECT * FROM model..sysobjects"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE, dialect=TSQL)
        assert exc_info.value.code in ("SYSTEM_TABLE_DENIED", "TABLE_NOT_ALLOWED")

    def test_msdb_denied(self):
        sql = "SELECT * FROM msdb..sysjobs"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE, dialect=TSQL)
        assert exc_info.value.code in ("SYSTEM_TABLE_DENIED", "TABLE_NOT_ALLOWED")

    def test_mysql_system_schemas_not_in_tsql_set(self):
        """MySQL 系统库不应出现在 T-SQL 禁止列表中"""
        tsql_forbidden = _get_forbidden_schemas(TSQL)
        assert "mysql" not in tsql_forbidden
        assert "master" in tsql_forbidden

    def test_mysql_system_schemas_in_mysql_set(self):
        mysql_forbidden = _get_forbidden_schemas(MYSQL)
        assert "mysql" in mysql_forbidden
        assert "master" not in mysql_forbidden


class TestSqlserverDangerousFunctions:
    """SQL Server 危险存储过程/函数拒绝"""

    def test_xp_cmdshell_denied(self):
        sql = "SELECT * FROM dws_example_summary WHERE n_year = 2026; EXEC xp_cmdshell 'dir'"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE, dialect=TSQL)
        # 多语句或危险函数
        assert exc_info.value.code in ("DANGEROUS_FUNCTION", "MULTI_STATEMENT", "STATEMENT_DENIED")

    def test_sp_oacreate_denied(self):
        sql = "EXEC sp_oacreate 'Scripting.FileSystemObject'"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE, dialect=TSQL)
        assert exc_info.value.code in ("DANGEROUS_FUNCTION", "STATEMENT_DENIED")

    def test_openrowset_denied(self):
        sql = "SELECT * FROM OPENROWSET('SQLNCLI', 'server=.;uid=sa;pwd=pass', 'SELECT 1')"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE, dialect=TSQL)
        assert exc_info.value.code in ("DANGEROUS_FUNCTION", "TABLE_NOT_ALLOWED")

    def test_opendatasource_denied(self):
        sql = "SELECT * FROM OPENDATASOURCE('SQLNCLI', 'Data Source=server;User ID=sa;Password=pass').db.dbo.t"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE, dialect=TSQL)
        assert exc_info.value.code in ("DANGEROUS_FUNCTION", "TABLE_NOT_ALLOWED")

    def test_bulk_insert_denied(self):
        sql = "BULK INSERT dws_example_summary FROM 'C:\\evil.csv'"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE, dialect=TSQL)
        # sqlglot tsql 可能无法解析 BULK INSERT → SYNTAX_ERROR
        # 或解析成功后被 DANGEROUS_FUNCTION/STATEMENT_DENIED 拦截
        assert exc_info.value.code in ("DANGEROUS_FUNCTION", "STATEMENT_DENIED", "SYNTAX_ERROR")

    def test_sp_configure_denied(self):
        sql = "EXEC sp_configure 'show advanced options', 1"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE, dialect=TSQL)
        assert exc_info.value.code in ("DANGEROUS_FUNCTION", "STATEMENT_DENIED")

    def test_sp_executesql_denied(self):
        sql = "EXEC sp_executesql N'SELECT 1'"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE, dialect=TSQL)
        assert exc_info.value.code in ("DANGEROUS_FUNCTION", "STATEMENT_DENIED")

    def test_mysql_functions_not_in_tsql_set(self):
        """MySQL 危险函数不应出现在 T-SQL 禁止列表中"""
        tsql_dangerous = _get_dangerous_functions(TSQL)
        assert "sleep" not in tsql_dangerous
        assert "xp_cmdshell" in tsql_dangerous

    def test_mysql_dangerous_in_mysql_set(self):
        mysql_dangerous = _get_dangerous_functions(MYSQL)
        assert "sleep" in mysql_dangerous
        assert "xp_cmdshell" not in mysql_dangerous

    def test_mysql_sleep_still_denied_in_mysql_dialect(self):
        """确保 MySQL 方言下 SLEEP 仍被拒绝"""
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(
                "SELECT SLEEP(10) FROM dws_example_summary WHERE n_year = 2026",
                DEV_ROLE, dialect=MYSQL,
            )
        assert exc_info.value.code == "DANGEROUS_FUNCTION"


class TestSqlserverLockHints:
    """SQL Server 锁提示拒绝 (WITH (NOLOCK) 等)"""

    def test_nolock_denied(self):
        sql = "SELECT * FROM dws_example_summary WITH (NOLOCK) WHERE n_year = 2026"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE, dialect=TSQL)
        assert exc_info.value.code == "FOR_UPDATE_DENIED"

    def test_updlock_denied(self):
        sql = "SELECT * FROM dws_example_summary WITH (UPDLOCK) WHERE n_year = 2026"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE, dialect=TSQL)
        assert exc_info.value.code == "FOR_UPDATE_DENIED"

    def test_xlock_denied(self):
        sql = "SELECT * FROM dws_example_summary WITH (XLOCK) WHERE n_year = 2026"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE, dialect=TSQL)
        assert exc_info.value.code == "FOR_UPDATE_DENIED"

    def test_tablock_denied(self):
        sql = "SELECT * FROM dws_example_summary WITH (TABLOCK) WHERE n_year = 2026"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE, dialect=TSQL)
        assert exc_info.value.code == "FOR_UPDATE_DENIED"

    def test_holdlock_denied(self):
        sql = "SELECT * FROM dws_example_summary WITH (HOLDLOCK) WHERE n_year = 2026"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE, dialect=TSQL)
        assert exc_info.value.code == "FOR_UPDATE_DENIED"

    def test_serializable_hint_denied(self):
        sql = "SELECT * FROM dws_example_summary WITH (SERIALIZABLE) WHERE n_year = 2026"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE, dialect=TSQL)
        assert exc_info.value.code == "FOR_UPDATE_DENIED"

    def test_nolock_not_denied_in_mysql_dialect(self):
        """MySQL 方言下 WITH (NOLOCK) 不触发锁提示检查（但可能被表名校验拒绝）"""
        # MySQL 不识别 WITH (NOLOCK)，不会触发 _SQLSERVER_LOCK_HINTS
        # 但 sqlglot mysql 方言解析可能报语法错误或表名不匹配
        # 关键是不会以 FOR_UPDATE_DENIED 拒绝
        try:
            validate_sql(
                "SELECT * FROM dws_example_summary WITH (NOLOCK) WHERE n_year = 2026",
                DEV_ROLE, dialect=MYSQL,
            )
        except GatewayDeniedError as e:
            assert e.code != "FOR_UPDATE_DENIED"


class TestSqlserverForUpdate:
    """FOR UPDATE 在 T-SQL 方言下仍被拒绝"""

    def test_for_update_denied_tsql(self):
        sql = "SELECT * FROM dws_example_summary WHERE n_year = 2026 FOR UPDATE"
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(sql, DEV_ROLE, dialect=TSQL)
        # T-SQL 不支持 FOR UPDATE 语法，sqlglot 可能解析失败
        # 或解析成功后被 FOR_UPDATE_DENIED 拦截
        assert exc_info.value.code in ("FOR_UPDATE_DENIED", "SYNTAX_ERROR")


# ══════════════════════════════════════════════════════════════
# 4. LIMIT → TOP 自动转换
# ══════════════════════════════════════════════════════════════

class TestSqlserverLimitConversion:
    """T-SQL 方言下 LIMIT 自动转换为 TOP"""

    def test_no_limit_injects_top(self):
        sql = "SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2026"
        result = validate_sql(sql, DEV_ROLE, dialect=TSQL)
        # T-SQL 使用 TOP N 而非 LIMIT N
        assert "TOP" in result.upper()
        assert "5000" in result  # developer max_rows

    def test_excessive_limit_capped_tsql(self):
        sql = "SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2026 LIMIT 99999"
        result = validate_sql(sql, DEV_ROLE, dialect=TSQL)
        assert "5000" in result
        assert "99999" not in result

    def test_small_limit_preserved_tsql(self):
        sql = "SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2026 LIMIT 100"
        result = validate_sql(sql, DEV_ROLE, dialect=TSQL)
        # 100 保留，但以 TOP 形式输出
        assert "100" in result

    def test_viewer_limit_capped_tsql(self):
        sql = "SELECT n_year FROM v_example_view WHERE n_year = 2026 LIMIT 5000"
        result = validate_sql(sql, VIEWER_ROLE, dialect=TSQL)
        assert "1000" in result  # viewer max_rows

    def test_top_not_limit_in_output(self):
        """T-SQL 输出应包含 TOP 而非 LIMIT"""
        sql = "SELECT n_year FROM dws_example_summary WHERE n_year = 2026"
        result = validate_sql(sql, DEV_ROLE, dialect=TSQL)
        result_upper = result.upper()
        assert "TOP" in result_upper
        # sqlglot tsql 方言应输出 TOP 而非 LIMIT
        assert "LIMIT" not in result_upper


# ══════════════════════════════════════════════════════════════
# 5. 列别名血缘追踪 (tsql 方言)
# ══════════════════════════════════════════════════════════════

class TestSqlserverColumnAliases:
    """T-SQL 方言下的列别名提取"""

    def test_simple_alias_tsql(self):
        sql = "SELECT customer_name AS amount FROM dws_example_summary WHERE n_year = 2026"
        aliases = extract_column_aliases(sql, dialect=TSQL)
        assert "amount" in aliases
        assert aliases["amount"] == "customer_name"

    def test_no_alias_tsql(self):
        sql = "SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2026"
        aliases = extract_column_aliases(sql, dialect=TSQL)
        assert len(aliases) == 0

    def test_multiple_aliases_tsql(self):
        sql = """
            SELECT
                customer_name AS col_a,
                phone_number AS col_b,
                n_year AS col_c
            FROM dws_example_summary WHERE n_year = 2026
        """
        aliases = extract_column_aliases(sql, dialect=TSQL)
        assert aliases.get("col_a") == "customer_name"
        assert aliases.get("col_b") == "phone_number"
        assert aliases.get("col_c") == "n_year"

    def test_aggregate_aliases_tsql(self):
        sql = """
            SELECT
                COUNT(*) AS total_count,
                SUM(amount) AS total_amount,
                AVG(amount) AS avg_amount
            FROM dws_example_summary WHERE n_year = 2026
        """
        agg_aliases = extract_aggregate_aliases(sql, dialect=TSQL)
        assert "total_count" in agg_aliases
        assert "total_amount" in agg_aliases
        assert "avg_amount" in agg_aliases

    def test_case_insensitive_alias_tsql(self):
        """别名大小写不敏感（输出小写）"""
        sql = "SELECT customer_name AS MyAlias FROM dws_example_summary WHERE n_year = 2026"
        aliases = extract_column_aliases(sql, dialect=TSQL)
        assert "myalias" in aliases


# ══════════════════════════════════════════════════════════════
# 6. 跨方言兼容性
# ══════════════════════════════════════════════════════════════

class TestCrossDialectCompatibility:
    """确保 MySQL 方言测试不受 SQL Server 改动影响"""

    def test_mysql_select_still_works(self):
        sql = "SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2026"
        result = validate_sql(sql, DEV_ROLE, dialect=MYSQL)
        assert "n_year" in result
        assert "LIMIT" in result.upper()

    def test_mysql_limit_not_top(self):
        """MySQL 方言输出 LIMIT 而非 TOP"""
        sql = "SELECT n_year FROM dws_example_summary WHERE n_year = 2026"
        result = validate_sql(sql, DEV_ROLE, dialect=MYSQL)
        assert "LIMIT" in result.upper()
        assert "TOP" not in result.upper()

    def test_mysql_dangerous_function_still_denied(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(
                "SELECT SLEEP(10) FROM dws_example_summary WHERE n_year = 2026",
                DEV_ROLE, dialect=MYSQL,
            )
        assert exc_info.value.code == "DANGEROUS_FUNCTION"

    def test_tsql_dangerous_function_not_denied_in_mysql(self):
        """xp_cmdshell 在 MySQL 方言下不应被 DANGEROUS_FUNCTION 拒绝
        （但会被 STATEMENT_DENIED 拒绝，因为不是 SELECT）"""
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(
                "EXEC xp_cmdshell 'dir'",
                DEV_ROLE, dialect=MYSQL,
            )
        # 不应该是 DANGEROUS_FUNCTION，因为 MySQL 不检查 xp_cmdshell
        assert exc_info.value.code != "DANGEROUS_FUNCTION"

    def test_same_sql_validates_in_both_dialects(self):
        """同一条标准 SELECT 在两种方言下都能通过"""
        sql = "SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2026"
        mysql_result = validate_sql(sql, DEV_ROLE, dialect=MYSQL)
        tsql_result = validate_sql(sql, DEV_ROLE, dialect=TSQL)
        # 两者都应包含表名
        assert "dws_example_summary" in mysql_result.lower()
        assert "dws_example_summary" in tsql_result.lower()

    def test_normalize_sql_works_with_tsql(self):
        import sqlglot
        sql = "SELECT amount FROM dws_example_summary WHERE n_year = 2026 AND n_period = 6"
        tree = sqlglot.parse(sql, dialect=TSQL)[0]
        normalized = normalize_sql_for_audit(tree, dialect=TSQL)
        assert "2026" not in normalized
        assert "?" in normalized

    def test_normalize_sql_works_with_mysql(self):
        import sqlglot
        sql = "SELECT amount FROM dws_example_summary WHERE n_year = 2026 AND n_period = 6"
        tree = sqlglot.parse(sql, dialect=MYSQL)[0]
        normalized = normalize_sql_for_audit(tree, dialect=MYSQL)
        assert "2026" not in normalized
        assert "?" in normalized


# ══════════════════════════════════════════════════════════════
# 7. 基本语句类型检查 (T-SQL 方言)
# ══════════════════════════════════════════════════════════════

class TestSqlserverStatementTypes:
    """T-SQL 方言下的语句类型检查"""

    def test_select_allowed_tsql(self):
        sql = "SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2026"
        result = validate_sql(sql, DEV_ROLE, dialect=TSQL)
        assert "n_year" in result

    def test_insert_denied_tsql(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(
                "INSERT INTO dws_example_summary VALUES (1)",
                DEV_ROLE, dialect=TSQL,
            )
        assert exc_info.value.code == "STATEMENT_DENIED"

    def test_update_denied_tsql(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(
                "UPDATE dws_example_summary SET amount = 0 WHERE n_year = 2026",
                DEV_ROLE, dialect=TSQL,
            )
        assert exc_info.value.code == "STATEMENT_DENIED"

    def test_delete_denied_tsql(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(
                "DELETE FROM dws_example_summary WHERE n_year = 2026",
                DEV_ROLE, dialect=TSQL,
            )
        assert exc_info.value.code == "STATEMENT_DENIED"

    def test_drop_denied_tsql(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(
                "DROP TABLE dws_example_summary",
                DEV_ROLE, dialect=TSQL,
            )
        assert exc_info.value.code == "STATEMENT_DENIED"

    def test_create_denied_tsql(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(
                "CREATE TABLE hack (id INT)",
                DEV_ROLE, dialect=TSQL,
            )
        assert exc_info.value.code == "STATEMENT_DENIED"

    def test_table_whitelist_enforced_tsql(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(
                "SELECT * FROM some_random_table WHERE n_year = 2026",
                DEV_ROLE, dialect=TSQL,
            )
        assert exc_info.value.code == "TABLE_NOT_ALLOWED"

    def test_union_allowed_tsql(self):
        sql = """SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2026
                 UNION ALL
                 SELECT n_year, amount FROM dws_example_summary WHERE n_year = 2025"""
        result = validate_sql(sql, DEV_ROLE, dialect=TSQL)
        assert "UNION" in result.upper()

    def test_user_variable_denied_tsql(self):
        """MySQL 风格用户变量在 T-SQL 中也应被拒绝"""
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(
                "SELECT @myvar := amount FROM dws_example_summary WHERE n_year = 2026",
                DEV_ROLE, dialect=TSQL,
            )
        # 可能在解析阶段就失败（T-SQL 不支持 := ），也可能被 USER_VARIABLE_DENIED 拦截
        assert exc_info.value.code in ("USER_VARIABLE_DENIED", "SYNTAX_ERROR")


# ══════════════════════════════════════════════════════════════
# 8. 大表过滤条件 (T-SQL 方言)
# ══════════════════════════════════════════════════════════════

class TestSqlserverLargeTableFilter:
    """T-SQL 方言下大表过滤条件检查"""

    def test_large_table_without_filter_denied_tsql(self):
        with pytest.raises(GatewayDeniedError) as exc_info:
            validate_sql(
                "SELECT amount FROM dws_example_bill_detail",
                DEV_ROLE, dialect=TSQL,
            )
        assert exc_info.value.code == "FILTER_REQUIRED"

    def test_large_table_with_year_filter_ok_tsql(self):
        sql = "SELECT amount FROM dws_example_bill_detail WHERE n_year = 2026"
        validate_sql(sql, DEV_ROLE, dialect=TSQL)

    def test_large_table_with_period_filter_ok_tsql(self):
        sql = "SELECT amount FROM dws_example_bill_detail WHERE n_period = 6"
        validate_sql(sql, DEV_ROLE, dialect=TSQL)

    def test_small_table_no_filter_ok_tsql(self):
        sql = "SELECT level_1 FROM dim_example_dimension"
        validate_sql(sql, DEV_ROLE, dialect=TSQL)
