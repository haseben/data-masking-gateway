"""SQL 安全校验引擎 — 基于 SQLGlot AST 解析，支持多数据库方言

通过 dialect 参数适配不同数据库（MySQL: "mysql", SQL Server: "tsql"），
所有 sqlglot.parse() 和 tree.sql() 调用均使用传入的 dialect。
"""
import re

import sqlglot
from sqlglot import exp

from security.errors import GatewayDeniedError
from security.column_tracker import check_sensitive_columns
from auth.roles import get_large_tables, get_large_table_filter_columns

# 各数据库禁止访问的系统库
_FORBIDDEN_SCHEMAS = {
    "mysql": {"mysql", "sys", "performance_schema", "information_schema"},
    "tsql": {"master", "tempdb", "model", "msdb", "information_schema"},
}

# 各数据库禁止的危险函数/存储过程
_DANGEROUS_FUNCTIONS = {
    "mysql": {
        "load_file", "sleep", "benchmark",
        "get_lock", "release_lock", "is_free_lock", "is_used_lock",
        "sys_exec", "sys_eval", "sys_get",
        "into_outfile", "into_dumpfile",
    },
    "tsql": {
        "xp_cmdshell", "xp_regread", "xp_regwrite", "xp_regdeletevalue",
        "xp_servicecontrol", "xp_terminate_process",
        "sp_oacreate", "sp_oamethod", "sp_oagetproperty", "sp_oasetproperty",
        "openrowset", "opendatasource",
        "bulk_insert",
        "sp_configure", "sp_executesql",
    },
}

# SQL Server 锁提示（WITH (NOLOCK) 等）
_SQLSERVER_LOCK_HINTS = re.compile(
    r"WITH\s*\(\s*(NOLOCK|UPDLOCK|XLOCK|ROWLOCK|TABLOCK|PAGLOCK|HOLDLOCK|SERIALIZABLE)",
    re.IGNORECASE,
)


def _get_forbidden_schemas(dialect: str) -> set[str]:
    """获取指定 dialect 的禁止系统库集合"""
    return _FORBIDDEN_SCHEMAS.get(dialect, _FORBIDDEN_SCHEMAS["mysql"])


def _get_dangerous_functions(dialect: str) -> set[str]:
    """获取指定 dialect 的危险函数集合"""
    return _DANGEROUS_FUNCTIONS.get(dialect, _DANGEROUS_FUNCTIONS["mysql"])


def validate_sql(sql: str, role_config: dict, dialect: str = "mysql") -> str:
    """
    校验 SQL 安全性，返回可能被修改的 SQL（注入/覆盖 LIMIT）。

    Args:
        sql: 用户提交的原始 SQL
        role_config: 当前角色的权限配置
        dialect: sqlglot 方言（"mysql" / "tsql" / "postgres"）

    Returns:
        经过 LIMIT 处理后的安全 SQL

    Raises:
        GatewayDeniedError: 校验不通过时抛出
    """
    # 1. SQLGlot 解析
    try:
        expressions = sqlglot.parse(sql, dialect=dialect)
    except sqlglot.errors.ParseError:
        raise GatewayDeniedError("SYNTAX_ERROR")

    # 多语句检查
    valid_exprs = [e for e in expressions if e is not None]
    if len(valid_exprs) != 1:
        raise GatewayDeniedError("MULTI_STATEMENT")

    tree = valid_exprs[0]

    # 2. 语句类型检查
    _check_statement_type(tree, role_config, dialect)

    # 3. 用户变量检查
    _check_user_variables(tree, dialect)

    # 4. FOR UPDATE 检查
    _check_for_update(tree, dialect)

    # 5. 危险函数检查
    _check_dangerous_functions(tree, dialect)

    # 6. 表名白名单校验
    _check_tables(tree, role_config, dialect)

    # 7. UNION 检查
    _check_union(tree, role_config)

    # 8. 敏感列使用约束
    if isinstance(tree, exp.Select) or tree.find(exp.Select):
        check_sensitive_columns(tree)

    # 9. 大表必要过滤条件
    _check_large_table_filter(tree)

    # 10. LIMIT 强制处理
    sql_out = _enforce_limit(tree, role_config, dialect)

    return sql_out


def _check_statement_type(tree: exp.Expression, role_config: dict, dialect: str) -> None:
    """只允许 SELECT 和普通 EXPLAIN"""
    if isinstance(tree, exp.Select):
        return

    if isinstance(tree, exp.Union):
        return

    if isinstance(tree, exp.Subquery):
        return

    if isinstance(tree, exp.Command):
        cmd_text = tree.this
        if isinstance(cmd_text, str) and cmd_text.upper() == "EXPLAIN":
            if not role_config.get("allow_explain", False):
                raise GatewayDeniedError("STATEMENT_DENIED", "当前角色不允许 EXPLAIN")
            sql_text = tree.sql(dialect=dialect).upper()
            if "ANALYZE" in sql_text:
                raise GatewayDeniedError("EXPLAIN_ANALYZE_DENIED")
            return

    if isinstance(tree, exp.Describe):
        if not role_config.get("allow_explain", False):
            raise GatewayDeniedError("STATEMENT_DENIED", "当前角色不允许 DESCRIBE")
        return

    raise GatewayDeniedError("STATEMENT_DENIED")


def _check_user_variables(tree: exp.Expression, dialect: str) -> None:
    """禁止用户变量 @var（MySQL 语法）"""
    sql_text = tree.sql(dialect=dialect)
    if re.search(r"(?<!@)@[a-zA-Z_]", sql_text):
        raise GatewayDeniedError("USER_VARIABLE_DENIED")


def _check_for_update(tree: exp.Expression, dialect: str) -> None:
    """禁止 FOR UPDATE / LOCK IN SHARE MODE / SQL Server 锁提示"""
    if tree.find(exp.Lock):
        raise GatewayDeniedError("FOR_UPDATE_DENIED")
    sql_upper = tree.sql(dialect=dialect).upper()
    if "FOR UPDATE" in sql_upper or "LOCK IN SHARE MODE" in sql_upper:
        raise GatewayDeniedError("FOR_UPDATE_DENIED")

    # SQL Server 锁提示：WITH (NOLOCK/UPDLOCK/XLOCK/...)
    if dialect == "tsql":
        if _SQLSERVER_LOCK_HINTS.search(sql_upper):
            raise GatewayDeniedError("FOR_UPDATE_DENIED")


def _check_dangerous_functions(tree: exp.Expression, dialect: str) -> None:
    """禁止危险函数调用"""
    dangerous = _get_dangerous_functions(dialect)

    for func_node in tree.find_all(exp.Anonymous):
        if func_node.name.lower() in dangerous:
            raise GatewayDeniedError(
                "DANGEROUS_FUNCTION", func_node.name
            )

    for func_node in tree.find_all(exp.Func):
        func_name = type(func_node).__name__.lower()
        if func_name in dangerous:
            raise GatewayDeniedError(
                "DANGEROUS_FUNCTION", func_name
            )

    # 检查 SQL 文本中的危险关键字（INTO OUTFILE、BULK INSERT 等）
    sql_upper = tree.sql(dialect=dialect).upper()
    if dialect == "mysql":
        if "INTO OUTFILE" in sql_upper or "INTO DUMPFILE" in sql_upper:
            raise GatewayDeniedError("DANGEROUS_FUNCTION", "INTO OUTFILE/DUMPFILE")
    elif dialect == "tsql":
        if "BULK INSERT" in sql_upper:
            raise GatewayDeniedError("DANGEROUS_FUNCTION", "BULK INSERT")


def _check_tables(tree: exp.Expression, role_config: dict, dialect: str) -> None:
    """表名白名单校验 + schema/catalog 校验（防止跨库查询）

    MySQL 两段式名称 database.table：
      - table_node.db = database（数据库名）

    T-SQL 三段式名称 database.schema.table：
      - table_node.catalog = database（数据库名）
      - table_node.db = schema（如 dbo）
    """
    allowed = {t.lower() for t in role_config.get("allowed_tables", [])}
    forbidden_schemas = _get_forbidden_schemas(dialect)

    # 获取配置的数据源 database（用于校验跨库查询）
    from config import get_datasource_config
    configured_databases: set[str] = set()
    for ds in get_datasource_config().get("datasources", []):
        db = ds.get("database", "")
        if db:
            configured_databases.add(db.lower())

    for table_node in tree.find_all(exp.Table):
        if dialect == "tsql":
            # T-SQL: catalog = database, db = schema (dbo)
            catalog = table_node.catalog  # 数据库名
            schema = table_node.db        # schema 名（如 dbo）

            # 校验 schema 是否为系统 schema
            if schema and schema.lower() in forbidden_schemas:
                raise GatewayDeniedError("SYSTEM_TABLE_DENIED", schema)

            # 校验 catalog（database）是否在配置的数据源中
            if catalog and configured_databases:
                if catalog.lower() not in configured_databases:
                    raise GatewayDeniedError(
                        "TABLE_NOT_ALLOWED",
                        f"跨库查询被拒绝: database '{catalog}' 不在配置的数据源中",
                    )
        else:
            # MySQL: db = database
            schema = table_node.db
            if schema and schema.lower() in forbidden_schemas:
                raise GatewayDeniedError("SYSTEM_TABLE_DENIED", schema)

            if schema and configured_databases:
                if schema.lower() not in configured_databases:
                    raise GatewayDeniedError(
                        "TABLE_NOT_ALLOWED",
                        f"跨库查询被拒绝: schema '{schema}' 不在配置的数据源中",
                    )

        table_name = table_node.name.lower()

        if table_name in forbidden_schemas:
            raise GatewayDeniedError("SYSTEM_TABLE_DENIED", table_name)

        if table_name not in allowed:
            raise GatewayDeniedError(
                "TABLE_NOT_ALLOWED", table_node.name
            )


def _check_union(tree: exp.Expression, role_config: dict) -> None:
    """UNION 校验：角色允许时放行，但限制嵌套深度。"""
    union_node = tree.find(exp.Union)
    if union_node is None:
        return

    if not role_config.get("allow_union", False):
        raise GatewayDeniedError("UNION_DENIED")

    max_depth = role_config.get("max_union_depth", 2)
    depth = _count_union_depth(tree)
    if depth > max_depth:
        raise GatewayDeniedError(
            "UNION_DENIED",
            f"UNION 嵌套深度 {depth} 超过限制 {max_depth}",
        )


def _count_union_depth(node: exp.Expression) -> int:
    """计算 UNION 嵌套深度（顶层 UNION = 1）"""
    if not isinstance(node, exp.Union):
        inner = node.find(exp.Union)
        if inner is None:
            return 0
        return _count_union_depth(inner)

    depth = 1
    for child in (node.this, node.expression):
        if isinstance(child, exp.Union):
            depth = max(depth, 1 + _count_union_depth(child))
    return depth


def _check_large_table_filter(tree: exp.Expression) -> None:
    """大表查询必须包含时间过滤条件"""
    large_tables = get_large_tables()
    filter_cols = get_large_table_filter_columns()

    referenced_tables = set()
    for table_node in tree.find_all(exp.Table):
        referenced_tables.add(table_node.name.lower())

    large_tables_used = referenced_tables & large_tables
    if not large_tables_used:
        return

    where = tree.find(exp.Where)
    if where is None:
        raise GatewayDeniedError(
            "FILTER_REQUIRED",
            f"查询涉及大表 {', '.join(large_tables_used)}，必须包含时间过滤条件",
        )

    where_columns = {col.name.lower() for col in where.find_all(exp.Column)}
    if not where_columns & filter_cols:
        raise GatewayDeniedError(
            "FILTER_REQUIRED",
            f"查询涉及大表 {', '.join(large_tables_used)}，WHERE 中必须包含时间过滤",
        )


def _enforce_limit(tree: exp.Expression, role_config: dict, dialect: str) -> str:
    """AST 层面强制 LIMIT 不超过 max_rows

    sqlglot 会根据 dialect 自动转换 LIMIT 语法：
      MySQL  → LIMIT N
      T-SQL  → TOP N
    """
    max_rows = role_config.get("max_rows", 1000)

    if not isinstance(tree, exp.Select):
        return tree.sql(dialect=dialect)

    existing_limit = tree.args.get("limit")
    if existing_limit:
        limit_expr = existing_limit.expression
        if isinstance(limit_expr, exp.Literal) and limit_expr.is_int:
            user_limit = int(limit_expr.this)
            if user_limit > max_rows:
                tree.set("limit", exp.Limit(expression=exp.Literal.number(max_rows)))
        else:
            tree.set("limit", exp.Limit(expression=exp.Literal.number(max_rows)))
    else:
        tree.set("limit", exp.Limit(expression=exp.Literal.number(max_rows)))

    return tree.sql(dialect=dialect)


def normalize_sql_for_audit(tree: exp.Expression, dialect: str = "mysql") -> str:
    """
    生成规范化 SQL 用于审计日志：字面量替换为 ?
    不记录实际筛选值。
    """
    import copy
    audit_tree = tree.copy()
    for literal in audit_tree.find_all(exp.Literal):
        literal.replace(exp.Placeholder())
    return audit_tree.sql(dialect=dialect)


# 允许的聚合函数类型（产出数值，不泄露原始文本）
# MIN/MAX 可返回字符串值，不加入安全聚合列表，
# 其别名不会被自动放行，需通过脱敏规则匹配。
# column_tracker 仍禁止敏感列出现在任何函数（含 MIN/MAX）参数中。
_SAFE_AGG_TYPES = (exp.Count, exp.Sum, exp.Avg)


def extract_column_aliases(sql: str, dialect: str = "mysql") -> dict[str, str]:
    """
    从 SQL AST 提取输出别名 -> 源列名的映射（均小写）。

    防止通过别名绕过脱敏：
        SELECT customer_name AS amount FROM t
    数据库返回字段名为 "amount"，但数据实际来自 customer_name。
    本函数返回 {"amount": "customer_name"}，供 apply_masking 按源列名匹配规则。

    **递归分析所有 SELECT 节点**（包括子查询和 CTE），防止嵌套查询绕过：
        SELECT amount FROM (SELECT customer_name AS amount FROM t) s
    内层子查询将 customer_name 别名为 amount，外层直接引用 amount。
    本函数会收集所有 SELECT 层级的别名映射，确保 apply_masking
    能追溯到真正的源列名。

    仅处理 "简单列 AS 别名" 的情况。表达式别名（如 CONCAT(...) AS x）
    已被 column_tracker 在 SQL 校验阶段拦截，无需此处处理。
    """
    try:
        expressions = sqlglot.parse(sql, dialect=dialect)
    except sqlglot.errors.ParseError:
        return {}

    if not expressions or not expressions[0]:
        return {}

    tree = expressions[0]

    aliases: dict[str, str] = {}

    # 遍历所有 SELECT 节点（外层 + 子查询 + CTE），收集全部别名映射
    for select_node in tree.find_all(exp.Select):
        for projection in select_node.expressions:
            if isinstance(projection, exp.Alias):
                alias_name = projection.alias
                inner = projection.this
                if isinstance(inner, exp.Column):
                    key = alias_name.lower()
                    # 首次出现优先（外层 SELECT 的别名更接近实际输出列名）
                    if key not in aliases:
                        aliases[key] = inner.name.lower()

    return aliases


def _is_safe_numeric_expression(expr: exp.Expression) -> bool:
    """检查表达式是否仅由安全聚合、数值常量和数值运算组成。

    安全条件（全部满足）：
      1. 所有 Column 节点必须位于安全聚合（COUNT/SUM/AVG）内部
      2. 不含 GROUP_CONCAT 等文本拼接聚合
      3. 不含 CASE/CONCAT 等可能泄露原始值的表达式

    安全示例：
      COUNT(*)、SUM(amount)、ROUND(SUM(amount), 2)、COUNT(*) + 1
    不安全示例：
      CONCAT(COUNT(*), ':', secret_col)  — secret_col 在聚合外部
      COUNT(*) + secret_col              — secret_col 在聚合外部
    """
    # 安全聚合：内部所有列已被聚合，整体安全
    if isinstance(expr, _SAFE_AGG_TYPES):
        return True

    # 裸列引用（在聚合外部）：不安全
    if isinstance(expr, exp.Column):
        return False

    # 字面量、占位符：安全
    if isinstance(expr, (exp.Literal, exp.Placeholder)):
        return True

    # Star (*)：安全（如 COUNT(*) 中的 *）
    if isinstance(expr, exp.Star):
        return True

    # 禁止的类型：CASE、CONCAT、DPipe（字符串拼接）等
    if isinstance(expr, (exp.Case, exp.Concat, exp.DPipe)):
        return False

    # 对于其他节点（算术运算、ROUND 等数值包装函数），
    # 递归检查所有子节点：任一子节点不安全则整体不安全
    for child in expr.args.values():
        if child is None:
            continue
        if isinstance(child, list):
            for item in child:
                if isinstance(item, exp.Expression) and not _is_safe_numeric_expression(item):
                    return False
        elif isinstance(child, exp.Expression):
            if not _is_safe_numeric_expression(child):
                return False
    return True


def extract_aggregate_aliases(sql: str, dialect: str = "mysql") -> set[str]:
    """
    从 SQL 的 SELECT 列表中提取**纯数值聚合**的输出别名（小写）。

    这些别名对应的表达式仅包含 COUNT/SUM/AVG 及数值常量/运算，
    可安全 passthrough 而不触发 unknown_column: deny。

    **严格检查整个表达式树**：如果表达式中存在聚合外部的裸列引用，
    则不视为安全别名。防止如下绕过：
        SELECT CONCAT(COUNT(*), ':', unknown_secret) AS total_count
    """
    try:
        expressions = sqlglot.parse(sql, dialect=dialect)
    except sqlglot.errors.ParseError:
        return set()

    if not expressions or not expressions[0]:
        return set()

    tree = expressions[0]

    select_node = tree if isinstance(tree, exp.Select) else tree.find(exp.Select)
    if select_node is None:
        return set()

    aliases: set[str] = set()
    for projection in select_node.expressions:
        alias = projection.alias
        if not alias:
            continue

        inner = projection.this if isinstance(projection, exp.Alias) else projection

        # 严格检查：整个表达式树只允许安全聚合 + 数值常量 + 数值运算
        if _is_safe_numeric_expression(inner):
            aliases.add(alias.lower())

    return aliases
