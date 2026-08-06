"""插件安全执行管线 - 所有业务插件必须通过此模块执行查询

强制执行：
  1. 角色认证检查
  2. SQL 安全校验（语句类型、表白名单、危险函数、LIMIT 注入）
  3. 行数限制 + 查询超时
  4. 结果脱敏
  5. 审计日志

支持多数据库方言：根据 SQL 表名路由的数据源类型自动选择 dialect。

使用方式（在插件中）：
    from tools.plugin_base import plugin_query

    rows = await plugin_query(
        sql="SELECT ... FROM ... WHERE ...",
        params=[year],
        tool_name="my_plugin_tool",
    )
"""
import time
import sqlglot

from db import execute_with_limit, current_client, resolve_dialect
from auth.roles import get_role_config
from masking.engine import apply_masking
from security.sql_validator import (
    validate_sql,
    normalize_sql_for_audit,
    extract_column_aliases,
    extract_aggregate_aliases,
)
from security.errors import GatewayDeniedError
from audit.logger import log_query, log_denied

# 角色层级（数值越大权限越高）
_ROLE_RANK = {"viewer": 1, "developer": 2}


def _extract_table_names(sql: str, dialect: str = "mysql") -> list[str]:
    """从 SQL 中提取表名（fail-closed：解析失败时返回 None）"""
    try:
        from sqlglot import exp
        expressions = sqlglot.parse(sql, dialect=dialect)
        if not expressions or not expressions[0]:
            return None  # fail-closed
        tables = set()
        for t in expressions[0].find_all(exp.Table):
            if t.name:
                tables.add(t.name.lower())
        return sorted(tables)
    except Exception:
        return None  # fail-closed：解析失败视为安全风险


def _check_plugin_tables(sql: str, role_config: dict, dialect: str) -> list[str]:
    """校验插件 SQL 中的表是否在角色白名单内（fail-closed）"""
    allowed = {t.lower() for t in role_config.get("allowed_tables", [])}
    tables = _extract_table_names(sql, dialect)

    # fail-closed：无法解析表名时拒绝执行
    if tables is None:
        raise GatewayDeniedError(
            "TABLE_NOT_ALLOWED",
            "插件 SQL 解析失败，无法校验表白名单",
        )

    for tbl in tables:
        if tbl not in allowed:
            raise GatewayDeniedError(
                "TABLE_NOT_ALLOWED",
                f"插件查询涉及表 {tbl}，不在当前角色白名单中",
            )
    return tables


async def plugin_query(
    sql: str,
    params: list | None = None,
    tool_name: str = "plugin",
    require_role: str | None = None,
) -> tuple[list[dict], list[str], bool]:
    """
    插件安全查询执行器。

    Args:
        sql: 参数化 SQL（由插件开发者编写，非用户输入）
        params: 查询参数
        tool_name: 工具名称（用于审计日志）
        require_role: 要求的最低角色层级（如 "developer"），
                      viewer 可访问的工具设为 "viewer" 或 None

    Returns:
        (masked_rows, masked_fields, truncated)

    Raises:
        GatewayDeniedError: 权限不足或表不在白名单
    """
    client = current_client.get()
    if not client:
        raise GatewayDeniedError("ROLE_DENIED", "未认证")

    role_config = get_role_config(client["role"])
    if not role_config:
        raise GatewayDeniedError("ROLE_DENIED", "无效角色")

    # 角色层级检查：require_role 设定最低权限门槛
    if require_role:
        client_rank = _ROLE_RANK.get(client["role"], 0)
        required_rank = _ROLE_RANK.get(require_role, 0)
        if client_rank < required_rank:
            raise GatewayDeniedError(
                "ROLE_DENIED",
                f"工具 {tool_name} 需要 {require_role} 及以上角色",
            )

    client_name = client["client_name"]
    role = client["role"]
    start_time = time.perf_counter()

    # 0. 解析数据库方言
    dialect = resolve_dialect(sql)

    # 1. SQL 安全校验（语句类型、表白名单、危险函数、LIMIT 注入）
    #    插件 SQL 虽由开发者编写，但仍需防止：
    #    - 开发者误写 UPDATE/DELETE
    #    - 表名不在白名单
    #    - 危险函数调用
    try:
        safe_sql = validate_sql(sql, role_config, dialect=dialect)
    except GatewayDeniedError as e:
        # 安全校验失败，记录审计并拒绝
        try:
            expressions = sqlglot.parse(sql, dialect=dialect)
            norm_sql = normalize_sql_for_audit(expressions[0], dialect=dialect) if expressions and expressions[0] else ""
        except Exception:
            norm_sql = ""
        tables = _extract_table_names(sql, dialect) or []
        log_denied(
            client_name=client_name,
            role=role,
            tool=tool_name,
            normalized_sql=norm_sql,
            tables=tables,
            reason=f"{e.code}: {e.detail}",
        )
        raise

    # 2. 表白名单校验（fail-closed）
    tables = _check_plugin_tables(sql, role_config, dialect)

    # 3. 执行查询（带超时和行数限制）
    max_rows = role_config["max_rows"]
    timeout = role_config["timeout_seconds"]

    try:
        rows, truncated = await execute_with_limit(
            safe_sql, params=params,
            max_rows=max_rows,
            timeout_seconds=timeout,
        )
    except (TimeoutError, Exception) as e:
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        try:
            expressions = sqlglot.parse(sql, dialect=dialect)
            norm_sql = normalize_sql_for_audit(expressions[0], dialect=dialect) if expressions and expressions[0] else ""
        except Exception:
            norm_sql = ""

        error_code = "TIMEOUT" if isinstance(e, (TimeoutError,)) else "SYNTAX_ERROR"
        log_denied(
            client_name=client_name,
            role=role,
            tool=tool_name,
            normalized_sql=norm_sql,
            tables=tables,
            reason=f"{error_code}: {type(e).__name__}",
        )
        if isinstance(e, (TimeoutError,)):
            raise GatewayDeniedError("TIMEOUT", f"{timeout}s")
        raise GatewayDeniedError("SYNTAX_ERROR", "查询执行失败")

    # 4. 脱敏（聚合派生别名安全放行 + 列别名血缘追踪）
    agg_aliases = extract_aggregate_aliases(sql, dialect=dialect)
    col_aliases = extract_column_aliases(sql, dialect=dialect)
    masked_rows, masked_fields = apply_masking(
        rows, safe_aliases=agg_aliases, tables=set(tables),
        column_aliases=col_aliases,
    )

    # 5. 审计日志
    duration_ms = int((time.perf_counter() - start_time) * 1000)
    try:
        expressions = sqlglot.parse(safe_sql, dialect=dialect)
        norm_sql = normalize_sql_for_audit(expressions[0], dialect=dialect) if expressions and expressions[0] else ""
    except Exception:
        norm_sql = ""

    log_query(
        client_name=client_name,
        role=role,
        tool=tool_name,
        normalized_sql=norm_sql,
        tables=tables,
        masked_columns=masked_fields,
        rows_returned=len(masked_rows),
        duration_ms=duration_ms,
        status="success",
    )

    return masked_rows, masked_fields, truncated
