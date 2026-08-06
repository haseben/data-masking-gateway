"""通用 SQL 查询工具 — 仅 developer 角色可用，经过完整安全管线

支持多数据库方言：根据 SQL 中表名路由到的数据源类型，
自动选择对应的 sqlglot dialect 进行解析和校验。
"""
import time

import sqlglot

from db import execute_with_limit, current_client, resolve_dialect
from auth.roles import get_role_config
from security.sql_validator import validate_sql, normalize_sql_for_audit, extract_aggregate_aliases, extract_column_aliases
from security.errors import GatewayDeniedError
from masking.engine import apply_masking
from audit.logger import log_query, log_denied


def register_generic_query_tools(mcp):

    @mcp.tool()
    async def execute_query_tool(sql: str) -> dict:
        """执行只读 SQL 查询（经过安全校验和动态脱敏）。

        仅 developer 角色可用。
        支持 SELECT 和普通 EXPLAIN。
        禁止 INSERT/UPDATE/DELETE/DDL/UNION/SHOW。
        敏感字段（客户名、员工名、单据号等）会自动令牌化。
        大表查询必须包含年份或月份过滤条件。

        Args:
            sql: 要执行的 SQL 语句（仅限单条只读语句）
        """
        client = current_client.get()
        if not client:
            raise GatewayDeniedError("ROLE_DENIED", "未认证")

        role_config = get_role_config(client["role"])
        if not role_config:
            raise GatewayDeniedError("ROLE_DENIED", "无效角色")

        if not role_config.get("allow_generic_query", False):
            raise GatewayDeniedError(
                "ROLE_DENIED", "当前角色无权使用通用查询，请使用固定工具"
            )

        client_name = client["client_name"]
        role = client["role"]
        start_time = time.perf_counter()

        # 0. 解析数据库方言（根据 SQL 表名路由的数据源类型）
        dialect = resolve_dialect(sql)

        # 1. SQL 安全校验（含 LIMIT 注入）
        try:
            safe_sql = validate_sql(sql, role_config, dialect=dialect)
        except GatewayDeniedError as e:
            # 记录拒绝日志（不记录原始 SQL，防止泄露筛选值）
            try:
                expressions = sqlglot.parse(sql, dialect=dialect)
                if expressions and expressions[0]:
                    norm_sql = normalize_sql_for_audit(expressions[0], dialect=dialect)
                else:
                    norm_sql = "<unparseable>"
            except Exception:
                norm_sql = "<unparseable>"

            # 提取表名用于审计
            tables = _extract_table_names(sql)
            log_denied(
                client_name=client_name,
                role=role,
                tool="execute_query",
                normalized_sql=norm_sql,
                tables=tables,
                reason=f"{e.code}: {e.detail}",
            )
            raise

        # 2. 执行查询
        max_rows = role_config["max_rows"]
        timeout = role_config["timeout_seconds"]

        try:
            rows, truncated = await execute_with_limit(
                safe_sql,
                max_rows=max_rows,
                timeout_seconds=timeout,
            )
        except (TimeoutError, Exception) as e:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            try:
                expressions = sqlglot.parse(sql, dialect=dialect)
                norm_sql = normalize_sql_for_audit(expressions[0], dialect=dialect) if expressions and expressions[0] else "<unparseable>"
            except Exception:
                norm_sql = "<unparseable>"
            tables = _extract_table_names(sql)

            error_code = "TIMEOUT" if isinstance(e, (TimeoutError,)) else "SYNTAX_ERROR"
            log_denied(
                client_name=client_name,
                role=role,
                tool="execute_query",
                normalized_sql=norm_sql,
                tables=tables,
                reason=f"{error_code}: {type(e).__name__}",
            )
            if isinstance(e, (TimeoutError,)):
                raise GatewayDeniedError("TIMEOUT", f"{timeout}s")
            raise GatewayDeniedError("SYNTAX_ERROR", "查询执行失败")

        # 3. 脱敏（聚合派生别名安全放行 + 列别名血缘追踪 + 表级列覆盖）
        agg_aliases = extract_aggregate_aliases(sql, dialect=dialect)
        col_aliases = extract_column_aliases(sql, dialect=dialect)
        query_tables = set(_extract_table_names(sql))
        masked_rows, masked_fields = apply_masking(
            rows, safe_aliases=agg_aliases, tables=query_tables,
            column_aliases=col_aliases,
        )

        # 4. 审计日志
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        expressions = sqlglot.parse(safe_sql, dialect=dialect)
        norm_sql = normalize_sql_for_audit(expressions[0], dialect=dialect) if expressions and expressions[0] else ""
        tables = _extract_table_names(safe_sql)

        log_query(
            client_name=client_name,
            role=role,
            tool="execute_query",
            normalized_sql=norm_sql,
            tables=tables,
            masked_columns=masked_fields,
            rows_returned=len(masked_rows),
            duration_ms=duration_ms,
            status="success",
        )

        # 5. 返回结果
        return {
            "rows": masked_rows,
            "row_count": len(masked_rows),
            "truncated": truncated,
            "masked_fields": masked_fields,
        }


def _extract_table_names(sql: str) -> list[str]:
    """从 SQL 中提取表名（用于审计，尽力而为，使用默认 dialect）"""
    try:
        from sqlglot import exp
        expressions = sqlglot.parse(sql)
        if not expressions or not expressions[0]:
            return []
        tables = set()
        for t in expressions[0].find_all(exp.Table):
            if t.name:
                tables.add(t.name.lower())
        return sorted(tables)
    except Exception:
        return []
