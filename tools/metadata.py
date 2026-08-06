"""元数据查询工具 - 数据集列表 + 列描述（通用，无硬编码表名/库名）

支持多数据库：根据表名路由的数据源类型自动适配 information_schema 查询。
"""
from db import execute_query, resolve_schema, current_client, resolve_dialect, get_pool_type
from auth.roles import get_role_config
from masking.engine import get_column_masking_info
from security.errors import GatewayDeniedError
from audit.logger import log_query


def register_metadata_tools(mcp):

    @mcp.tool()
    async def list_datasets() -> dict:
        """列出当前角色可访问的所有数据集（表和视图）。

        返回每个数据集的名称、类型（表/视图）和所属数据库。
        """
        client = current_client.get()
        if not client:
            raise GatewayDeniedError("ROLE_DENIED", "未认证")

        role_config = get_role_config(client["role"])
        if not role_config:
            raise GatewayDeniedError("ROLE_DENIED", "无效角色")

        allowed_tables = role_config["allowed_tables"]

        datasets = []
        for table_name in allowed_tables:
            # 通过路由配置解析表所属的数据库
            schema = resolve_schema(table_name)

            # 判断表类型（基于命名约定，可按需扩展）
            if table_name.lower().startswith("v_"):
                ds_type = "视图"
            else:
                ds_type = "表"

            usage = f"SELECT ... FROM {table_name} WHERE ..."
            if schema:
                usage = f"SELECT ... FROM {table_name} WHERE ..."

            datasets.append({
                "name": table_name,
                "type": ds_type,
                "database": schema,
                "usage": usage,
            })

        return {
            "role": client["role"],
            "datasets": datasets,
            "count": len(datasets),
        }

    @mcp.tool()
    async def describe_columns(table_name: str) -> dict:
        """查看指定表/视图的列名、类型和脱敏标记。

        替代 SHOW COLUMNS，不开放任意 SHOW 命令。
        自动根据数据源类型选择 information_schema 查询语法。

        Args:
            table_name: 表名或视图名（必须在当前角色白名单内）
        """
        client = current_client.get()
        if not client:
            raise GatewayDeniedError("ROLE_DENIED", "未认证")

        role_config = get_role_config(client["role"])
        if not role_config:
            raise GatewayDeniedError("ROLE_DENIED", "无效角色")

        # 白名单校验
        allowed = {t.lower() for t in role_config["allowed_tables"]}
        if table_name.lower() not in allowed:
            # 审计：拒绝
            log_query(
                client_name=client["client_name"],
                role=client["role"],
                tool="describe_columns",
                normalized_sql="",
                tables=[table_name],
                status="denied",
                reason="TABLE_NOT_ALLOWED",
            )
            raise GatewayDeniedError("TABLE_NOT_ALLOWED", table_name)

        # 通过路由配置解析表所属的数据库 schema
        schema = resolve_schema(table_name)

        # 根据数据源类型选择 information_schema 查询
        from db import resolve_datasource
        ds_name = resolve_datasource(table_name)
        ds_type = get_pool_type(ds_name)

        if ds_type in ("sqlserver", "mssql"):
            # SQL Server: TABLE_SCHEMA 是 schema 名（如 dbo），不是数据库名
            # 连接已指定数据库，按 TABLE_SCHEMA + TABLE_NAME 精确过滤
            # 默认 schema 为 dbo，可通过 datasource.yaml 的 schema 字段配置
            ds_config = None
            from config import get_datasource_config
            for ds in get_datasource_config().get("datasources", []):
                if ds.get("name") == ds_name:
                    ds_config = ds
                    break
            table_schema = ds_config.get("schema", "dbo") if ds_config else "dbo"

            sql = """
                SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s
                ORDER BY ORDINAL_POSITION
            """
            rows = await execute_query(sql, [table_schema, table_name], datasource=ds_name)
        else:
            # MySQL: TABLE_SCHEMA 是数据库名
            sql = """
                SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_COMMENT
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s
                ORDER BY ORDINAL_POSITION
            """
            rows = await execute_query(sql, [schema, table_name], datasource=ds_name)

        if not rows:
            # 可能是视图，尝试从 SELECT 推断
            if ds_type in ("sqlserver", "mssql"):
                # SQL Server 用 TOP 0 和方括号
                sql2 = f"SELECT TOP 0 * FROM [{table_name}]"
            else:
                sql2 = f"SELECT * FROM `{table_name}` LIMIT 0"
            try:
                await execute_query(sql2, datasource=ds_name)
                columns = []
            except Exception:
                columns = []
        else:
            columns = [
                {
                    "name": r["COLUMN_NAME"],
                    "type": r["DATA_TYPE"],
                    "nullable": r["IS_NULLABLE"] == "YES",
                    "comment": r.get("COLUMN_COMMENT", ""),
                }
                for r in rows
            ]

        # 附加脱敏标记
        col_names = [c["name"] for c in columns]
        masking_info = get_column_masking_info(col_names)
        for col in columns:
            col["masking"] = masking_info.get(col["name"], "deny")

        # 审计：成功
        log_query(
            client_name=client["client_name"],
            role=client["role"],
            tool="describe_columns",
            normalized_sql="DESCRIBE ?",
            tables=[table_name],
            rows_returned=len(columns),
            status="success",
        )

        return {
            "table": table_name,
            "columns": columns,
            "column_count": len(columns),
        }
