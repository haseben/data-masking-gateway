"""异步数据库连接池 — 多数据源 + 多数据库类型支持（MySQL/SQL Server）

支持 MySQL/MariaDB（aiomysql）和 SQL Server（aioodbc）。
通过 datasource.yaml 的 type 字段自动选择驱动和 SQL 方言。
"""
import asyncio

import aiomysql
from contextvars import ContextVar

from config import get_datasource_config, get_dialect_for_datasource

# 存储当前协程上下文的客户端权限配置
current_client: ContextVar[dict] = ContextVar("current_client", default=None)

# 多数据源连接池: {datasource_name: Pool}
_pools: dict[str, object] = {}
# 数据源类型记录: {datasource_name: "mysql" | "sqlserver"}
_pool_types: dict[str, str] = {}


def _get_datasource_list() -> list[dict]:
    """获取数据源配置列表"""
    cfg = get_datasource_config()
    return cfg.get("datasources", [])


def _get_datasource_by_name(name: str) -> dict | None:
    """按名称获取数据源配置"""
    for ds in _get_datasource_list():
        if ds["name"] == name:
            return ds
    return None


def _get_routing_rules() -> list[dict]:
    """获取表名路由规则"""
    cfg = get_datasource_config()
    return cfg.get("table_routing", [])


def resolve_datasource(table_name: str) -> str:
    """
    根据表名路由规则解析数据源名称。

    支持通配符前缀匹配（* 结尾），按声明顺序匹配，首个命中生效。
    未匹配则返回 "default"。
    """
    table_lower = table_name.lower()
    for rule in _get_routing_rules():
        pattern = rule["pattern"].lower()
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            if table_lower.startswith(prefix):
                return rule["datasource"]
        elif pattern == table_lower:
            return rule["datasource"]
    return "default"


def resolve_schema(table_name: str) -> str:
    """
    根据表名解析所属数据库 schema 名。

    用于 information_schema 查询和表名前缀路由。
    """
    ds_name = resolve_datasource(table_name)
    ds = _get_datasource_by_name(ds_name)
    if ds:
        return ds.get("database", "")
    return ""


def _resolve_pool_from_sql(sql: str) -> str:
    """从 SQL 中提取表名并解析数据源（尽力而为，使用默认 dialect 解析）"""
    try:
        import sqlglot
        from sqlglot import exp
        expressions = sqlglot.parse(sql)
        if not expressions or not expressions[0]:
            return "default"
        for table_node in expressions[0].find_all(exp.Table):
            return resolve_datasource(table_node.name)
    except Exception:
        pass
    return "default"


def resolve_dialect(sql: str) -> str:
    """从 SQL 中提取表名，解析对应数据源的 sqlglot dialect。

    用于 SQL 校验器和审计日志，确保按正确的方言解析和生成 SQL。
    """
    ds_name = _resolve_pool_from_sql(sql)
    return get_dialect_for_datasource(ds_name)


def get_pool_type(datasource: str = "default") -> str:
    """获取数据源类型（mysql/sqlserver）。"""
    if datasource in _pool_types:
        return _pool_types[datasource]
    # 尚未创建连接池时，从配置读取
    ds = _get_datasource_by_name(datasource)
    if ds:
        return ds.get("type", "mysql").lower()
    return "mysql"


def _convert_placeholders(sql: str, ds_type: str) -> str:
    """将 MySQL 风格 %s 占位符转换为 SQL Server 风格 ? 占位符。

    仅对 SQL Server 数据源生效。MySQL 的参数化 SQL 统一使用 %s，
    SQL Server (aioodbc) 使用 ?。

    使用词法级扫描，跳过单引号字符串字面量内的 %s，
    避免破坏 SQL 文本内容。
    """
    if ds_type not in ("sqlserver", "mssql"):
        return sql

    result: list[str] = []
    in_string = False  # 是否在单引号字符串内
    i = 0
    while i < len(sql):
        ch = sql[i]

        if ch == "'":
            # 处理转义的单引号 ''（SQL 标准）
            if in_string and i + 1 < len(sql) and sql[i + 1] == "'":
                result.append("''")
                i += 2
                continue
            in_string = not in_string
            result.append(ch)
            i += 1
            continue

        if not in_string and ch == "%" and i + 1 < len(sql) and sql[i + 1] == "s":
            result.append("?")
            i += 2
            continue

        result.append(ch)
        i += 1

    return "".join(result)


# ── 连接池创建 ──────────────────────────────────────────────

async def _create_mysql_pool(ds_config: dict) -> aiomysql.Pool:
    """创建 MySQL/MariaDB 连接池"""
    return await aiomysql.create_pool(
        host=ds_config.get("host", "127.0.0.1"),
        port=ds_config.get("port", 3306),
        user=ds_config["user"],
        password=ds_config["password"],
        db=ds_config["database"],
        charset=ds_config.get("charset", "utf8mb4"),
        minsize=ds_config.get("minsize", 2),
        maxsize=ds_config.get("maxsize", 10),
        autocommit=True,
    )


async def _create_sqlserver_pool(ds_config: dict):
    """创建 SQL Server 连接池（aioodbc）"""
    import aioodbc

    driver = ds_config.get("driver", "ODBC Driver 18 for SQL Server")
    host = ds_config.get("host", "127.0.0.1")
    port = ds_config.get("port", 1433)
    database = ds_config["database"]
    user = ds_config["user"]
    password = ds_config["password"]
    trust_cert = ds_config.get("trust_server_certificate", "yes")
    encrypt = ds_config.get("encrypt", "yes")

    conn_str = (
        f"DRIVER={{{driver}}};"
        f"SERVER={host},{port};"
        f"DATABASE={database};"
        f"UID={user};"
        f"PWD={password};"
        f"TrustServerCertificate={trust_cert};"
        f"Encrypt={encrypt};"
    )

    return await aioodbc.create_pool(
        dsn=conn_str,
        minsize=ds_config.get("minsize", 2),
        maxsize=ds_config.get("maxsize", 10),
        autocommit=True,
    )


async def get_pool(datasource: str = "default"):
    """获取或创建指定数据源的连接池"""
    if datasource in _pools and not _pools[datasource].closed:
        return _pools[datasource]

    ds_config = _get_datasource_by_name(datasource)
    if ds_config is None:
        raise RuntimeError(f"数据源 '{datasource}' 未在 datasource.yaml 中配置")

    ds_type = ds_config.get("type", "mysql").lower()
    if ds_type in ("mysql", "mariadb"):
        _pools[datasource] = await _create_mysql_pool(ds_config)
        _pool_types[datasource] = "mysql"
    elif ds_type in ("sqlserver", "mssql"):
        _pools[datasource] = await _create_sqlserver_pool(ds_config)
        _pool_types[datasource] = "sqlserver"
    else:
        raise RuntimeError(f"不支持的数据源类型: {ds_type}")

    return _pools[datasource]


# ── 查询执行 ────────────────────────────────────────────────

async def execute_query(
    sql: str,
    params: list | None = None,
    datasource: str | None = None,
) -> list[dict]:
    """
    执行只读查询（固定工具专用），返回字典列表。
    固定工具内部 SQL 写死，不经过 SQL 校验，但仍使用参数化查询。

    Args:
        sql: SQL 语句
        params: 参数化查询参数
        datasource: 指定数据源名称，为 None 时自动从 SQL 推断
    """
    if datasource is None:
        datasource = _resolve_pool_from_sql(sql)

    ds_type = get_pool_type(datasource)
    pool = await get_pool(datasource)
    sql = _convert_placeholders(sql, ds_type)

    if ds_type in ("sqlserver", "mssql"):
        return await _sqlserver_execute(pool, sql, params)
    else:
        return await _mysql_execute(pool, sql, params)


async def _mysql_execute(pool, sql: str, params: list | None) -> list[dict]:
    """MySQL 查询执行（DictCursor）"""
    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            await cur.execute(sql, params or [])
            rows = await cur.fetchall()
            return [
                {k: float(v) if hasattr(v, "as_tuple") else v for k, v in row.items()}
                for row in rows
            ]


async def _sqlserver_execute(pool, sql: str, params: list | None) -> list[dict]:
    """SQL Server 查询执行（手动构建字典行）"""
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(sql, params or [])
            rows = await cur.fetchall()
            if not cur.description:
                return []
            columns = [desc[0] for desc in cur.description]
            return [
                {k: float(v) if hasattr(v, "as_tuple") else v
                 for k, v in zip(columns, row)}
                for row in rows
            ]


async def execute_with_limit(
    sql: str,
    params: list | None = None,
    max_rows: int = 1000,
    timeout_seconds: int = 10,
    datasource: str | None = None,
) -> tuple[list[dict], bool]:
    """
    带超时和行数限制的查询执行（通用查询工具专用）。

    MySQL 使用 SSDictCursor（服务端游标）避免大结果集一次性加载。
    SQL Server 使用 fetchmany 分批获取。
    Python 侧 asyncio.timeout() 兜底。

    Args:
        sql: SQL 语句
        params: 参数化查询参数
        max_rows: 最大返回行数
        timeout_seconds: 查询超时秒数
        datasource: 指定数据源名称，为 None 时自动从 SQL 推断

    Returns:
        (rows, truncated) — 结果行列表 + 是否被截断
    """
    if datasource is None:
        datasource = _resolve_pool_from_sql(sql)

    ds_type = get_pool_type(datasource)
    pool = await get_pool(datasource)
    sql = _convert_placeholders(sql, ds_type)

    if ds_type in ("sqlserver", "mssql"):
        return await _sqlserver_execute_with_limit(
            pool, sql, params, max_rows, timeout_seconds
        )
    else:
        return await _mysql_execute_with_limit(
            pool, sql, params, max_rows, timeout_seconds
        )


async def _mysql_execute_with_limit(
    pool, sql: str, params: list | None,
    max_rows: int, timeout_seconds: int,
) -> tuple[list[dict], bool]:
    """MySQL 带限制查询执行（SSDictCursor + 服务端超时）"""
    conn = await pool.acquire()
    try:
        async with asyncio.timeout(timeout_seconds):
            async with conn.cursor(aiomysql.SSDictCursor) as cur:
                # MySQL 会话级超时（毫秒）
                await cur.execute(
                    "SET SESSION MAX_EXECUTION_TIME = %s",
                    [timeout_seconds * 1000],
                )
                await cur.execute(sql, params or [])

                rows: list[dict] = []
                truncated = False
                async for row in cur:
                    if len(rows) >= max_rows:
                        truncated = True
                        break
                    # Decimal -> float 以便 JSON 序列化
                    rows.append(
                        {k: float(v) if hasattr(v, "as_tuple") else v
                         for k, v in row.items()}
                    )
                return rows, truncated

    except (asyncio.TimeoutError, TimeoutError):
        # 超时后关闭连接，不放回池
        conn.close()
        raise
    except Exception:
        # 其他异常也关闭连接
        conn.close()
        raise
    finally:
        if not conn.closed:
            pool.release(conn)


async def _sqlserver_execute_with_limit(
    pool, sql: str, params: list | None,
    max_rows: int, timeout_seconds: int,
) -> tuple[list[dict], bool]:
    """SQL Server 带限制查询执行（fetchmany 分批 + asyncio 超时兜底）"""
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            async with asyncio.timeout(timeout_seconds):
                await cur.execute(sql, params or [])

                rows: list[tuple] = []
                truncated = False
                # 分批获取，避免一次性加载全部结果
                while True:
                    batch = await cur.fetchmany(100)
                    if not batch:
                        break
                    for row in batch:
                        if len(rows) >= max_rows:
                            truncated = True
                            break
                        rows.append(row)
                    if truncated:
                        break

                if not cur.description:
                    return [], truncated
                columns = [desc[0] for desc in cur.description]
                dict_rows = [
                    {k: float(v) if hasattr(v, "as_tuple") else v
                     for k, v in zip(columns, row)}
                    for row in rows
                ]
                return dict_rows, truncated


async def close_pool():
    """关闭所有连接池（服务停止时调用）"""
    global _pools, _pool_types
    for name, pool in _pools.items():
        if pool and not pool.closed:
            ds_type = _pool_types.get(name, "mysql")
            if ds_type in ("sqlserver", "mssql"):
                # aioodbc: close() 是同步方法，wait_closed() 是协程
                pool.close()
                await pool.wait_closed()
            else:
                # aiomysql: close() 同步, wait_closed() 异步
                pool.close()
                await pool.wait_closed()
    # 使用 .clear() 而非 = {}，保留原 dict 对象引用
    # 避免 from db import _pools 的调用方持有旧引用导致状态不一致
    _pools.clear()
    _pool_types.clear()
