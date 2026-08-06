"""角色权限定义 — 从 config/roles.yaml 加载，无硬编码表名"""
from config import get_roles_config


def _load() -> tuple[dict, set, set]:
    """加载角色配置，返回 (roles, large_tables, large_table_filter_columns)"""
    cfg = get_roles_config()
    roles = cfg.get("roles", {})
    large_tables = set(t.lower() for t in cfg.get("large_tables", []))
    filter_cols = set(
        col.lower() for col in cfg.get("large_table_filter_columns", [])
    )
    # 如果未配置过滤列，使用通用默认值
    if not filter_cols:
        filter_cols = {"n_year", "n_period", "fyear", "fperiod"}
    return roles, large_tables, filter_cols


def get_role_config(role_name: str) -> dict | None:
    """获取角色配置，不存在返回 None"""
    roles, _, _ = _load()
    return roles.get(role_name)


def get_roles() -> dict:
    """获取全部角色配置"""
    roles, _, _ = _load()
    return roles


def get_large_tables() -> set[str]:
    """获取大表集合"""
    _, large_tables, _ = _load()
    return large_tables


def get_large_table_filter_columns() -> set[str]:
    """获取大表必须包含的过滤列名"""
    _, _, filter_cols = _load()
    return filter_cols


# 向后兼容：供 sql_validator.py 导入
# 注意：这些是动态读取的，不再硬编码
LARGE_TABLES = set()  # 占位，实际值通过 get_large_tables() 获取
