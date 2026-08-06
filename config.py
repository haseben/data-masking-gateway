"""网关配置加载 — 从 YAML 文件和环境变量加载全部配置"""
import os
import re
from pathlib import Path
from functools import lru_cache

import yaml
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent
CONFIG_DIR = BASE_DIR / "config"


def _resolve_env_vars(value):
    """递归处理字符串中的 ${VAR} 引用，从环境变量替换"""
    if isinstance(value, str):
        def _replacer(m):
            return os.environ.get(m.group(1), "")
        return re.sub(r"\$\{(\w+)\}", _replacer, value)
    if isinstance(value, dict):
        return {k: _resolve_env_vars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_env_vars(v) for v in value]
    return value


@lru_cache(maxsize=1)
def _load_yaml(filename: str) -> dict:
    """加载 config/ 目录下的 YAML 文件，找不到则返回空 dict"""
    path = CONFIG_DIR / filename
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return _resolve_env_vars(data)


@lru_cache(maxsize=1)
def get_gateway_config() -> dict:
    """网关元信息"""
    return _load_yaml("gateway.yaml")


@lru_cache(maxsize=1)
def get_roles_config() -> dict:
    """角色权限"""
    return _load_yaml("roles.yaml")


@lru_cache(maxsize=1)
def get_datasource_config() -> dict:
    """数据源"""
    return _load_yaml("datasource.yaml")


# 数据库类型 → sqlglot dialect 映射
_DIALECT_MAP = {
    "mysql": "mysql",
    "mariadb": "mysql",
    "sqlserver": "tsql",
    "mssql": "tsql",
    "postgresql": "postgres",
    "postgres": "postgres",
}


def get_dialect_for_datasource(ds_name: str = "default") -> str:
    """返回指定数据源的 sqlglot dialect 名称。

    根据 datasource.yaml 中该数据源的 type 字段映射到 sqlglot dialect。
    未知类型默认返回 "mysql"。
    """
    cfg = get_datasource_config()
    for ds in cfg.get("datasources", []):
        if ds.get("name") == ds_name:
            ds_type = ds.get("type", "mysql").lower()
            return _DIALECT_MAP.get(ds_type, "mysql")
    return "mysql"


def get_datasource_type(ds_name: str = "default") -> str:
    """返回指定数据源的原始类型（mysql/sqlserver/postgresql）。"""
    cfg = get_datasource_config()
    for ds in cfg.get("datasources", []):
        if ds.get("name") == ds_name:
            return ds.get("type", "mysql").lower()
    return "mysql"


@lru_cache(maxsize=1)
def get_masking_config() -> dict:
    """脱敏规则"""
    return _load_yaml("masking_rules.yaml")


class Settings:
    # HMAC 脱敏密钥
    HMAC_SECRET: str = os.getenv("HMAC_SECRET", "")

    # 服务
    GATEWAY_HOST: str = os.getenv("GATEWAY_HOST", "127.0.0.1")
    GATEWAY_PORT: int = int(os.getenv("GATEWAY_PORT", "8765"))

    # 审计日志
    AUDIT_LOG_DIR: str = os.getenv("AUDIT_LOG_DIR", str(BASE_DIR / "logs"))

    # Token 配置
    TOKENS_FILE: Path = BASE_DIR / "tokens.json"

    # 配置文件目录
    CONFIG_DIR: Path = CONFIG_DIR


settings = Settings()
