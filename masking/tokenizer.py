"""HMAC-SHA256 稳定令牌化 — 同值同令牌，支持跨查询关联"""
import hashlib
import hmac
import re
import unicodedata

from config import get_masking_config

KEY_VERSION = "V1"


def _get_placeholders() -> set[str]:
    """从配置加载占位符值集合"""
    cfg = get_masking_config()
    defaults = cfg.get("defaults", {})
    return set(defaults.get("tokenizer_placeholders", [""]))


def normalize_input(value: str) -> str:
    """Unicode NFKC 标准化 + 去首尾空格 + 合并连续空格"""
    value = unicodedata.normalize("NFKC", value)
    value = value.strip()
    value = re.sub(r"\s+", " ", value)
    return value


def tokenize(value: str, namespace: str, prefix: str, secret: bytes) -> str:
    """
    同一 value 在同一 namespace 下始终返回相同令牌。

    格式: PREFIX_V1_XXXXXXXXXXXXXXXX (16位hex)
    示例: CUST_V1_71A9F2C093E807C4
    """
    if value is None:
        return value

    placeholders = _get_placeholders()
    if value in placeholders:
        return value

    normalized = normalize_input(value)
    if not normalized:
        return value

    msg = f"{namespace}:{normalized}".encode("utf-8")
    digest = hmac.new(secret, msg, hashlib.sha256).hexdigest()[:16].upper()
    return f"{prefix}_{KEY_VERSION}_{digest}"


def mask_phone(value: str) -> str:
    """手机号部分遮掩: 138****5678"""
    if not value or len(value) < 7:
        return "***"
    return value[:3] + "****" + value[-4:]


def mask_email(value: str) -> str:
    """邮箱部分遮掩: z***@example.com"""
    if not value or "@" not in value:
        return "***"
    local, domain = value.rsplit("@", 1)
    if len(local) <= 1:
        masked_local = "*"
    else:
        masked_local = local[0] + "***"
    return f"{masked_local}@{domain}"
