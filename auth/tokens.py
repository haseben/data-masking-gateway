"""Token 哈希校验与客户端身份管理"""
import hashlib
import json
import secrets
from datetime import date
from pathlib import Path

from config import settings


def generate_token() -> tuple[str, str]:
    """生成新 Token，返回 (明文token, sha256哈希)。明文仅展示一次。"""
    raw = secrets.token_hex(32)  # 32字节 = 64个hex字符
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    return raw, f"sha256:{token_hash}"


def hash_token(raw_token: str) -> str:
    """计算 Token 的 SHA-256 哈希"""
    return f"sha256:{hashlib.sha256(raw_token.encode()).hexdigest()}"


def _load_tokens_file() -> list[dict]:
    """加载 tokens.json"""
    path: Path = settings.TOKENS_FILE
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("tokens", [])
    except (json.JSONDecodeError, OSError):
        return []


def authenticate(raw_token: str) -> dict | None:
    """
    校验 Token，返回客户端信息 dict 或 None。
    检查：哈希匹配、状态 active、未过期。
    """
    token_hash = hash_token(raw_token)
    today = date.today().isoformat()

    for entry in _load_tokens_file():
        if entry.get("token_hash") != token_hash:
            continue
        if entry.get("status") != "active":
            return None
        # 过期检查
        expires_at = entry.get("expires_at")
        if expires_at and expires_at < today:
            return None
        return {
            "client_name": entry.get("client_name", "unknown"),
            "role": entry.get("role", "viewer"),
        }
    return None
