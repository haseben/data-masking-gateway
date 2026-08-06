"""结构化审计日志 — JSON Lines 格式，记录规范化 SQL"""
import json
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

from config import settings, get_gateway_config

# 专用 logger，输出到文件
_audit_logger = logging.getLogger("gateway.audit")
_audit_logger.setLevel(logging.INFO)
_audit_logger.propagate = False


def _get_tz():
    """从配置读取时区，默认 UTC+8"""
    cfg = get_gateway_config()
    tz_name = cfg.get("timezone", "Asia/Shanghai")
    # 简单映射常见时区名到偏移量
    _TZ_MAP = {
        "Asia/Shanghai": timezone(timedelta(hours=8)),
        "Asia/Tokyo": timezone(timedelta(hours=9)),
        "UTC": timezone.utc,
        "America/Los_Angeles": timezone(timedelta(hours=-8)),
        "America/New_York": timezone(timedelta(hours=-5)),
        "Europe/London": timezone(timedelta(hours=0)),
    }
    return _TZ_MAP.get(tz_name, timezone(timedelta(hours=8)))


def _ensure_handler():
    """确保日志 handler 已初始化"""
    if _audit_logger.handlers:
        return
    log_dir = Path(settings.AUDIT_LOG_DIR)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "audit.jsonl"

    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    _audit_logger.addHandler(handler)


def log_query(
    client_name: str,
    role: str,
    tool: str,
    normalized_sql: str,
    tables: list[str],
    columns_accessed: list[str] | None = None,
    masked_columns: list[str] | None = None,
    rows_returned: int = 0,
    duration_ms: int = 0,
    status: str = "success",
    reason: str = "",
) -> None:
    """
    记录一条审计日志。

    绝不记录：查询结果、Token、数据库密码、实际筛选值。
    记录规范化 SQL（字面量已替换为 ?）。
    """
    _ensure_handler()

    entry = {
        "ts": datetime.now(_get_tz()).isoformat(),
        "client": client_name,
        "role": role,
        "tool": tool,
        "normalized_sql": normalized_sql,
        "sql_hash": f"sha256:{hashlib.sha256(normalized_sql.encode()).hexdigest()[:16]}",
        "tables": tables,
        "status": status,
    }

    if columns_accessed:
        entry["columns_accessed"] = columns_accessed
    if masked_columns:
        entry["masked_columns"] = masked_columns
    if rows_returned:
        entry["rows_returned"] = rows_returned
    if duration_ms:
        entry["duration_ms"] = duration_ms
    if reason:
        entry["reason"] = reason

    _audit_logger.info(json.dumps(entry, ensure_ascii=False))


def log_denied(
    client_name: str,
    role: str,
    tool: str,
    normalized_sql: str,
    tables: list[str],
    reason: str,
) -> None:
    """记录被拒绝的查询"""
    log_query(
        client_name=client_name,
        role=role,
        tool=tool,
        normalized_sql=normalized_sql,
        tables=tables,
        status="denied",
        reason=reason,
    )


def read_recent_logs(limit: int = 20) -> list[dict]:
    """读取最近的审计日志（仅 admin 工具调用）"""
    log_file = Path(settings.AUDIT_LOG_DIR) / "audit.jsonl"
    if not log_file.exists():
        return []

    lines = []
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    lines.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    # 返回最后 N 条（倒序）
    return list(reversed(lines[-limit:]))
