"""脱敏执行器 - 对查询结果集逐列应用脱敏规则

规则从 config/masking_rules.yaml 加载，不在代码中硬编码任何列名。
支持 SQL 别名血缘追踪：根据源列名（而非输出别名）匹配脱敏规则。
"""
import re

from config import get_masking_config, settings
from masking.tokenizer import tokenize, mask_phone, mask_email

# 兜底正则（仅扫描字符串值）
# 使用负向断言确保匹配独立的数字序列，避免在长数字串中误匹配子串
_PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
_ID_CARD_RE = re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")
_BANK_CARD_RE = re.compile(r"(?<!\d)\d{16,19}(?!\d)")


def _get_secret() -> bytes:
    """获取 HMAC 密钥（延迟读取，避免 import 顺序问题）"""
    import os
    secret = os.environ.get("HMAC_SECRET", "") or settings.HMAC_SECRET
    if not secret:
        raise RuntimeError("HMAC_SECRET 未配置")
    return secret.encode("utf-8")


def _fallback_scan(value: str) -> str:
    """兜底正则扫描：识别疑似身份证、银行卡、手机号

    检查顺序：长模式优先（身份证18位 > 银行卡16-19位 > 手机号11位），
    避免短模式在长数字串中误匹配子串。
    """
    if not isinstance(value, str):
        return value
    if _ID_CARD_RE.search(value):
        return "[已遮掩:疑似证件号]"
    if _BANK_CARD_RE.search(value):
        return "[已遮掩:疑似银行卡号]"
    if _PHONE_RE.search(value):
        return "[已遮掩:疑似手机号]"
    return value


def apply_masking(
    rows: list[dict],
    safe_aliases: set[str] | None = None,
    tables: set[str] | None = None,
    column_aliases: dict[str, str] | None = None,
) -> tuple[list[dict], list[str]]:
    """
    对查询结果逐行逐列应用脱敏规则。

    Args:
        rows: 查询结果集
        safe_aliases: 由 SQL 校验阶段提取的聚合派生别名（小写），
                      命中时按 passthrough 处理（仅限未注册列）。
        tables: 当前 SQL 涉及的表名集合（小写），用于 table_overrides 匹配。
        column_aliases: 输出别名 -> 源列名映射（均小写）。
                        防止 SELECT customer_name AS amount 绕过脱敏。
                        优先按源列名匹配规则，而非输出别名。

    Returns:
        (masked_rows, masked_field_names)
        masked_field_names: 被处理的列名列表（供 Agent 知晓）
    """
    if not rows:
        return rows, []

    rules_cfg = get_masking_config()

    # 构建列名 -> 规则查找表
    col_map: dict[str, dict] = {}
    for rule in rules_cfg.get("rules", []):
        action = rule["action"]
        for col in rule.get("columns", []):
            col_map[col.lower()] = {
                "action": action,
                "namespace": rule.get("namespace", ""),
                "prefix": rule.get("prefix", ""),
            }

    default_action = rules_cfg.get("defaults", {}).get("unknown_column", "deny")
    overrides = rules_cfg.get("table_overrides", {})
    secret = _get_secret()
    _safe = safe_aliases or set()
    _tables = tables or set()
    _col_aliases = column_aliases or {}

    masked_fields: set[str] = set()       # 被显式规则处理的列（tokenize/deny/mask 等）
    fallback_masked: set[str] = set()     # 被兜底扫描处理的列（仅用于返回值）
    masked_rows: list[dict] = []

    for row in rows:
        masked_row = {}
        for col_name, value in row.items():
            col_lower = col_name.lower()

            # 列别名血缘：如果输出列名是别名，按源列名匹配规则
            source_col = _col_aliases.get(col_lower, col_lower)

            # 优先级 1：表级列覆盖（按源列名匹配）
            override_action = None
            for tbl in _tables:
                tbl_override = overrides.get(tbl, {})
                if source_col in tbl_override:
                    override_action = tbl_override[source_col]
                    break

            # 优先级 2：全局规则（按源列名匹配）
            rule = None
            if override_action:
                action = override_action
                # 对于 tokenize 覆盖，从全局规则中查找 namespace/prefix
                if action == "tokenize":
                    rule = col_map.get(source_col)
            else:
                rule = col_map.get(source_col)
                if rule:
                    action = rule["action"]
                elif col_lower in _safe:
                    action = "passthrough"
                else:
                    action = default_action

            if action == "passthrough":
                masked_row[col_name] = value

            elif action == "deny":
                masked_row[col_name] = None
                masked_fields.add(col_name)

            elif action == "tokenize":
                # 安全获取 namespace/prefix：优先从 rule，兜底默认值
                ns = rule["namespace"] if rule else ""
                pfx = rule["prefix"] if rule else ""
                if value is not None and isinstance(value, str):
                    masked_row[col_name] = tokenize(
                        value,
                        namespace=ns,
                        prefix=pfx,
                        secret=secret,
                    )
                else:
                    masked_row[col_name] = value
                masked_fields.add(col_name)

            elif action == "mask_phone":
                if value and isinstance(value, str):
                    masked_row[col_name] = mask_phone(value)
                else:
                    masked_row[col_name] = value
                masked_fields.add(col_name)

            elif action == "mask_email":
                if value and isinstance(value, str):
                    masked_row[col_name] = mask_email(value)
                else:
                    masked_row[col_name] = value
                masked_fields.add(col_name)

            else:
                masked_row[col_name] = None
                masked_fields.add(col_name)

        masked_rows.append(masked_row)

    # 兜底正则扫描：仅对 passthrough 的字符串列逐行扫描
    # 注意：不能将 fallback 命中的列加入 masked_fields，否则后续同名列会被跳过
    for row in masked_rows:
        for col_name, value in row.items():
            if col_name in masked_fields:
                continue
            if isinstance(value, str) and len(value) > 5:
                scanned = _fallback_scan(value)
                if scanned != value:
                    row[col_name] = scanned
                    fallback_masked.add(col_name)

    return masked_rows, sorted(masked_fields | fallback_masked)


def get_column_masking_info(table_columns: list[str]) -> dict[str, str]:
    """
    返回每列的脱敏标记，用于 describe_columns 工具。
    {column_name: action}
    """
    rules_cfg = get_masking_config()
    col_map: dict[str, str] = {}
    for rule in rules_cfg.get("rules", []):
        action = rule["action"]
        for col in rule.get("columns", []):
            col_map[col.lower()] = action

    default_action = rules_cfg.get("defaults", {}).get("unknown_column", "deny")

    result = {}
    for col in table_columns:
        rule = col_map.get(col.lower())
        if rule:
            result[col] = rule
        else:
            result[col] = default_action
    return result
