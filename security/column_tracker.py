"""敏感列血缘追踪 — 保守策略：无法确认来源时一律拒绝

敏感列集合从 config/masking_rules.yaml 自动派生，
不再在代码中硬编码列名。
"""
import sqlglot
from sqlglot import exp

from security.errors import GatewayDeniedError
from config import get_masking_config


def _derive_sensitive_columns() -> set[str]:
    """从 masking_rules.yaml 自动派生敏感列集合。

    action 为 tokenize / deny / mask_phone / mask_email 的列
    均视为敏感列，需要使用约束保护。
    passthrough 列不视为敏感列。
    """
    cfg = get_masking_config()
    sensitive_actions = {"tokenize", "deny", "mask_phone", "mask_email"}
    cols: set[str] = set()

    for rule in cfg.get("rules", []):
        if rule.get("action") in sensitive_actions:
            for col in rule.get("columns", []):
                cols.add(col.lower())

    # table_overrides 中 deny/tokenize/mask 的列也加入
    for table, overrides in cfg.get("table_overrides", {}).items():
        for col, action in overrides.items():
            if action in sensitive_actions:
                cols.add(col.lower())

    return cols


def get_sensitive_columns() -> set[str]:
    """获取敏感列集合（每次调用动态读取）"""
    return _derive_sensitive_columns()


def _is_sensitive(name: str) -> bool:
    """判断列名是否为敏感列（小写匹配）"""
    return name.lower() in get_sensitive_columns()


def _check_function_args(node: exp.Expression) -> None:
    """检查函数参数中是否引用了敏感列。"""
    _EXCLUDED_TYPES = (
        exp.And, exp.Or, exp.Not,
        exp.EQ, exp.NEQ, exp.GT, exp.GTE, exp.LT, exp.LTE,
        exp.Is, exp.Like, exp.ILike, exp.Between, exp.In,
        exp.Add, exp.Sub, exp.Mul, exp.Div, exp.Mod,
        exp.DPipe,
        exp.Case, exp.If,
        exp.Paren, exp.Neg,
        exp.Column, exp.Table, exp.Select,
    )

    for func_node in node.find_all(exp.Anonymous, exp.Func):
        if isinstance(func_node, _EXCLUDED_TYPES):
            continue

        func_name = ""
        if isinstance(func_node, exp.Anonymous):
            func_name = func_node.name.upper()
        else:
            func_name = type(func_node).__name__.upper()

        for col in func_node.find_all(exp.Column):
            if _is_sensitive(col.name):
                raise GatewayDeniedError(
                    "FUNCTION_DENIED",
                    f"禁止对敏感列 {col.name} 使用函数 {func_name}",
                )


def _check_order_by(node: exp.Expression) -> None:
    """检查 ORDER BY 中是否引用了敏感列"""
    for order in node.find_all(exp.Order):
        for col in order.find_all(exp.Column):
            if _is_sensitive(col.name):
                raise GatewayDeniedError(
                    "COLUMN_DENIED",
                    f"禁止在 ORDER BY 中使用敏感列 {col.name}（防止排序泄漏）",
                )


def _check_having(node: exp.Expression) -> None:
    """检查 HAVING 中是否有敏感列的非聚合引用"""
    for having in node.find_all(exp.Having):
        for col in having.find_all(exp.Column):
            if _is_sensitive(col.name):
                parent = col.parent
                in_agg = False
                while parent and parent is not having:
                    if isinstance(parent, (exp.Sum, exp.Count, exp.Avg, exp.Min, exp.Max)):
                        in_agg = True
                        break
                    parent = parent.parent
                if not in_agg:
                    raise GatewayDeniedError(
                        "COLUMN_DENIED",
                        f"禁止在 HAVING 中直接引用敏感列 {col.name}",
                    )


def _check_case_expressions(node: exp.Expression) -> None:
    """检查 CASE WHEN 表达式中的敏感列"""
    for case_node in node.find_all(exp.Case):
        for col in case_node.find_all(exp.Column):
            if _is_sensitive(col.name):
                raise GatewayDeniedError(
                    "COLUMN_DENIED",
                    f"禁止在 CASE 表达式中使用敏感列 {col.name}",
                )


def _check_arithmetic_expressions(node: exp.Expression) -> None:
    """检查算术/拼接表达式中的敏感列"""
    for binary in node.find_all(exp.Add, exp.Sub, exp.Mul, exp.Div,
                                exp.DPipe, exp.Concat):
        for col in binary.find_all(exp.Column):
            if _is_sensitive(col.name):
                raise GatewayDeniedError(
                    "COLUMN_DENIED",
                    f"禁止在表达式运算中使用敏感列 {col.name}",
                )


def check_sensitive_columns(tree: exp.Expression) -> None:
    """
    对 AST 执行敏感列使用约束检查。
    保守策略：任何无法确认安全的用法一律拒绝。

    允许：
      - SELECT 直接输出列（返回时令牌化）
      - GROUP BY 键（分组名令牌化）
      - WHERE 等值比较（= 'xxx'）

    禁止：
      - 函数参数
      - 表达式运算
      - ORDER BY
      - HAVING 非聚合引用
      - CASE 表达式
    """
    _check_function_args(tree)
    _check_order_by(tree)
    _check_having(tree)
    _check_case_expressions(tree)
    _check_arithmetic_expressions(tree)
