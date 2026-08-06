"""统一错误码 — 绝不透传数据库原始异常"""


class GatewayDeniedError(Exception):
    """网关拒绝执行，携带安全错误码"""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(self.message)

    @property
    def message(self) -> str:
        base = ERROR_MESSAGES.get(self.code, "请求被拒绝")
        if self.detail:
            return f"{base}（{self.detail}）"
        return base


ERROR_MESSAGES = {
    "SYNTAX_ERROR": "SQL 解析失败，请检查语法",
    "MULTI_STATEMENT": "仅允许单条 SQL 语句",
    "STATEMENT_DENIED": "仅允许 SELECT 和 EXPLAIN",
    "TABLE_NOT_ALLOWED": "无权访问该表",
    "SYSTEM_TABLE_DENIED": "禁止访问系统库",
    "COLUMN_DENIED": "该列不允许在此上下文使用",
    "FUNCTION_DENIED": "禁止对敏感列使用函数",
    "UNION_DENIED": "当前版本不支持 UNION 查询",
    "DANGEROUS_FUNCTION": "禁止使用危险函数",
    "USER_VARIABLE_DENIED": "禁止使用用户变量",
    "FOR_UPDATE_DENIED": "禁止 FOR UPDATE",
    "ROW_LIMIT": "结果已截断",
    "TIMEOUT": "查询超时，请优化查询条件",
    "CONCURRENT_LIMIT": "并发查询数已达上限，请稍后重试",
    "FILTER_REQUIRED": "大表查询必须包含年份或月份过滤条件",
    "EXPLAIN_ANALYZE_DENIED": "禁止 EXPLAIN ANALYZE",
    "ROLE_DENIED": "当前角色无权使用此功能",
    "UNKNOWN_COLUMN_DENIED": "未登记字段默认拒绝访问",
}
