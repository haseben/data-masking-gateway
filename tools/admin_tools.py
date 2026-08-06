"""管理员工具 — 审计日志查看（仅 admin 角色）"""
from db import current_client
from auth.roles import get_role_config
from security.errors import GatewayDeniedError
from audit.logger import read_recent_logs


def register_admin_tools(mcp):

    @mcp.tool()
    async def query_audit_log(limit: int = 20) -> dict:
        """查看最近的审计日志（developer 角色可用）。

        返回最近的查询记录，包括：时间、客户端、角色、规范化SQL、
        访问的表、脱敏列、返回行数、耗时、状态。

        Args:
            limit: 返回最近 N 条记录，默认 20，最大 100
        """
        client = current_client.get()
        if not client:
            raise GatewayDeniedError("ROLE_DENIED", "未认证")

        role_config = get_role_config(client["role"])
        if not role_config:
            raise GatewayDeniedError("ROLE_DENIED", "无效角色")

        if not role_config.get("allow_audit_log", False):
            raise GatewayDeniedError(
                "ROLE_DENIED", "当前角色无权查看审计日志"
            )

        # 限制最大条数
        limit = min(max(1, limit), 100)

        logs = read_recent_logs(limit=limit)
        return {
            "logs": logs,
            "count": len(logs),
            "note": "日志中 normalized_sql 已将字面量替换为 ?，不含实际筛选值",
        }
