"""示例业务查询插件 - 展示如何编写自定义固定工具

这是插件模板，展示标准模式：
1. 使用 plugin_query 安全执行器（强制角色检查+表白名单+脱敏+审计）
2. 编写参数化 SQL
3. 返回值已自动脱敏

部署时：
1. 复制本文件，重命名为你的业务模块（如 sales_query.py）
2. 修改 SQL 和工具描述
3. 在 config/gateway.yaml 的 plugins.enabled 中添加模块名

安全须知：
- 必须使用 plugin_query()，不要直接调用 execute_query()
- plugin_query 会自动执行：角色校验、表白名单、行数限制、超时、脱敏、审计
"""
from typing import Optional

from tools.plugin_base import plugin_query


def register(mcp):

    @mcp.tool()
    async def query_summary(
        year: int,
        period: Optional[int] = None,
    ) -> dict:
        """查询业务汇总数据（示例插件，请按实际业务修改）。

        Args:
            year: 年份
            period: 月份（1-12），不传则查全年
        """
        conditions = ["n_year = %s"]
        params = [year]

        if period:
            conditions.append("n_period = %s")
            params.append(period)

        where_clause = " AND ".join(conditions)

        sql = f"""
            SELECT
                org_name,
                n_period,
                SUM(amount) AS total_amount
            FROM dws_example_summary
            WHERE {where_clause}
            GROUP BY org_name, n_period
            ORDER BY org_name, n_period
        """

        masked_rows, masked_fields, truncated = await plugin_query(
            sql=sql,
            params=params,
            tool_name="query_summary",
        )

        return {
            "year": year,
            "data": masked_rows,
            "record_count": len(masked_rows),
            "masked_fields": masked_fields,
            "truncated": truncated,
        }
