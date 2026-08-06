"""数据库脱敏 MCP 网关 — 通用入口，元信息从 config/gateway.yaml 加载"""
import os
import importlib
import logging

os.environ["FASTMCP_STATELESS_HTTP"] = "true"

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastmcp import FastMCP

from config import get_gateway_config, settings
from db import close_pool, current_client
from auth.tokens import authenticate

logger = logging.getLogger("gateway.main")

# 从配置加载网关元信息
_gateway_cfg = get_gateway_config()
GATEWAY_NAME = _gateway_cfg.get("name", "Data Masking Gateway")
GATEWAY_DESCRIPTION = _gateway_cfg.get("description", "为 AI Agent 提供安全、脱敏的数据库查询能力")
MCP_SERVER_NAME = _gateway_cfg.get("mcp_server_name", "DataMaskingGateway")
MCP_INSTRUCTIONS = _gateway_cfg.get("instructions", "你是数据库查询助手。所有查询均为只读操作，敏感字段会自动脱敏。")

mcp = FastMCP(
    MCP_SERVER_NAME,
    instructions=MCP_INSTRUCTIONS,
)

# 注册内置工具
from tools.metadata import register_metadata_tools
from tools.generic_query import register_generic_query_tools
from tools.admin_tools import register_admin_tools

register_metadata_tools(mcp)
register_generic_query_tools(mcp)
register_admin_tools(mcp)

# 动态加载业务插件
_plugins_cfg = _gateway_cfg.get("plugins", {})
_enabled_plugins = _plugins_cfg.get("enabled", [])

for plugin_name in _enabled_plugins:
    try:
        module = importlib.import_module(f"tools.plugins.{plugin_name}")
        if hasattr(module, "register"):
            module.register(mcp)
            logger.info(f"插件已加载: {plugin_name}")
        else:
            logger.warning(f"插件 {plugin_name} 缺少 register(mcp) 函数，跳过")
    except Exception as e:
        logger.error(f"加载插件 {plugin_name} 失败: {e}")

# 生成 FastMCP 的 ASGI 子应用
mcp_app = mcp.http_app()

# 初始化父级 FastAPI 应用
app = FastAPI(
    title=GATEWAY_NAME,
    description=GATEWAY_DESCRIPTION,
    version="1.0.0",
    lifespan=mcp_app.lifespan,
)


# 鉴权中间件：Token 哈希校验
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    # 只拦截 MCP 数据接口路径
    if request.url.path.startswith("/mcp_api"):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={
                    "jsonrpc": "2.0",
                    "id": "auth-error",
                    "error": {
                        "code": -32001,
                        "message": "Unauthorized: Missing Bearer Token",
                    },
                },
            )

        raw_token = auth_header.split(" ", 1)[1]
        client_info = authenticate(raw_token)
        if not client_info:
            return JSONResponse(
                status_code=401,
                content={
                    "jsonrpc": "2.0",
                    "id": "auth-error",
                    "error": {
                        "code": -32002,
                        "message": "Unauthorized: Invalid or expired token",
                    },
                },
            )

        # developer 角色必须通过 SSH 隧道接入（无 X-Forwarded-For）
        # 公网经 Nginx 转发的请求只允许非 developer 角色
        if client_info["role"] == "developer":
            if request.headers.get("X-Forwarded-For"):
                return JSONResponse(
                    status_code=403,
                    content={
                        "jsonrpc": "2.0",
                        "id": "auth-error",
                        "error": {
                            "code": -32003,
                            "message": "Forbidden: Developer access requires SSH tunnel",
                        },
                    },
                )

        # 绑定到协程上下文
        current_client.set(client_info)

    response = await call_next(request)
    return response


# 挂载 MCP 子应用
app.mount("/mcp_api", mcp_app)


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": MCP_SERVER_NAME, "version": "1.0.0"}


@app.on_event("shutdown")
async def shutdown_event():
    await close_pool()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=settings.GATEWAY_HOST,
        port=settings.GATEWAY_PORT,
        workers=1,  # 单 worker 保证并发计数准确
    )
