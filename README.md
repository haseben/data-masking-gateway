# 数据库脱敏 MCP 网关

## 项目定位

通用企业级数据库安全网关，为 AI 智能体提供受控的生产数据库只读访问。所有查询经过 SQL 安全校验、动态数据脱敏、角色权限控制和审计日志记录。通过 YAML 配置文件驱动，无需修改代码即可适配不同业务场景。

技术栈：FastAPI + FastMCP 3.0（Stateless HTTP）+ aiomysql + SQLGlot AST 解析 + PyYAML 脱敏规则引擎。

## 架构概览

```
AI Agent (MCP Client)
    │
    ├── viewer 角色 → 公网 HTTPS (Nginx) → Gateway :8765
    │
    └── developer 角色 → SSH 隧道 → Gateway :8765
                              │
                              ▼
                    ┌─────────────────────┐
                    │   FastAPI 中间件     │  Bearer Token 鉴权
                    │   (auth middleware)  │  developer 拒绝 X-Forwarded-For
                    └────────┬────────────┘
                             │
                    ┌────────▼────────────┐
                    │   MCP Tools 层      │  内置工具 + 业务插件
                    └────────┬────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
     sql_validator     db.py (aiomysql)   masking/engine.py
     (SQLGlot AST)     (多数据源路由)      (YAML 规则脱敏)
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                    audit/logger.py (JSONL)
```

## 目录结构

```
data-masking-gateway/
├── main.py                  # FastAPI 入口 + MCP 挂载 + 鉴权中间件 + 插件加载
├── config.py                # YAML 配置加载 + 环境变量
├── db.py                    # aiomysql 多数据源连接池 + 表名路由
├── auth/
│   ├── roles.py             # 角色配置（从 roles.yaml 加载）
│   └── tokens.py            # Token 生成/校验（SHA-256 哈希）
├── security/
│   ├── sql_validator.py     # SQLGlot AST 安全校验 + LIMIT 注入
│   ├── column_tracker.py    # 敏感列使用约束（从规则自动派生）
│   └── errors.py            # GatewayDeniedError 异常定义
├── masking/
│   ├── engine.py            # 脱敏执行器（逐列匹配 masking_rules.yaml）
│   └── tokenizer.py         # HMAC-SHA256 稳定令牌化 + 手机/邮箱遮掩
├── tools/
│   ├── generic_query.py     # execute_query_tool（developer 通用查询）
│   ├── metadata.py          # list_datasets / describe_columns
│   ├── admin_tools.py       # 管理工具（审计日志查看）
│   └── plugins/             # 业务工具插件目录
│       ├── __init__.py
│       └── example_query.py # 示例插件模板
├── config/                  # YAML 配置文件
│   ├── gateway.yaml         # 网关元信息（名称/描述/插件列表）
│   ├── roles.yaml           # 角色权限（表白名单/大表/行数限制）
│   ├── datasource.yaml      # 数据源连接 + 表名路由
│   ├── masking_rules.yaml   # 脱敏规则（列名 → action 映射）
│   └── *.yaml.example       # 配置模板（复制后修改）
├── audit/
│   └── logger.py            # JSONL 审计日志
├── tests/                   # pytest 测试
├── deploy/                  # 部署配置（systemd / SQL / SSH 脚本）
├── pyproject.toml
└── .env.example             # 环境变量模板
```

## 快速开始

### 1. 安装依赖

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### 2. 配置

```bash
# 复制环境变量模板
cp .env.example .env
# 编辑 .env，填入 HMAC_SECRET 和 MYSQL_PASSWORD

# config/ 目录下已有工作配置（通用示例数据）
# 按实际业务修改以下文件：
#   config/gateway.yaml       — 网关名称、MCP 指令
#   config/roles.yaml         — 角色权限、表白名单
#   config/datasource.yaml    — 数据库连接信息
#   config/masking_rules.yaml — 脱敏规则
```

### 3. 生成 Token

```python
from auth.tokens import generate_token
raw, hashed = generate_token()
print(f"Token: {raw}")
print(f"Hash:  {hashed}")
```

将 hash 写入 `tokens.json`：

```json
{
  "tokens": [
    {
      "token_hash": "sha256:...",
      "client_name": "my-agent",
      "role": "developer",
      "status": "active",
      "expires_at": "2099-12-31"
    }
  ]
}
```

### 4. 启动服务

```bash
python main.py
# 或
uvicorn main:app --host 127.0.0.1 --port 8765
```

### 5. 调用网关

```bash
# 建立 SSH 隧道（developer 角色必须）
ssh -L 8765:127.0.0.1:8765 -N ai-gateway-tunnel@<SERVER_IP>

# 调用 MCP 工具
curl -s -X POST http://127.0.0.1:8765/mcp_api/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer <TOKEN>" \
  -d @request.json
```

## 配置说明

### gateway.yaml — 网关元信息

| 字段 | 说明 |
|------|------|
| name | 网关名称（显示在 API 文档中） |
| description | 网关描述 |
| mcp_server_name | FastMCP 实例名称 |
| instructions | MCP 指令（告诉 AI Agent 网关能力） |
| timezone | 审计日志时区 |
| plugins.enabled | 启用的插件模块名列表 |

### roles.yaml — 角色权限

| 字段 | 说明 |
|------|------|
| roles.{name}.allowed_tables | 表名白名单 |
| roles.{name}.max_rows | 最大返回行数 |
| roles.{name}.timeout_seconds | 查询超时 |
| roles.{name}.allow_generic_query | 是否允许通用 SQL 查询 |
| roles.{name}.allow_union | 是否允许 UNION |
| large_tables | 大表列表（查询需时间过滤） |
| large_table_filter_columns | 大表必须包含的过滤列 |

### datasource.yaml — 数据源

支持多数据源，通过表名路由规则自动选择连接池：

```yaml
datasources:
  - name: default
    host: 127.0.0.1
    database: your_database
    ...
  - name: secondary
    host: 10.0.0.2
    database: another_db
    ...

table_routing:
  - pattern: "ods_*"        # 通配符匹配
    datasource: secondary
  - pattern: "*"
    datasource: default
```

### masking_rules.yaml — 脱敏规则

| Action | 行为 | 示例 |
|--------|------|------|
| passthrough | 原值返回 | amount, n_year |
| tokenize | HMAC-SHA256 稳定令牌 | customer_name → CUST_V1_xxxx |
| mask_phone | 手机号遮掩 | 138****5678 |
| mask_email | 邮箱遮掩 | z***@example.com |
| deny | 置 null | id_card, bank_account |

匹配优先级：table_overrides > 全局 rules > 聚合别名放行 > unknown_column deny

## 业务插件开发

1. 在 `tools/plugins/` 下创建新模块（如 `sales_query.py`）
2. 导出 `register(mcp)` 函数
3. 在 `config/gateway.yaml` 的 `plugins.enabled` 中添加模块名

```python
# tools/plugins/sales_query.py
from db import execute_query
from masking.engine import apply_masking

def register(mcp):
    @mcp.tool()
    async def query_sales(year: int) -> dict:
        sql = "SELECT ... FROM your_table WHERE n_year = %s"
        rows = await execute_query(sql, [year])
        masked_rows, masked_fields = apply_masking(rows)
        return {"data": masked_rows, "masked_fields": masked_fields}
```

参考 `tools/plugins/example_query.py` 获取完整模板。

## 安全红线

1. **禁止直连数据库**：所有查询必须通过 MCP 网关（SSH 隧道 + Token）
2. **只读原则**：网关只允许 SELECT 和 EXPLAIN
3. **unknown_column: deny**：未在 masking_rules.yaml 注册的列名一律置空
4. **敏感列约束**：tokenize/deny 列禁止出现在函数参数、ORDER BY、CASE、算术表达式中
5. **审计不可跳过**：每次查询（成功或拒绝）都写入 audit.jsonl
6. **不记录敏感数据**：审计日志不记录查询结果、Token、密码、实际筛选值

## 角色与权限

| 角色 | 网络接入 | 可用工具 | 表范围 |
|------|----------|----------|--------|
| viewer | 公网 HTTPS | 固定工具 + 元数据 | 受限（仅视图） |
| developer | 仅 SSH 隧道 | 全部工具含通用查询 | 完整白名单 |

## 测试

```bash
python -m pytest tests/ -x -q
```

覆盖范围：Token 鉴权、SQL 校验（语句类型/白名单/危险函数/UNION/LIMIT/大表过滤）、脱敏引擎（tokenize/mask/deny/passthrough）、敏感列追踪。

## 部署

提供三种部署方式，按场景选择：

### 方式 A: Docker 部署（推荐）

```bash
# 1. 初始化配置（交互式向导，生成 .env / datasource.yaml / tokens.json）
docker compose run --rm gateway python init.py

# 2. 启动服务
docker compose up -d

# 3. 验证
curl http://127.0.0.1:8765/health

# 查看日志 / 停止
docker compose logs -f
docker compose down
```

### 方式 B: 一键脚本部署

```bash
# 1. 初始化配置
python init.py

# 2. 检查环境 + 启动
./start.sh

# 或 Docker 方式
./start.sh docker

# 其他命令
./start.sh check     # 仅检查环境
./start.sh stop      # 停止服务
./start.sh restart   # 重启服务
```

### 方式 C: systemd 生产部署

```bash
# 1. 初始化配置
python init.py

# 2. 创建只读数据库账号
mysql < deploy/setup_gateway_user.sql

# 3. 创建 SSH 隧道账号（developer 角色必须）
bash deploy/ssh_tunnel_account.sh

# 4. 安装 systemd 服务
cp deploy/mcp-server.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now mcp-server

# 5. 验证
curl http://127.0.0.1:8765/health
```

### 部署架构

```
AI Agent
  │
  ├─ viewer 角色 → 公网 HTTPS (Nginx) → Gateway :8765
  │
  └─ developer 角色 → SSH 隧道 → Gateway :8765
                          │
                          ▼
                   MySQL (只读账号 ai_gateway_ro)
```

网关只监听 127.0.0.1:8765，外部无法直连。viewer 通过 Nginx 反代访问，developer 通过 SSH 隧道访问。

## 新增表/列的操作步骤

1. `config/roles.yaml`：在角色白名单中添加表名
2. `config/masking_rules.yaml`：为每列注册 action（未注册列会被 deny）
3. `config/datasource.yaml`：如属于不同数据库，添加路由规则
4. 本地 pytest → 部署 → 网关验证
