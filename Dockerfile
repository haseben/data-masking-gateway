# 数据库脱敏 MCP 网关 - Docker 镜像
# 多阶段构建：builder 安装依赖，runner 仅运行
# 参考 Presidio 的容器化方案
#
# 构建参数：
#   DB_MODE=mysql       仅安装 MySQL 依赖（默认，镜像更小）
#   DB_MODE=sqlserver   安装 SQL Server 依赖（含 ODBC 驱动）
#   DB_MODE=all          安装全部数据库依赖
#
# 示例：
#   docker build -t data-masking-gateway .
#   docker build --build-arg DB_MODE=sqlserver -t data-masking-gateway:mssql .
#   docker build --build-arg DB_MODE=all -t data-masking-gateway:full .

ARG DB_MODE=mysql

# ── Stage 1: Builder ──
FROM python:3.12-slim AS builder

ARG DB_MODE

WORKDIR /build

# 系统依赖（编译用，不进入最终镜像）
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc default-libmysqlclient-dev pkg-config \
    curl gnupg2 apt-transport-https \
    && rm -rf /var/lib/apt/lists/*

# SQL Server: 安装 Microsoft ODBC Driver 18（仅 sqlserver/all 模式）
RUN if [ "$DB_MODE" = "sqlserver" ] || [ "$DB_MODE" = "all" ]; then \
        curl -sSL https://packages.microsoft.com/keys/microsoft.asc \
            | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg && \
        echo "deb [signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" \
            > /etc/apt/sources.list.d/mssql-release.list && \
        apt-get update && \
        ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 unixodbc-dev && \
        rm -rf /var/lib/apt/lists/* ; \
    fi

COPY pyproject.toml ./

# 根据 DB_MODE 安装对应依赖
RUN if [ "$DB_MODE" = "sqlserver" ]; then \
        pip install --no-cache-dir --prefix=/install -e ".[sqlserver]"; \
    elif [ "$DB_MODE" = "all" ]; then \
        pip install --no-cache-dir --prefix=/install -e ".[sqlserver,dev]"; \
    else \
        pip install --no-cache-dir --prefix=/install -e ".[dev]"; \
    fi

# ── Stage 2: Runner ──
FROM python:3.12-slim AS runner

ARG DB_MODE

LABEL maintainer="Data Masking Gateway"
LABEL description="通用企业级数据库脱敏 MCP 网关"

# 运行时系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -m -s /sbin/nologin gateway

# SQL Server: 复制 ODBC 驱动到 runner（仅 sqlserver/all 模式）
RUN if [ "$DB_MODE" = "sqlserver" ] || [ "$DB_MODE" = "all" ]; then \
        apt-get update && \
        apt-get install -y --no-install-recommends apt-transport-https gnupg2 && \
        curl -sSL https://packages.microsoft.com/keys/microsoft.asc \
            | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg && \
        echo "deb [signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" \
            > /etc/apt/sources.list.d/mssql-release.list && \
        apt-get update && \
        ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 unixodbc && \
        rm -rf /var/lib/apt/lists/* ; \
    fi

# 从 builder 复制已安装的 Python 包
COPY --from=builder /install /usr/local

WORKDIR /app

# 复制源码
COPY --chown=gateway:gateway . /app/

# 创建运行时目录
RUN mkdir -p /app/logs /app/config && \
    chown -R gateway:gateway /app

# 切换非 root 用户
USER gateway

# 默认环境变量（可被 .env 覆盖）
ENV GATEWAY_HOST=0.0.0.0 \
    GATEWAY_PORT=8765 \
    AUDIT_LOG_DIR=/app/logs \
    PYTHONUNBUFFERED=1

EXPOSE 8765

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://127.0.0.1:8765/health || exit 1

# 启动命令
CMD ["python", "main.py"]
