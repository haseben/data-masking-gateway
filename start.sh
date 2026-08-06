#!/bin/bash
# 数据库脱敏 MCP 网关 - 一键启动脚本
# 参考 ShardingSphere 的 start.sh 设计
#
# 用法:
#   ./start.sh          # 检查环境 + 启动服务
#   ./start.sh docker   # Docker 方式启动
#   ./start.sh check    # 仅检查环境，不启动
#   ./start.sh stop     # 停止服务
#   ./start.sh restart  # 重启服务

set -e

# ── 颜色输出 ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ── 路径 ──
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PORT="${GATEWAY_PORT:-8765}"

# ══════════════════════════════════════════════════════════════
# 环境检查
# ══════════════════════════════════════════════════════════════
check_env() {
    echo ""
    echo "══════════════════════════════════════════════════"
    echo "  环境检查"
    echo "══════════════════════════════════════════════════"
    echo ""

    local has_error=0

    # Python 版本
    if command -v python3 &>/dev/null; then
        PY=python3
    elif command -v python &>/dev/null; then
        PY=python
    else
        error "未找到 Python，请安装 Python 3.11+"
        return 1
    fi

    PY_VERSION=$($PY -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
    PY_MAJOR=$($PY -c 'import sys; print(sys.version_info[0])')
    PY_MINOR=$($PY -c 'import sys; print(sys.version_info[1])')

    if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]); then
        error "Python 版本 $PY_VERSION 过低，需要 3.11+"
        return 1
    fi
    info "Python $PY_VERSION ✓"

    # .env 文件
    if [ ! -f ".env" ]; then
        warn ".env 不存在，运行初始化向导: python init.py"
        has_error=1
    else
        info ".env 文件 ✓"
    fi

    # config 目录
    for cfg in gateway.yaml roles.yaml datasource.yaml masking_rules.yaml; do
        if [ ! -f "config/$cfg" ]; then
            warn "config/$cfg 不存在"
            has_error=1
        fi
    done
    if [ $has_error -eq 0 ]; then
        info "配置文件 ✓"
    fi

    # tokens.json
    if [ ! -f "tokens.json" ]; then
        warn "tokens.json 不存在，运行: python init.py"
        has_error=1
    else
        info "tokens.json ✓"
    fi

    # 依赖检查
    if [ -d ".venv" ]; then
        info "虚拟环境 .venv ✓"
        PY=".venv/bin/python"
    elif $PY -c "import fastapi, fastmcp, aiomysql, sqlglot, yaml" 2>/dev/null; then
        info "Python 依赖 ✓"
    else
        warn "Python 依赖未安装，正在安装..."
        $PY -m pip install -e ".[dev]" || {
            error "依赖安装失败"
            return 1
        }
        info "Python 依赖安装完成 ✓"
    fi

    # 端口检查
    if command -v lsof &>/dev/null; then
        if lsof -i :$PORT &>/dev/null; then
            warn "端口 $PORT 已被占用"
            has_error=1
        else
            info "端口 $PORT 可用 ✓"
        fi
    fi

    if [ $has_error -eq 1 ]; then
        echo ""
        warn "存在配置问题，建议运行: python init.py"
        echo ""
        return 1
    fi

    echo ""
    info "环境检查通过"
    return 0
}

# ══════════════════════════════════════════════════════════════
# 启动方式
# ══════════════════════════════════════════════════════════════

start_direct() {
    check_env || exit 1

    echo ""
    info "启动脱敏网关 (直接运行模式)..."
    echo ""

    if [ -d ".venv" ]; then
        .venv/bin/python main.py
    else
        exec $PY main.py
    fi
}

start_docker() {
    echo ""
    info "启动脱敏网关 (Docker 模式)..."

    if ! command -v docker &>/dev/null; then
        error "未安装 Docker"
        exit 1
    fi

    # 检查 .env
    if [ ! -f ".env" ]; then
        warn "首次使用，运行初始化向导..."
        docker compose run --rm gateway python init.py
    fi

    docker compose up -d --build

    echo ""
    info "服务已启动: http://127.0.0.1:$PORT"
    info "查看日志:   docker compose logs -f"
    info "停止服务:   docker compose down"
}

stop_service() {
    echo ""
    if [ -f ".docker_pid" ] || docker compose ps 2>/dev/null | grep -q gateway; then
        info "停止 Docker 服务..."
        docker compose down
    else
        info "查找并停止本地进程..."
        PID=$(lsof -t -i :$PORT 2>/dev/null || true)
        if [ -n "$PID" ]; then
            kill $PID 2>/dev/null || true
            info "已停止进程 PID=$PID"
        else
            warn "未找到运行中的服务"
        fi
    fi
}

# ══════════════════════════════════════════════════════════════
# 主入口
# ══════════════════════════════════════════════════════════════

case "${1:-start}" in
    start)
        start_direct
        ;;
    docker)
        start_docker
        ;;
    check)
        check_env
        ;;
    stop)
        stop_service
        ;;
    restart)
        stop_service
        sleep 1
        start_direct
        ;;
    *)
        echo "用法: $0 {start|docker|check|stop|restart}"
        echo ""
        echo "  start    检查环境并启动服务（默认）"
        echo "  docker   Docker 方式启动"
        echo "  check    仅检查环境"
        echo "  stop     停止服务"
        echo "  restart  重启服务"
        exit 1
        ;;
esac
