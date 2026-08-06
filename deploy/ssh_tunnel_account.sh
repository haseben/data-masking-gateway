#!/bin/bash
# 数据库脱敏 MCP 网关 - SSH 隧道账号创建脚本（通用模板）
# 在网关服务器上以 root 执行
# 执行前请替换 <GATEWAY_SERVER_IP> 为你的服务器公网 IP

set -e

TUNNEL_USER="ai-gateway-tunnel"
GATEWAY_PORT=8765

echo "=== 创建 SSH 隧道受限账号: ${TUNNEL_USER} ==="

# 创建无 shell 用户
useradd -r -m -s /usr/sbin/nologin "${TUNNEL_USER}" 2>/dev/null || true

# 创建 .ssh 目录
mkdir -p "/home/${TUNNEL_USER}/.ssh"
chmod 700 "/home/${TUNNEL_USER}/.ssh"

# authorized_keys 模板（每个 Agent 一行，替换公钥）
cat > "/home/${TUNNEL_USER}/.ssh/authorized_keys" << 'EOF'
# 格式: command="/usr/bin/false",no-pty,no-agent-forwarding,no-X11-forwarding,permitopen="127.0.0.1:8765" <key-type> <key> <comment>
# 示例（替换为实际公钥）:
# command="/usr/bin/false",no-pty,no-agent-forwarding,no-X11-forwarding,permitopen="127.0.0.1:8765" ssh-ed25519 AAAA... agent-1
# command="/usr/bin/false",no-pty,no-agent-forwarding,no-X11-forwarding,permitopen="127.0.0.1:8765" ssh-ed25519 AAAA... agent-2
EOF

chmod 600 "/home/${TUNNEL_USER}/.ssh/authorized_keys"
chown -R "${TUNNEL_USER}:${TUNNEL_USER}" "/home/${TUNNEL_USER}/.ssh"

echo "=== 完成 ==="
echo ""
echo "后续步骤:"
echo "1. 编辑 /home/${TUNNEL_USER}/.ssh/authorized_keys，添加各 Agent 公钥"
echo "2. 确保 sshd_config 中 AllowTcpForwarding 未被全局禁用（permitopen 由 authorized_keys 控制）"
echo "3. 各 Agent 连接方式: ssh -L 8765:127.0.0.1:${GATEWAY_PORT} ${TUNNEL_USER}@<GATEWAY_SERVER_IP> -N"
echo "4. 然后 Agent 访问 http://127.0.0.1:8765/mcp_api/mcp"
