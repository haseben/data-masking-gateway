#!/usr/bin/env python3
"""
数据库脱敏 MCP 网关 - 交互式初始化向导

首次部署时运行，引导用户完成：
  1. 环境变量配置（.env）
  2. 数据源配置（datasource.yaml）— 支持 MySQL 和 SQL Server
  3. 生成访问 Token（tokens.json）
  4. 生成 HMAC 密钥
  5. 验证配置完整性

使用方式：
  python init.py            # 交互式
  python init.py --check    # 仅检查配置完整性
"""
import os
import sys
import json
import secrets
import hashlib
from pathlib import Path
from datetime import date

# Windows 控制台编码修复：GBK 环境下正确输出 Unicode 符号
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass

# 项目根目录
ROOT = Path(__file__).parent
CONFIG_DIR = ROOT / "config"


def banner(title: str):
    print()
    print("═" * 60)
    print(f"  {title}")
    print("═" * 60)


def prompt(label: str, default: str = "", password: bool = False) -> str:
    """交互式输入，支持默认值"""
    hint = f" [{default}]" if default else ""
    if password:
        val = input(f"  {label}{hint}: ").strip() or default
        # 简单遮掩显示
        display = "*" * min(len(val), 20) if val else "(空)"
        print(f"    ↳ 已输入: {display}")
        return val
    return input(f"  {label}{hint}: ").strip() or default


def confirm(label: str, default_yes: bool = True) -> bool:
    hint = "Y/n" if default_yes else "y/N"
    val = input(f"  {label} [{hint}]: ").strip().lower()
    if not val:
        return default_yes
    return val in ("y", "yes", "是")


def generate_hmac_secret() -> str:
    return secrets.token_hex(32)


def generate_token() -> tuple[str, str]:
    raw = secrets.token_hex(32)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    return raw, f"sha256:{token_hash}"


# ══════════════════════════════════════════════════════════════

def step_env():
    """Step 1: 生成 .env 文件"""
    banner("Step 1/4: 环境变量配置")

    env_path = ROOT / ".env"
    if env_path.exists():
        if not confirm("  .env 已存在，要覆盖吗？", default_yes=False):
            print("  跳过 .env 配置")
            return

    print("  正在生成 HMAC 密钥...")
    hmac_secret = generate_hmac_secret()

    db_password = prompt("数据库密码 (DB_PASSWORD)", password=True)
    gateway_host = prompt("监听地址", "127.0.0.1")
    gateway_port = prompt("监听端口", "8765")
    log_dir = prompt("审计日志目录", "logs")

    content = f"""# 数据库脱敏 MCP 网关 - 环境变量
# 由 init.py 自动生成，可手动编辑

# 数据库密码（datasource.yaml 中通过 ${{DB_PASSWORD}} 引用）
DB_PASSWORD={db_password}

# HMAC 令牌化密钥（32字节 hex）
HMAC_SECRET={hmac_secret}

# 服务配置
GATEWAY_HOST={gateway_host}
GATEWAY_PORT={gateway_port}

# 审计日志路径
AUDIT_LOG_DIR={log_dir}
"""
    env_path.write_text(content, encoding="utf-8")
    print(f"\n  ✓ .env 已生成: {env_path}")
    print(f"  ✓ HMAC 密钥已生成（64位 hex）")


def step_datasource():
    """Step 2: 生成 datasource.yaml"""
    banner("Step 2/4: 数据源配置")

    ds_path = CONFIG_DIR / "datasource.yaml"
    if ds_path.exists():
        if not confirm("  datasource.yaml 已存在，要覆盖吗？", default_yes=False):
            print("  跳过数据源配置")
            return

    print("  选择数据库类型：")
    print("    1. MySQL / MariaDB")
    print("    2. SQL Server")
    choice = prompt("请选择 (1/2)", "1")

    db_host = prompt("数据库地址", "127.0.0.1")
    db_user = prompt("数据库用户名（只读账号）", "readonly_user")
    db_name = prompt("数据库名", "")

    if choice == "2":
        # SQL Server
        db_port = prompt("数据库端口", "1433")
        db_driver = prompt("ODBC 驱动名", "ODBC Driver 18 for SQL Server")
        content = f"""# 数据源配置（由 init.py 生成）
datasources:
  - name: default
    type: sqlserver
    host: {db_host}
    port: {db_port}
    user: {db_user}
    password: "${{DB_PASSWORD}}"
    database: {db_name}
    driver: "{db_driver}"
    encrypt: yes
    trust_server_certificate: yes
    minsize: 2
    maxsize: 10

# 表名 → 数据源路由
table_routing:
  - pattern: "*"
    datasource: default
"""
        print(f"\n  ✓ SQL Server 数据源已配置")
        print(f"  ⚠ 请确保已安装 ODBC 驱动: {db_driver}")
        print(f"    Ubuntu: apt-get install msodbcsql18")
        print(f"    Windows: 下载 SQL Server ODBC Driver")
    else:
        # MySQL
        db_port = prompt("数据库端口", "3306")
        content = f"""# 数据源配置（由 init.py 生成）
datasources:
  - name: default
    type: mysql
    host: {db_host}
    port: {db_port}
    user: {db_user}
    password: "${{DB_PASSWORD}}"
    database: {db_name}
    charset: utf8mb4
    minsize: 2
    maxsize: 10

# 表名 → 数据源路由
table_routing:
  - pattern: "*"
    datasource: default
"""
        print(f"\n  ✓ MySQL 数据源已配置")

    ds_path.write_text(content, encoding="utf-8")
    print(f"  ✓ datasource.yaml 已生成: {ds_path}")


def step_token():
    """Step 3: 生成 Token"""
    banner("Step 3/4: 生成访问 Token")

    tokens_path = ROOT / "tokens.json"
    if tokens_path.exists():
        if not confirm("  tokens.json 已存在，要追加新 Token 吗？", default_yes=False):
            print("  跳过 Token 生成")
            return

    print("  生成一个新的访问 Token...")
    client_name = prompt("Agent 名称", "my-agent")
    role = prompt("角色 (viewer/developer)", "developer")

    raw_token, token_hash = generate_token()

    # 加载已有 tokens 或创建新的
    existing = {"tokens": []}
    if tokens_path.exists():
        try:
            existing = json.loads(tokens_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass

    existing["tokens"].append({
        "token_hash": token_hash,
        "client_name": client_name,
        "role": role,
        "status": "active",
        "expires_at": "2099-12-31",
    })

    tokens_path.write_text(
        json.dumps(existing, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print(f"\n  ✓ Token 已生成并写入 tokens.json")
    print(f"\n  ┌─────────────────────────────────────────────────┐")
    print(f"  │  Token（仅显示一次，请妥善保存）:               │")
    print(f"  │                                                   │")
    print(f"  │  {raw_token}  │")
    print(f"  │                                                   │")
    print(f"  │  角色: {role:<12}  名称: {client_name:<20}  │")
    print(f"  └─────────────────────────────────────────────────┘")
    print(f"\n  ⚠ 此 Token 明文仅显示一次，丢失需重新生成")


def step_check():
    """Step 4: 验证配置完整性"""
    banner("Step 4/4: 配置完整性检查")

    checks = []
    all_ok = True

    # 检查 .env
    env_path = ROOT / ".env"
    if env_path.exists():
        content = env_path.read_text(encoding="utf-8")
        if "HMAC_SECRET=" in content and ("DB_PASSWORD=" in content or "MYSQL_PASSWORD=" in content):
            checks.append(("✓", ".env 文件", "存在且包含必要变量"))
        else:
            checks.append(("✗", ".env 文件", "缺少 HMAC_SECRET 或 DB_PASSWORD"))
            all_ok = False
    else:
        checks.append(("✗", ".env 文件", "不存在（运行 init.py 生成）"))
        all_ok = False

    # 检查 config 文件
    for cfg_file in ["gateway.yaml", "roles.yaml", "datasource.yaml", "masking_rules.yaml"]:
        path = CONFIG_DIR / cfg_file
        if path.exists():
            checks.append(("✓", f"config/{cfg_file}", "存在"))
        else:
            checks.append(("✗", f"config/{cfg_file}", "不存在（从 .yaml.example 复制）"))
            all_ok = False

    # 检查 tokens.json
    tokens_path = ROOT / "tokens.json"
    if tokens_path.exists():
        try:
            data = json.loads(tokens_path.read_text(encoding="utf-8"))
            count = len(data.get("tokens", []))
            checks.append(("✓", "tokens.json", f"存在，{count} 个 Token"))
        except (json.JSONDecodeError, OSError):
            checks.append(("✗", "tokens.json", "格式错误"))
            all_ok = False
    else:
        checks.append(("✗", "tokens.json", "不存在（运行 init.py 生成）"))
        all_ok = False

    # 打印结果
    print()
    for status, name, desc in checks:
        print(f"  {status}  {name:<30} {desc}")

    print()
    if all_ok:
        print("  ✓ 所有配置就绪！可以启动服务：")
        print("     Docker:  docker compose up -d")
        print("     直接运行: python main.py")
        print("     脚本:    ./start.sh")
    else:
        print("  ✗ 部分配置缺失，请按提示修复后重试")
        print("     重新运行: python init.py")

    return all_ok


# ══════════════════════════════════════════════════════════════

def main():
    banner("数据库脱敏 MCP 网关 - 初始化向导")
    print("  本向导将引导你完成首次配置（约 2 分钟）")
    print("  支持 MySQL/MariaDB 和 SQL Server")

    # 仅检查模式
    if "--check" in sys.argv:
        step_check()
        return

    step_env()
    step_datasource()
    step_token()
    step_check()

    banner("初始化完成")
    print("  下一步:")
    print("    1. 编辑 config/roles.yaml — 配置角色可访问的表名")
    print("    2. 编辑 config/masking_rules.yaml — 配置脱敏规则")
    print("    3. 启动服务: ./start.sh 或 docker compose up -d")
    print()


if __name__ == "__main__":
    main()
