"""认证与权限测试"""
import pytest
import sys
import json
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from auth.tokens import generate_token, hash_token, authenticate
from auth.roles import get_role_config, get_roles, get_large_tables


class TestTokenGeneration:
    """Token 生成测试"""

    def test_generate_returns_tuple(self):
        raw, hashed = generate_token()
        assert isinstance(raw, str)
        assert isinstance(hashed, str)

    def test_raw_token_length(self):
        raw, _ = generate_token()
        assert len(raw) == 64  # 32 bytes = 64 hex chars

    def test_hash_format(self):
        _, hashed = generate_token()
        assert hashed.startswith("sha256:")
        assert len(hashed) == 7 + 64  # "sha256:" + 64 hex

    def test_hash_deterministic(self):
        raw, hashed = generate_token()
        assert hash_token(raw) == hashed

    def test_different_tokens_different_hashes(self):
        raw1, hash1 = generate_token()
        raw2, hash2 = generate_token()
        assert hash1 != hash2


class TestAuthentication:
    """Token 校验测试"""

    def test_valid_token(self, tmp_path):
        """有效 Token 通过校验"""
        raw, hashed = generate_token()
        tokens_file = tmp_path / "tokens.json"
        tokens_file.write_text(json.dumps({
            "tokens": [{
                "token_hash": hashed,
                "client_name": "test-agent",
                "role": "developer",
                "status": "active",
                "expires_at": "2099-12-31",
            }]
        }))

        # 临时修改配置
        import config
        original = config.settings.TOKENS_FILE
        config.settings.TOKENS_FILE = tokens_file
        try:
            result = authenticate(raw)
            assert result is not None
            assert result["client_name"] == "test-agent"
            assert result["role"] == "developer"
        finally:
            config.settings.TOKENS_FILE = original

    def test_invalid_token(self, tmp_path):
        """无效 Token 返回 None"""
        tokens_file = tmp_path / "tokens.json"
        tokens_file.write_text(json.dumps({"tokens": []}))

        import config
        original = config.settings.TOKENS_FILE
        config.settings.TOKENS_FILE = tokens_file
        try:
            result = authenticate("invalid_token_here")
            assert result is None
        finally:
            config.settings.TOKENS_FILE = original

    def test_expired_token(self, tmp_path):
        """过期 Token 返回 None"""
        raw, hashed = generate_token()
        tokens_file = tmp_path / "tokens.json"
        tokens_file.write_text(json.dumps({
            "tokens": [{
                "token_hash": hashed,
                "client_name": "expired-agent",
                "role": "developer",
                "status": "active",
                "expires_at": "2020-01-01",
            }]
        }))

        import config
        original = config.settings.TOKENS_FILE
        config.settings.TOKENS_FILE = tokens_file
        try:
            result = authenticate(raw)
            assert result is None
        finally:
            config.settings.TOKENS_FILE = original

    def test_inactive_token(self, tmp_path):
        """停用 Token 返回 None"""
        raw, hashed = generate_token()
        tokens_file = tmp_path / "tokens.json"
        tokens_file.write_text(json.dumps({
            "tokens": [{
                "token_hash": hashed,
                "client_name": "disabled-agent",
                "role": "developer",
                "status": "inactive",
                "expires_at": "2099-12-31",
            }]
        }))

        import config
        original = config.settings.TOKENS_FILE
        config.settings.TOKENS_FILE = tokens_file
        try:
            result = authenticate(raw)
            assert result is None
        finally:
            config.settings.TOKENS_FILE = original


class TestRoles:
    """角色配置测试"""

    def test_viewer_role_exists(self):
        config = get_role_config("viewer")
        assert config is not None
        assert config["allow_generic_query"] is False

    def test_developer_role_exists(self):
        config = get_role_config("developer")
        assert config is not None
        assert config["allow_generic_query"] is True
        assert config["allow_union"] is True
        assert config["max_union_depth"] == 2
        assert config["allow_audit_log"] is True

    def test_unknown_role_returns_none(self):
        assert get_role_config("hacker") is None

    def test_viewer_tables_subset_of_developer(self):
        roles = get_roles()
        viewer_tables = set(roles["viewer"]["allowed_tables"])
        dev_tables = set(roles["developer"]["allowed_tables"])
        assert viewer_tables.issubset(dev_tables)

    def test_large_tables_defined(self):
        large_tables = get_large_tables()
        assert "dws_example_bill_detail" in large_tables
        assert "dwd_example_detail" in large_tables

    def test_developer_max_rows(self):
        roles = get_roles()
        assert roles["developer"]["max_rows"] == 5000

    def test_viewer_max_rows(self):
        roles = get_roles()
        assert roles["viewer"]["max_rows"] == 1000
