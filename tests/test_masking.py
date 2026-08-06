"""脱敏引擎测试"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# 设置测试用 HMAC 密钥
import os
os.environ["HMAC_SECRET"] = "test_secret_key_for_unit_tests_only_32bytes!"

from masking.tokenizer import tokenize, mask_phone, mask_email, normalize_input
from masking.engine import apply_masking


class TestTokenizer:
    """HMAC 令牌化测试"""

    SECRET = b"test_secret_key_for_unit_tests_only_32bytes!"

    def test_same_value_same_token(self):
        """同值同令牌"""
        t1 = tokenize("某客户有限公司", "customer", "CUST", self.SECRET)
        t2 = tokenize("某客户有限公司", "customer", "CUST", self.SECRET)
        assert t1 == t2

    def test_different_value_different_token(self):
        """不同值不同令牌"""
        t1 = tokenize("客户A", "customer", "CUST", self.SECRET)
        t2 = tokenize("客户B", "customer", "CUST", self.SECRET)
        assert t1 != t2

    def test_token_format(self):
        """令牌格式: PREFIX_V1_16位HEX"""
        token = tokenize("测试客户", "customer", "CUST", self.SECRET)
        assert token.startswith("CUST_V1_")
        hex_part = token.split("_")[-1]
        assert len(hex_part) == 16
        assert all(c in "0123456789ABCDEF" for c in hex_part)

    def test_placeholder_not_tokenized(self):
        """占位符值不令牌化"""
        assert tokenize("N/A", "customer", "CUST", self.SECRET) == "N/A"
        assert tokenize("", "customer", "CUST", self.SECRET) == ""
        assert tokenize(None, "customer", "CUST", self.SECRET) is None

    def test_different_namespace_different_token(self):
        """不同 namespace 产生不同令牌"""
        t1 = tokenize("张三", "customer", "CUST", self.SECRET)
        t2 = tokenize("张三", "employee", "EMP", self.SECRET)
        assert t1 != t2

    def test_whitespace_normalized(self):
        """空格标准化后同值"""
        t1 = tokenize("某  客户  有限公司", "customer", "CUST", self.SECRET)
        t2 = tokenize("某 客户 有限公司", "customer", "CUST", self.SECRET)
        assert t1 == t2

    def test_leading_trailing_space_normalized(self):
        """首尾空格标准化"""
        t1 = tokenize("  客户A  ", "customer", "CUST", self.SECRET)
        t2 = tokenize("客户A", "customer", "CUST", self.SECRET)
        assert t1 == t2


class TestNormalizeInput:
    """输入标准化测试"""

    def test_nfkc(self):
        assert normalize_input("ＡＢＣ") == "ABC"

    def test_strip(self):
        assert normalize_input("  hello  ") == "hello"

    def test_collapse_spaces(self):
        assert normalize_input("a   b   c") == "a b c"


class TestMaskPhone:
    """手机号遮掩测试"""

    def test_normal_phone(self):
        assert mask_phone("13812345678") == "138****5678"

    def test_short_value(self):
        assert mask_phone("123") == "***"


class TestMaskEmail:
    """邮箱遮掩测试"""

    def test_normal_email(self):
        assert mask_email("zhangsan@example.com") == "z***@example.com"

    def test_single_char_local(self):
        assert mask_email("a@test.com") == "*@test.com"

    def test_no_at_sign(self):
        assert mask_email("notanemail") == "***"


class TestApplyMasking:
    """结果集脱敏测试"""

    def test_customer_name_tokenized(self):
        rows = [{"customer_name": "某客户有限公司", "amount": 100.0}]
        masked, fields = apply_masking(rows)
        assert masked[0]["customer_name"].startswith("CUST_V1_")
        assert masked[0]["amount"] == 100.0
        assert "customer_name" in fields

    def test_remark_denied(self):
        rows = [{"remark": "这是备注内容", "amount": 50.0}]
        masked, fields = apply_masking(rows)
        assert masked[0]["remark"] is None
        assert "remark" in fields

    def test_amount_passthrough(self):
        rows = [{"amount": 13570.05, "n_year": 2026}]
        masked, fields = apply_masking(rows)
        assert masked[0]["amount"] == 13570.05
        assert masked[0]["n_year"] == 2026
        assert "amount" not in fields

    def test_unknown_column_denied(self):
        """未登记字段默认拒绝"""
        rows = [{"some_new_secret_field": "敏感数据", "amount": 10.0}]
        masked, fields = apply_masking(rows)
        assert masked[0]["some_new_secret_field"] is None
        assert "some_new_secret_field" in fields

    def test_department_name_passthrough(self):
        """department_name 保留原值"""
        rows = [{"department_name": "研发部", "amount": 10.0}]
        masked, fields = apply_masking(rows)
        assert masked[0]["department_name"] == "研发部"
        assert "department_name" not in fields

    def test_bill_no_tokenized(self):
        rows = [{"bill_no": "AR00000125", "amount": 10.0}]
        masked, fields = apply_masking(rows)
        assert masked[0]["bill_no"].startswith("BILL_V1_")

    def test_empty_rows(self):
        masked, fields = apply_masking([])
        assert masked == []
        assert fields == []

    def test_fallback_phone_scan(self):
        """兜底正则：passthrough 列中出现手机号"""
        rows = [{"level_4": "报销联系电话13812345678", "amount": 10.0}]
        masked, fields = apply_masking(rows)
        assert "13812345678" not in str(masked[0]["level_4"])

    def test_consistency_across_rows(self):
        """同一客户在不同行中得到相同令牌"""
        rows = [
            {"customer_name": "客户X", "amount": 10.0},
            {"customer_name": "客户X", "amount": 20.0},
            {"customer_name": "客户Y", "amount": 30.0},
        ]
        masked, _ = apply_masking(rows)
        assert masked[0]["customer_name"] == masked[1]["customer_name"]
        assert masked[0]["customer_name"] != masked[2]["customer_name"]
