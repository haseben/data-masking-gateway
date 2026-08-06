"""
随机数据库表生成器 + 脱敏拦截压力测试

生成各种格式和字段的随机表，验证脱敏网关能否准确拦截敏感字段。
运行: python test_random_tables.py
"""
import os
import sys
import random
import string
import json
import time
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import Any

# ── 环境初始化 ──
sys.path.insert(0, str(Path(__file__).parent))
os.environ["HMAC_SECRET"] = "test_secret_key_for_unit_tests_only_32bytes!"

from masking.engine import apply_masking, get_column_masking_info
from config import get_masking_config

random.seed(42)  # 可复现


# ══════════════════════════════════════════════════════════════
# 1. 字段库定义 — 覆盖所有脱敏类别
# ══════════════════════════════════════════════════════════════

@dataclass
class FieldSpec:
    """字段规格定义"""
    name: str
    category: str          # sensitive_tokenize / sensitive_mask / sensitive_deny / safe / unknown
    expected_action: str   # 期望的脱敏动作
    data_samples: list[Any] = field(default_factory=list)


# --- 已登记敏感字段 ---
SENSITIVE_FIELDS: list[FieldSpec] = [
    # tokenize 类
    FieldSpec("customer_name", "sensitive_tokenize", "tokenize",
              ["张三", "李四", "王五", "张三丰", "诸葛亮"]),
    FieldSpec("client_name", "sensitive_tokenize", "tokenize",
              ["客户A", "客户B", "有限公司"]),
    FieldSpec("employee_name", "sensitive_tokenize", "tokenize",
              ["员工甲", "员工乙", "John Doe"]),
    FieldSpec("staff_name", "sensitive_tokenize", "tokenize",
              ["赵六", "钱七", "孙八"]),
    FieldSpec("supplier_name", "sensitive_tokenize", "tokenize",
              ["供应商A", "供应商B", "Vendor X"]),
    FieldSpec("vendor_name", "sensitive_tokenize", "tokenize",
              ["卖方A", "卖方B"]),
    FieldSpec("bill_no", "sensitive_tokenize", "tokenize",
              ["BILL-2026-001", "INV-2026-99999", "DOC-ABC-123"]),
    FieldSpec("contact_name", "sensitive_tokenize", "tokenize",
              ["联系人张三", "联系人李四"]),

    # mask_phone 类
    FieldSpec("phone", "sensitive_mask", "mask_phone",
              ["13812345678", "15987654321", "13600001111", "18999998888"]),
    FieldSpec("mobile", "sensitive_mask", "mask_phone",
              ["15012345678", "17700009999", "13344556677"]),
    FieldSpec("telephone", "sensitive_mask", "mask_phone",
              ["13600001111", "18922223333"]),

    # mask_email 类
    FieldSpec("email", "sensitive_mask", "mask_email",
              ["zhangsan@example.com", "lisi@test.org", "user@domain.cn",
               "a@b.cn", "very.long.name@company.co.uk"]),

    # deny 类 — 证件
    FieldSpec("id_card", "sensitive_deny", "deny",
              ["110101199001011234", "440301199003071234", "320102198812121234"]),
    FieldSpec("id_number", "sensitive_deny", "deny",
              ["110101199001011234", "44030119900307123X"]),
    FieldSpec("passport_no", "sensitive_deny", "deny",
              ["G12345678", "E98765432", "D45678901"]),

    # deny 类 — 金融
    FieldSpec("bank_account", "sensitive_deny", "deny",
              ["6222021234567890123", "6228481234567890123"]),
    FieldSpec("bank_account_no", "sensitive_deny", "deny",
              ["6222020987654321098"]),
    FieldSpec("account_no", "sensitive_deny", "deny",
              ["6228480000000000000", "6217001234567890123"]),

    # deny 类 — 凭证
    FieldSpec("password", "sensitive_deny", "deny",
              ["P@ssw0rd123", "my_secret_password", "123456"]),
    FieldSpec("secret", "sensitive_deny", "deny",
              ["api_secret_key_123", "encryption_key_xyz"]),
    FieldSpec("api_key", "sensitive_deny", "deny",
              ["sk-1234567890abcdef", "ak-abcdef1234567890"]),
    FieldSpec("token", "sensitive_deny", "deny",
              ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature",
               "ghp_1234567890abcdef"]),

    # deny 类 — 地址/备注
    FieldSpec("address", "sensitive_deny", "deny",
              ["北京市朝阳区某某街道100号", "上海市浦东新区某某路200号"]),
    FieldSpec("home_address", "sensitive_deny", "deny",
              ["广州市天河区珠江新城A座", "深圳市南山区科技园B栋"]),
    FieldSpec("remark", "sensitive_deny", "deny",
              ["这是一个备注", "客户要求加急处理", None, ""]),
    FieldSpec("comment", "sensitive_deny", "deny",
              ["这是一个评论", "审核通过", None]),
    FieldSpec("description", "sensitive_deny", "deny",
              ["产品描述文本", "详细的业务描述"]),
    FieldSpec("note", "sensitive_deny", "deny",
              ["内部笔记", "TODO: 跟进客户"]),
    FieldSpec("attachment_url", "sensitive_deny", "deny",
              ["https://internal.example.com/files/secret.pdf",
               "https://10.0.0.1:8080/data/export.csv"]),
    FieldSpec("raw_json", "sensitive_deny", "deny",
              ['{"key": "value", "secret": "data"}',
               '{"user": "admin", "password": "123456"}']),
]

# --- 安全字段（应 passthrough）---
SAFE_FIELDS: list[FieldSpec] = [
    # 数值类
    FieldSpec("amount", "safe", "passthrough", [12345.67, 0.01, 9999999.99, -100.50]),
    FieldSpec("quantity", "safe", "passthrough", [100, 0, 999999, 1]),
    FieldSpec("price", "safe", "passthrough", [99.9, 0.01, 12345.67]),
    FieldSpec("total", "safe", "passthrough", [1000.0, 0.0, 999999.99]),
    FieldSpec("sum", "safe", "passthrough", [500.0, 12345.67]),
    FieldSpec("balance", "safe", "passthrough", [9999.99, 0.0, -500.00]),
    FieldSpec("sales_amount", "safe", "passthrough", [50000.0, 0.01, 9999999.99]),
    FieldSpec("cost_amount", "safe", "passthrough", [30000.0, 100.50]),
    FieldSpec("gross_amount", "safe", "passthrough", [20000.0, 5000.25]),

    # 时间类
    FieldSpec("n_year", "safe", "passthrough", [2024, 2025, 2026]),
    FieldSpec("n_period", "safe", "passthrough", [202401, 202607, 202512]),
    FieldSpec("created_at", "safe", "passthrough",
              ["2026-07-24 10:00:00", "2025-01-15 08:30:00"]),
    FieldSpec("updated_at", "safe", "passthrough",
              ["2026-07-24 12:00:00", "2025-06-30 23:59:59"]),
    FieldSpec("date", "safe", "passthrough", ["2026-07-24", "2025-12-31"]),
    FieldSpec("year", "safe", "passthrough", [2024, 2025, 2026]),
    FieldSpec("month", "safe", "passthrough", [1, 6, 7, 12]),

    # 标识/维度类
    FieldSpec("id", "safe", "passthrough", [1, 100, 99999]),
    FieldSpec("status", "safe", "passthrough", ["active", "inactive", "pending"]),
    FieldSpec("type", "safe", "passthrough", ["A", "B", "C", "normal"]),
    FieldSpec("code", "safe", "passthrough", ["CODE001", "PROD-2026-A"]),
    FieldSpec("name_code", "safe", "passthrough", ["NC001", "NC002"]),
    FieldSpec("org_name", "safe", "passthrough", ["总部", "华东大区"]),
    FieldSpec("department_name", "safe", "passthrough", ["销售部", "技术部", "财务部"]),
    FieldSpec("level_1", "safe", "passthrough", ["一级分类A", "电子产品"]),
    FieldSpec("level_2", "safe", "passthrough", ["二级分类B", "手机"]),
    FieldSpec("level_3", "safe", "passthrough", ["三级分类C", "配件"]),
    FieldSpec("level_4", "safe", "passthrough", ["四级分类D", "充电器"]),
]

# --- 未登记字段（应被 default deny 拦截）---
UNKNOWN_FIELDS: list[FieldSpec] = [
    FieldSpec("user_preference", "unknown", "deny", ["dark_mode", "zh-CN"]),
    FieldSpec("custom_field", "unknown", "deny", ["custom_value_123"]),
    FieldSpec("extra_info", "unknown", "deny", ["some extra info"]),
    FieldSpec("metadata", "unknown", "deny", ['{"k": "v"}']),
    FieldSpec("internal_code", "unknown", "deny", ["INT-001"]),
    FieldSpec("flag", "unknown", "deny", [True, False, 1, 0]),
    FieldSpec("tag", "unknown", "deny", ["VIP", "NEW"]),
    FieldSpec("label", "unknown", "deny", ["重要", "普通"]),
    FieldSpec("category", "unknown", "deny", ["cat_A", "cat_B"]),
    FieldSpec("region", "unknown", "deny", ["华东", "华北"]),
    FieldSpec("source", "unknown", "deny", ["online", "offline"]),
    FieldSpec("priority", "unknown", "deny", [1, 2, 3]),
    FieldSpec("score", "unknown", "deny", [85.5, 90.0]),
    FieldSpec("rating", "unknown", "deny", [5, 4, 3]),
]

# --- 大小写变体测试字段 ---
CASE_VARIATION_TESTS: list[tuple[str, str, str]] = [
    # (变体列名, 原始列名, 期望动作)
    ("Customer_Name", "customer_name", "tokenize"),
    ("CUSTOMER_NAME", "customer_name", "tokenize"),
    ("CustomeR_NamE", "customer_name", "tokenize"),
    ("Phone", "phone", "mask_phone"),
    ("PHONE", "phone", "mask_phone"),
    ("Email", "email", "mask_email"),
    ("EMAIL", "email", "mask_email"),
    ("Id_Card", "id_card", "deny"),
    ("ID_CARD", "id_card", "deny"),
    ("Password", "password", "deny"),
    ("PASSWORD", "password", "deny"),
    ("Address", "address", "deny"),
    ("ADDRESS", "address", "deny"),
    ("Bill_No", "bill_no", "tokenize"),
    ("BILL_NO", "bill_no", "tokenize"),
]

# --- 安全字段中藏敏感数据（测试兜底正则扫描）---
TRICKY_SAFE_DATA: list[FieldSpec] = [
    FieldSpec("department_name", "tricky_safe", "fallback_scan",
              ["联系电话13812345678", "手机号15987654321请回拨"]),
    FieldSpec("level_1", "tricky_safe", "fallback_scan",
              ["身份证号110101199001011234"]),
    FieldSpec("org_name", "tricky_safe", "fallback_scan",
              ["银行卡号6222021234567890123"]),
    FieldSpec("status", "tricky_safe", "fallback_scan",
              ["13812345678"]),  # 纯手机号在安全列
    FieldSpec("code", "tricky_safe", "fallback_scan",
              ["110101199001011234"]),  # 纯身份证号在安全列
    FieldSpec("remark", "tricky_safe", "fallback_scan",
              ["备用电话13600001111"]),  # 但 remark 是 deny，不会被兜底扫描
]

# --- 边界值测试 ---
# 每个边界值用唯一列名，避免同名列互相覆盖
BOUNDARY_VALUES: list[tuple[str, Any, str]] = [
    # (列名, 值, 期望行为描述)
    ("customer_name", "", "placeholder_skip"),
    ("client_name", "N/A", "placeholder_skip"),
    ("employee_name", "null", "placeholder_skip"),
    ("supplier_name", None, "null_passthrough"),
    ("phone", "", "short_value"),
    ("mobile", "123", "short_value"),
    ("email", "", "no_at_sign"),
    ("bill_no", "noatsign", "tokenize_normal"),
    ("contact_name", "a@b.c", "tokenize_normal"),
]


# ══════════════════════════════════════════════════════════════
# 2. 随机表生成器
# ══════════════════════════════════════════════════════════════

class RandomTableGenerator:
    """随机生成各种格式和字段的数据库表"""

    def __init__(self):
        self.all_fields = SENSITIVE_FIELDS + SAFE_FIELDS + UNKNOWN_FIELDS
        self.table_counter = 0

    def generate_table_name(self) -> str:
        """生成随机表名（数仓命名规范）"""
        prefixes = ["dws", "dwd", "dim", "ods", "st", "v", "ext"]
        domains = ["order", "user", "product", "finance", "logistic",
                   "hr", "crm", "payment", "inventory", "report"]
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
        prefix = random.choice(prefixes)
        domain = random.choice(domains)
        self.table_counter += 1
        return f"{prefix}_random_{domain}_{suffix}"

    def generate_table_schema(self, min_cols: int = 5, max_cols: int = 15) -> tuple[str, list[FieldSpec]]:
        """随机生成一张表的 schema"""
        table_name = self.generate_table_name()
        num_cols = random.randint(min_cols, max_cols)

        # 确保每张表至少有一个敏感字段和一个安全字段
        sensitive = random.sample(
            SENSITIVE_FIELDS, min(random.randint(2, 5), len(SENSITIVE_FIELDS)))
        safe = random.sample(
            SAFE_FIELDS, min(random.randint(2, 5), len(SAFE_FIELDS)))

        # 随机添加未登记字段
        unknown_count = random.randint(0, 3)
        unknown = random.sample(UNKNOWN_FIELDS, min(unknown_count, len(UNKNOWN_FIELDS)))

        all_cols = sensitive + safe + unknown
        random.shuffle(all_cols)

        # 如果列数不够，补充更多字段
        while len(all_cols) < num_cols:
            all_cols.append(random.choice(self.all_fields))

        return table_name, all_cols[:num_cols]

    def generate_row(self, fields: list[FieldSpec]) -> dict:
        """为给定的 schema 生成一行随机数据"""
        row = {}
        for spec in fields:
            if spec.data_samples:
                row[spec.name] = random.choice(spec.data_samples)
            else:
                row[spec.name] = None
        return row

    def generate_table_data(self, fields: list[FieldSpec], num_rows: int = None) -> list[dict]:
        """生成多行随机数据"""
        if num_rows is None:
            num_rows = random.randint(1, 20)
        return [self.generate_row(fields) for _ in range(num_rows)]

    def generate_case_variation_table(self) -> tuple[str, list[tuple[str, str, str]], list[dict]]:
        """生成大小写变体测试表"""
        table_name = "test_case_variations"

        # 构建列名列表
        col_names = [(v[0], v[1], v[2]) for v in CASE_VARIATION_TESTS]

        # 生成数据行
        rows = []
        for _ in range(5):
            row = {}
            for variant_name, original_name, expected_action in col_names:
                # 从原始字段找数据样本
                original_spec = next(
                    (f for f in SENSITIVE_FIELDS if f.name == original_name), None)
                if original_spec and original_spec.data_samples:
                    row[variant_name] = random.choice(original_spec.data_samples)
                else:
                    row[variant_name] = "test_value"
            rows.append(row)

        return table_name, col_names, rows

    def generate_tricky_table(self) -> tuple[str, list[FieldSpec], list[dict]]:
        """生成安全字段中藏敏感数据的表"""
        table_name = "test_tricky_safe_data"
        rows = []
        for _ in range(5):
            row = {}
            for spec in TRICKY_SAFE_DATA:
                if spec.data_samples:
                    row[spec.name] = random.choice(spec.data_samples)
                else:
                    row[spec.name] = None
            rows.append(row)
        return table_name, TRICKY_SAFE_DATA, rows

    def generate_boundary_table(self) -> tuple[str, list[dict]]:
        """生成边界值测试表"""
        table_name = "test_boundary_values"
        row = {}
        for col_name, value, _ in BOUNDARY_VALUES:
            row[col_name] = value
        return table_name, [row]


# ══════════════════════════════════════════════════════════════
# 3. 脱敏拦截测试框架
# ══════════════════════════════════════════════════════════════

@dataclass
class TestResult:
    """单个测试结果"""
    test_name: str
    table_name: str
    total_fields: int
    passed: int
    failed: int
    details: list[dict] = field(default_factory=list)

    @property
    def pass_rate(self) -> float:
        return self.passed / self.total_fields if self.total_fields > 0 else 0.0


class MaskingTestRunner:
    """脱敏拦截测试运行器"""

    def __init__(self):
        self.generator = RandomTableGenerator()
        self.results: list[TestResult] = []

        # 加载脱敏规则，构建期望值查找表
        self._build_expectations()

    def _build_expectations(self):
        """从配置构建期望动作查找表"""
        cfg = get_masking_config()
        self.col_action_map: dict[str, str] = {}
        for rule in cfg.get("rules", []):
            for col in rule.get("columns", []):
                self.col_action_map[col.lower()] = rule["action"]
        self.default_action = cfg.get("defaults", {}).get("unknown_column", "deny")

    def _check_masked_value(self, col_name: str, original_value: Any,
                            masked_value: Any, expected_action: str) -> tuple[bool, str]:
        """检查脱敏后的值是否符合预期"""
        # None 值特殊处理
        if original_value is None:
            if masked_value is None:
                return True, "None值正确透传"
            return False, f"None值应透传，但得到了 {masked_value}"

        # 空字符串/占位符
        if isinstance(original_value, str) and original_value in ("", "N/A", "null"):
            if expected_action == "tokenize":
                if masked_value == original_value:
                    return True, "占位符正确跳过令牌化"
                return False, f"占位符应跳过令牌化，但得到了 {masked_value}"
            if expected_action == "deny":
                if masked_value is None:
                    return True, "空值正确deny"
                return False, f"空值应deny为None，但得到了 {masked_value}"

        if expected_action == "tokenize":
            # 应该变成令牌格式
            if isinstance(masked_value, str) and "_V1_" in masked_value:
                return True, f"正确令牌化: {masked_value}"
            return False, f"应令牌化但得到: {masked_value}"

        elif expected_action == "mask_phone":
            if isinstance(masked_value, str) and "****" in masked_value:
                return True, f"正确手机号遮掩: {masked_value}"
            if original_value and len(str(original_value)) < 7:
                if masked_value == "***":
                    return True, "短值正确遮掩为***"
                return False, f"短值应遮掩为***，但得到: {masked_value}"
            return False, f"应手机号遮掩但得到: {masked_value}"

        elif expected_action == "mask_email":
            # 邮箱遮掩：本地部分 >1 字符时为 x***@domain，=1 字符时为 *@domain
            if isinstance(masked_value, str) and (
                "***@" in masked_value or masked_value == "***"
                or (masked_value.startswith("*@") and masked_value != original_value)
            ):
                return True, f"正确邮箱遮掩: {masked_value}"
            return False, f"应邮箱遮掩但得到: {masked_value}"

        elif expected_action == "deny":
            if masked_value is None:
                return True, "正确deny为None"
            return False, f"应deny为None但得到: {masked_value}"

        elif expected_action == "passthrough":
            if masked_value == original_value:
                return True, "正确原值通过"
            # 兜底扫描可能改变了值
            if isinstance(masked_value, str) and "[已遮掩:" in masked_value:
                return True, f"兜底正则正确拦截: {masked_value}"
            return False, f"应原值通过但值被改变: {original_value} -> {masked_value}"

        elif expected_action == "fallback_scan":
            # 安全字段中的敏感数据应被兜底扫描拦截
            if isinstance(masked_value, str) and "[已遮掩:" in masked_value:
                return True, f"兜底正则正确拦截: {masked_value}"
            # remark 列是 deny，所以应该为 None
            if masked_value is None:
                return True, "deny列正确置空"
            return False, f"应被兜底扫描拦截但未被处理: {original_value} -> {masked_value}"

        return True, "未定义检查规则，默认通过"

    # ─── 测试 1: 随机表综合测试 ───
    def test_random_tables(self, num_tables: int = 50):
        """生成多张随机表，测试脱敏拦截"""
        result = TestResult("随机表综合测试", "", 0, 0, 0)

        for i in range(num_tables):
            table_name, fields = self.generator.generate_table_schema()
            rows = self.generator.generate_table_data(fields)

            masked_rows, masked_fields = apply_masking(
                rows, tables={table_name})

            for row_idx, (orig_row, masked_row) in enumerate(zip(rows, masked_rows)):
                for spec in fields:
                    col_name = spec.name
                    original_val = orig_row.get(col_name)
                    masked_val = masked_row.get(col_name)
                    expected = spec.expected_action

                    passed, reason = self._check_masked_value(
                        col_name, original_val, masked_val, expected)

                    result.total_fields += 1
                    if passed:
                        result.passed += 1
                    else:
                        result.failed += 1
                        result.details.append({
                            "table": table_name,
                            "row": row_idx,
                            "column": col_name,
                            "category": spec.category,
                            "original": str(original_val)[:60],
                            "masked": str(masked_val)[:60],
                            "expected": expected,
                            "reason": reason,
                        })

        result.table_name = f"{num_tables}张随机表"
        self.results.append(result)

    # ─── 测试 2: 大小写变体测试 ───
    def test_case_variations(self):
        """测试列名大小写变体是否被正确拦截"""
        result = TestResult("大小写变体测试", "", 0, 0, 0)

        table_name, col_specs, rows = self.generator.generate_case_variation_table()
        masked_rows, _ = apply_masking(rows, tables={table_name})

        for variant_name, original_name, expected_action in col_specs:
            for row_idx, (orig_row, masked_row) in enumerate(zip(rows, masked_rows)):
                original_val = orig_row.get(variant_name)
                masked_val = masked_row.get(variant_name)

                passed, reason = self._check_masked_value(
                    variant_name, original_val, masked_val, expected_action)

                result.total_fields += 1
                if passed:
                    result.passed += 1
                else:
                    result.failed += 1
                    result.details.append({
                        "table": table_name,
                        "row": row_idx,
                        "column": variant_name,
                        "category": "case_variation",
                        "original": str(original_val)[:60],
                        "masked": str(masked_val)[:60],
                        "expected": expected_action,
                        "reason": reason,
                    })

        result.table_name = f"{len(col_specs)}个大小写变体"
        self.results.append(result)

    # ─── 测试 3: 安全字段藏敏感数据测试 ───
    def test_tricky_safe_data(self):
        """测试安全字段中藏有敏感数据时，兜底正则能否拦截"""
        result = TestResult("兜底正则扫描测试", "", 0, 0, 0)

        table_name, fields, rows = self.generator.generate_tricky_table()
        masked_rows, masked_fields = apply_masking(rows, tables={table_name})

        for row_idx, (orig_row, masked_row) in enumerate(zip(rows, masked_rows)):
            for spec in TRICKY_SAFE_DATA:
                col_name = spec.name
                original_val = orig_row.get(col_name)
                masked_val = masked_row.get(col_name)

                passed, reason = self._check_masked_value(
                    col_name, original_val, masked_val, "fallback_scan")

                result.total_fields += 1
                if passed:
                    result.passed += 1
                else:
                    result.failed += 1
                    result.details.append({
                        "table": table_name,
                        "row": row_idx,
                        "column": col_name,
                        "category": "tricky_safe",
                        "original": str(original_val)[:60],
                        "masked": str(masked_val)[:60],
                        "expected": "fallback_scan",
                        "reason": reason,
                    })

        result.table_name = f"{len(TRICKY_SAFE_DATA)}个安全列藏敏感数据"
        self.results.append(result)

    # ─── 测试 4: 边界值测试 ───
    def test_boundary_values(self):
        """测试边界值处理"""
        result = TestResult("边界值测试", "", 0, 0, 0)

        table_name, rows = self.generator.generate_boundary_table()
        masked_rows, _ = apply_masking(rows, tables={table_name})

        for col_name, original_val, expected_behavior in BOUNDARY_VALUES:
            masked_val = masked_rows[0].get(col_name)

            # 根据期望行为检查
            if expected_behavior == "placeholder_skip":
                # tokenize 列的占位符应原样返回
                expected_action = "tokenize"
                passed, reason = self._check_masked_value(
                    col_name, original_val, masked_val, expected_action)
            elif expected_behavior == "null_passthrough":
                passed = masked_val is None
                reason = "None正确透传" if passed else f"None应透传但得到: {masked_val}"
            elif expected_behavior == "short_value":
                # mask_phone 对短值返回 "***"，空字符串原样返回（无敏感数据）
                if masked_val == "***" or masked_val == original_val:
                    passed = True
                    reason = f"短值正确处理: {masked_val}"
                else:
                    passed = False
                    reason = f"短值应遮掩为***或原样返回，但得到: {masked_val}"
            elif expected_behavior == "no_at_sign":
                # mask_email 对无 @ 的值返回 "***"，空字符串原样返回
                if masked_val == "***" or masked_val == original_val:
                    passed = True
                    reason = f"无@符号正确处理: {masked_val}"
                else:
                    passed = False
                    reason = f"无@符号应遮掩为***或原样返回，但得到: {masked_val}"
            elif expected_behavior == "tokenize_normal":
                # tokenize 列的正常值应被令牌化
                expected_action = "tokenize"
                passed, reason = self._check_masked_value(
                    col_name, original_val, masked_val, expected_action)
            else:
                passed = True
                reason = "默认通过"

            result.total_fields += 1
            if passed:
                result.passed += 1
            else:
                result.failed += 1
                result.details.append({
                    "table": table_name,
                    "column": col_name,
                    "original": str(original_val)[:60],
                    "masked": str(masked_val)[:60],
                    "expected": expected_behavior,
                    "reason": reason,
                })

        result.table_name = f"{len(BOUNDARY_VALUES)}个边界值"
        self.results.append(result)

    def _check_masking(self, col_name, original_val, masked_val, expected_action):
        """_check_masked_value 的别名"""
        return self._check_masked_value(col_name, original_val, masked_val, expected_action)

    # ─── 测试 5: 令牌一致性测试 ───
    def test_token_consistency(self):
        """测试相同值在不同行中产生相同令牌"""
        result = TestResult("令牌一致性测试", "", 0, 0, 0)

        # 构造测试数据：同一客户名出现在多行
        test_name = "张三"
        rows = [
            {"customer_name": test_name, "amount": 100},
            {"customer_name": test_name, "amount": 200},
            {"customer_name": test_name, "amount": 300},
            {"customer_name": "李四", "amount": 400},
            {"customer_name": test_name, "amount": 500},
        ]

        masked_rows, _ = apply_masking(rows, tables={"test_consistency"})

        # 所有 "张三" 的令牌应该相同
        tokens_zhangsan = set()
        token_lisi = None
        for row in masked_rows:
            if row["customer_name"] and "_V1_" in str(row["customer_name"]):
                if row["amount"] in (100, 200, 300, 500):
                    tokens_zhangsan.add(row["customer_name"])
                else:
                    token_lisi = row["customer_name"]

        result.total_fields = 1
        if len(tokens_zhangsan) == 1:
            result.passed = 1
            result.details.append({
                "check": "相同值相同令牌",
                "token": tokens_zhangsan.pop(),
                "status": "PASS",
            })
        else:
            result.failed = 1
            result.details.append({
                "check": "相同值相同令牌",
                "tokens": str(tokens_zhangsan),
                "status": "FAIL - 产生了不同的令牌",
            })

        # 李四的令牌应该不同于张三
        result.total_fields += 1
        if token_lisi and token_lisi not in tokens_zhangsan:
            result.passed += 1
            result.details.append({
                "check": "不同值不同令牌",
                "status": "PASS",
            })
        else:
            result.failed += 1
            result.details.append({
                "check": "不同值不同令牌",
                "status": "FAIL",
            })

        result.table_name = "令牌一致性"
        self.results.append(result)

    # ─── 测试 6: 列元信息查询测试 ───
    def test_column_info(self):
        """测试 get_column_masking_info 返回正确的脱敏标记"""
        result = TestResult("列元信息查询测试", "", 0, 0, 0)

        # 随机选 20 个字段检查
        all_specs = SENSITIVE_FIELDS + SAFE_FIELDS + UNKNOWN_FIELDS
        sample = random.sample(all_specs, min(20, len(all_specs)))

        for spec in sample:
            info = get_column_masking_info([spec.name])
            actual = info.get(spec.name, "unknown")
            expected = spec.expected_action

            result.total_fields += 1
            if actual == expected:
                result.passed += 1
            else:
                result.failed += 1
                result.details.append({
                    "column": spec.name,
                    "expected": expected,
                    "actual": actual,
                })

        result.table_name = f"{len(sample)}个字段元信息"
        self.results.append(result)

    # ─── 运行所有测试 ───
    def run_all(self, num_random_tables: int = 50):
        """运行全部测试"""
        print("=" * 80)
        print("  随机数据库表生成器 — 脱敏拦截压力测试")
        print(f"  运行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        print()

        start = time.time()

        print("[1/6] 随机表综合测试...")
        self.test_random_tables(num_random_tables)

        print("[2/6] 大小写变体测试...")
        self.test_case_variations()

        print("[3/6] 兜底正则扫描测试...")
        self.test_tricky_safe_data()

        print("[4/6] 边界值测试...")
        self.test_boundary_values()

        print("[5/6] 令牌一致性测试...")
        self.test_token_consistency()

        print("[6/6] 列元信息查询测试...")
        self.test_column_info()

        elapsed = time.time() - start
        print(f"\n测试完成，耗时 {elapsed:.2f}s\n")

        self._print_report()

    def _print_report(self):
        """打印测试报告"""
        total_fields = sum(r.total_fields for r in self.results)
        total_passed = sum(r.passed for r in self.results)
        total_failed = sum(r.failed for r in self.results)
        overall_rate = total_passed / total_fields * 100 if total_fields > 0 else 0

        print("═" * 80)
        print("  测试报告")
        print("═" * 80)
        print()

        # 汇总表
        print(f"{'测试名称':<24} {'表/范围':<20} {'总字段':>8} {'通过':>8} {'失败':>8} {'通过率':>8}")
        print("─" * 80)
        for r in self.results:
            rate = r.pass_rate * 100
            status = "✓" if r.failed == 0 else "✗"
            print(f"{r.test_name:<22} {r.table_name:<20} {r.total_fields:>8} {r.passed:>8} {r.failed:>8} {rate:>7.1f}% {status}")
        print("─" * 80)
        print(f"{'总计':<22} {'':<20} {total_fields:>8} {total_passed:>8} {total_failed:>8} {overall_rate:>7.1f}%")
        print()

        # 失败详情
        all_failures = []
        for r in self.results:
            for d in r.details:
                if "status" not in d or "PASS" not in str(d.get("status", "")):
                    all_failures.append({**d, "test": r.test_name})

        if all_failures:
            print("─" * 80)
            print(f"  失败详情 ({len(all_failures)} 项)")
            print("─" * 80)
            for i, f in enumerate(all_failures[:30], 1):  # 只显示前30条
                print(f"\n  [{i}] 测试: {f.get('test', '')}")
                if "column" in f:
                    print(f"      列名:   {f['column']}")
                if "table" in f:
                    print(f"      表名:   {f['table']}")
                if "category" in f:
                    print(f"      类别:   {f['category']}")
                if "original" in f:
                    print(f"      原始值: {f['original']}")
                if "masked" in f:
                    print(f"      脱敏后: {f['masked']}")
                if "expected" in f:
                    print(f"      期望:   {f['expected']}")
                if "reason" in f:
                    print(f"      原因:   {f['reason']}")
                elif "status" in f:
                    print(f"      状态:   {f['status']}")
                elif "actual" in f:
                    print(f"      实际:   {f['actual']}")

            if len(all_failures) > 30:
                print(f"\n  ... 还有 {len(all_failures) - 30} 条失败详情未显示")
        else:
            print("✓ 所有测试全部通过！脱敏网关准确拦截了所有敏感字段。")

        print()
        print("═" * 80)

        # 分类统计
        print("\n  按字段类别统计:")
        print("─" * 50)
        categories = {}
        for r in self.results:
            for d in r.details:
                cat = d.get("category", "other")
                if cat not in categories:
                    categories[cat] = {"pass": 0, "fail": 0}
                # 这里 details 只有失败的，所以都算 fail
                categories[cat]["fail"] += 1

        # 从测试结果中统计通过数
        for r in self.results:
            if r.test_name == "随机表综合测试":
                # 从 total - failed 估算各类通过数
                pass

        if not categories:
            print("  (无分类失败记录)")
        else:
            for cat, counts in sorted(categories.items()):
                print(f"  {cat:<24} 失败: {counts['fail']}")

        print()
        print("═" * 80)


# ══════════════════════════════════════════════════════════════
# 4. 主入口
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    runner = MaskingTestRunner()
    runner.run_all(num_random_tables=50)
