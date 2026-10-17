"""
Unit tests for PiiSanitizerSPI, BuiltInPiiSanitizer, and in-flight redaction scopes.
"""

import unittest
from typing import Any, Dict, Optional, Set

from security_core.constants import (
    DEFAULT_PAYLOAD_MAX_CHARS,
    PII_SCOPE_AUDIT_ONLY,
    PII_SCOPE_DISABLED,
    PII_SCOPE_FULL_IN_FLIGHT,
    PII_STAGE_AUDIT_PAYLOAD,
    PII_STAGE_INBOUND_PROMPT,
    PII_STAGE_OUTBOUND_RESPONSE,
    PII_STAGE_TOOL_ARGUMENT,
    PII_STAGE_TOOL_OUTPUT,
    PII_STAGE_RETRIEVAL_DOCUMENT,
    DECISION_PERMIT,
    CLEARANCE_RANK_PUBLIC,
    CLEARANCE_RANK_RESTRICTED,
)
from security_core.identity import SecurityIdentity
from security_core.pdp import EmbeddedPolicyEngine
from security_core.audit import AuditEvent, AuditManager
from security_core.pii import (
    BuiltInPiiSanitizer,
    PiiContext,
    PiiSanitizerSPI,
    get_pii_sanitizer,
    set_pii_sanitizer,
    reset_pii_sanitizer,
    get_pii_scope,
    set_pii_scope,
    reset_pii_scope,
    is_valid_luhn,
)
from security_adapter_langchain.runnable_guard import SecureRunnable
from security_adapter_langchain.tool_decorator import secured_tool
from security_adapter_langchain.retriever_wrapper import SecureRetriever, SecureDocument


class CustomEnterpriseSanitizer(PiiSanitizerSPI):
    """Custom test SPI implementation substituting emails with custom tokens."""

    def sanitize_text(
        self,
        text: str,
        context: Optional[PiiContext],
        *args: Any,
        **kwargs: Any,
    ) -> str:
        if "@" in text:
            import re
            return re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b', "<CUSTOM_EMAIL_TOKEN>", text)
        return text

    def sanitize_payload(
        self,
        payload: Dict[str, Any],
        context: Optional[PiiContext],
        *args: Any,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        result = {}
        for k, v in payload.items():
            if isinstance(v, str):
                result[k] = self.sanitize_text(v, context)
            elif isinstance(v, dict):
                result[k] = self.sanitize_payload(v, context)
            else:
                result[k] = v
        return result


class TestPiiSanitizer(unittest.TestCase):

    def setUp(self):
        reset_pii_sanitizer()
        reset_pii_scope()

    def tearDown(self):
        reset_pii_sanitizer()
        reset_pii_scope()

    def test_luhn_algorithm_validation(self):
        # Valid cards (Visa, Mastercard, Amex test numbers)
        self.assertTrue(is_valid_luhn("4111111111111111"))
        self.assertTrue(is_valid_luhn("5105105105105100"))
        self.assertTrue(is_valid_luhn("378282246310005"))

        # Invalid cards (checksum failure or invalid length)
        self.assertFalse(is_valid_luhn("1234567890123456"))
        self.assertFalse(is_valid_luhn("12345"))
        self.assertFalse(is_valid_luhn("9999999999999999"))

    def test_builtin_sanitizer_regex_entities(self):
        sanitizer = BuiltInPiiSanitizer()
        ctx = PiiContext.create(PII_STAGE_AUDIT_PAYLOAD, "TENANT_1", "user_1", "res_1", None)

        # 1. Emails
        self.assertEqual(
            sanitizer.sanitize_text("Contact user at alice.smith+tag@example.com for support.", ctx),
            "Contact user at [REDACTED] for support."
        )

        # 2. Phone Numbers
        self.assertEqual(
            sanitizer.sanitize_text("Call hotline: +1 (555) 123-4567 or 555-987-6543 today.", ctx),
            "Call hotline: [REDACTED] or [REDACTED] today."
        )
        # 10-digit phone numbers near phone/telephone/fone/fon keywords
        self.assertEqual(
            sanitizer.sanitize_text("Reach my phone 9876543210 or fone at 1234567890.", ctx),
            "Reach my phone [REDACTED] or fone at [REDACTED]."
        )
        self.assertEqual(
            sanitizer.sanitize_text("Telephone: 5551234567 / Fon: 9998887777.", ctx),
            "Telephone: [REDACTED] / Fon: [REDACTED]."
        )
        # 10-digit Unix timestamps and IDs not near phone keywords -> Untouched
        self.assertEqual(
            sanitizer.sanitize_text("System event epoch timestamp 1792133343 and TCK-SIEM-1792133632.", ctx),
            "System event epoch timestamp 1792133343 and TCK-SIEM-1792133632."
        )

        # 3. US Social Security Numbers
        self.assertEqual(
            sanitizer.sanitize_text("SSN record is 123-45-6789 and secondary is 987 65 4321.", ctx),
            "SSN record is [REDACTED] and secondary is [REDACTED]."
        )
        # Unformatted 9-digit SSN near hint keyword -> Redacted
        self.assertEqual(
            sanitizer.sanitize_text("Employee SSN: 123456789 verified in payroll.", ctx),
            "Employee SSN: [REDACTED] verified in payroll."
        )
        self.assertEqual(
            sanitizer.sanitize_text("Social Security Number: 987654321 on file.", ctx),
            "Social Security Number: [REDACTED] on file."
        )
        # Unformatted 9-digit number with no SSN hint keywords -> Untouched
        self.assertEqual(
            sanitizer.sanitize_text("Package tracking ID 123456789 dispatched to warehouse.", ctx),
            "Package tracking ID 123456789 dispatched to warehouse."
        )

        # 4. Credit Cards (Luhn verified vs random numbers)
        # Valid Visa 4111-1111-1111-1111 -> Redacted
        self.assertEqual(
            sanitizer.sanitize_text("Card number: 4111-1111-1111-1111 for transaction.", ctx),
            "Card number: [REDACTED] for transaction."
        )
        # Random 16 digits failing Luhn -> Untouched
        self.assertEqual(
            sanitizer.sanitize_text("Tracking ID: 1234-5678-9012-3456 in invoice.", ctx),
            "Tracking ID: 1234-5678-9012-3456 in invoice."
        )

        # 5. IPv4 Addresses
        self.assertEqual(
            sanitizer.sanitize_text("Host located at 192.168.1.100 and dns 10.0.0.1.", ctx),
            "Host located at [REDACTED] and dns [REDACTED]."
        )

        # 6. Cloud Keys & Tokens
        self.assertEqual(
            sanitizer.sanitize_text("Deploy with AKIAIOSFODNN7EXAMPLE key.", ctx),
            "Deploy with [REDACTED] key."
        )
        self.assertEqual(
            sanitizer.sanitize_text("GCP key AIzaSyD-1234567890abcdef123456789012345 active.", ctx),
            "GCP key [REDACTED] active."
        )
        self.assertEqual(
            sanitizer.sanitize_text("GitHub token ghp_1234567890abcdefghijklmnopqrstuvwxyz generated.", ctx),
            "GitHub token [REDACTED] generated."
        )
        self.assertEqual(
            sanitizer.sanitize_text("Slack bot xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx connected.", ctx),
            "Slack bot [REDACTED] connected."
        )

        # 7. Database connection URIs
        self.assertEqual(
            sanitizer.sanitize_text("postgres://dbuser:supersecretpass@db.prod.internal:5432/corpdb", ctx),
            "postgres://dbuser:[REDACTED]@db.prod.internal:5432/corpdb"
        )

        # 8. Private Keys
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA04\n-----END RSA PRIVATE KEY-----"
        self.assertEqual(sanitizer.sanitize_text(f"Key data:\n{pem}", ctx), "Key data:\n[REDACTED]")

    def test_builtin_sanitizer_payload_masking(self):
        sanitizer = BuiltInPiiSanitizer()
        sanitizer.register_masked_field("custom_token_field")

        payload = {
            "password": "secret_password_1",
            "email": "user@domain.com",
            "phone_number": "+1-555-555-5555",
            "dob": "1990-01-01",
            "custom_token_field": "confidential_val",
            "normal_field": "Plain text note",
            "nested": {
                "credit_card": "4111-1111-1111-1111",
                "ssn": "000-12-3456",
                "comment": "Reach me at support@helpdesk.org tomorrow.",
            },
        }

        ctx = PiiContext.create(PII_STAGE_AUDIT_PAYLOAD, None, None, None, None)
        cleaned = sanitizer.sanitize_payload(payload, ctx)

        self.assertEqual(cleaned["password"], "[REDACTED]")
        self.assertEqual(cleaned["email"], "[REDACTED]")
        self.assertEqual(cleaned["phone_number"], "[REDACTED]")
        self.assertEqual(cleaned["dob"], "[REDACTED]")
        self.assertEqual(cleaned["custom_token_field"], "[REDACTED]")
        self.assertEqual(cleaned["normal_field"], "Plain text note")
        self.assertEqual(cleaned["nested"]["credit_card"], "[REDACTED]")
        self.assertEqual(cleaned["nested"]["ssn"], "[REDACTED]")
        self.assertIn("[REDACTED]", cleaned["nested"]["comment"])
        self.assertNotIn("support@helpdesk.org", cleaned["nested"]["comment"])

    def test_payload_size_truncation(self):
        sanitizer = BuiltInPiiSanitizer()
        ctx = PiiContext.create(PII_STAGE_AUDIT_PAYLOAD, None, None, None, None)
        long_str = "X" * 3000
        truncated = sanitizer.sanitize_text(long_str, ctx, 50)
        self.assertEqual(len(truncated), 50 + len("...[TRUNCATED]"))
        self.assertTrue(truncated.endswith("...[TRUNCATED]"))

    def test_scope_audit_only_vs_full_in_flight_runnable(self):
        engine = EmbeddedPolicyEngine.create()
        identity = SecurityIdentity.create(
            subject_id="test_user",
            tenant_id="TENANT_A",
            roles=["engineer"],
            clearance_level=CLEARANCE_RANK_RESTRICTED,
            department_id="ENG",
        )

        def mock_agent(prompt: str) -> str:
            return f"Processed query: {prompt} for client."

        guarded = SecureRunnable(
            runnable=mock_agent,
            pdp_engine=engine,
            agent_name="TestAgent",
            required_roles=None,
            min_clearance=CLEARANCE_RANK_PUBLIC,
            target_tenant="TENANT_A",
        )

        cfg = {"configurable": {"security_identity": identity}}
        raw_prompt = "Contact alice@company.com with phone 555-123-4567."

        # Case 1: AUDIT_ONLY (Default) - In-flight prompt and response are NOT altered
        set_pii_scope(PII_SCOPE_AUDIT_ONLY)
        result_audit_only = guarded.invoke(raw_prompt, config=cfg)
        self.assertIn("alice@company.com", result_audit_only)
        self.assertIn("555-123-4567", result_audit_only)

        # Case 2: FULL_IN_FLIGHT - In-flight prompt and response are one-way redacted
        set_pii_scope(PII_SCOPE_FULL_IN_FLIGHT)
        result_full = guarded.invoke(raw_prompt, config=cfg)
        self.assertNotIn("alice@company.com", result_full)
        self.assertNotIn("555-123-4567", result_full)
        self.assertIn("[REDACTED]", result_full)

    def test_scope_full_in_flight_tool_execution(self):
        identity = SecurityIdentity.create(
            subject_id="test_user",
            tenant_id="TENANT_A",
            roles=["admin"],
            clearance_level=CLEARANCE_RANK_RESTRICTED,
            department_id="OPS",
        )

        @secured_tool(
            required_roles=["admin"],
            min_clearance=CLEARANCE_RANK_PUBLIC,
            cel_expression=None,
            is_mutative=False,
        )
        def process_customer_order(customer_email: str, order_id: str) -> Dict[str, Any]:
            return {
                "order_id": order_id,
                "received_email": customer_email,
                "confirmation": f"Sent receipt to {customer_email}",
            }


        cfg = {"configurable": {"security_identity": identity}}

        # Case 1: AUDIT_ONLY - Tool receives raw argument and returns raw result
        set_pii_scope(PII_SCOPE_AUDIT_ONLY)
        res_audit = process_customer_order(customer_email="bob@corp.com", order_id="ORD-100", config=cfg)
        self.assertEqual(res_audit["received_email"], "bob@corp.com")
        self.assertIn("bob@corp.com", res_audit["confirmation"])

        # Case 2: FULL_IN_FLIGHT - Tool arguments and return values are redacted
        set_pii_scope(PII_SCOPE_FULL_IN_FLIGHT)
        res_flight = process_customer_order(customer_email="bob@corp.com", order_id="ORD-100", config=cfg)
        self.assertEqual(res_flight["received_email"], "[REDACTED]")
        self.assertNotIn("bob@corp.com", res_flight["confirmation"])
        self.assertIn("[REDACTED]", res_flight["confirmation"])

    def test_custom_spi_sanitizer_registration(self):
        custom_provider = CustomEnterpriseSanitizer()
        set_pii_sanitizer(custom_provider)
        set_pii_scope(PII_SCOPE_FULL_IN_FLIGHT)

        sanitizer = get_pii_sanitizer()
        self.assertIs(sanitizer, custom_provider)

        ctx = PiiContext.create(PII_STAGE_INBOUND_PROMPT, "TENANT_1", "user_1", "res_1", None)
        output = sanitizer.sanitize_text("Please notify developer@enterprise.io immediately.", ctx)
        self.assertIn("<CUSTOM_EMAIL_TOKEN>", output)
        self.assertNotIn("developer@enterprise.io", output)


if __name__ == "__main__":
    unittest.main()
