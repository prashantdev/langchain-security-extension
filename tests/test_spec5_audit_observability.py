"""
Unit tests for Spec 5 Security Audit & Telemetry Observability Subsystem.
"""

import os
import json
import tempfile
import unittest
from security_core.audit import (
    AuditEvent,
    AuditSanitizer,
    AuditManager,
    InMemoryAuditLogger,
    JsonFileAuditLogger,
    OpenTelemetryLogsPublisher,
)
from security_core.constants import (
    SEVERITY_INFORMATIONAL,
    SEVERITY_CRITICAL_ALERT,
    DECISION_PERMIT,
    DECISION_DENY,
    EVENT_PROMPT_INJECTION_DETECTED,
    STRATEGY_HARD_ABORT,
)

SAMPLE_SUBJECT_ID = "sarah.employee@enterprise.com"
SAMPLE_TENANT_ID = "CORP_MAIN"
SAMPLE_TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
SAMPLE_SPAN_ID = "00f067aa0ba902b7"


class TestSpec5AuditObservability(unittest.TestCase):

    def test_credential_and_pii_scrubbing(self):
        raw_payload = {
            "aws_key": "AKIAIOSFODNN7EXAMPLE",
            "bearer_token": "Bearer_secretToken_12345",
            "kv_secret": "secret=SUPER_SECRET_PASSWORD_999",
            "nested": {
                "password": "my_db_password_123",
                "normal_attr": "normal_val",
            },
            "list_items": [
                "raw_text_with_AKIAIOSFODNN7EXAMPLE",
                {"api_key": "secret_api_key_val"},
            ],
        }

        cleaned = AuditSanitizer.sanitize_payload(raw_payload)
        self.assertEqual(cleaned["aws_key"], "[REDACTED]")
        self.assertEqual(cleaned["bearer_token"], "[REDACTED]")
        self.assertIn("secret=[REDACTED]", cleaned["kv_secret"])
        self.assertNotIn("SUPER_SECRET_PASSWORD_999", cleaned["kv_secret"])
        self.assertEqual(cleaned["nested"]["password"], "[REDACTED]")
        self.assertEqual(cleaned["nested"]["normal_attr"], "normal_val")
        self.assertIn("[REDACTED]", cleaned["list_items"][0])
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", cleaned["list_items"][0])
        self.assertEqual(cleaned["list_items"][1]["api_key"], "[REDACTED]")

    def test_threat_event_attributes(self):
        event = AuditEvent.create(
            subject_id=SAMPLE_SUBJECT_ID,
            tenant_id=SAMPLE_TENANT_ID,
            action="prompt:scan",
            resource="INGESTION_PIPELINE",
            decision=DECISION_DENY,
            diagnostic_reason="Prompt injection detected",
            severity=SEVERITY_CRITICAL_ALERT,
            metadata={"pattern_id": "JAILBREAK_SYSTEM_OVERRIDE"},
            enforcement_point="INGESTION_PIPELINE",
            reason_code=EVENT_PROMPT_INJECTION_DETECTED,
        )
        event.threat_category = "PROMPT_INJECTION"
        event.threat_score = 0.95
        event.detected_pattern = "JAILBREAK_SYSTEM_OVERRIDE"
        event.mitigation_action = STRATEGY_HARD_ABORT

        data = event.to_dict()
        self.assertEqual(data["threat_category"], "PROMPT_INJECTION")
        self.assertEqual(data["threat_score"], 0.95)
        self.assertEqual(data["detected_pattern"], "JAILBREAK_SYSTEM_OVERRIDE")
        self.assertEqual(data["mitigation_action"], STRATEGY_HARD_ABORT)
        self.assertEqual(data["reason_code"], EVENT_PROMPT_INJECTION_DETECTED)
        self.assertEqual(data["severity"], SEVERITY_CRITICAL_ALERT)

    def test_json_file_audit_logger_sanitization_on_write(self):
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".json") as tmp_file:
            log_path = tmp_file.name

        try:
            logger = JsonFileAuditLogger.create(log_path)
            manager = AuditManager.create(publishers=[logger])

            event = AuditEvent.create(
                subject_id=SAMPLE_SUBJECT_ID,
                tenant_id=SAMPLE_TENANT_ID,
                action="ticket:submit",
                resource="ticket:123",
                decision=DECISION_PERMIT,
                diagnostic_reason="Processed",
                severity=SEVERITY_INFORMATIONAL,
                metadata={
                    "rawTicketText": "test secret=SUPER_SECRET_999 aws_key=AKIAIOSFODNN7EXAMPLE",
                    "trace_id": SAMPLE_TRACE_ID,
                    "span_id": SAMPLE_SPAN_ID,
                },
            )
            event.trace_id = SAMPLE_TRACE_ID
            event.span_id = SAMPLE_SPAN_ID
            manager.record_event(event)
            manager.flush()

            with open(log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            self.assertEqual(len(lines), 1)
            record = json.loads(lines[0])
            self.assertEqual(record["trace_id"], SAMPLE_TRACE_ID)
            self.assertEqual(record["span_id"], SAMPLE_SPAN_ID)
            self.assertNotIn("SUPER_SECRET_999", record["payload_snapshot"]["rawTicketText"])
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", record["payload_snapshot"]["rawTicketText"])
            self.assertIn("[REDACTED]", record["payload_snapshot"]["rawTicketText"])

        finally:
            if os.path.exists(log_path):
                os.remove(log_path)

    def test_opentelemetry_logs_publisher(self):
        pub = OpenTelemetryLogsPublisher()
        event = AuditEvent.create(
            subject_id=SAMPLE_SUBJECT_ID,
            tenant_id=SAMPLE_TENANT_ID,
            action="agent:invoke",
            resource="RemediationAgent",
            decision=DECISION_PERMIT,
            diagnostic_reason="OK",
            severity=SEVERITY_INFORMATIONAL,
            metadata={"trace_id": SAMPLE_TRACE_ID, "span_id": SAMPLE_SPAN_ID},
        )
        # Verify publish executes safely without errors even without full OTel collector SDK setup
        pub.publish(event)


if __name__ == "__main__":
    unittest.main()
