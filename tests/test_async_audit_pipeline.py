"""
Unit tests for OCSF Audit Event Schema, 3-Stage Sanitization, and SIEM publishing.
"""

import unittest
from security_core.audit import AuditEvent, AuditSanitizer, PythonLoggingAuditPublisher, AuditManager, InMemoryAuditLogger
from security_core.constants import SEVERITY_INFORMATIONAL, DECISION_PERMIT


class TestAsyncAuditPipeline(unittest.TestCase):

    def test_audit_event_ocsf_schema_fields(self):
        event = AuditEvent.create(
            subject_id="u_001",
            tenant_id="TENANT_A",
            action="agent:invoke",
            resource="RemediationAgent",
            decision=DECISION_PERMIT,
            diagnostic_reason="Authorized",
            severity=SEVERITY_INFORMATIONAL,
            metadata={"trace_id": "tr_123", "span_id": "sp_456"},
            enforcement_point="AGENT_GUARD",
        )

        d = event.to_dict()
        self.assertEqual(d["schema_version"], "1.0")
        self.assertEqual(d["enforcement_point"], "AGENT_GUARD")
        self.assertIsNotNone(d["event_id"])
        self.assertEqual(d["trace_id"], "tr_123")
        self.assertEqual(d["span_id"], "sp_456")

    def test_3_stage_sanitization_pipeline(self):
        raw_payload = {
            "password": "supersecretpassword123",
            "token": "bearer eyJhbGciOiJIUzI1NiJ9.test",
            "auth_header": "Authorization: Bearer my_secret_token_value",
            "normal_field": "Normal operational text",
            "long_text": "A" * 3000,
        }

        cleaned = AuditSanitizer.sanitize_payload(raw_payload, max_chars=2000)
        self.assertEqual(cleaned["password"], "[REDACTED]")
        self.assertEqual(cleaned["token"], "[REDACTED]")
        self.assertTrue(cleaned["long_text"].endswith("...[TRUNCATED]"))
        self.assertEqual(cleaned["normal_field"], "Normal operational text")

    def test_audit_manager_ring_buffer_backpressure(self):
        logger = InMemoryAuditLogger.create()
        # Ring buffer capacity of 2
        manager = AuditManager.create(publishers=[logger], capacity=2)

        ev1 = AuditEvent.create("u1", "t1", "act1", "res1", "PERMIT", "ok", "INFO", {})
        ev2 = AuditEvent.create("u2", "t1", "act2", "res2", "PERMIT", "ok", "INFO", {})
        ev3 = AuditEvent.create("u3", "t1", "act3", "res3", "PERMIT", "ok", "INFO", {})

        manager.record_event(ev1)
        manager.record_event(ev2)
        manager.record_event(ev3)

        self.assertEqual(manager.dropped_count, 1)

    def test_audit_manager_default_capacity_and_drop_oldest(self):
        from security_core.constants import DEFAULT_RING_BUFFER_CAPACITY
        logger = InMemoryAuditLogger.create()
        manager = AuditManager.create(publishers=[logger])
        self.assertEqual(manager._capacity, DEFAULT_RING_BUFFER_CAPACITY)
        self.assertEqual(manager._capacity, 16384)

    def test_audit_manager_async_worker_dispatches_to_external_publishers(self):
        events_received = []

        class ExternalSpyPublisher:
            def publish(self, event):
                events_received.append(event)
            def flush(self):
                pass
            def close(self):
                pass

        spy = ExternalSpyPublisher()
        manager = AuditManager.create(publishers=[spy])
        ev = AuditEvent.create("u1", "t1", "act1", "res1", "PERMIT", "ok", "INFO", {})
        manager.record_event(ev)
        manager.flush()
        self.assertEqual(len(events_received), 1)
        self.assertEqual(events_received[0].subject_id, "u1")
        manager.close()

