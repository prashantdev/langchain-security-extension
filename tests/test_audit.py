import unittest
from security_core.audit import AuditEvent, AuditManager, InMemoryAuditLogger
from security_core.constants import AUDIT_SEVERITY_INFO, DECISION_PERMIT


class TestAuditSubsystem(unittest.TestCase):

    def test_audit_event_creation_and_logging(self):
        logger = InMemoryAuditLogger.create()
        manager = AuditManager.create(publishers=[logger])

        event = AuditEvent.create(
            subject_id="user_123",
            tenant_id="CORP",
            action="tool:execute",
            resource="restart_server",
            decision=DECISION_PERMIT,
            diagnostic_reason="AUTHORIZED",
            severity=AUDIT_SEVERITY_INFO,
            metadata={"run_id": "r_001"},
        )
        manager.record_event(event)

        events = logger.get_events()
        self.assertEqual(len(events), 1)
        recorded = events[0]
        self.assertEqual(recorded.subject_id, "user_123")
        self.assertEqual(recorded.resource, "restart_server")
        self.assertEqual(recorded.decision, DECISION_PERMIT)
        self.assertEqual(recorded.metadata["run_id"], "r_001")


if __name__ == "__main__":
    unittest.main()
