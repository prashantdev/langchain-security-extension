"""
Unit tests for ToolViolationHandler, RetryBudgetTracker, AbuseThrottleTracker, and ViolationResolution.
"""

import time
import unittest
from security_core.identity import SecurityIdentity, IdentityBridge
from security_core.pdp import EmbeddedPolicyEngine
from security_core.audit import AuditManager
from tests.audit_test_collector import TestAuditCollector
from security_core.exceptions import ToolExecutionDeniedError
from security_core.constants import (
    EVENT_POLICY_BRUTE_FORCE_DETECTED,
    EVENT_POLICY_BRUTE_FORCE_SCANNING,
)
from security_adapter_langchain.violation_handler import (
    ToolViolationHandler,
    RetryBudgetTracker,
    AbuseThrottleTracker,
    ViolationResolution,
    STATUS_BLOCKED_BY_POLICY,
    REMED_SEC_BLOCKED_POLICY,
    REMED_EXEC_ABORTED,
)


class TestViolationHandler(unittest.TestCase):

    def setUp(self) -> None:
        self.logger = TestAuditCollector.create()
        self.audit_mgr = AuditManager.create(publishers=[self.logger])
        self.pdp = EmbeddedPolicyEngine.create()
        self.pdp._audit_manager = self.audit_mgr

        self.identity = SecurityIdentity.create(
            subject_id="devops_user",
            tenant_id="CORP_MAIN",
            roles={"DEVOPS"},
            clearance_level=2,
            department_id="ENG",
            attributes={},
        )

    def test_retry_budget_tracker_lifecycle(self) -> None:
        tracker = RetryBudgetTracker.create(max_feedback_violations=2)
        config = {"configurable": {}}

        self.assertEqual(tracker.max_feedback_violations, 2)
        self.assertEqual(tracker.get_retry_count(config), 0)
        self.assertFalse(tracker.is_budget_exceeded(config))

        count1 = tracker.increment_retry_count(config)
        self.assertEqual(count1, 1)
        self.assertFalse(tracker.is_budget_exceeded(config))

        count2 = tracker.increment_retry_count(config)
        self.assertEqual(count2, 2)
        self.assertFalse(tracker.is_budget_exceeded(config))

        count3 = tracker.increment_retry_count(config)
        self.assertEqual(count3, 3)
        self.assertTrue(tracker.is_budget_exceeded(config))

        tracker.reset(config)
        self.assertEqual(tracker.get_retry_count(config), 0)
        self.assertFalse(tracker.is_budget_exceeded(config))

    def test_abuse_throttle_tracker_sliding_window(self) -> None:
        tracker = AbuseThrottleTracker.create(window_seconds=10.0, max_denials=3)
        subject = "attacker@evil.com"
        now = time.time()

        self.assertFalse(tracker.record_denial(subject, now))
        self.assertFalse(tracker.is_throttled(subject, now))

        self.assertFalse(tracker.record_denial(subject, now + 1.0))
        self.assertFalse(tracker.is_throttled(subject, now + 1.0))

        # 3rd denial within window reaches threshold
        self.assertTrue(tracker.record_denial(subject, now + 2.0))
        self.assertTrue(tracker.is_throttled(subject, now + 2.0))

        # Outside sliding window
        self.assertFalse(tracker.is_throttled(subject, now + 15.0))

    def test_violation_handler_standard_resolution(self) -> None:
        handler = ToolViolationHandler.default_handler(self.pdp)
        config = IdentityBridge.create_runnable_config(self.identity)

        exc = ToolExecutionDeniedError.for_tool(
            tool_name="restartService",
            message="Access denied",
            diagnostic_reason="INSUFFICIENT_CLEARANCE",
        )

        resolution = handler.resolve_tool_exception(exc, config)

        self.assertIsInstance(resolution, ViolationResolution)
        self.assertEqual(resolution.status, STATUS_BLOCKED_BY_POLICY)
        self.assertEqual(resolution.policy_decision, REMED_SEC_BLOCKED_POLICY)
        self.assertEqual(resolution.execution_action, REMED_EXEC_ABORTED)
        self.assertEqual(resolution.remediation_security, REMED_SEC_BLOCKED_POLICY)
        self.assertEqual(resolution.remediation_execution, REMED_EXEC_ABORTED)
        self.assertTrue(resolution.should_abort)
        self.assertEqual(resolution.tool_name, "restartService")
        self.assertIn("INSUFFICIENT_CLEARANCE", resolution.root_cause)

        last_viol = config["configurable"].get("sec:last_violation")
        self.assertIsNotNone(last_viol)
        self.assertEqual(last_viol.tool_name, "restartService")

    def test_violation_handler_retry_budget_exceeded_escalation(self) -> None:
        handler = ToolViolationHandler.default_handler(self.pdp)
        config = IdentityBridge.create_runnable_config(self.identity)

        # Exhaust retry budget
        handler.retry_tracker.increment_retry_count(config)
        handler.retry_tracker.increment_retry_count(config)
        handler.retry_tracker.increment_retry_count(config)
        self.assertTrue(handler.retry_tracker.is_budget_exceeded(config))

        exc = ToolExecutionDeniedError.for_tool(
            tool_name="restartService",
            message="Denied again",
            diagnostic_reason="PARAMETER_CONSTRAINT_FAILED",
        )

        resolution = handler.resolve_tool_exception(exc, config)

        self.assertIn("POLICY_BRUTE_FORCE_SCANNING", resolution.root_cause)
        self.assertIn("retry budget exceeded", resolution.user_message)

        events = self.logger.get_events()
        bf_events = [e for e in events if e.reason_code == EVENT_POLICY_BRUTE_FORCE_DETECTED]
        self.assertEqual(len(bf_events), 1)
        self.assertEqual(bf_events[0].target_resource, "restartService")

    def test_violation_handler_abuse_throttle_escalation(self) -> None:
        handler = ToolViolationHandler.default_handler(self.pdp)
        config = IdentityBridge.create_runnable_config(self.identity)

        exc = ToolExecutionDeniedError.for_tool(
            tool_name="sensitiveDump",
            message="Denied",
            diagnostic_reason="MISSING_ROLE",
        )

        # Trigger denials up to throttle limit
        handler.resolve_tool_exception(exc, config)
        handler.resolve_tool_exception(exc, config)
        handler.resolve_tool_exception(exc, config)

        events = self.logger.get_events()
        throttle_events = [e for e in events if e.reason_code == EVENT_POLICY_BRUTE_FORCE_SCANNING]
        self.assertGreaterEqual(len(throttle_events), 1)


if __name__ == "__main__":
    unittest.main()
