"""
Unit tests for SecureRunnable service boundary wrapper.
"""

import unittest
import asyncio
from typing import Dict, Any, Optional
from langchain_security_extension.security_core.identity import SecurityIdentity, IdentityBridge
from langchain_security_extension.security_core.pdp import EmbeddedPolicyEngine
from langchain_security_extension.security_core.exceptions import AgentAccessDeniedException, ToolExecutionDeniedError
from langchain_security_extension.security_adapter_langchain.runnable_guard import SecureRunnable
from langchain_security_extension.security_adapter_langchain.violation_handler import ToolViolationHandler, ViolationResolution


class TestSecureRunnableGuard(unittest.TestCase):

    def setUp(self) -> None:
        self.pdp = EmbeddedPolicyEngine.create()
        self.admin_identity = SecurityIdentity.create(
            subject_id="admin_01",
            tenant_id="CORP_MAIN",
            roles={"ADMIN"},
            clearance_level=3,
            department_id="IT_OPS",
            attributes={},
        )
        self.user_identity = SecurityIdentity.create(
            subject_id="user_01",
            tenant_id="CORP_MAIN",
            roles={"USER"},
            clearance_level=1,
            department_id="SALES",
            attributes={},
        )

    def test_secure_runnable_permit_invocation(self) -> None:
        def target_agent(payload: str, config: Optional[Dict[str, Any]] = None) -> str:
            return f"Processed: {payload}"

        guarded = SecureRunnable.wrap(
            runnable=target_agent,
            pdp_engine=self.pdp,
            agent_name="admin_agent",
            required_roles=["ADMIN"],
            min_clearance=2,
            target_tenant="CORP_MAIN",
        )

        run_config = IdentityBridge.create_runnable_config(self.admin_identity)
        result = guarded.invoke("ticket-101", config=run_config)
        self.assertEqual(result, "Processed: ticket-101")
        self.assertTrue(run_config["configurable"].get("sec:entry_verified:admin_agent"))

    def test_secure_runnable_denied_invocation_raises_exception(self) -> None:
        def target_agent(payload: str) -> str:
            return payload

        guarded = SecureRunnable.wrap(
            runnable=target_agent,
            pdp_engine=self.pdp,
            agent_name="restricted_agent",
            required_roles=["ADMIN"],
            min_clearance=3,
            target_tenant="CORP_MAIN",
        )

        run_config = IdentityBridge.create_runnable_config(self.user_identity)
        with self.assertRaises(AgentAccessDeniedException):
            guarded.invoke("runbook", config=run_config)

    def test_secure_runnable_with_violation_handler_fallback(self) -> None:
        def failing_tool_runner(payload: str, config: Optional[Dict[str, Any]] = None) -> str:
            raise ToolExecutionDeniedError.for_tool(
                tool_name="restartService",
                message="Denied by policy",
                diagnostic_reason="INSUFFICIENT_CLEARANCE",
            )

        def fallback_builder(payload: str, resolution: ViolationResolution, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
            return {
                "input": payload,
                "status": resolution.status,
                "root_cause": resolution.root_cause,
                "user_message": resolution.user_message,
            }

        handler = ToolViolationHandler.default_handler(self.pdp)
        guarded = SecureRunnable.wrap(
            runnable=failing_tool_runner,
            pdp_engine=self.pdp,
            agent_name="remediation_agent",
            required_roles=["ADMIN"],
            min_clearance=2,
            target_tenant="CORP_MAIN",
        ).with_violation_handler(
            violation_handler=handler,
            fallback_builder=fallback_builder,
        )

        run_config = IdentityBridge.create_runnable_config(self.admin_identity)
        report = guarded.invoke("ticket-202", config=run_config)

        self.assertEqual(report["status"], "BLOCKED_BY_POLICY")
        self.assertIn("restartService", report["root_cause"])
        self.assertIn("INSUFFICIENT_CLEARANCE", report["root_cause"])

    def test_secure_runnable_handoff(self) -> None:
        def triage_step(payload: str, config: Optional[Dict[str, Any]] = None) -> str:
            return f"Triaged: {payload}"

        def remed_step(payload: str, config: Optional[Dict[str, Any]] = None) -> str:
            return f"Remediated: {payload}"

        triage_guard = SecureRunnable.wrap(
            runnable=triage_step,
            pdp_engine=self.pdp,
            agent_name="triage_agent",
            required_roles=["ADMIN"],
            min_clearance=2,
            target_tenant="CORP_MAIN",
        )
        remed_guard = SecureRunnable.wrap(
            runnable=remed_step,
            pdp_engine=self.pdp,
            agent_name="remediation_agent",
            required_roles=["ADMIN"],
            min_clearance=2,
            target_tenant="CORP_MAIN",
        )

        run_config = IdentityBridge.create_runnable_config(self.admin_identity)
        triage_res = triage_guard.invoke("incident-1", config=run_config)
        remed_res = SecureRunnable.handoff(remed_guard, triage_res, run_config)

        self.assertEqual(remed_res, "Remediated: Triaged: incident-1")
        self.assertTrue(run_config["configurable"].get("sec:handoff_propagated"))
        self.assertEqual(run_config["configurable"].get("sec:handoff_target"), "remediation_agent")

    def test_secure_runnable_batch_and_stream(self) -> None:
        def echo_fn(payload: str, config: Optional[Dict[str, Any]] = None) -> str:
            return f"Echo {payload}"

        guarded = SecureRunnable.wrap(
            runnable=echo_fn,
            pdp_engine=self.pdp,
            agent_name="echo_agent",
            required_roles=["ADMIN"],
            min_clearance=2,
            target_tenant="CORP_MAIN",
        )

        run_config = IdentityBridge.create_runnable_config(self.admin_identity)
        batch_results = guarded.batch(["1", "2", "3"], config=run_config)
        self.assertEqual(batch_results, ["Echo 1", "Echo 2", "Echo 3"])

        stream_chunks = list(guarded.stream("stream-test", config=run_config))
        self.assertEqual(stream_chunks, ["Echo stream-test"])

    def test_secure_runnable_ainvoke(self) -> None:
        async def async_agent(payload: str, config: Optional[Dict[str, Any]] = None) -> str:
            await asyncio.sleep(0.01)
            return f"Async: {payload}"

        guarded = SecureRunnable.wrap(
            runnable=async_agent,
            pdp_engine=self.pdp,
            agent_name="async_agent",
            required_roles=["ADMIN"],
            min_clearance=2,
            target_tenant="CORP_MAIN",
        )

        run_config = IdentityBridge.create_runnable_config(self.admin_identity)
        result = asyncio.run(guarded.ainvoke("async-item", config=run_config))
        self.assertEqual(result, "Async: async-item")


if __name__ == "__main__":
    unittest.main()
