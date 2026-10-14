"""
Unit tests for Policy Decision Point caching, Deny-Overrides resolution, and OPA adapter.
"""

import unittest
from security_core.identity import SecurityIdentity
from security_core.pdp import (
    EmbeddedPolicyEngine,
    PolicyRule,
    PolicyEvaluationRequest,
    DecisionEnum,
)
from security_core.pdp_opa import RemotePDPAdapter
from security_core.constants import ACTION_TOOL_EXECUTE, DECISION_DENY, DECISION_PERMIT, STRATEGY_HARD_ABORT


class TestPDPCachingAndOPA(unittest.TestCase):

    def test_deny_overrides_rule_matching(self):
        engine = EmbeddedPolicyEngine.create()
        rule_deny = PolicyRule.from_dict({
            "rule_id": "rule_01",
            "target_action": ACTION_TOOL_EXECUTE,
            "effect": DECISION_DENY,
            "on_denial": STRATEGY_HARD_ABORT,
        })
        engine.add_rule(rule_deny)

        identity = SecurityIdentity.create("user1", "TENANT_1", {"ADMIN"}, 3, "DEVOPS", {})
        request = PolicyEvaluationRequest.create(
            subject=identity,
            action=ACTION_TOOL_EXECUTE,
            resource={"target_id": "dangerous_tool"},
            context={},
        )
        decision = engine.evaluate(request)
        self.assertEqual(decision.decision, DECISION_DENY)
        self.assertEqual(decision.decision_enum, DecisionEnum.DENY)

    def test_remote_opa_adapter_circuit_breaker(self):
        # Invalid endpoint URL to test circuit breaker tripping on failures
        adapter = RemotePDPAdapter.create(
            endpoint_url="http://localhost:9999/v1/data/authz/allow",
            timeout_seconds=0.01,
            failure_threshold=2,
        )

        identity = SecurityIdentity.create("user1", "TENANT_1", {"USER"}, 1, "ENG", {})
        request = PolicyEvaluationRequest.create(
            subject=identity,
            action=ACTION_TOOL_EXECUTE,
            resource={"target_id": "test_tool"},
            context={},
        )

        # First request fails network call
        d1 = adapter.evaluate(request)
        self.assertEqual(d1.decision, DECISION_DENY)

        # Second request fails and trips circuit breaker
        d2 = adapter.evaluate(request)
        self.assertEqual(d2.decision, DECISION_DENY)
        self.assertTrue(adapter.is_circuit_open)

        # Third request short-circuits immediately with circuit breaker OPEN
        d3 = adapter.evaluate(request)
        self.assertIn("circuit breaker OPEN", d3.diagnostic_reason)

    def test_tier1_invocation_cache(self):
        from security_core.pdp import RoleGraph
        from security_core.cel_evaluator import CELEvaluator
        from security_core.audit import AuditManager, InMemoryAuditLogger
        role_graph = RoleGraph.create()
        cel_eval = CELEvaluator.create()
        audit_logger = InMemoryAuditLogger.create()
        audit_mgr = AuditManager.create(publishers=[audit_logger])
        engine = EmbeddedPolicyEngine.with_components(role_graph, cel_eval, audit_mgr)

        identity = SecurityIdentity.create("user1", "TENANT_A", {"USER"}, 1, "OPS", {})
        config = {"configurable": {}}

        req = PolicyEvaluationRequest.create(
            subject=identity,
            action="agent:invoke",
            resource={"target_id": "agent1"},
            context={"config": config},
        )

        dec1 = engine.evaluate(req)
        self.assertTrue(dec1.is_permitted)
        self.assertIn("sec:decision_cache", config["configurable"])
        self.assertEqual(len(config["configurable"]["sec:decision_cache"]), 1)

        dec2 = engine.evaluate(req)
        self.assertIs(dec2, dec1)

    def test_remote_pdp_adapter_async(self):
        import asyncio
        async def run_test():
            adapter = RemotePDPAdapter.create("http://localhost:8181/v1/data/authz", timeout_seconds=0.1)
            req = PolicyEvaluationRequest.create(
                subject=SecurityIdentity.anonymous(),
                action="tool:execute",
                resource={},
                context={},
            )
            decision = await adapter.evaluate_async(req)
            self.assertFalse(decision.is_permitted)

        asyncio.run(run_test())

    def test_opa_cache_invalidation_handler(self):
        from security_core.pdp import TwoTierDecisionCache
        from security_pdp_opa.opa_adapter import OPACacheInvalidationHandler

        cache = TwoTierDecisionCache.create()
        cache.put_static("k1", None)
        self.assertEqual(len(cache._tier2_cache), 1)

        adapter = RemotePDPAdapter.create("http://localhost:8181/v1/data/authz", decision_cache=cache)
        handler = OPACacheInvalidationHandler(adapter)

        handler.handle_bundle_reload_webhook({"bundle": "v2"})
        self.assertEqual(len(cache._tier2_cache), 0)


if __name__ == "__main__":
    unittest.main()

