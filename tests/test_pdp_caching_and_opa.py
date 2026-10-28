"""
Unit tests for Policy Decision Point caching, Deny-Overrides resolution, and OPA adapter.
"""

import unittest
from langchain_security_extension.security_core.identity import SecurityIdentity
from langchain_security_extension.security_core.pdp import (
    EmbeddedPolicyEngine,
    PolicyRule,
    PolicyEvaluationRequest,
    DecisionEnum,
)
from langchain_security_extension.security_core.pdp_opa import RemotePDPAdapter
from langchain_security_extension.security_core.constants import ACTION_TOOL_EXECUTE, DECISION_DENY, DECISION_PERMIT, STRATEGY_HARD_ABORT


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

    def test_rule_constraints_roles_clearance_and_cel(self):
        engine = EmbeddedPolicyEngine.create()
        # Rule that denies only if role is CONTRACTOR and clearance < 3
        rule_constrained_deny = PolicyRule.from_dict({
            "rule_id": "rule_contractor_deny",
            "target_action": ACTION_TOOL_EXECUTE,
            "effect": DECISION_DENY,
            "required_roles": ["CONTRACTOR"],
            "min_clearance": 3,
            "on_denial": STRATEGY_HARD_ABORT,
        })
        rule_permit = PolicyRule.from_dict({
            "rule_id": "rule_default_permit",
            "target_action": ACTION_TOOL_EXECUTE,
            "effect": DECISION_PERMIT,
            "on_denial": STRATEGY_HARD_ABORT,
        })
        engine.add_rule(rule_constrained_deny)
        engine.add_rule(rule_permit)

        # Subject has role USER (not CONTRACTOR) -> rule_contractor_deny does NOT match, permit matches
        user_identity = SecurityIdentity.create("user1", "TENANT_1", {"USER"}, 3, "ENG", {})
        req1 = PolicyEvaluationRequest.create(
            subject=user_identity,
            action=ACTION_TOOL_EXECUTE,
            resource={"target_id": "normal_tool"},
            context={},
        )
        dec1 = engine.evaluate(req1)
        self.assertEqual(dec1.decision, DECISION_PERMIT)

        # Subject has CONTRACTOR with clearance 3 -> matches rule_contractor_deny
        contractor_identity = SecurityIdentity.create("c1", "TENANT_1", {"CONTRACTOR"}, 3, "ENG", {})
        req2 = PolicyEvaluationRequest.create(
            subject=contractor_identity,
            action=ACTION_TOOL_EXECUTE,
            resource={"target_id": "normal_tool"},
            context={},
        )
        dec2 = engine.evaluate(req2)
        self.assertEqual(dec2.decision, DECISION_DENY)

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
        from langchain_security_extension.security_core.pdp import RoleGraph
        from langchain_security_extension.security_core.cel_evaluator import CELEvaluator
        from langchain_security_extension.security_core.audit import AuditManager
        from tests.audit_test_collector import TestAuditCollector
        role_graph = RoleGraph.create()
        cel_eval = CELEvaluator.create()
        audit_logger = TestAuditCollector.create()
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
        from langchain_security_extension.security_core.pdp import TwoTierDecisionCache
        from langchain_security_extension.security_pdp_opa import OPACacheInvalidationHandler

        cache = TwoTierDecisionCache.create()
        cache.put_static("k1", None)
        self.assertEqual(len(cache._tier2_cache), 1)

        adapter = RemotePDPAdapter.create("http://localhost:8181/v1/data/authz", decision_cache=cache)
        handler = OPACacheInvalidationHandler(adapter)

        handler.handle_bundle_reload_webhook({"bundle": "v2"})
        self.assertEqual(len(cache._tier2_cache), 0)


if __name__ == "__main__":
    unittest.main()

