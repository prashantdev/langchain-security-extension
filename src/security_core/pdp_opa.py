import unittest
from security_core.identity import SecurityIdentity
from security_core.pdp import (
    EmbeddedPolicyEngine,
    PolicyRule,
    PolicyEvaluationRequest,
    DecisionEnum
)
from security_pdp_opa.opa_adapter import RemotePDPAdapter
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
import unittest
from security_core.identity import SecurityIdentity
from security_core.pdp import EmbeddedPolicyEngine
from security_adapter_langchain.retriever_wrapper import SecureRetriever, SecureDocument
class TestSecureRetriever(unittest.TestCase):
    def test_secure_retriever_prefilter_ast(self):
        pdp = EmbeddedPolicyEngine.create()
        identity = SecurityIdentity.create(
            subject_id="retriever_user",
            tenant_id="CORP_X",
            roles={"ANALYST"},
            clearance_level=2,
            department_id="FINANCE",
            attributes={},
        )
        retriever = SecureRetriever.wrap(base_retriever=None, pdp_engine=pdp, oversampling_factor=2.0)
        ast = retriever.build_prefilter_ast(identity)
        self.assertEqual(ast["sec:tenant_id"], "CORP_X")
        self.assertEqual(ast["sec:clearance_level"], {"$lte": 2})
    def test_secure_retriever_post_pruning(self):
        pdp = EmbeddedPolicyEngine.create()
        identity = SecurityIdentity.create(
            subject_id="user_clearance_2",
            tenant_id="CORP_MAIN",
            roles={"DEVOPS"},
            clearance_level=2,
            department_id="DEVOPS",
            attributes={},
        )
        doc_authorized = SecureDocument.create(
            page_content="Public devops docs",
            metadata={"sec:tenant_id": "CORP_MAIN", "sec:clearance_level": 2},
        )
        doc_unauthorized = SecureDocument.create(
            page_content="Top secret infrastructure key",
            metadata={"sec:tenant_id": "CORP_MAIN", "sec:clearance_level": 4},
        )
        retriever = SecureRetriever.wrap(base_retriever=None, pdp_engine=pdp, oversampling_factor=1.5)
        pruned = retriever.prune_documents([doc_authorized, doc_unauthorized], identity)
        self.assertEqual(len(pruned), 1)
        self.assertEqual(pruned[0].page_content, "Public devops docs")
    def test_retriever_store_capability_profiles(self):
        from security_core.constants import STORE_PROFILE_FULL_AST, STORE_PROFILE_CONSTRAINED, STORE_PROFILE_NO_FILTER
        pdp = EmbeddedPolicyEngine.create()
        identity = SecurityIdentity.create("user1", "TENANT_A", {"DEVOPS"}, 2, "OPS", {})
        retriever_full = SecureRetriever.wrap(None, pdp, store_profile=STORE_PROFILE_FULL_AST)
        ast_full = retriever_full.build_prefilter_ast(identity)
        self.assertIn("sec:clearance_floor", ast_full)
        retriever_constrained = SecureRetriever.wrap(None, pdp, store_profile=STORE_PROFILE_CONSTRAINED)
        ast_constrained = retriever_constrained.build_prefilter_ast(identity)
        self.assertIn("sec:tenant_id", ast_constrained)
        self.assertNotIn("sec:clearance_floor", ast_constrained)
        retriever_no_filter = SecureRetriever.wrap(None, pdp, store_profile=STORE_PROFILE_NO_FILTER)
        ast_none = retriever_no_filter.build_prefilter_ast(identity)
        self.assertEqual(len(ast_none), 0)
    def test_retriever_secondary_paging_and_audit(self):
        from security_core.pdp import RoleGraph
        from security_core.cel_evaluator import CELEvaluator
        from security_core.audit import AuditManager, InMemoryAuditLogger
        from security_core.constants import EVENT_RAG_UNAUTHORIZED_PRUNING
        role_graph = RoleGraph.create()
        cel_eval = CELEvaluator.create()
        audit_logger = InMemoryAuditLogger.create()
        audit_mgr = AuditManager.create(publishers=[audit_logger])
        engine = EmbeddedPolicyEngine.with_components(role_graph, cel_eval, audit_mgr)
        identity = SecurityIdentity.create("user1", "TENANT_A", {"USER"}, 1, "OPS", {})
        cands = [
            SecureDocument.create("doc1", {"sec:tenant_id": "TENANT_A", "sec:clearance_floor": 1, "sec:allowed_roles": ["USER"]}),
            SecureDocument.create("doc2", {"sec:tenant_id": "TENANT_A", "sec:clearance_floor": 3, "sec:allowed_roles": ["ADMIN"]}),
            SecureDocument.create("doc3", {"sec:tenant_id": "TENANT_A", "sec:clearance_floor": 3, "sec:allowed_roles": ["ADMIN"]}),
            SecureDocument.create("doc4", {"sec:tenant_id": "TENANT_A", "sec:clearance_floor": 1, "sec:allowed_roles": ["USER"]}),
        ]
        retriever = SecureRetriever.wrap(None, engine, oversampling_factor=1.0)
        result = retriever.prune_candidates(cands, identity, top_k=2)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].page_content, "doc1")
        self.assertEqual(result[1].page_content, "doc4")
        events = audit_logger.get_events()
        pruned_events = [e for e in events if e.reason_code == EVENT_RAG_UNAUTHORIZED_PRUNING]
        self.assertGreaterEqual(len(pruned_events), 2)
    def test_secure_retriever_secondary_paging_and_similarity_cutoff(self):
        pdp = EmbeddedPolicyEngine.create()
        identity = SecurityIdentity.create("u1", "t1", ["USER"], 2, "GENERAL", {})
        doc1 = SecureDocument.create("c1", {"sec:tenant_id": "t1", "sec:clearance_floor": 1, "sec:allowed_roles": ["USER"]})
        doc2 = SecureDocument.create("c2", {"sec:tenant_id": "t1", "sec:clearance_floor": 3, "sec:allowed_roles": ["USER"]})
        doc1.score = 0.85
        doc2.score = 0.90
        secondary_db = [
            SecureDocument.create("c3", {"sec:tenant_id": "t1", "sec:clearance_floor": 1, "sec:allowed_roles": ["USER"]}),
        ]
        secondary_db[0].score = 0.88
        def secondary_fetch(offset: int, limit: int):
            return secondary_db
        retriever = SecureRetriever.wrap(
            base_retriever=None,
            pdp_engine=pdp,
            secondary_fetch_fn=secondary_fetch,
            similarity_cutoff=0.80,
        )
        result = retriever.prune_candidates([doc1, doc2], identity, top_k=2)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].page_content, "c1")
        self.assertEqual(result[1].page_content, "c3")
if __name__ == "__main__":
    unittest.main()
