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
