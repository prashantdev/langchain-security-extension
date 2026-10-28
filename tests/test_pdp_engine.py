import unittest
from langchain_security_extension.security_core.identity import SecurityIdentity
from langchain_security_extension.security_core.pdp import (
    EmbeddedPolicyEngine,
    PolicyEvaluationRequest,
    RoleGraph,
)
from langchain_security_extension.security_core.constants import (
    REASON_TENANT_MISMATCH,
    REASON_INSUFFICIENT_CLEARANCE,
)


class TestPolicyDecisionEngine(unittest.TestCase):

    def test_tenant_isolation_evaluation(self):
        engine = EmbeddedPolicyEngine.create()
        subject = SecurityIdentity.create(
            subject_id="user_tenant_a",
            tenant_id="TENANT_A",
            roles={"USER"},
            clearance_level=1,
            department_id="FINANCE",
            attributes={},
        )
        request = PolicyEvaluationRequest.create(
            subject=subject,
            action="tool:execute",
            resource={"name": "read_ledger", "tenant_id": "TENANT_B"},
            context={},
        )
        decision = engine.evaluate(request)
        self.assertFalse(decision.is_permitted)
        self.assertEqual(decision.diagnostic_reason, REASON_TENANT_MISMATCH)

    def test_clearance_level_evaluation(self):
        engine = EmbeddedPolicyEngine.create()
        subject = SecurityIdentity.create(
            subject_id="user_low_clearance",
            tenant_id="CORP",
            roles={"STAFF"},
            clearance_level=1,
            department_id="HR",
            attributes={},
        )
        request = PolicyEvaluationRequest.create(
            subject=subject,
            action="agent:invoke",
            resource={"target_id": "top_secret_agent", "tenant_id": "CORP", "min_clearance": 3},
            context={},
        )
        decision = engine.evaluate(request)
        self.assertFalse(decision.is_permitted)
        self.assertEqual(decision.diagnostic_reason, REASON_INSUFFICIENT_CLEARANCE)

    def test_role_graph_inheritance(self):
        role_graph = RoleGraph.create()
        role_graph.add_inheritance("SUPER_ADMIN", "DEVOPS_TIER2")
        role_graph.add_inheritance("DEVOPS_TIER2", "READ_DIAGNOSTICS")

        expanded = role_graph.expand_roles({"SUPER_ADMIN"})
        self.assertIn("SUPER_ADMIN", expanded)
        self.assertIn("DEVOPS_TIER2", expanded)
        self.assertIn("READ_DIAGNOSTICS", expanded)

        engine = EmbeddedPolicyEngine.create()
        engine.role_graph.add_inheritance("SUPER_ADMIN", "DEVOPS_TIER2")

        subject = SecurityIdentity.create(
            subject_id="admin_user",
            tenant_id="CORP",
            roles={"SUPER_ADMIN"},
            clearance_level=5,
            department_id="ENG",
            attributes={},
        )
        request = PolicyEvaluationRequest.create(
            subject=subject,
            action="tool:execute",
            resource={"name": "restart_server", "tenant_id": "CORP", "required_roles": ["DEVOPS_TIER2"]},
            context={},
        )
        decision = engine.evaluate(request)
        self.assertTrue(decision.is_permitted)

    def test_cyclic_role_graph_detection(self):
        role_graph = RoleGraph.create()
        role_graph.add_inheritance("ROLE_A", "ROLE_B")
        with self.assertRaises(ValueError):
            role_graph.add_inheritance("ROLE_B", "ROLE_A")

    def test_cel_parameter_constraint_evaluation(self):
        engine = EmbeddedPolicyEngine.create()
        subject = SecurityIdentity.create(
            subject_id="dev_user",
            tenant_id="CORP",
            roles={"DEVELOPER", "PROD_OPS"},
            clearance_level=3,
            department_id="DEVOPS",
            attributes={},
        )

        # 1. Attribute comparison
        req1 = PolicyEvaluationRequest.create(
            subject=subject,
            action="tool:execute",
            resource={
                "name": "restart_service",
                "tenant_id": "CORP",
                "cel_expression": "args.targetDepartment == subject.dept",
                "arguments": {"targetDepartment": "DEVOPS"},
            },
            context={},
        )
        self.assertTrue(engine.evaluate(req1).is_permitted)

        # 2. String method invocation + prefix evaluation
        req2 = PolicyEvaluationRequest.create(
            subject=subject,
            action="tool:execute",
            resource={
                "name": "restart_server",
                "tenant_id": "CORP",
                "cel_expression": "args.serverName.startswith('devops-')",
                "arguments": {"serverName": "devops-srv-01"},
            },
            context={},
        )
        self.assertTrue(engine.evaluate(req2).is_permitted)

        # 3. Ternary expression + in list operator
        req3 = PolicyEvaluationRequest.create(
            subject=subject,
            action="tool:execute",
            resource={
                "name": "deploy_code",
                "tenant_id": "CORP",
                "cel_expression": "args.env == 'PROD' ? ('PROD_OPS' in subject.roles && subject.clearance >= 3) : true",
                "arguments": {"env": "PROD"},
            },
            context={},
        )
        self.assertTrue(engine.evaluate(req3).is_permitted)

        # 4. Subscript indexing expression
        req4 = PolicyEvaluationRequest.create(
            subject=subject,
            action="tool:execute",
            resource={
                "name": "update_hosts",
                "tenant_id": "CORP",
                "cel_expression": "args.hosts[0].startswith('10.0.')",
                "arguments": {"hosts": ["10.0.1.5", "192.168.1.1"]},
            },
            context={},
        )
        self.assertTrue(engine.evaluate(req4).is_permitted)


if __name__ == "__main__":
    unittest.main()
