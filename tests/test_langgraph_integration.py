import unittest
from security_core.identity import SecurityIdentity, InvocationParameters
from security_core.pdp import EmbeddedPolicyEngine
from security_core.exceptions import SecurityAuthorizationError
from security_adapter_langchain.langgraph_integration import LangGraphNodeGuard


class TestLangGraphIntegration(unittest.TestCase):

    def test_langgraph_node_guard_authorized_state_transition(self):
        pdp = EmbeddedPolicyEngine.create()
        identity = SecurityIdentity.create(
            subject_id="graph_user",
            tenant_id="TENANT_G",
            roles={"DEVOPS"},
            clearance_level=2,
            department_id="ENG",
            attributes={},
        )
        inv_params = InvocationParameters.create(security_identity=identity, metadata={"trace_id": "tr_100"})
        state = inv_params.serialize_to_state()
        state["messages"] = ["Analyze system logs"]

        guard = LangGraphNodeGuard.create(
            node_name="log_analyzer_node",
            required_roles=["DEVOPS"],
            min_clearance=1,
            pdp_engine=pdp,
        )

        def sample_node_fn(s):
            return {"messages": s["messages"] + ["Logs analyzed."]}

        guarded = guard.wrap_node(sample_node_fn)
        res_state = guarded(state)

        self.assertEqual(len(res_state["messages"]), 2)
        self.assertIn("sec:invocation_parameters", res_state)

    def test_langgraph_node_guard_unauthorized(self):
        pdp = EmbeddedPolicyEngine.create()
        identity = SecurityIdentity.create(
            subject_id="unauth_user",
            tenant_id="TENANT_G",
            roles={"GUEST"},
            clearance_level=0,
            department_id="GUEST",
            attributes={},
        )
        inv_params = InvocationParameters.create(security_identity=identity, metadata={})
        state = inv_params.serialize_to_state()

        guard = LangGraphNodeGuard.create(
            node_name="admin_node",
            required_roles=["ADMIN"],
            min_clearance=3,
            pdp_engine=pdp,
        )

        def sample_node_fn(s):
            return s

        guarded = guard.wrap_node(sample_node_fn)
        with self.assertRaises(SecurityAuthorizationError):
            guarded(state)


if __name__ == "__main__":
    unittest.main()
