import unittest
from langchain_security_extension.security_core.identity import SecurityIdentity
from langchain_security_extension.security_core.pdp import EmbeddedPolicyEngine
from langchain_security_extension.security_core.exceptions import ToolExecutionDeniedError
from langchain_security_extension.security_adapter_langchain.tool_decorator import secured_tool


class TestSecuredToolDecorator(unittest.TestCase):

    def test_secured_tool_permit(self):
        pdp = EmbeddedPolicyEngine.create()
        subject = SecurityIdentity.create(
            subject_id="admin_01",
            tenant_id="CORP",
            roles={"ADMIN"},
            clearance_level=3,
            department_id="DEVOPS",
            attributes={},
        )

        @secured_tool(
            required_roles=["ADMIN"],
            min_clearance=2,
            cel_expression="args.targetDept == subject.dept",
            is_mutative=True,
            pdp_engine=pdp,
        )
        def restart_server(server_name: str, targetDept: str) -> str:
            return f"Server {server_name} restarted."

        result = restart_server(security_identity=subject, server_name="srv-01", targetDept="DEVOPS")
        self.assertEqual(result, "Server srv-01 restarted.")

    def test_secured_tool_hard_abort_on_mutative_violation(self):
        pdp = EmbeddedPolicyEngine.create()
        subject = SecurityIdentity.create(
            subject_id="user_01",
            tenant_id="CORP",
            roles={"USER"},
            clearance_level=1,
            department_id="SALES",
            attributes={},
        )

        @secured_tool(
            required_roles=["ADMIN"],
            min_clearance=3,
            cel_expression="",
            is_mutative=True,
            pdp_engine=pdp,
        )
        def wipe_database(db_id: str) -> str:
            return f"Database {db_id} wiped."

        with self.assertRaises(ToolExecutionDeniedError):
            wipe_database(security_identity=subject, db_id="db_main")

    def test_secured_tool_model_feedback_refusal_for_read_tool(self):
        pdp = EmbeddedPolicyEngine.create()
        subject = SecurityIdentity.create(
            subject_id="user_02",
            tenant_id="CORP",
            roles={"STAFF"},
            clearance_level=2,
            department_id="HR",
            attributes={},
        )

        @secured_tool(
            required_roles=["HR_ADMIN"],
            min_clearance=2,
            cel_expression="",
            is_mutative=False,
            pdp_engine=pdp,
        )
        def read_salary_records(employee_id: str) -> str:
            return f"Salary records for {employee_id}"

        res = read_salary_records(security_identity=subject, employee_id="emp_99")
        self.assertIsInstance(res, dict)
        self.assertEqual(res["status"], "ACCESS_DENIED")
        self.assertEqual(res["tool"], "read_salary_records")
        self.assertEqual(res["diagnostic_reason"], "MISSING_REQUIRED_ROLE")

    def test_parameter_privilege_escalation_detection(self):
        from langchain_security_extension.security_core.audit import AuditManager
        from tests.audit_test_collector import TestAuditCollector
        from langchain_security_extension.security_core.constants import EVENT_PARAMETER_PRIVILEGE_ESCALATION

        logger = TestAuditCollector.create()
        audit_mgr = AuditManager.create(publishers=[logger])
        pdp = EmbeddedPolicyEngine.create()
        pdp._audit_manager = audit_mgr

        @secured_tool(
            required_roles=["ADMIN"],
            min_clearance=3,
            cel_expression="args.dept == subject.dept",
            is_mutative=False,
            pdp_engine=pdp,
        )
        def my_tool(dept: str, config: dict = None):
            return "success"

        identity = SecurityIdentity.create("u1", "t1", ["USER"], 1, "DEVOPS", {})
        config_env = {"configurable": {"security_identity": identity}}

        # First attempt - denied due to clearance/role
        res1 = my_tool(dept="DEVOPS", config=config_env)
        self.assertEqual(res1.get("status"), "ACCESS_DENIED")

        # Second attempt with mutated args -> PARAMETER_PRIVILEGE_ESCALATION
        res2 = my_tool(dept="SEC_OPS", config=config_env)
        self.assertEqual(res2.get("status"), "ACCESS_DENIED")

        events = logger.get_events()
        escalation_events = [e for e in events if e.reason_code == EVENT_PARAMETER_PRIVILEGE_ESCALATION]
        self.assertEqual(len(escalation_events), 1)
        self.assertEqual(escalation_events[0].payload_snapshot["previous_args"]["dept"], "DEVOPS")
        self.assertEqual(escalation_events[0].payload_snapshot["current_args"]["dept"], "SEC_OPS")

    def test_security_identity_and_config_injection_and_schema_concealment(self):
        import inspect
        from langchain_security_extension.security_adapter_langchain.tool_decorator import get_tool_schema

        pdp = EmbeddedPolicyEngine.create()
        subject = SecurityIdentity.create(
            subject_id="admin_02",
            tenant_id="CORP",
            roles={"ADMIN"},
            clearance_level=3,
            department_id="DEVOPS",
            attributes={},
        )

        injected_records = {}

        @secured_tool(
            required_roles=["ADMIN"],
            min_clearance=2,
            cel_expression="",
            is_mutative=False,
            pdp_engine=pdp,
        )
        def inspect_node(
            node_id: str,
            security_identity: SecurityIdentity,
            config: dict,
        ) -> str:
            injected_records["security_identity"] = security_identity
            injected_records["config"] = config
            return f"Node {node_id} OK"

        run_cfg = {"configurable": {"security_identity": subject, "test_key": "val123"}}
        res = inspect_node("node-1", config=run_cfg)
        self.assertEqual(res, "Node node-1 OK")
        self.assertEqual(injected_records["security_identity"], subject)
        self.assertEqual(injected_records["config"], run_cfg)

        # Confirm wrapper.__signature__ conceals security_identity and config
        wrapper_sig = inspect.signature(inspect_node)
        self.assertIn("node_id", wrapper_sig.parameters)
        self.assertNotIn("security_identity", wrapper_sig.parameters)
        self.assertNotIn("config", wrapper_sig.parameters)
        self.assertNotIn("runnable_config", wrapper_sig.parameters)

        # Confirm get_tool_schema conceals security_identity and config
        schema = get_tool_schema(inspect_node)
        self.assertTrue(schema["schema_hiding_verified"])
        self.assertIn("node_id", schema["parameters"]["properties"])
        self.assertNotIn("security_identity", schema["parameters"]["properties"])
        self.assertNotIn("config", schema["parameters"]["properties"])
        self.assertNotIn("runnable_config", schema["parameters"]["properties"])


if __name__ == "__main__":
    unittest.main()

