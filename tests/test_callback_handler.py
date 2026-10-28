import unittest
from langchain_security_extension.security_core.identity import SecurityIdentity
from langchain_security_extension.security_core.pdp import EmbeddedPolicyEngine
from langchain_security_extension.security_core.exceptions import ToolExecutionDeniedError
from langchain_security_extension.security_adapter_langchain.callback_handler import SecureCallbackHandler


class TestCallbackHandler(unittest.TestCase):

    def test_callback_handler_chain_start_permission(self):
        pdp = EmbeddedPolicyEngine.create()
        identity = SecurityIdentity.create(
            subject_id="valid_user",
            tenant_id="CORP",
            roles={"USER"},
            clearance_level=2,
            department_id="ENG",
            attributes={},
        )
        handler = SecureCallbackHandler.create(pdp_engine=pdp, security_identity=identity)

        handler.on_chain_start(
            serialized={"name": "test_chain"},
            inputs={"query": "hello"},
            run_id="run_1",
            parent_run_id=None,
            tags=[],
            metadata={},
        )

    def test_callback_handler_tool_start_denial(self):
        pdp = EmbeddedPolicyEngine.create()
        # Guest identity attempting to execute tool with required ADMIN role or higher clearance
        identity = SecurityIdentity.create(
            subject_id="guest_user",
            tenant_id="GUEST_TENANT",
            roles={"GUEST"},
            clearance_level=0,
            department_id="GUEST",
            attributes={},
        )
        handler = SecureCallbackHandler.create(pdp_engine=pdp, security_identity=identity)

        with self.assertRaises(ToolExecutionDeniedError):
            handler.on_tool_start(
                serialized={"name": "delete_database", "required_roles": ["ADMIN"]},
                input_str="db_01",
                run_id="run_2",
                parent_run_id=None,
                tags=[],
                metadata={"tenant_id": "PROD_TENANT"},
                inputs={"db_name": "db_01"},
            )


if __name__ == "__main__":
    unittest.main()
