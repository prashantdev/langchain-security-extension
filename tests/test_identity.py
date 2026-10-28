import unittest
from langchain_security_extension.security_core.identity import SecurityIdentity, InvocationParameters
from langchain_security_extension.security_core.constants import SECURITY_INVOCATION_PARAMS_KEY


class TestSecurityIdentity(unittest.TestCase):

    def test_security_identity_creation_and_immutability(self):
        identity = SecurityIdentity.create(
            subject_id="usr_001",
            tenant_id="TENANT_A",
            roles={"ADMIN", "DEVOPS"},
            clearance_level=3,
            department_id="IT",
            attributes={"location": "US_EAST"},
        )

        self.assertEqual(identity.subject_id, "usr_001")
        self.assertEqual(identity.tenant_id, "TENANT_A")
        self.assertIn("ADMIN", identity.roles)
        self.assertEqual(identity.clearance_level, 3)
        self.assertEqual(identity.department_id, "IT")
        self.assertEqual(identity.attributes["location"], "US_EAST")

        # Test immutability via dict export
        d = identity.to_dict()
        self.assertEqual(d["subject_id"], "usr_001")

        reconstructed = SecurityIdentity.from_dict(d)
        self.assertEqual(reconstructed.subject_id, identity.subject_id)
        self.assertEqual(reconstructed.tenant_id, identity.tenant_id)
        self.assertEqual(reconstructed.roles, identity.roles)

    def test_anonymous_identity(self):
        anon = SecurityIdentity.anonymous()
        self.assertEqual(anon.subject_id, "ANONYMOUS")
        self.assertEqual(anon.clearance_level, 0)
        self.assertEqual(len(anon.roles), 0)

    def test_invocation_parameters_state_serialization(self):
        identity = SecurityIdentity.create(
            subject_id="usr_002",
            tenant_id="TENANT_B",
            roles={"USER"},
            clearance_level=1,
            department_id="SALES",
            attributes={},
        )
        inv = InvocationParameters.create(security_identity=identity, metadata={"session_id": "s_99"})
        state_dict = inv.serialize_to_state()

        self.assertIn(SECURITY_INVOCATION_PARAMS_KEY, state_dict)

        deserialized = InvocationParameters.deserialize_from_state(state_dict)
        self.assertEqual(deserialized.security_identity.subject_id, "usr_002")
        self.assertEqual(deserialized.security_identity.tenant_id, "TENANT_B")
        self.assertEqual(deserialized.metadata["session_id"], "s_99")


if __name__ == "__main__":
    unittest.main()
