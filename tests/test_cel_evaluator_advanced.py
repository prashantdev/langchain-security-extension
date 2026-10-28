"""
Unit tests for CEL string helper bindings and EntityAttributeResolverSPI integration.
"""

import unittest
from langchain_security_extension.security_core.identity import SecurityIdentity
from langchain_security_extension.security_core.cel_evaluator import CELEvaluator, EntityAttributeResolverSPI


class MockServerResolver(EntityAttributeResolverSPI):
    def resolve(self, entity_type: str, entity_id: str):
        if entity_type == "server" and entity_id == "srv-prod-east-01":
            return {"ownerDepartment": "DEVOPS", "environment": "PROD"}
        return {"ownerDepartment": "UNKNOWN"}


class TestCELEvaluatorAdvanced(unittest.TestCase):

    def test_string_helpers(self):
        evaluator = CELEvaluator.create()
        identity = SecurityIdentity.create("u1", "TENANT_1", {"DEVOPS"}, 2, "DEVOPS", {})
        args = {"serverName": "devops-server-01"}
        tool = {"name": "restart"}

        expr1 = "args.serverName.startsWith('devops-')"
        self.assertTrue(evaluator.evaluate(expr1, identity, args, tool))

        expr2 = "args.serverName.contains('server')"
        self.assertTrue(evaluator.evaluate(expr2, identity, args, tool))

        expr3 = "args.serverName.endsWith('-01')"
        self.assertTrue(evaluator.evaluate(expr3, identity, args, tool))

    def test_entity_hydration_spi(self):
        resolver = MockServerResolver()
        evaluator = CELEvaluator.create(entity_resolver=resolver)
        identity = SecurityIdentity.create("u1", "TENANT_1", {"DEVOPS"}, 2, "DEVOPS", {})
        args = {"serverName": "srv-prod-east-01"}
        tool = {"name": "restart"}

        expr = "entities.server[args.serverName].ownerDepartment == subject.dept"
        self.assertTrue(evaluator.evaluate(expr, identity, args, tool))

    def test_cel_evaluator_fail_closed(self):
        evaluator = CELEvaluator.create()
        identity = SecurityIdentity.anonymous()
        # Invalid syntax or undefined variable should return False (fail closed), not raise exception
        res = evaluator.evaluate("non_existent_var == 123", identity, {}, {})
        self.assertFalse(res)

