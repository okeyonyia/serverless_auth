import unittest
from authorizer_lambda.policy import generate_policy
from authorizer_lambda.models import PolicyDocument, StatementEffect


class TestGeneratePolicy(unittest.TestCase):
    def test_generate_policy(self):
        principal_id = "user123"
        method_arn = "some_method_arn"
        owner_uuid = "owner123"

        policy = generate_policy(
            principal_id, method_arn, owner_uuid, {"owner_uuid": owner_uuid}
        )
        policyDocument = policy.policyDocument
        self.assertIsInstance(policyDocument, PolicyDocument)
        self.assertEqual(policyDocument.Statement[0].Effect, StatementEffect.ALLOW)

        # Assert the construction of the Resource in the PolicyStatement
        expected_resource = f"{method_arn}"
        self.assertEqual(policyDocument.Statement[0].Resource, expected_resource)

        # Assert the principalId in the AuthorizationResponse
        self.assertEqual(policy.principalId, principal_id)

        # Assert the context in the AuthorizationResponse
        self.assertDictEqual(policy.context, {"owner_uuid": owner_uuid})
