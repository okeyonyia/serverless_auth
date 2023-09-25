from authorizer_lambda.models import PolicyStatement, StatementEffect, PolicyDocument, AuthorizationResponse
import logging

def generate_policy(principal_id, method_arn, owner_uuid, context):

    parts = method_arn.split("/")
    if len(parts) >= 3:
        parts[2] = "*"  # Replace the httpVerb part of the method_arn with "*"
    if len(parts) >= 6:
        parts[5:] = "*"  # Replace the resource and child resources part of the method_arn with "*"

    modified_method_arn = "/".join(parts).rstrip('/')
    statement = PolicyStatement(
        Effect=StatementEffect.ALLOW,
        Resource=f"{modified_method_arn}"
    )
    policy_document = PolicyDocument(
        Statement=[statement]
    )
    return AuthorizationResponse(
        principalId=principal_id,
        policyDocument=policy_document,
        context=context
    )
