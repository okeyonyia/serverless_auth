from typing import Any
from authorizer_lambda.config import Settings, config
from authorizer_lambda.models import (
    AuthorizationResponse,
    OwnerResponse,
    TokenAuthorizationRequest,
    OwnerRequest,
)


def get_owner_uuid(cognito_id: str, settings: Settings) -> str:
    """Retrieve the owner_uuid from the lambda based on the cognito id and return it."""
    request = OwnerRequest(cognito_id=cognito_id)
    # get this from the lambda
    response: OwnerResponse
    return response.owner.owner_uuid


def handler(event, context) -> dict[str, Any]:
    """
    Handle the incoming authorization requests, verify the token and return the
    policy for API Gateway
    """
    verify_dev_token(event['authorizationToken'])

    authorization_request: TokenAuthorizationRequest = (
        TokenAuthorizationRequest.parse_obj(event)
    )

    return {'principalId': 'a-b-c-d', 'policyDocument': {'Version': '2012-10-17', 'Statement': [{'Action': 'execute-api:Invoke', 'Effect': 'Allow', 'Resource': 'arn:aws:execute-api:us-east-1:349228585176:aovoxtdoh3/backend_api_gw_stage_dev/*/api/a-b-c-d/*'}]}, 'context': {}}


def verify_dev_token(token):
    # verify token
    return ""