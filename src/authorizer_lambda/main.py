from typing import Any
from authorizer_lambda.config import Settings, config
from authorizer_lambda.models import (
    OwnerResponse,
    TokenAuthorizationRequest,
    OwnerRequest,
    AuthorizationType
)
from authorizer_lambda import util, verify_cognito_token
import boto3
import json
from jwt.exceptions import InvalidTokenError
from botocore.exceptions import BotoCoreError, ClientError
from authorizer_lambda.policy import generate_policy
from pydantic import ValidationError

def get_owner_uuid(cognito_id: str, settings: Settings) -> str:
    """Retrieve the owner_uuid from the lambda based on the cognito id and return it."""
    lambda_client = boto3.client('lambda')

    request = OwnerRequest(cognito_id=cognito_id)
    input_payload = json.dumps(request.dict()).encode('utf-8')

    # get this from the lambda
    result = lambda_client.invoke(
                                      FunctionName=settings.backend_lambda_arn,
                                      InvocationType='RequestResponse',
                                      Payload=input_payload
                                  )

    result_payload = json.loads(result['Payload'].read().decode('utf-8'))
    response: OwnerResponse = OwnerResponse(**result_payload)
    return response.owner.owner_uuid


def handler(event, context) -> dict[str, Any]:
    """
    Handle the incoming authorization requests, verify the token and return the
    policy for API Gateway
    """
    try:
        token_request = TokenAuthorizationRequest(**event)
        if token_request.type == AuthorizationType.TOKEN:
            if util.is_dev_token(token_request.authorizationToken):
                # For development token
                payload = util.verify_dev_token(token_request.authorizationToken, config.dev_jwt_secret)
                owner_uuid = payload.get('owner_uuid')
            else:
                # For Cognito token
                payload = verify_cognito_token.verify_cognito_token(token_request.authorizationToken, config.cognito_user_pool_id)
                owner_uuid = get_owner_uuid(cognito_id=payload['sub'], settings=config)

            # Generating policy and returning it
            policy = generate_policy(owner_uuid, token_request.methodArn, owner_uuid, context)
            return policy.dict()
    except ValidationError as e:
        return {"message": f"Validation error: {str(e)}", "statusCode": 400}
    except BotoCoreError as e:
        return {"message": f"AWS SDK error: {str(e)}", "statusCode": 500}
    except ClientError as e:
        return {"message": f"AWS client error: {str(e)}", "statusCode": 500}
    except Exception as e:
        return {"message": f"An unexpected error occurred: {str(e)}", "statusCode": 500}