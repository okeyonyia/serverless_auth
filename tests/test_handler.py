from pathlib import Path
import unittest
import json
from authorizer_lambda import main, util, verify_cognito_token
from authorizer_lambda.config import config
from unittest.mock import patch, MagicMock
from authorizer_lambda.models import (
    AuthorizationResponse,
    PolicyDocument,
    PolicyStatement,
    StatementEffect,
    OwnerResponse,
    Owner,
)
import io
from jwt.exceptions import InvalidTokenError
from botocore.exceptions import BotoCoreError, ClientError


def test_handler(mocker):
    mock_verify_dev_token = mocker.patch.object(util, "verify_dev_token")
    mock_verify_dev_token.return_value = {"owner_uuid": "a-b-c-d"}
    request = Path(__file__).parent / Path("data/authorization_request.json")
    request = json.load(request.open("rt"))
    token = request["authorizationToken"]
    response = main.handler(request, {})
    expected = AuthorizationResponse(
        principalId="a-b-c-d",
        policyDocument=PolicyDocument(
            Statement=[
                PolicyStatement(
                    Effect=StatementEffect.ALLOW,
                    Action="execute-api:Invoke",
                    Resource="arn:aws:execute-api:us-east-1:349228585176:aovoxtdoh3/backend_api_gw_stage_dev/*/api/a-b-c-d/*",
                )
            ]
        ),
    ).dict()
    assert response == expected
    assert mock_verify_dev_token.call_count == 1
    assert len(mock_verify_dev_token.call_args[0]) == 2
    assert mock_verify_dev_token.call_args[0][0] == token


def test_handler_cognito_token(mocker):
    mock_verify_cognito_token = mocker.patch.object(
        verify_cognito_token, "verify_cognito_token"
    )
    mock_verify_cognito_token.return_value = {"sub": "some_sub"}
    mocker.patch.object(util, "is_dev_token", return_value=False)
    mocker.patch.object(main, "get_owner_uuid", return_value="owner_uuid")
    request = json.load(
        (Path(__file__).parent / "data/authorization_request.json").open("rt")
    )
    response = main.handler(request, {})
    expected = AuthorizationResponse(
        principalId="owner_uuid",
        policyDocument=PolicyDocument(
            Statement=[
                PolicyStatement(
                    Effect=StatementEffect.ALLOW,
                    Action="execute-api:Invoke",
                    Resource="arn:aws:execute-api:us-east-1:349228585176:aovoxtdoh3/backend_api_gw_stage_dev/*/api/a-b-c-d/*",
                )
            ]
        ),
    ).dict()
    assert response == expected


def test_handler_invalid_token_error(mocker):
    mocker.patch.object(util, "verify_dev_token", side_effect=InvalidTokenError)
    request = {"type": "TOKEN"}  # missing methodArn and authorizationToken
    response = main.handler(request, {})
    assert " 2 validation errors for TokenAuthorizationRequest" in response["message"]


def test_handler_botocore_error(mocker):
    mocker.patch.object(util, "verify_dev_token", side_effect=BotoCoreError)
    request = json.load(
        (Path(__file__).parent / "data/authorization_request.json").open("rt")
    )
    response = main.handler(request, {})
    assert response["message"].startswith("AWS SDK error:")
    assert response["statusCode"] == 500


def test_handler_client_error(mocker):
    mocker.patch.object(util, "verify_dev_token", side_effect=ClientError({}, ""))
    request = json.load(
        (Path(__file__).parent / "data/authorization_request.json").open("rt")
    )
    response = main.handler(request, {})
    assert response["message"].startswith("AWS client error:")
    assert response["statusCode"] == 500


def test_handler_general_exception(mocker):
    mocker.patch.object(
        util, "verify_dev_token", side_effect=Exception("Unexpected Error")
    )
    request = json.load(
        (Path(__file__).parent / "data/authorization_request.json").open("rt")
    )
    response = main.handler(request, {})
    assert response == {
        "message": "An unexpected error occurred: Unexpected Error",
        "statusCode": 500,
    }


def test_handler_unsupported_authorization_type():
    request = {"type": "FOO", "authorizationToken": "bar", "methodArn": "some-arn"}
    response = main.handler(request, {})
    assert (
        "Validation error: 1 validation error for TokenAuthorizationRequest"
        in response["message"]
    )

    request = {
        "type": "UNSUPPORTED_TYPE",
        "authorizationToken": "some_token",
        "methodArn": "some_method_arn",
    }
    main.handler(request, {})
    assert (
        "unexpected value; permitted: <AuthorizationType.TOKEN: 'TOKEN'>"
        in response["message"]
    )


def test_handler_missing_payload_keys(mocker):
    # Test for missing sub in payload for Cognito token
    mock_verify_cognito_token = mocker.patch.object(
        verify_cognito_token, "verify_cognito_token"
    )
    mock_verify_cognito_token.return_value = {}  # Return an empty payload
    mocker.patch.object(util, "is_dev_token", return_value=False)
    request_cognito_token = json.load(
        (Path(__file__).parent / "data/authorization_request.json").open("rt")
    )
    response_cognito_token = main.handler(request_cognito_token, {})
    assert response_cognito_token["message"].startswith("An unexpected error occurred:")
    assert response_cognito_token["statusCode"] == 500


class TestGetOwnerUuid(unittest.TestCase):
    @patch("authorizer_lambda.main.boto3.client")
    def test_get_owner_uuid_success(self, mock_boto3_client):
        cognito_id = "testCognitoId"
        owner_uuid = "testOwnerUuid"

        owner_response = OwnerResponse(
            owner=Owner(
                owner_uuid=owner_uuid,
                first_name="John",
                last_name="Doe",
                email_address="john.doe@example.com",
                phone_number="1234567890",
            )
        )

        # Creating a MagicMock for the lambda client
        mock_lambda_client = MagicMock()
        mock_lambda_client.invoke.return_value = {
            "Payload": io.BytesIO(owner_response.json().encode("utf-8"))
        }
        mock_boto3_client.return_value = mock_lambda_client

        result = main.get_owner_uuid(cognito_id=cognito_id, settings=config)

        self.assertEqual(result, owner_uuid)

    @patch("authorizer_lambda.main.boto3.client")
    def test_get_owner_uuid_failure(self, mock_boto3_client):
        cognito_id = "testCognitoId"

        # Creating a MagicMock for the lambda client
        mock_lambda_client = MagicMock()
        mock_lambda_client.invoke.side_effect = Exception("Lambda invocation failed")

        mock_boto3_client.return_value = mock_lambda_client

        with self.assertRaises(Exception) as context:
            main.get_owner_uuid(cognito_id=cognito_id, settings=config)
        self.assertTrue("Lambda invocation failed" in str(context.exception))
