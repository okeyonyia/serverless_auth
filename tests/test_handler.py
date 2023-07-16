from pathlib import Path
import json
from authorizer_lambda import main
from authorizer_lambda.models import (
    AuthorizationResponse,
    PolicyDocument,
    PolicyStatement,
    StatementEffect,
)


def test_handler(mocker):
    mock_verify_dev_token = mocker.patch.object(main, "verify_dev_token")
    mock_verify_dev_token.return_value = "a-b-c-d"
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
    mock_verify_dev_token.assert_called_once_with(token)
