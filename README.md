# Authorization Lambda assignment

## Note on Github use
NOTE: please do NOT fork this repository on Github. This would give an advantage to people who still have to do this assignment.
You can clone the repository locally, then make your own Github repository, and push the code there with

```
git clone https://github.com/dolfandringa/aws_serverless_python_assignment
cd aws_serverless_python_assignment
git remote set-url origin git@github.com:<you>/your_respository.git
```

## Installation

```shell
poetry install
```

## Running tests

```shell
poetry run pytest
```

## Assignment
This lambda is meant to authorize requests coming into to AWS' API Gateway before they are handed off to the backend. It should handle [token based authorization requests](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html) and return [a policy](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-output.html) based on two different JWT tokens.

The tokens it should be able to verify and authorize:
* A dev JWT token, created and signed by us with a symmetric JWT secret signed using HS256, and with the issuer `dev.myapp.ai`. The secret is available in [the config](src/authorizer_lambda/config.py).
* A JWT token created by AWS cognito, [signed using JWK and RS256](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html). The issuer in that token is defined by AWS. The cognito user-pool-id is in [the config](src/authorizer_lambda/config.py).

The request coming in to this lambda is [defined by AWS in their docs](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-input.html), and has also already been captured in the `TokenAuthorizationRequest` schema in [the models](src/authorizer_lambda/models.py). The output of the lambda is already defined in the `TokenAuthorizationResponse`, again in [the models](src/authorizer_lambda/models.py)

Access to the backend urls is based on the `owner_uuid` attribute of the user.
* For the dev token, this is part of the payload of the JWT token.
* For the Cognito token, you should lookup the `owner_uuid` by retrieving it from another lambda, based on the `sub` field from the payload of the JWT token. The arn for that lambda is available in [the config](src/authorizer_lambda/config.py), and the expected request and response from the lambda are defined as the `OwnerRequest` and `OwnerResponse` in [the models](src/authorizer_lambda/models.py). Your code should assume this lambda exists. But since it doesn't (at least not in a way that is accessible to you), you write both the code to call the lambda, and to make unittests which mock the library that handles the lambda's request/response.

The output of your code should contain a policy based on the methodArn, allowing `arn:aws:execute-api:us-east-1:349228585176:aovoxtdoh3/sunrise_backend_api_gw_stage_dev/*/api/{owner_uuid}/*`

There already is a single test that should work once you implemented your code. But you should write your own tests for all other functions you write. Each function should be tested individually, while mocking any functions in depends upon. The code should have 100% test coverage.

## Some links

For API Gateway authorizer lambdas, this is the expected input and output:
* https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-input.html
* https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-output.html
* https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html

JWT:
* https://jwt.io/
* https://pyjwt.readthedocs.io/en/latest/usage.html

Boto3:
* https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/lambda/client/invoke.html
