import unittest
import jwt
from authorizer_lambda import verify_cognito_token as util
from jose import jwt as jose_jwt
from unittest.mock import patch, Mock
from jose.exceptions import JOSEError
import requests

token_header = {
   "alg": "RS256",
   "typ": "JWT",
   "kid": "testKid"
}

token_payload = {
   "sub": "1234567890",
   "name": "John Doe",
   "admin": True
}

encoded_token = "testToken"

jwks = {
   "keys": [
       {
           "kty": "RSA",
           "alg": "RS256",
           "use": "sig",
           "kid": "testKid",
           "n": "testN",
           "e": "testE"
       }
   ]
}
class TestVerifyCognitoJwt(unittest.TestCase):

    @patch("authorizer_lambda.verify_cognito_token.fetch_jwks")
    @patch("jose.jwt.decode")
    @patch("jose.jwt.get_unverified_header")
    def test_valid_cognito_jwt(self, mock_header, mock_decode, mock_fetch_jwks):

        mock_fetch_jwks.return_value = jwks
        mock_header.return_value = token_header
        mock_decode.return_value = token_payload

        cognito_pool_id = "cognito_user_pool_id"
        payload = util.verify_cognito_token(encoded_token, cognito_pool_id)

        expected_sub = "1234567890"
        self.assertEqual(payload['sub'], expected_sub)

        mock_fetch_jwks.assert_called_once_with(cognito_pool_id)

    @patch("authorizer_lambda.verify_cognito_token.fetch_jwks")
    @patch("jose.jwt.decode")
    @patch("jose.jwt.get_unverified_header")
    def test_invalid_cognito_jwt(self, mock_header, mock_decode, mock_fetch_jwks):
        mock_fetch_jwks.return_value = jwks
        mock_header.return_value = token_header
        mock_decode.side_effect = JOSEError

        with self.assertRaises(ValueError) as context:
            util.verify_cognito_token(encoded_token, "cognito_user_pool_id")

        self.assertEqual(str(context.exception), "Invalid token")

    @patch("requests.get")
    def test_fetch_jwks_success(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = jwks

        mock_get.return_value = mock_response

        user_pool_id = "cognito_user_pool_id"
        result = util.fetch_jwks(user_pool_id)

        self.assertEqual(result, jwks)
        mock_get.assert_called_once_with(f"https://cognito-idp.us-east-1.amazonaws.com/{user_pool_id}/.well-known/jwks.json")

    @patch("requests.get")
    def test_fetch_jwks_failure(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = requests.RequestException

        mock_get.return_value = mock_response

        user_pool_id = "cognito_user_pool_id"
        with self.assertRaises(requests.RequestException):
            util.fetch_jwks(user_pool_id)