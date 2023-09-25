import unittest
import jwt
from authorizer_lambda import util
from unittest.mock import patch


class TestIsDevToken(unittest.TestCase):

    def test_valid_dev_token(self):
        token = jwt.encode({"iss": "dev.myapp.ai"}, "secret", algorithm="HS256")
        self.assertTrue(util.is_dev_token(token))

    def test_invalid_issuer(self):
        token = jwt.encode({"iss": "not_dev.myapp.ai"}, "secret", algorithm="HS256")
        self.assertFalse(util.is_dev_token(token))

    def test_invalid_token(self):
        self.assertFalse(util.is_dev_token("invalid_token"))

class TestVerifyDevJwt(unittest.TestCase):

    @patch("jwt.decode")
    def test_valid_dev_jwt(self, mocked_decode):
        mock_payload = {'iss': 'dev.myapp.ai', 'owner_uuid': '1234'}
        valid_token = jwt.encode(mock_payload, 'mock_secret', algorithm='HS256')

        secret = 'mock_secret'

        mocked_decode.return_value = mock_payload
        payload = util.verify_dev_token(valid_token, secret)
        self.assertEqual(payload['iss'], 'dev.myapp.ai')

    @patch("jwt.decode")
    def test_invalid_dev_jwt(self, mocked_decode):
        invalid_token = "invalid token"
        secret = 'mock_secret'

        mocked_decode.side_effect = jwt.InvalidTokenError
        with self.assertRaises(ValueError):
            util.verify_dev_token(invalid_token, secret)

    @patch("jwt.decode")
    def test_expired_dev_jwt(self, mocked_decode):
        expired_token = jwt.encode({'iss': 'dev.myapp.ai'}, 'mock_secret', algorithm='HS256')

        secret = 'mock_secret'

        mocked_decode.side_effect = jwt.ExpiredSignatureError
        with self.assertRaises(ValueError) as context:
            util.verify_dev_token(expired_token, secret)
        self.assertEqual(str(context.exception), "Expired token")

    @patch("jwt.decode")
    def test_invalid_issuer_dev_jwt(self, mocked_decode):
        mock_payload = {'iss': 'invalid.issuer', 'owner_uuid': '1234'}
        invalid_issuer_token = jwt.encode(mock_payload, 'mock_secret', algorithm='HS256')

        secret = 'mock_secret'

        mocked_decode.return_value = mock_payload
        with self.assertRaises(ValueError) as context:
            util.verify_dev_token(invalid_issuer_token, secret)
        self.assertEqual(str(context.exception), "Invalid issuer")