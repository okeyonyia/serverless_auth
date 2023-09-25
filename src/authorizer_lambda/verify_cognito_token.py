from jose import jwt as jose_jwt
from jose.exceptions import JOSEError
import requests


def verify_cognito_token(token, user_pool_id):
    try:
        jwks = fetch_jwks(user_pool_id)
        if jwks is not None:
            header = jose_jwt.get_unverified_header(token)
            rsa_key = {}

            for key in jwks["keys"]:
                if key["kid"] == header["kid"]:
                    rsa_key = {
                        "kty": key["kty"],
                        "kid": key["kid"],
                        "use": key["use"],
                        "alg": key["alg"],
                        "e": key["e"],
                        "n": key["n"],
                    }

            payload = jose_jwt.decode(
                token, rsa_key, algorithms=["RS256"], audience=user_pool_id
            )

            return payload
        else:
            raise ValueError("Invalid token")

    except JOSEError:
        raise ValueError("Invalid token")


def fetch_jwks(user_pool_id, region="us-east-1"):
    """
    Fetch the JSON Web Key Set (JWKS) for an AWS Cognito User Pool.

    :param user_pool_id: The ID of the Cognito User Pool.
    :param region: AWS region where the Cognito User Pool is located'.
    :return: The JWKS as a dictionary.
    """
    url = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json"
    response = requests.get(url)

    if response.status_code == 200:
        return response.json()
    else:
        response.raise_for_status()
