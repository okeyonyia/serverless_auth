import jwt


def is_dev_token(token, dev_issuer="dev.myapp.ai"):
    """
    Check if the given JWT token is a dev token.

    :param token: The JWT token string.
    :param dev_issuer: The issuer field value expected for dev tokens.
    :return: True if the token is a dev token, False otherwise.
    """
    try:
        # Decode the token without verification to access the payload
        payload = jwt.decode(token, options={"verify_signature": False})

        # Check if the issuer field in the payload matches the expected dev issuer
        return payload.get("iss") == dev_issuer
    except jwt.DecodeError:
        return False


def verify_dev_token(token, secret):
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        if payload["iss"] != "dev.myapp.ai":
            raise ValueError("Invalid issuer")
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Expired token")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")
