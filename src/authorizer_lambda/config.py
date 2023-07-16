from pydantic import BaseSettings


class Settings(BaseSettings):
    """Configuration"""

    class Config:
        env_file = ".env"

    cognito_user_pool_id: str = "some_user_pool_id"
    dev_jwt_secret: str = "some_secret"
    backend_lambda_arn = (
        "arn:aws:lambda:us-east-1:11111111111:function:some-backend-lambda-dev"
    )


config = Settings()
