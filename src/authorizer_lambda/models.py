"""Types used in the authorization lambda"""
import enum
from typing import Literal

from pydantic import BaseModel, constr


class ModelConfig(BaseModel):
    class Config:
        use_enum_values = True


class Owner(ModelConfig):
    """Owner of a property"""

    first_name: str
    last_name: str
    email_address: str
    phone_number: str
    owner_uuid: str


class OwnerResponse(ModelConfig):
    """Response from the lambda."""

    owner: Owner


class OwnerRequest(ModelConfig):
    """Request an Owner from the lambda based on the cognito_id"""

    cognito_id: str


class AuthorizationType(str, enum.Enum):
    """Authorization Types."""

    TOKEN = "TOKEN"
    REQUEST = "REQUEST"


class StatementEffect(str, enum.Enum):
    ALLOW = "Allow"
    DENY = "Deny"


class TokenAuthorizationRequest(ModelConfig):
    """JWT Token Authorization request"""

    type: Literal[AuthorizationType.TOKEN]
    methodArn: str
    authorizationToken: str


class PolicyStatement(ModelConfig):
    Action: str = "execute-api:Invoke"
    Effect: StatementEffect
    Resource: str


class PolicyDocument(ModelConfig):
    Version: constr(regex=r"[0-9]{4}-[0-9]{2}-[0-9]{2}") = "2012-10-17"  # type: ignore
    Statement: list[PolicyStatement]


class AuthorizationResponse(ModelConfig):
    principalId: str
    policyDocument: PolicyDocument
    context: dict[str, str | bool | int] = {}
