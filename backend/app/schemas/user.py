"""User authentication and profile Pydantic schemas with zero-dependency email validator."""

import re
import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.core.security import is_rfc1918_private_subnet

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def validate_email_format(v: str) -> str:
    """Zero-dependency RFC email validation."""
    clean = v.strip().lower()
    if not clean or not EMAIL_REGEX.match(clean):
        raise ValueError(f"Invalid email address format: '{v}'")
    return clean


class UserBase(BaseModel):
    """Base user properties."""
    email: str = Field(..., description="User email address")
    full_name: Optional[str] = ""
    authorized_network_scope: str = Field(
        default="192.168.1.0/24",
        description="Authorized RFC 1918 private network subnet (e.g. 192.168.1.0/24)",
    )

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        return validate_email_format(v)

    @field_validator("authorized_network_scope")
    @classmethod
    def validate_scope(cls, v: str) -> str:
        v_clean = v.strip()
        if not is_rfc1918_private_subnet(v_clean):
            raise ValueError(
                f"Scope '{v_clean}' must be a valid private RFC 1918 CIDR subnet (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)."
            )
        return v_clean


class UserRegisterRequest(UserBase):
    """User registration payload."""
    password: str = Field(..., min_length=8, description="User password (minimum 8 characters)")


class UserLoginRequest(BaseModel):
    """User login payload."""
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        return validate_email_format(v)


class UserUpdateRequest(BaseModel):
    """User profile update payload."""
    full_name: Optional[str] = None
    authorized_network_scope: Optional[str] = None

    @field_validator("authorized_network_scope")
    @classmethod
    def validate_scope(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v_clean = v.strip()
            if not is_rfc1918_private_subnet(v_clean):
                raise ValueError(
                    f"Scope '{v_clean}' must be a valid private RFC 1918 CIDR subnet (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)."
                )
            return v_clean
        return v


class UserResponse(UserBase):
    """Public user response schema."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    is_active: bool
    is_superuser: bool
    created_at: datetime


class TokenResponse(BaseModel):
    """Bearer access token response schema."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # Seconds
    user: UserResponse

