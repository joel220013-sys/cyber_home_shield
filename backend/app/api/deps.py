"""API dependency injection utilities: DB sessions, user authentication, and rate limiting."""

import uuid
from typing import AsyncGenerator, Optional
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.exceptions import (
    AuthError,
    TokenExpiredError,
    TokenInvalidError,
)
from app.core.security import (
    decode_access_token,
    rate_limiter,
)
from app.db.session import get_db
from app.models.user import User

# Optional & Required Bearer token schemes
security_scheme = HTTPBearer(auto_error=True)
optional_security_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Validate Bearer JWT access token and return authenticated User record.
    Raises HTTP 401 on invalid/expired credentials, or HTTP 403 on deactivated account.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        user_id_str: Optional[str] = payload.get("sub")
        if not user_id_str:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token payload missing subject identifier.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user_id = uuid.UUID(user_id_str)
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (TokenInvalidError, ValueError, AuthError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with token no longer exists.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )

    return user


async def get_optional_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(optional_security_scheme),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """
    Optional authentication dependency. Returns User if valid token present, otherwise None.
    Does not reject unauthenticated calls.
    """
    if not credentials or not credentials.credentials:
        return None

    try:
        payload = decode_access_token(credentials.credentials)
        user_id_str = payload.get("sub")
        if not user_id_str:
            return None
        user_id = uuid.UUID(user_id_str)
        stmt = select(User).where(User.id == user_id)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        if user and user.is_active:
            return user
    except Exception:
        return None

    return None


async def get_current_active_superuser(
    current_user: User = Depends(get_current_user),
) -> User:
    """Dependency verifying that current authenticated user has administrative superuser rights."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation requires administrative privileges.",
        )
    return current_user


# ---------------------------------------------------------------------------
# Rate Limiting Dependencies
# ---------------------------------------------------------------------------

def check_rate_limit(request: Request, limit_per_minute: int, key_prefix: str = "ip") -> None:
    """Check sliding window rate limit for client IP or route."""
    if not settings.RATE_LIMIT_ENABLED:
        return

    client_ip = request.client.host if request.client else "unknown"
    key = f"{key_prefix}:{client_ip}"
    allowed, remaining = rate_limiter.is_allowed(key, max_requests=limit_per_minute, window_seconds=60)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {limit_per_minute} requests per minute allowed.",
            headers={"Retry-After": "60"},
        )


async def rate_limit_auth(request: Request) -> None:
    """Rate limit authentication attempts (login/register)."""
    check_rate_limit(request, settings.RATE_LIMIT_LOGIN_PER_MINUTE, key_prefix="auth")


async def rate_limit_scans(request: Request) -> None:
    """Rate limit scan executions."""
    check_rate_limit(request, settings.RATE_LIMIT_SCANS_PER_MINUTE, key_prefix="scan")


async def rate_limit_ai(request: Request) -> None:
    """Rate limit AI advisor invocations."""
    check_rate_limit(request, settings.RATE_LIMIT_AI_PER_MINUTE, key_prefix="ai")


async def rate_limit_honeypot(request: Request) -> None:
    """Rate limit Honeypot management and simulation operations."""
    check_rate_limit(request, settings.RATE_LIMIT_HONEYPOT_PER_MINUTE, key_prefix="honeypot")


__all__ = [
    "get_db",
    "AsyncSession",
    "get_current_user",
    "get_optional_current_user",
    "get_current_active_superuser",
    "rate_limit_auth",
    "rate_limit_scans",
    "rate_limit_ai",
    "rate_limit_honeypot",
]

