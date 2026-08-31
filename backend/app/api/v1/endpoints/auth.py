"""Authentication & User Profile API endpoints."""

import uuid
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_current_user,
    get_db,
    rate_limit_auth,
)
from app.config import settings
from app.core.security import (
    create_access_token,
    get_password_hash,
    revoke_access_token,
    verify_password,
)
from app.models.user import User
from app.schemas.user import (
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
    UserUpdateRequest,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])
_auth_scheme = HTTPBearer(auto_error=True)


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new security administrator account",
    dependencies=[Depends(rate_limit_auth)],
)
async def register(
    request: UserRegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """
    Register a new user account with authorized defensive network scope and generate an access token.
    """
    email_clean = request.email.lower().strip()

    # Check if email is already taken
    stmt = select(User).where(User.email == email_clean)
    result = await db.execute(stmt)
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists.",
        )

    # Hash password and create user
    hashed_pw = get_password_hash(request.password)
    user = User(
        id=uuid.uuid4(),
        email=email_clean,
        hashed_password=hashed_pw,
        full_name=request.full_name or "",
        authorized_network_scope=request.authorized_network_scope,
        is_active=True,
        is_superuser=False,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    # Generate JWT
    expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(
        subject=str(user.id),
        claims={"email": user.email, "is_superuser": user.is_superuser},
        expires_delta=expires_delta,
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user),
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate security administrator and issue JWT access token",
    dependencies=[Depends(rate_limit_auth)],
)
async def login(
    request: UserLoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """
    Validate email and password credentials, returning a signed JWT access token.
    """
    email_clean = request.email.lower().strip()

    stmt = select(User).where(User.email == email_clean)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not verify_password(request.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )

    expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(
        subject=str(user.id),
        claims={"email": user.email, "is_superuser": user.is_superuser},
        expires_delta=expires_delta,
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user),
    )


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Log out and invalidate client session",
)
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(_auth_scheme),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Revoke the presented access token for the remainder of its lifetime."""
    revoke_access_token(credentials.credentials)
    return {"message": "Successfully logged out."}


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current authenticated user profile",
)
async def get_me(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Return profile details and authorized defensive network scope for current user."""
    return UserResponse.model_validate(current_user)


@router.put(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Update current user profile and defensive network scope",
)
async def update_me(
    request: UserUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Update profile and authorized RFC 1918 scope for the current authenticated user."""
    if request.full_name is not None:
        current_user.full_name = request.full_name
    if request.authorized_network_scope is not None:
        current_user.authorized_network_scope = request.authorized_network_scope

    await db.commit()
    await db.refresh(current_user)
    return UserResponse.model_validate(current_user)

