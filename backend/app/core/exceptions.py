"""Custom application domain exceptions."""

from typing import Any, Optional


class AppBaseException(Exception):
    """Base exception for all domain errors."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class ScopeValidationError(AppBaseException):
    """Raised when an IP or subnet is outside authorized defensive private network boundaries."""
    pass


class EntityNotFoundError(AppBaseException):
    """Raised when a requested resource is not found."""
    pass


class SecurityPolicyError(AppBaseException):
    """Raised when an operation violates defensive cybersecurity safety boundaries."""
    pass


class ConfigurationError(AppBaseException):
    """Raised when application configuration is missing or invalid."""
    pass


class AuthError(AppBaseException):
    """Raised when authentication credentials or token are invalid."""
    pass


class TokenExpiredError(AuthError):
    """Raised when authentication token has expired."""
    pass


class TokenInvalidError(AuthError):
    """Raised when authentication token signature or format is invalid."""
    pass


class AuthorizationError(AppBaseException):
    """Raised when an authenticated user attempts to access resources owned by another user."""
    pass


class RateLimitExceededError(AppBaseException):
    """Raised when request rate exceeds configured thresholds."""
    pass
