"""Application configuration using Pydantic Settings."""

import json
from typing import List, Union

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables or .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # =========================================================================
    # APPLICATION
    # =========================================================================

    APP_NAME: str = "Cyber Home Shield"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False

    # =========================================================================
    # DATABASE
    # =========================================================================

    DATABASE_URL: str = (
        "postgresql+asyncpg://postgres:postgres@localhost:5432/"
        "cyber_home_shield"
    )

    API_V1_PREFIX: str = "/api/v1"

    # =========================================================================
    # CORS
    # =========================================================================

    CORS_ORIGINS: Union[List[str], str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

    # =========================================================================
    # AUTHENTICATION & SESSION SECURITY
    # =========================================================================

    SECRET_KEY: str = (
        "cyber-home-shield-development-secret-key-change-this"
    )

    JWT_ALGORITHM: str = "HS256"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 24 hours

    # =========================================================================
    # RATE LIMITING & TELEMETRY
    # =========================================================================

    RATE_LIMIT_ENABLED: bool = True

    RATE_LIMIT_LOGIN_PER_MINUTE: int = 10

    RATE_LIMIT_SCANS_PER_MINUTE: int = 20

    RATE_LIMIT_AI_PER_MINUTE: int = 30

    RATE_LIMIT_HONEYPOT_PER_MINUTE: int = 60

    TELEMETRY_RETENTION_DAYS: int = 30

    # =========================================================================
    # AI / NVIDIA NEMOTRON
    # =========================================================================

    NVIDIA_API_KEY: str = ""

    NVIDIA_MODEL: str = "nvidia/nemotron-4-340b-instruct"

    NVIDIA_BASE_URL: str = (
        "https://integrate.api.nvidia.com/v1"
    )

    # =========================================================================
    # DEFENSIVE DISCOVERY
    # =========================================================================

    # Maximum time allowed for a discovery operation.
    DISCOVERY_TIMEOUT: float = 30.0

    # Timeout for an individual TCP connection.
    CONNECT_TIMEOUT: float = 1.5

    # Maximum number of hosts that can be inspected.
    MAX_HOSTS: int = 254

    # Maximum concurrent TCP checks.
    MAX_CONCURRENT_CHECKS: int = 20

    # Defensive TCP ports used by the discovery engine.
    DEFAULT_DISCOVERY_PORTS: List[int] = [
        22,
        53,
        80,
        443,
        445,
        554,
        631,
        8080,
        8443,
    ]

    # IMPORTANT:
    #
    # "network" -> LiveNetworkDiscoveryProvider
    #
    # We want REAL defensive discovery.
    DISCOVERY_PROVIDER: str = "network"

    # =========================================================================
    # HONEYPOT / DECEPTION
    # =========================================================================

    HONEYPOT_ENABLED: bool = False

    HONEYPOT_BIND_HOST: str = "127.0.0.1"

    HONEYPOT_ALLOW_NON_LOCAL: bool = False

    HONEYPOT_HTTP_PORT: int = 8088

    HONEYPOT_SSH_PORT: int = 2222

    HONEYPOT_CAMERA_PORT: int = 8554

    # =========================================================================
    # DATABASE URL VALIDATION
    # =========================================================================

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_db_url(cls, value: str) -> str:
        """
        Normalize PostgreSQL URLs for async SQLAlchemy.

        Supported:

            postgres://...
            postgresql://...
            postgresql+asyncpg://...
        """

        if not value:
            return (
                "postgresql+asyncpg://postgres:postgres@localhost:5432/"
                "cyber_home_shield"
            )

        value = str(value).strip()

        # postgres://
        if value.startswith("postgres://"):
            return value.replace(
                "postgres://",
                "postgresql+asyncpg://",
                1,
            )

        # postgresql://
        if (
            value.startswith("postgresql://")
            and "+asyncpg" not in value
        ):
            return value.replace(
                "postgresql://",
                "postgresql+asyncpg://",
                1,
            )

        return value

    # =========================================================================
    # CORS VALIDATION
    # =========================================================================

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(
        cls,
        value: Union[str, List[str]],
    ) -> List[str]:
        """
        Normalize CORS origins from:

        1. Python list
        2. JSON list
        3. Comma-separated string
        """

        if isinstance(value, str):

            value = value.strip()

            # -------------------------------------------------------------
            # JSON list
            #
            # Example:
            #
            # ["http://localhost:3000", "http://localhost:5173"]
            # -------------------------------------------------------------

            if (
                value.startswith("[")
                and value.endswith("]")
            ):
                try:
                    parsed = json.loads(value)

                    if isinstance(parsed, list):
                        return [
                            str(origin).strip()
                            for origin in parsed
                            if str(origin).strip()
                        ]

                except json.JSONDecodeError:
                    pass

            # -------------------------------------------------------------
            # Comma-separated values
            #
            # Example:
            #
            # http://localhost:3000,http://localhost:5173
            # -------------------------------------------------------------

            return [
                origin.strip()
                for origin in value.split(",")
                if origin.strip()
            ]

        # -----------------------------------------------------------------
        # Python list
        # -----------------------------------------------------------------

        if isinstance(value, list):

            return [
                str(origin).strip()
                for origin in value
                if str(origin).strip()
            ]

        return ["*"]

    # =========================================================================
    # HELPERS
    # =========================================================================

    def is_production(self) -> bool:
        """Return True when running in production."""

        return self.ENVIRONMENT.lower() in (
            "production",
            "prod",
        )

    # =========================================================================
    # SAFE REPRESENTATION
    # =========================================================================

    def __repr__(self) -> str:
        """
        Return a safe representation without exposing secrets.
        """

        masked_api_key = (
            "***"
            if self.NVIDIA_API_KEY
            else "<not set>"
        )

        return (
            f"<Settings "
            f"app={self.APP_NAME} "
            f"env={self.ENVIRONMENT} "
            f"debug={self.DEBUG} "
            f"honeypot={self.HONEYPOT_ENABLED} "
            f"nvidia_key={masked_api_key}>"
        )


# ============================================================================
# GLOBAL SETTINGS INSTANCE
# ============================================================================

settings = Settings()
