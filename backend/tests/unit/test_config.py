"""Test application configuration loading and validation."""

import pytest
from app.config import Settings


def test_default_config_loading():
    """Verify standard default configuration values."""
    cfg = Settings()
    assert cfg.APP_NAME == "Cyber Home Shield"
    assert cfg.APP_VERSION == "0.1.0"
    assert cfg.API_V1_PREFIX == "/api/v1"
    assert cfg.NVIDIA_BASE_URL == "https://integrate.api.nvidia.com/v1"
    assert cfg.NVIDIA_MODEL == "nvidia/nemotron-4-340b-instruct"


def test_cors_parsing_from_list():
    """Verify CORS origins parsed properly from list."""
    cfg = Settings(CORS_ORIGINS=["http://localhost:3000", "http://127.0.0.1:3000"])
    assert "http://localhost:3000" in cfg.CORS_ORIGINS
    assert "http://127.0.0.1:3000" in cfg.CORS_ORIGINS


def test_cors_parsing_from_json_string():
    """Verify CORS origins parsed from JSON string format."""
    cfg = Settings(CORS_ORIGINS='["http://example.com", "http://app.local"]')
    assert cfg.CORS_ORIGINS == ["http://example.com", "http://app.local"]


def test_cors_parsing_from_comma_string():
    """Verify CORS origins parsed from comma-separated string."""
    cfg = Settings(CORS_ORIGINS="http://site1.com, http://site2.com")
    assert cfg.CORS_ORIGINS == ["http://site1.com", "http://site2.com"]


def test_secret_masking_in_repr():
    """Verify secrets like NVIDIA_API_KEY are never printed in string representation."""
    cfg = Settings(NVIDIA_API_KEY="nvapi-super-secret-key-12345")
    repr_str = repr(cfg)
    assert "nvapi-super-secret-key-12345" not in repr_str
    assert "***" in repr_str

