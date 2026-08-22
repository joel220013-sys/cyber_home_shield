"""Pytest fixtures and testing configuration."""

import asyncio
import os
import sys
from pathlib import Path
from typing import AsyncGenerator
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Ensure repository root is on Python path so 'backend' is importable
repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from app.main import app
from app.config import Settings
from app.core.security import rate_limiter
from app.db.base import Base
from app.db.session import get_db

# Create in-memory SQLite async engine for tests
TEST_DB_URL = "sqlite+aiosqlite:///:memory:"
test_engine = create_async_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    future=True,
)
TestAsyncSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


@pytest.fixture
def test_settings() -> Settings:
    """Fixture providing test configuration."""
    return Settings(
        APP_NAME="Cyber Home Shield",
        ENVIRONMENT="testing",
        DEBUG=True,
        DATABASE_URL=TEST_DB_URL,
        DISCOVERY_PROVIDER="network",
    )


@pytest_asyncio.fixture(autouse=True)
async def reset_rate_limiter_state():
    """Reset rate limiter before each test."""
    rate_limiter.reset()
    yield
    rate_limiter.reset()


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provide a fresh in-memory database session with all tables created."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestAsyncSessionLocal() as session:
        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def async_client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP test client bound to FastAPI application with DB dependency override."""
    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client

    app.dependency_overrides.clear()

