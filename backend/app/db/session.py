"""Database connection session management with SQLAlchemy 2.x async engine."""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from app.config import settings

# Create async engine. Connect arguments can be adjusted based on dialect.
connect_args = {}
if "sqlite" in settings.DATABASE_URL:
    connect_args["check_same_thread"] = False

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    pool_pre_ping=True,
    connect_args=connect_args,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that provides an isolated async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            # Endpoint raised — rollback and let the exception propagate.
            await session.rollback()
            raise
        else:
            # Endpoint succeeded — try to commit; if the session was left in a
            # rolled-back state (e.g. by an internal flush error that the
            # endpoint caught), just rollback silently so the connection is
            # returned cleanly to the pool.
            try:
                await session.commit()
            except Exception:
                await session.rollback()
        finally:
            await session.close()

