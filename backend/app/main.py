"""FastAPI application entrypoint for Cyber Home Shield with security hardening."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from datetime import datetime, timezone
from sqlalchemy import update

from app.api.v1.api_router import api_router
from app.config import settings
from app.core.exceptions import AppBaseException
from app.core.logging import logger, setup_logging
from app.db.session import AsyncSessionLocal
from app.models.enums import ScanStatus
from app.models.scan_job import ScanJob


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware enforcing defense-in-depth HTTP security headers."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        if settings.is_production():
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response


async def _recover_orphaned_scans(session_factory=None) -> None:
    """Mark any leftover PENDING or RUNNING scans from previous interrupted process as FAILED."""
    factory = session_factory or AsyncSessionLocal
    try:
        async with factory() as db:
            stmt = (
                update(ScanJob)
                .where(ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]))
                .values(
                    status=ScanStatus.FAILED,
                    completed_at=datetime.now(timezone.utc),
                    error_message="Scan interrupted by server restart or shutdown.",
                )
            )
            res = await db.execute(stmt)
            await db.commit()
            if res.rowcount and res.rowcount > 0:
                logger.info("Cleaned up %d orphaned scan job(s) from previous run.", res.rowcount)
    except Exception as e:
        logger.warning("Could not execute orphaned scan recovery on startup: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown lifespan management."""
    setup_logging(debug=settings.DEBUG)
    logger.info(
        "Starting %s (v%s) [env=%s, debug=%s]",
        settings.APP_NAME,
        settings.APP_VERSION,
        settings.ENVIRONMENT,
        settings.DEBUG,
    )
    await _recover_orphaned_scans()
    yield
    logger.info("Shutting down %s", settings.APP_NAME)


def create_application() -> FastAPI:
    """Factory creating configured FastAPI instance with security hardening."""
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="Ethical Home Network Cybersecurity Platform - Defensive Discovery, Risk & Mitigation",
        docs_url="/docs" if not settings.is_production() else None,
        redoc_url="/redoc" if not settings.is_production() else None,
        lifespan=lifespan,
    )

    # 1. Security Headers Middleware
    app.add_middleware(SecurityHeadersMiddleware)

    # 2. CORS Configuration
    if settings.is_production():
        cors_origins = [o for o in settings.CORS_ORIGINS if o != "*"]
        allow_all = False
    else:
        cors_origins = (
            ["*"]
            if "*" in settings.CORS_ORIGINS or settings.DEBUG
            else list(settings.CORS_ORIGINS)
        )
        allow_all = "*" in cors_origins

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins if not allow_all else ["*"],
        allow_credentials=True if not allow_all else False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"],
        allow_headers=["*"],
    )

    # 3. Global Exception Handlers
    @app.exception_handler(AppBaseException)
    async def app_exception_handler(request: Request, exc: AppBaseException):
        logger.warning("Application domain error: %s", exc.message)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": exc.message, "error_type": exc.__class__.__name__},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        logger.error("Unhandled exception: %s", str(exc), exc_info=settings.DEBUG)
        detail = str(exc) if settings.DEBUG else "An internal server error occurred."
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": detail},
        )

    # 4. Mount API v1 router
    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    @app.get("/", include_in_schema=False)
    async def root_redirect():
        return {
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "status": "operational",
            "docs": "/docs" if not settings.is_production() else "disabled",
        }

    return app


app = create_application()

