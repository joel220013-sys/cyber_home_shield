"""API v1 master router."""

from fastapi import APIRouter
from app.api.v1.endpoints import ai, auth, devices, findings, health, honeypot, network, risk, scans, telemetry

api_router = APIRouter()

# Include endpoints
api_router.include_router(auth.router, tags=["Authentication"])
api_router.include_router(health.router, tags=["Health"])
api_router.include_router(devices.router, tags=["Devices"])
api_router.include_router(findings.router, tags=["Security Findings"])
api_router.include_router(scans.router, tags=["Scans"])
api_router.include_router(risk.router, tags=["Risk Engine"])
api_router.include_router(ai.router, tags=["AI Security Advisor"])
api_router.include_router(honeypot.router, tags=["Honeypot & Deception"])
api_router.include_router(telemetry.router, tags=["Network Telemetry"])
api_router.include_router(network.router, tags=["Local Network"])

