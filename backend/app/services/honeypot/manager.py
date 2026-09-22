"""Honeypot Subsystem Manager.

Coordinates deception traps, lifecycle management, safe socket bindings,
and telemetry event routing.
"""

import asyncio
import logging
import socket
from datetime import datetime, timezone
from typing import Dict, List, Optional
import uuid

from app.config import settings
from app.models.enums import Severity
from app.schemas.honeypot import (
    HoneypotServiceStatus,
    HoneypotStatusResponse,
)
from app.services.honeypot.base import BaseHoneypotTrap, HoneypotTelemetryEvent
from app.services.honeypot.isolation import validate_honeypot_bind_host
from app.services.honeypot.services.http_trap import HttpIoTGatewayTrap
from app.services.honeypot.services.iot_trap import CameraDecoyTrap
from app.services.honeypot.services.ssh_trap import SshDecoyTrap

logger = logging.getLogger("cyber_shield.honeypot.manager")


class HoneypotManager:
    """Singleton manager controlling all defensive honeypot traps and listeners."""

    def __init__(self) -> None:
        self.bind_host: str = settings.HONEYPOT_BIND_HOST
        self._traps: Dict[str, BaseHoneypotTrap] = {}
        self._is_running: bool = False
        self._enabled: bool = settings.HONEYPOT_ENABLED
        self._init_traps()

    def _init_traps(self) -> None:
        """Initialize trap instances."""
        self._traps = {
            "iot_gateway": HttpIoTGatewayTrap(
                port=settings.HONEYPOT_HTTP_PORT,
                bind_host=self.bind_host,
            ),
            "fake_ssh": SshDecoyTrap(
                port=settings.HONEYPOT_SSH_PORT,
                bind_host=self.bind_host,
            ),
            "camera_rtsp": CameraDecoyTrap(
                port=settings.HONEYPOT_CAMERA_PORT,
                bind_host=self.bind_host,
            ),
        }

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def enable(self) -> None:
        self._enabled = True

    def disable(self) -> None:
        self._enabled = False

    async def start(
        self,
        custom_bind_host: Optional[str] = None,
        allow_non_local: Optional[bool] = None,
    ) -> List[str]:
        """
        Start all honeypot trap listeners on validated host.
        Enforces defensive isolation and rejects non-local host bindings unless configured.
        """
        effective_allow_non_local = (
            allow_non_local
            if allow_non_local is not None
            else settings.HONEYPOT_ALLOW_NON_LOCAL
        )
        target_host = custom_bind_host or self.bind_host or "127.0.0.1"
        validated_host = validate_honeypot_bind_host(
            target_host,
            allow_non_local=effective_allow_non_local,
        )
        self.bind_host = validated_host

        active_services: List[str] = []
        for trap_id, trap in self._traps.items():
            trap.bind_host = validated_host
            try:
                await trap.start()
                active_services.append(trap.service_name)
            except Exception as e:
                logger.error(f"Failed to start trap {trap_id}: {e}")

        self._is_running = True
        logger.info(f"Honeypot Manager started on {validated_host} with {len(active_services)} traps.")
        return active_services

    async def stop(self) -> None:
        """Stop all honeypot traps and release sockets."""
        for trap_id, trap in self._traps.items():
            try:
                await trap.stop()
            except Exception as e:
                logger.error(f"Error stopping trap {trap_id}: {e}")

        self._is_running = False
        logger.info("Honeypot Manager stopped.")

    @staticmethod
    def get_lan_ip() -> str:
        """Resolve the primary active LAN IPv4 address (e.g. 192.168.x.x, 10.x.x.x)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Route lookup without sending packets to external network
            s.connect(("10.255.255.255", 1))
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith("127."):
                return ip
        except Exception:
            pass
        return "127.0.0.1"

    def get_trap(self, trap_id: str) -> Optional[BaseHoneypotTrap]:
        return self._traps.get(trap_id)

    def get_status(
        self,
        total_events: int = 0,
        high_severity_events: int = 0,
        last_interaction: Optional[datetime] = None,
    ) -> HoneypotStatusResponse:
        """Compile status summary for all honeypot traps."""
        services = [
            HoneypotServiceStatus(
                id=trap.service_id,
                name=trap.service_name,
                service_type=trap.service_type,
                port=trap.port,
                running=trap.is_running,
                description=trap.description,
                interaction_count=trap.interaction_count,
            )
            for trap in self._traps.values()
        ]

        lan_ip = self.get_lan_ip()
        profile = getattr(settings, "HONEYPOT_DECOY_PROFILE", "realistic_iot")

        return HoneypotStatusResponse(
            enabled=self._enabled,
            running=self._is_running,
            bind_host=self.bind_host,
            lan_ip=lan_ip,
            decoy_profile=profile,
            services=services,
            total_events=total_events,
            high_severity_events=high_severity_events,
            last_interaction=last_interaction,
        )

    async def handle_simulated_probe(
        self,
        trap_type: str = "iot_gateway",
        source_ip: str = "192.168.1.188",
        interaction_type: str = "login_attempt",
        endpoint: str = "/login",
        user_id: Optional[uuid.UUID] = None,
    ) -> HoneypotTelemetryEvent:
        """Process a probe through a configured real honeypot trap."""
        trap_id = {
            "http_iot_gateway": "iot_gateway",
        }.get(trap_type, trap_type)
        trap = self._traps.get(trap_id)
        if trap:
            result = await trap.handle_simulated_interaction(
                source_ip=source_ip,
                method="POST" if "login" in endpoint or "admin" in endpoint else "GET",
                endpoint=endpoint,
                payload=f"simulated_action={interaction_type}",
                user_agent="CyberHomeShield-Simulator/1.0",
                user_id=user_id,
            )
            return result["event"]

        raise ValueError(
            f"Unknown honeypot trap type {trap_type!r}; "
            "no fallback provider is available."
        )


# Global honeypot manager instance
honeypot_manager = HoneypotManager()

