"""Simulated SSH Honeypot Trap."""

import asyncio
import logging
from typing import Any, Callable, Dict, Optional
import uuid

from app.models.enums import Protocol, Severity
from app.services.honeypot.base import BaseHoneypotTrap, HoneypotTelemetryEvent
from app.services.honeypot.isolation import (
    classify_interaction,
    sanitize_honeypot_payload,
    sanitize_metadata,
    validate_honeypot_bind_host,
)

logger = logging.getLogger("cyber_shield.honeypot.ssh")


class SshDecoyTrap(BaseHoneypotTrap):
    """Simulated SSH-style service trap. Does NOT provide shell or execute commands."""

    def __init__(
        self,
        service_id: str = "fake_ssh",
        service_name: str = "SSH Simulator Decoy",
        port: int = 2222,
        bind_host: str = "127.0.0.1",
        on_event_callback: Optional[Callable[[HoneypotTelemetryEvent], Any]] = None,
    ) -> None:
        super().__init__(
            service_id=service_id,
            service_name=service_name,
            service_type="SSH",
            port=port,
            bind_host=bind_host,
            description="Simulated SSH service banner with connection telemetry (SSH-2.0-CyberHomeShield-Simulated)",
            on_event_callback=on_event_callback,
        )
        self._server: Optional[asyncio.Server] = None
        self.banner = "SSH-2.0-CyberHomeShield-Simulated\r\n"

    async def start(self) -> None:
        """Start async TCP socket listener for SSH probes."""
        if self._is_running:
            return
        validated_host = validate_honeypot_bind_host(self.bind_host)
        try:
            self._server = await asyncio.start_server(
                self._handle_client_connection,
                host=validated_host,
                port=self.port,
            )
            self._is_running = True
            logger.info(f"SSH Honeypot Trap started on {validated_host}:{self.port}")
        except Exception as e:
            logger.warning(f"Could not bind SSH honeypot socket on port {self.port}: {e}. Operating in simulated mode.")
            self._is_running = True

    async def stop(self) -> None:
        """Stop TCP listener."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        self._is_running = False
        logger.info(f"SSH Honeypot Trap stopped on port {self.port}")

    async def _handle_client_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Safely send SSH simulated banner, record metadata, and close connection."""
        try:
            peer = writer.get_extra_info("peername")
            source_ip = peer[0] if peer else "127.0.0.1"
            source_port = peer[1] if peer else 0

            # Send simulated banner
            writer.write(self.banner.encode("utf-8"))
            await writer.drain()

            # Read client probe header safely with short timeout
            data = b""
            try:
                data = await asyncio.wait_for(reader.read(512), timeout=2.0)
            except asyncio.TimeoutError:
                pass

            client_banner = data.decode("utf-8", errors="replace").strip() if data else "SSH-Client-Probe"
            await self.handle_simulated_interaction(
                source_ip=source_ip,
                source_port=source_port,
                method="CONNECT",
                endpoint="ssh",
                payload=client_banner,
                user_agent=client_banner[:100],
            )
        except Exception as e:
            logger.debug(f"SSH Honeypot connection handled: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def handle_simulated_interaction(
        self,
        source_ip: str,
        source_port: int = 0,
        method: str = "CONNECT",
        endpoint: str = "ssh",
        payload: str = "",
        user_agent: str = "",
        user_id: Optional[uuid.UUID] = None,
    ) -> Dict[str, Any]:
        """Process safe SSH probe telemetry."""
        sanitized_payload = sanitize_honeypot_payload(payload)
        interaction_type, severity = classify_interaction(
            method=method,
            endpoint=endpoint,
            payload=sanitized_payload,
            protocol="SSH",
            service_type="SSH",
        )

        metadata = sanitize_metadata({
            "service_banner": self.banner.strip(),
            "client_probe": sanitized_payload[:150],
            "probe_action": "ssh_handshake_probe",
        })

        event = HoneypotTelemetryEvent(
            honeypot_id=self.service_id,
            source_ip=source_ip,
            destination_ip=self.bind_host,
            destination_port=self.port,
            protocol=Protocol.TCP,
            source_port=source_port,
            interaction_type=interaction_type,
            endpoint="ssh-service",
            user_agent=user_agent,
            payload_sample=sanitized_payload,
            metadata_fields=metadata,
            severity=severity,
            user_id=user_id,
        )
        self.record_interaction(event)

        return {
            "status_code": 200,
            "response_body": self.banner,
            "interaction_type": interaction_type,
            "severity": severity,
            "event": event,
        }

