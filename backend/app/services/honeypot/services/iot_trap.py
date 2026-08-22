"""Simulated IP Camera / RTSP Honeypot Trap."""

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

logger = logging.getLogger("cyber_shield.honeypot.camera")


class CameraDecoyTrap(BaseHoneypotTrap):
    """Simulated IP Camera & RTSP Stream decoy."""

    def __init__(
        self,
        service_id: str = "camera_rtsp",
        service_name: str = "IP Camera Simulator Decoy",
        port: int = 8554,
        bind_host: str = "127.0.0.1",
        on_event_callback: Optional[Callable[[HoneypotTelemetryEvent], Any]] = None,
    ) -> None:
        super().__init__(
            service_id=service_id,
            service_name=service_name,
            service_type="CAMERA",
            port=port,
            bind_host=bind_host,
            description="Simulated IP Camera web and stream decoy (/snapshot, /stream, /status, /live.sdp)",
            on_event_callback=on_event_callback,
        )
        self._server: Optional[asyncio.Server] = None

    async def start(self) -> None:
        """Start async TCP socket listener for Camera/RTSP requests."""
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
            logger.info(f"Camera Honeypot Trap started on {validated_host}:{self.port}")
        except Exception as e:
            logger.warning(f"Could not bind Camera honeypot socket on port {self.port}: {e}. Operating in simulated mode.")
            self._is_running = True

    async def stop(self) -> None:
        """Stop TCP listener."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        self._is_running = False
        logger.info(f"Camera Honeypot Trap stopped on port {self.port}")

    async def _handle_client_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming connection safely."""
        try:
            peer = writer.get_extra_info("peername")
            source_ip = peer[0] if peer else "127.0.0.1"
            source_port = peer[1] if peer else 0

            data = await asyncio.wait_for(reader.read(2048), timeout=3.0)
            if not data:
                writer.close()
                await writer.wait_closed()
                return

            req_text = data.decode("utf-8", errors="replace")
            lines = req_text.splitlines()
            first_line = lines[0] if lines else "GET / HTTP/1.1"
            parts = first_line.split()
            method = parts[0] if len(parts) > 0 else "GET"
            endpoint = parts[1] if len(parts) > 1 else "/"

            user_agent = ""
            for line in lines[1:]:
                if line.lower().startswith("user-agent:"):
                    user_agent = line.split(":", 1)[1].strip()

            resp = await self.handle_simulated_interaction(
                source_ip=source_ip,
                source_port=source_port,
                method=method,
                endpoint=endpoint,
                payload=req_text,
                user_agent=user_agent,
            )

            http_body = resp.get("response_body", "OK")
            status_code = resp.get("status_code", 200)
            http_response = (
                f"HTTP/1.1 {status_code} OK\r\n"
                f"Content-Type: text/plain; charset=utf-8\r\n"
                f"Content-Length: {len(http_body.encode('utf-8'))}\r\n"
                f"Server: CyberHomeShield-SimulatedCamera/1.0\r\n"
                f"Connection: close\r\n\r\n"
                f"{http_body}"
            )
            writer.write(http_response.encode("utf-8"))
            await writer.drain()
        except Exception as e:
            logger.debug(f"Camera Honeypot connection handled: {e}")
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
        method: str = "GET",
        endpoint: str = "/snapshot",
        payload: str = "",
        user_agent: str = "",
        user_id: Optional[uuid.UUID] = None,
    ) -> Dict[str, Any]:
        """Generate simulated camera response and emit sanitized telemetry."""
        method_clean = method.strip().upper()
        ep_clean = endpoint.strip()
        sanitized_payload = sanitize_honeypot_payload(payload)
        interaction_type, severity = classify_interaction(
            method=method_clean,
            endpoint=ep_clean,
            payload=sanitized_payload,
            protocol="TCP",
            service_type="CAMERA",
        )

        metadata = sanitize_metadata({
            "device_archetype": "IP-Camera-Simulated",
            "endpoint": ep_clean,
            "stream_resolution": "1080p-simulated",
            "probe_action": "camera_feed_inquiry",
        })

        if ep_clean.startswith("/snapshot"):
            response_body = "Simulated camera snapshot feed unavailable (Defensive Decoy Mode)."
            status_code = 503
        elif ep_clean.startswith("/stream") or ep_clean.startswith("/live.sdp"):
            response_body = "RTSP stream unavailable. Access restricted on simulated node."
            status_code = 503
        elif ep_clean.startswith("/status"):
            response_body = '{"camera": "Online", "mode": "Decoy-Simulated", "fps": 0}'
            status_code = 200
        else:
            response_body = "Cyber Home Shield Simulated IP Camera Interface."
            status_code = 200

        event = HoneypotTelemetryEvent(
            honeypot_id=self.service_id,
            source_ip=source_ip,
            destination_ip=self.bind_host,
            destination_port=self.port,
            protocol=Protocol.TCP,
            source_port=source_port,
            interaction_type=interaction_type,
            endpoint=ep_clean,
            user_agent=user_agent,
            payload_sample=sanitized_payload,
            metadata_fields=metadata,
            severity=severity,
            user_id=user_id,
        )
        self.record_interaction(event)

        return {
            "status_code": status_code,
            "response_body": response_body,
            "interaction_type": interaction_type,
            "severity": severity,
            "event": event,
        }

