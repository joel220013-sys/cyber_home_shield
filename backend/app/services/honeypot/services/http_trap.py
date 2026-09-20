"""Simulated IoT Gateway HTTP Honeypot Trap."""

import asyncio
import logging
from typing import Any, Callable, Dict, Optional
import uuid

from app.config import settings
from app.models.enums import Protocol, Severity
from app.services.honeypot.base import BaseHoneypotTrap, HoneypotTelemetryEvent
from app.services.honeypot.isolation import (
    classify_interaction,
    sanitize_honeypot_payload,
    sanitize_metadata,
    validate_honeypot_bind_host,
)

logger = logging.getLogger("cyber_shield.honeypot.http")


class HttpIoTGatewayTrap(BaseHoneypotTrap):
    """Simulated IoT Gateway HTTP web interface decoy."""

    def __init__(
        self,
        service_id: str = "iot_gateway",
        service_name: str = "IoT Gateway Decoy",
        port: int = 8088,
        bind_host: str = "127.0.0.1",
        on_event_callback: Optional[Callable[[HoneypotTelemetryEvent], Any]] = None,
    ) -> None:
        super().__init__(
            service_id=service_id,
            service_name=service_name,
            service_type="HTTP",
            port=port,
            bind_host=bind_host,
            description="Simulated IoT Gateway Web Console (/login, /admin, /device-info, /status)",
            on_event_callback=on_event_callback,
        )
        self._server: Optional[asyncio.Server] = None

    async def start(self) -> None:
        """Start async TCP socket listener for HTTP requests."""
        if self._is_running:
            return
        validated_host = validate_honeypot_bind_host(
            self.bind_host,
            allow_non_local=settings.HONEYPOT_ALLOW_NON_LOCAL,
        )
        try:
            self._server = await asyncio.start_server(
                self._handle_client_connection,
                host=validated_host,
                port=self.port,
            )
            self._is_running = True
            logger.info(f"HTTP Honeypot Trap started on {validated_host}:{self.port}")
        except Exception as e:
            logger.warning(f"Could not bind HTTP honeypot socket on port {self.port}: {e}. Operating in simulated mode.")
            self._is_running = False
            raise

    async def stop(self) -> None:
        """Stop TCP listener."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        self._is_running = False
        logger.info(f"HTTP Honeypot Trap stopped on port {self.port}")

    async def _handle_client_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Safely handle incoming HTTP socket connection without command execution."""
        try:
            peer = writer.get_extra_info("peername")
            source_ip = peer[0] if peer else "127.0.0.1"
            source_port = peer[1] if peer else 0

            # Read request line safely with timeout
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

            # Send safe HTTP response
            http_body = resp.get("response_body", "OK")
            status_code = resp.get("status_code", 200)
            status_text = "OK" if status_code == 200 else ("Unauthorized" if status_code == 401 else "Forbidden")
            banner = getattr(settings, "HONEYPOT_HTTP_BANNER", "mini_httpd/1.30 01Jan2018")
            auth_header = 'WWW-Authenticate: Basic realm="Broadband Router Management"\r\n' if status_code == 401 else ""
            http_response = (
                f"HTTP/1.1 {status_code} {status_text}\r\n"
                f"Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(http_body.encode('utf-8'))}\r\n"
                f"Server: {banner}\r\n"
                f"{auth_header}"
                f"Connection: close\r\n\r\n"
                f"{http_body}"
            )
            writer.write(http_response.encode("utf-8"))
            await writer.drain()
        except Exception as e:
            logger.debug(f"Honeypot connection handled: {e}")
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
        endpoint: str = "/",
        payload: str = "",
        user_agent: str = "",
        user_id: Optional[uuid.UUID] = None,
    ) -> Dict[str, Any]:
        """Generate safe simulated HTTP response and emit sanitized telemetry."""
        method_clean = method.strip().upper()
        ep_clean = endpoint.strip()
        sanitized_payload = sanitize_honeypot_payload(payload)
        interaction_type, severity = classify_interaction(
            method=method_clean,
            endpoint=ep_clean,
            payload=sanitized_payload,
            protocol="TCP",
            service_type="HTTP",
        )

        metadata = sanitize_metadata({
            "method": method_clean,
            "endpoint": ep_clean,
            "user_agent": user_agent[:200] if user_agent else "Generic/1.0",
            "simulated_device": "Broadband-Router-WNR2000",
            "probe_action": "auth_attempt" if interaction_type == "login_attempt" else "inspection",
        })

        # Generate realistic router response
        if ep_clean.startswith("/device-info"):
            response_body = '{"model": "WNR2000v5", "hardware": "V1.0", "firmware": "V1.0.0.70", "status": "active"}'
            status_code = 200
        elif ep_clean.startswith("/status"):
            response_body = '{"system": "active", "uplink": "connected", "connected_clients": 4}'
            status_code = 200
        elif ep_clean.startswith("/admin"):
            response_body = "<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>Administrative Access Restricted.</p></body></html>"
            status_code = 403 if method_clean == "GET" else 401
        elif ep_clean.startswith("/login"):
            response_body = '{"status": "error", "code": 401, "message": "Authentication failed: Invalid credentials. 3 attempts remaining.", "active": false}'
            status_code = 401
        else:
            response_body = (
                "<!DOCTYPE html><html><head><title>Wireless Broadband Router - Management Login</title>"
                "<style>"
                "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #eef2f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }"
                ".card { background: white; border: 1px solid #d0d7de; border-radius: 6px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); width: 340px; padding: 28px; }"
                "h2 { font-size: 17px; margin-top: 0; color: #1f2328; border-bottom: 2px solid #0969da; padding-bottom: 8px; }"
                ".field { margin-bottom: 14px; }"
                "label { display: block; font-size: 12px; font-weight: 600; color: #57606a; margin-bottom: 5px; }"
                "input { width: 100%; box-sizing: border-box; padding: 8px; border: 1px solid #d0d7de; border-radius: 4px; font-size: 13px; }"
                "button { width: 100%; padding: 9px; background: #0969da; color: white; border: none; border-radius: 4px; font-weight: 600; cursor: pointer; margin-top: 8px; }"
                "button:hover { background: #0856b5; }"
                "</style></head><body>"
                "<div class='card'>"
                "<h2>Router Management</h2>"
                "<form method='POST' action='/login'>"
                "<div class='field'><label>Username</label><input type='text' name='username' value='admin' autocomplete='username' /></div>"
                "<div class='field'><label>Password</label><input type='password' name='password' autocomplete='current-password' /></div>"
                "<button type='submit'>Sign In</button>"
                "</form>"
                "</div></body></html>"
            )
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

