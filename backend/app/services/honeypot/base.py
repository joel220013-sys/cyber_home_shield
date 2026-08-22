"""Base classes and interfaces for Honeypot deception subsystem."""

import abc
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from app.models.enums import Protocol, Severity


@dataclass
class HoneypotTelemetryEvent:
    """Safe internal representation of a honeypot interaction event."""
    honeypot_id: str
    source_ip: str
    destination_ip: str
    destination_port: int
    interaction_type: str
    protocol: Protocol = Protocol.TCP
    source_port: int = 0
    endpoint: str = ""
    user_agent: str = ""
    payload_sample: str = ""
    metadata_fields: Dict[str, Any] = field(default_factory=dict)
    severity: Severity = Severity.LOW
    user_id: Optional[uuid.UUID] = None
    event_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class BaseHoneypotTrap(abc.ABC):
    """Abstract Base Class for defensive honeypot deception traps."""

    def __init__(
        self,
        service_id: str,
        service_name: str,
        service_type: str,
        port: int,
        bind_host: str = "127.0.0.1",
        description: str = "",
        on_event_callback: Optional[Callable[[HoneypotTelemetryEvent], Any]] = None,
    ) -> None:
        self.service_id = service_id
        self.service_name = service_name
        self.service_type = service_type
        self.port = port
        self.bind_host = bind_host
        self.description = description
        self.on_event_callback = on_event_callback
        self._is_running = False
        self._interaction_count = 0

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def interaction_count(self) -> int:
        return self._interaction_count

    @abc.abstractmethod
    async def start(self) -> None:
        """Start listening / activating the trap."""
        pass

    @abc.abstractmethod
    async def stop(self) -> None:
        """Stop listener and release network resources safely."""
        pass

    @abc.abstractmethod
    async def handle_simulated_interaction(
        self,
        source_ip: str,
        method: str = "GET",
        endpoint: str = "/",
        payload: str = "",
        user_agent: str = "",
        user_id: Optional[uuid.UUID] = None,
    ) -> Dict[str, Any]:
        """Process a simulated or incoming interaction and emit sanitized telemetry."""
        pass

    def record_interaction(self, event: HoneypotTelemetryEvent) -> None:
        """Increment counter and dispatch event callback."""
        self._interaction_count += 1
        if self.on_event_callback:
            try:
                self.on_event_callback(event)
            except Exception:
                pass

