import asyncio
from datetime import datetime, timedelta, timezone

from app.db.session import AsyncSessionLocal
from app.models.network_event import NetworkEvent
from app.models.enums import Protocol, Severity

DEVICE_ID = "ef19016f-5947-4d7e-9606-02c529e91504"


async def main():
    async with AsyncSessionLocal() as db:
        now = datetime.now(timezone.utc)

        events = [
            NetworkEvent(
                device_id=DEVICE_ID,
                event_timestamp=now - timedelta(seconds=50),
                source_ip="192.168.1.50",
                destination_ip="8.8.8.8",
                source_port=51001,
                destination_port=1337,
                protocol=Protocol.TCP,
                bytes_transferred=500,
                is_anomaly=False,
                anomaly_reason="",
                severity=Severity.INFO,
            ),
            NetworkEvent(
                device_id=DEVICE_ID,
                event_timestamp=now - timedelta(seconds=40),
                source_ip="192.168.1.50",
                destination_ip="8.8.8.8",
                source_port=51002,
                destination_port=31337,
                protocol=Protocol.TCP,
                bytes_transferred=600,
                is_anomaly=False,
                anomaly_reason="",
                severity=Severity.INFO,
            ),
            NetworkEvent(
                device_id=DEVICE_ID,
                event_timestamp=now - timedelta(seconds=30),
                source_ip="192.168.1.50",
                destination_ip="8.8.8.8",
                source_port=51003,
                destination_port=4444,
                protocol=Protocol.TCP,
                bytes_transferred=700,
                is_anomaly=False,
                anomaly_reason="",
                severity=Severity.INFO,
            ),
            NetworkEvent(
                device_id=DEVICE_ID,
                event_timestamp=now - timedelta(seconds=20),
                source_ip="192.168.1.50",
                destination_ip="8.8.8.8",
                source_port=51004,
                destination_port=9001,
                protocol=Protocol.TCP,
                bytes_transferred=800,
                is_anomaly=False,
                anomaly_reason="",
                severity=Severity.INFO,
            ),
            NetworkEvent(
                device_id=DEVICE_ID,
                event_timestamp=now - timedelta(seconds=10),
                source_ip="192.168.1.50",
                destination_ip="8.8.8.8",
                source_port=51005,
                destination_port=9999,
                protocol=Protocol.TCP,
                bytes_transferred=900,
                is_anomaly=True,
                anomaly_reason="Test anomaly: unusual external destination and port",
                severity=Severity.HIGH,
            ),
        ]

        db.add_all(events)
        await db.commit()

        print(f"Inserted {len(events)} anomaly-test telemetry events.")


asyncio.run(main())
