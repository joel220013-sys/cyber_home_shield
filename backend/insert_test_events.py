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
                event_timestamp=now - timedelta(minutes=4),
                source_ip="192.168.1.50",
                destination_ip="192.168.1.1",
                source_port=50001,
                destination_port=443,
                protocol=Protocol.TCP,
                bytes_transferred=1200,
                is_anomaly=False,
                anomaly_reason="",
                severity=Severity.INFO,
            ),
            NetworkEvent(
                device_id=DEVICE_ID,
                event_timestamp=now - timedelta(minutes=3),
                source_ip="192.168.1.50",
                destination_ip="192.168.1.1",
                source_port=50002,
                destination_port=53,
                protocol=Protocol.UDP,
                bytes_transferred=800,
                is_anomaly=False,
                anomaly_reason="",
                severity=Severity.INFO,
            ),
            NetworkEvent(
                device_id=DEVICE_ID,
                event_timestamp=now - timedelta(minutes=2),
                source_ip="192.168.1.50",
                destination_ip="192.168.1.1",
                source_port=50003,
                destination_port=443,
                protocol=Protocol.TCP,
                bytes_transferred=1500,
                is_anomaly=False,
                anomaly_reason="",
                severity=Severity.INFO,
            ),
            NetworkEvent(
                device_id=DEVICE_ID,
                event_timestamp=now - timedelta(minutes=1),
                source_ip="192.168.1.50",
                destination_ip="192.168.1.1",
                source_port=50004,
                destination_port=554,
                protocol=Protocol.TCP,
                bytes_transferred=2000,
                is_anomaly=False,
                anomaly_reason="",
                severity=Severity.INFO,
            ),
            NetworkEvent(
                device_id=DEVICE_ID,
                event_timestamp=now,
                source_ip="192.168.1.50",
                destination_ip="192.168.1.1",
                source_port=50005,
                destination_port=443,
                protocol=Protocol.TCP,
                bytes_transferred=1800,
                is_anomaly=False,
                anomaly_reason="",
                severity=Severity.INFO,
            ),
        ]

        db.add_all(events)
        await db.commit()

        print(f"Inserted {len(events)} telemetry events.")


asyncio.run(main())
