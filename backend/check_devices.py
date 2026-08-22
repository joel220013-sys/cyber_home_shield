import asyncio

from sqlalchemy import select

from app.db.session import AsyncSessionLocal
from app.models.device import Device


async def main():
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Device).order_by(Device.created_at)
        )

        devices = result.scalars().all()

        print(f"\nTOTAL DEVICES: {len(devices)}\n")
        print("-" * 120)

        for device in devices:
            print(
                f"ID: {device.id}\n"
                f"IP: {device.ip_address}\n"
                f"MAC: {device.mac_address}\n"
                f"Hostname: {device.hostname}\n"
                f"User ID: {device.user_id}\n"
                f"Online: {device.is_online}\n"
                f"Created: {device.created_at}\n"
                f"Last Seen: {device.last_seen}\n"
            )
            print("-" * 120)


if __name__ == "__main__":
    asyncio.run(main())