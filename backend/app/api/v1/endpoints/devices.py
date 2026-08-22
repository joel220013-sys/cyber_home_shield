"""Device inventory and management API endpoints with resource ownership enforcement."""

import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import (
    get_db,
    get_optional_current_user,
)
from app.core.security import is_rfc1918_private_ip
from app.models.device import Device
from app.models.user import User
from app.schemas.device import (
    DeviceCreate,
    DeviceDetailResponse,
    DeviceResponse,
)

router = APIRouter(
    prefix="/devices",
    tags=["Devices"],
)


# ============================================================================
# LIST DEVICES
# ============================================================================


@router.get(
    "",
    response_model=List[DeviceResponse],
    status_code=status.HTTP_200_OK,
    summary="List authorized network devices",
)
async def list_devices(
    current_user: Optional[User] = Depends(
        get_optional_current_user
    ),
    db: AsyncSession = Depends(get_db),
) -> List[DeviceResponse]:
    """
    List devices visible to the current user.

    Ownership rules:

    1. Superuser:
       - Can see all devices.

    2. Normal authenticated user:
       - Can see ONLY devices owned by that user.

    3. Anonymous user:
       - Can see ONLY unowned/global devices.

    This prevents cross-user device enumeration and IDOR.
    """

    # ------------------------------------------------------------------------
    # Base query
    # ------------------------------------------------------------------------

    stmt = (
        select(Device)
        .order_by(Device.last_seen.desc())
    )

    # ------------------------------------------------------------------------
    # Ownership isolation
    # ------------------------------------------------------------------------

    if current_user is not None:

        if current_user.is_superuser:
            # Superuser can see everything.
            pass

        else:
            # Normal user can ONLY see their own devices.
            stmt = stmt.where(
                Device.user_id == current_user.id
            )

    else:
        # Anonymous users can ONLY see unowned devices.
        stmt = stmt.where(
            Device.user_id.is_(None)
        )

    # ------------------------------------------------------------------------
    # Execute
    # ------------------------------------------------------------------------

    result = await db.execute(stmt)

    devices = result.scalars().all()

    return [
        DeviceResponse.model_validate(device)
        for device in devices
    ]


# ============================================================================
# GET DEVICE
# ============================================================================


@router.get(
    "/{device_id}",
    response_model=DeviceDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get detailed device profile with open ports and findings",
)
async def get_device(
    device_id: str,
    current_user: Optional[User] = Depends(
        get_optional_current_user
    ),
    db: AsyncSession = Depends(get_db),
) -> DeviceDetailResponse:
    """
    Retrieve a device with strict resource ownership enforcement.

    Ownership rules:

    - Superuser -> any device.
    - Normal user -> only their own device.
    - Anonymous -> only unowned device.

    A foreign resource intentionally returns 404 instead of 403
    to avoid leaking resource existence.
    """

    # ------------------------------------------------------------------------
    # 1. Validate UUID
    # ------------------------------------------------------------------------

    try:
        dev_uuid = uuid.UUID(device_id)

    except (ValueError, AttributeError):

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid UUID format: {device_id}",
        )

    # ------------------------------------------------------------------------
    # 2. Load device
    # ------------------------------------------------------------------------

    stmt = (
        select(Device)
        .where(Device.id == dev_uuid)
        .options(
            selectinload(Device.ports),
            selectinload(Device.findings),
            selectinload(Device.events),
            selectinload(Device.risk_assessments),
        )
    )

    result = await db.execute(stmt)

    device = result.scalar_one_or_none()

    # ------------------------------------------------------------------------
    # 3. Device does not exist
    # ------------------------------------------------------------------------

    if device is None:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Device with ID '{device_id}' "
                "was not found."
            ),
        )

    # ------------------------------------------------------------------------
    # 4. Strict ownership check
    # ------------------------------------------------------------------------

    if current_user is not None:

        # Superuser can access any device.
        if current_user.is_superuser:
            pass

        # Normal authenticated user can access only own device.
        elif device.user_id != current_user.id:

            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"Device with ID '{device_id}' "
                    "was not found."
                ),
            )

    else:

        # Anonymous users can access only unowned devices.
        if device.user_id is not None:

            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"Device with ID '{device_id}' "
                    "was not found."
                ),
            )

    # ------------------------------------------------------------------------
    # 5. Return device
    # ------------------------------------------------------------------------

    return DeviceDetailResponse.model_validate(device)


# ============================================================================
# CREATE / ENROLL DEVICE
# ============================================================================


@router.post(
    "",
    response_model=DeviceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Enroll a new device manually",
)
async def create_device(
    request: DeviceCreate,
    current_user: Optional[User] = Depends(
        get_optional_current_user
    ),
    db: AsyncSession = Depends(get_db),
) -> DeviceResponse:
    """
    Enroll a new device.

    The IP address must belong to an authorized RFC 1918
    private IPv4 range.

    Ownership:

    - Authenticated user -> device belongs to that user.
    - Anonymous -> device remains unowned.
    """

    # ------------------------------------------------------------------------
    # 1. Validate private IP
    # ------------------------------------------------------------------------

    if not is_rfc1918_private_ip(
        request.ip_address
    ):

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"IP address '{request.ip_address}' "
                "is not within authorized RFC 1918 "
                "private range."
            ),
        )

    # ------------------------------------------------------------------------
    # 2. Create device
    # ------------------------------------------------------------------------

    device = Device(
        id=uuid.uuid4(),

        user_id=(
            current_user.id
            if current_user is not None
            else None
        ),

        ip_address=request.ip_address,
        mac_address=request.mac_address,
        hostname=request.hostname or "",
        custom_name=request.custom_name or "",
        vendor=request.vendor or "Unknown Vendor",
        device_type=request.device_type,
        is_trusted=request.is_trusted,
        is_online=True,
    )

    db.add(device)

    await db.commit()

    await db.refresh(device)

    return DeviceResponse.model_validate(device)


# ============================================================================
# DELETE DEVICE
# ============================================================================


@router.delete(
    "/{device_id}",
    status_code=status.HTTP_200_OK,
    summary="Remove a device from inventory",
)
async def delete_device(
    device_id: str,
    current_user: Optional[User] = Depends(
        get_optional_current_user
    ),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Delete a device with strict ownership enforcement.

    Ownership rules:

    - Superuser -> can delete any device.
    - Normal user -> can delete only their own device.
    - Anonymous -> can delete only an unowned device.

    Foreign resources return 404 to prevent resource enumeration.
    """

    # ------------------------------------------------------------------------
    # 1. Validate UUID
    # ------------------------------------------------------------------------

    try:
        dev_uuid = uuid.UUID(device_id)

    except (ValueError, AttributeError):

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid UUID format: {device_id}",
        )

    # ------------------------------------------------------------------------
    # 2. Load device
    # ------------------------------------------------------------------------

    stmt = (
        select(Device)
        .where(Device.id == dev_uuid)
    )

    result = await db.execute(stmt)

    device = result.scalar_one_or_none()

    # ------------------------------------------------------------------------
    # 3. Device not found
    # ------------------------------------------------------------------------

    if device is None:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Device with ID '{device_id}' "
                "was not found."
            ),
        )

    # ------------------------------------------------------------------------
    # 4. Strict ownership check
    # ------------------------------------------------------------------------

    if current_user is not None:

        # Superuser can delete any device.
        if current_user.is_superuser:
            pass

        # Normal user can delete only own device.
        elif device.user_id != current_user.id:

            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"Device with ID '{device_id}' "
                    "was not found."
                ),
            )

    else:

        # Anonymous users can delete only unowned devices.
        if device.user_id is not None:

            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"Device with ID '{device_id}' "
                    "was not found."
                ),
            )

    # ------------------------------------------------------------------------
    # 5. Delete
    # ------------------------------------------------------------------------

    await db.delete(device)

    await db.commit()

    return {
        "message": (
            f"Device {device_id} "
            "successfully deleted."
        )
    }