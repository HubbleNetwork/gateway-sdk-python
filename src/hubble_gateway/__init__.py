"""Hubble Network BLE Gateway SDK.

Import the components you need to build a gateway:

    from hubble_gateway import Scanner, GatewaySender, GatewayAuth, Location, BLEPacket
"""

__version__ = "0.2.0"

from hubble_gateway.auth import GatewayAuth
from hubble_gateway.config import (
    DEFAULT_SERVICE_UUIDS,
    GATEWAY_API_BASE_URL,
    HUBBLE_SERVICE_UUID,
    TILE_SERVICE_UUID,
    Settings,
)
from hubble_gateway.location import (
    FixedLocationProvider,
    GPSDLocationProvider,
    LocationProvider,
    SerialGPSLocationProvider,
    UBXLocationProvider,
    create_location_provider,
)
from hubble_gateway.models import BLEPacket, Location
from hubble_gateway.scanner import Scanner
from hubble_gateway.sender import GatewaySender

__all__ = [
    "BLEPacket",
    "DEFAULT_SERVICE_UUIDS",
    "FixedLocationProvider",
    "GATEWAY_API_BASE_URL",
    "GPSDLocationProvider",
    "GatewayAuth",
    "GatewaySender",
    "HUBBLE_SERVICE_UUID",
    "Location",
    "LocationProvider",
    "Scanner",
    "SerialGPSLocationProvider",
    "Settings",
    "TILE_SERVICE_UUID",
    "UBXLocationProvider",
    "create_location_provider",
]
