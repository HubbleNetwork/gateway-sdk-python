"""BLE scanner using bleak with multi-UUID filtering."""

import asyncio
from collections.abc import Callable
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import structlog
from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from hubble_gateway.config import DEFAULT_SERVICE_UUIDS
from hubble_gateway.models import BLEPacket, is_bluetooth_base_uuid, uuid_to_16bit

if TYPE_CHECKING:
    from hubble_gateway.auth import GatewayAuth

logger = structlog.get_logger(__name__)


class Scanner:
    """Continuous BLE scanner that filters by service UUID(s).

    Supports scanning for multiple UUIDs simultaneously (e.g. Hubble FCA6
    and Tile FEED). Works with both internal BLE adapters and external USB
    dongles — pass ``adapter='hci1'`` to select a specific adapter.

    Pass ``auth`` to let the server's ``scanServiceUuids`` replace
    ``service_uuids``. The list is re-read before each scan cycle, so a new
    server list applies at the next cycle without a restart.
    """

    def __init__(
        self,
        service_uuids: list[str] | None = None,
        scan_duration: float = 5.0,
        on_packet: Callable[[BLEPacket], None] | None = None,
        adapter: str | None = None,
        auth: "GatewayAuth | None" = None,
    ) -> None:
        self._local_service_uuids = list(service_uuids or DEFAULT_SERVICE_UUIDS)
        self._auth = auth
        self._service_uuids: list[str] = []
        self._uuid_variants: dict[str, str] = {}
        self._scan_duration = scan_duration
        self._on_packet = on_packet
        self._adapter = adapter or None
        self._running = False
        self._paused = False
        self._seen_devices: set[str] = set()
        self._devices_this_scan: set[str] = set()
        self._total_packets = 0
        self._refresh_service_uuids()

    @property
    def service_uuids(self) -> list[str]:
        """The UUIDs the current scan cycle filters on (lowercase 128-bit)."""
        return list(self._service_uuids)

    def _effective_service_uuids(self) -> list[str]:
        if self._auth is not None:
            server = self._auth.server_config.get("scanServiceUuids")
            if server:
                return server
        return self._local_service_uuids

    def _refresh_service_uuids(self) -> bool:
        """Adopt the effective UUID list; return True if it changed."""
        uuids = [u.lower() for u in self._effective_service_uuids()]
        if uuids == self._service_uuids:
            return False
        variants: dict[str, str] = {}
        for full_uuid in uuids:
            variants[full_uuid] = full_uuid
            # Only a Bluetooth Base UUID has a 16-bit alias; slicing any other
            # UUID would match an unrelated 16-bit service.
            if is_bluetooth_base_uuid(full_uuid):
                variants[full_uuid[4:8]] = full_uuid
        self._service_uuids = uuids
        self._uuid_variants = variants
        return True

    def _match_service_uuid(self, advertised_uuids: list[str]) -> str | None:
        for adv_uuid in advertised_uuids:
            key = adv_uuid.lower()
            if key in self._uuid_variants:
                return self._uuid_variants[key]
        return None

    def _detection_callback(
        self, device: BLEDevice, advertisement_data: AdvertisementData
    ) -> None:
        adv_uuids = [str(u).lower() for u in advertisement_data.service_uuids or []]
        matched_uuid = self._match_service_uuid(adv_uuids)
        if matched_uuid is None:
            return

        addr = device.address
        if addr not in self._seen_devices:
            self._seen_devices.add(addr)
        self._devices_this_scan.add(addr)
        self._total_packets += 1

        packet = BLEPacket(
            device_address=addr,
            device_name=device.name or advertisement_data.local_name,
            rssi=advertisement_data.rssi,
            service_uuids=adv_uuids,
            manufacturer_data=dict(advertisement_data.manufacturer_data or {}),
            service_data={str(k): v for k, v in (advertisement_data.service_data or {}).items()},
            tx_power=advertisement_data.tx_power,
            timestamp=datetime.now(timezone.utc),
            service_uuid=matched_uuid,
        )

        short = uuid_to_16bit(matched_uuid)
        logger.debug(
            "BLE packet",
            uuid=short,
            addr=addr[-8:],
            rssi=packet.rssi,
            name=packet.device_name,
        )

        if self._on_packet:
            self._on_packet(packet)

    async def start(self) -> None:
        self._running = True
        uuid_labels = [uuid_to_16bit(u) for u in self._service_uuids]
        logger.info(
            "Scanner started",
            service_uuids=uuid_labels,
            scan_duration=self._scan_duration,
            adapter=self._adapter or "default",
        )

        while self._running:
            if self._paused:
                await asyncio.sleep(0.5)
                continue
            if self._refresh_service_uuids():
                logger.info(
                    "Scan UUIDs changed",
                    service_uuids=[uuid_to_16bit(u) for u in self._service_uuids],
                )
            scanner_kwargs: dict = {
                "detection_callback": self._detection_callback,
                "service_uuids": self._service_uuids,
            }
            if self._adapter:
                scanner_kwargs["adapter"] = self._adapter
            try:
                self._devices_this_scan.clear()
                async with BleakScanner(**scanner_kwargs) as _scanner:
                    await asyncio.sleep(self._scan_duration)
                logger.debug(
                    "Scan cycle",
                    devices=len(self._devices_this_scan),
                    total_unique=len(self._seen_devices),
                    total_packets=self._total_packets,
                )
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Scanner error", error=str(e))
                await asyncio.sleep(2.0)

        logger.info("Scanner stopped", total_devices=len(self._seen_devices))

    async def stop(self) -> None:
        self._running = False

    def pause(self) -> None:
        self._paused = True

    def resume(self) -> None:
        self._paused = False

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def stats(self) -> dict[str, int]:
        return {
            "total_packets": self._total_packets,
            "unique_devices": len(self._seen_devices),
            "active_devices": len(self._devices_this_scan),
        }
