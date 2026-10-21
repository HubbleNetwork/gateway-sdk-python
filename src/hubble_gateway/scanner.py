"""BLE scanner using bleak with multi-UUID filtering."""

import asyncio
from collections.abc import Callable
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import structlog
from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from hubble_gateway.config import HUBBLE_SERVICE_UUID
from hubble_gateway.models import BLEPacket, normalize_service_uuid, uuid_to_16bit

if TYPE_CHECKING:
    from hubble_gateway.auth import GatewayAuth

logger = structlog.get_logger(__name__)


def _normalize_all(uuids: list[str]) -> list[str]:
    """Lowercase 128-bit forms of the valid UUIDs, in order."""
    result = []
    for u in uuids:
        full = normalize_service_uuid(u) if isinstance(u, str) else None
        if full is not None:
            result.append(full.lower())
    return result


def _dedupe(uuids: list[str]) -> list[str]:
    return list(dict.fromkeys(uuids))


class Scanner:
    """Continuous BLE scanner that filters by service UUID(s).

    Service classes:

    - Hubble ``FCA6``: always scanned; service data is a payload.
    - Payload services: the ``payloadServiceUuids`` list in
      ``auth.server_config`` (0 to 8, ordered); service data is a payload.
    - ``service_uuids``: scan-only; matching advertisements reach
      ``on_advertisement`` but are not payloads.

    One advertisement gives at most one payload, passed to ``on_packet``: the
    first UUID with non-empty service data, in priority order ``FCA6`` then
    the payload list. An advertisement with service data for more than one
    payload UUID is counted in ``stats["multi_payload_advertisements"]``.

    Works with both internal BLE adapters and external USB dongles — pass
    ``adapter='hci1'`` to select a specific adapter.
    """

    def __init__(
        self,
        service_uuids: list[str] | None = None,
        scan_duration: float = 5.0,
        on_packet: Callable[[BLEPacket], None] | None = None,
        adapter: str | None = None,
        auth: "GatewayAuth | None" = None,
        on_advertisement: Callable[[BLEPacket], None] | None = None,
    ) -> None:
        self._scan_only_uuids = _normalize_all(service_uuids or [])
        self._auth = auth
        self._payload_uuids: list[str] = []
        self._service_uuids: list[str] = []
        self._scan_duration = scan_duration
        self._on_packet = on_packet
        self._on_advertisement = on_advertisement
        self._adapter = adapter or None
        self._running = False
        self._paused = False
        self._seen_devices: set[str] = set()
        self._devices_this_scan: set[str] = set()
        self._total_packets = 0
        self._multi_payload_advertisements = 0
        self._refresh_service_uuids()

    @property
    def service_uuids(self) -> list[str]:
        """The UUIDs the current scan cycle filters on (lowercase 128-bit)."""
        return list(self._service_uuids)

    @property
    def payload_service_uuids(self) -> list[str]:
        """Payload UUIDs in priority order, ``FCA6`` first (lowercase 128-bit)."""
        return list(self._payload_uuids)

    def _effective_payload_uuids(self) -> list[str]:
        configured: list[str] = []
        if self._auth is not None:
            value = self._auth.server_config.get("payloadServiceUuids")
            if isinstance(value, list):
                configured = value
        return _dedupe([HUBBLE_SERVICE_UUID.lower(), *_normalize_all(configured)])

    def _refresh_service_uuids(self) -> bool:
        """Adopt the effective UUID lists; return True if they changed."""
        payload = self._effective_payload_uuids()
        scan = _dedupe([*payload, *self._scan_only_uuids])
        if payload == self._payload_uuids and scan == self._service_uuids:
            return False
        self._payload_uuids = payload
        self._service_uuids = scan
        return True

    def _detection_callback(self, device: BLEDevice, advertisement_data: AdvertisementData) -> None:
        adv_uuids = [str(u).lower() for u in advertisement_data.service_uuids or []]
        raw_service_data = advertisement_data.service_data or {}
        service_data: dict[str, bytes] = {}
        for k, v in raw_service_data.items():
            u = normalize_service_uuid(str(k))
            if u is not None:
                service_data[u.lower()] = v

        with_payload = [u for u in self._payload_uuids if service_data.get(u)]
        if len(with_payload) > 1:
            self._multi_payload_advertisements += 1
        payload_uuid = with_payload[0] if with_payload else None

        matched_uuid = payload_uuid
        if matched_uuid is None:
            present = set(_normalize_all(adv_uuids)) | set(service_data)
            matched_uuid = next((u for u in self._service_uuids if u in present), None)
        if matched_uuid is None:
            return

        addr = device.address
        self._seen_devices.add(addr)
        self._devices_this_scan.add(addr)

        packet = BLEPacket(
            device_address=addr,
            device_name=device.name or advertisement_data.local_name,
            rssi=advertisement_data.rssi,
            service_uuids=adv_uuids,
            manufacturer_data=dict(advertisement_data.manufacturer_data or {}),
            service_data={str(k): v for k, v in raw_service_data.items()},
            tx_power=advertisement_data.tx_power,
            timestamp=datetime.now(timezone.utc),
            service_uuid=matched_uuid,
        )

        if self._on_advertisement:
            self._on_advertisement(packet)

        if payload_uuid is None:
            return

        self._total_packets += 1
        logger.debug(
            "BLE packet",
            uuid=uuid_to_16bit(payload_uuid),
            addr=addr[-8:],
            rssi=packet.rssi,
            name=packet.device_name,
        )

        if self._on_packet:
            self._on_packet(packet)

    async def start(self) -> None:
        self._running = True
        logger.info(
            "Scanner started",
            payload_service_uuids=[uuid_to_16bit(u) for u in self._payload_uuids],
            service_uuids=[uuid_to_16bit(u) for u in self._service_uuids],
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
                    payload_service_uuids=[uuid_to_16bit(u) for u in self._payload_uuids],
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
            "multi_payload_advertisements": self._multi_payload_advertisements,
        }
