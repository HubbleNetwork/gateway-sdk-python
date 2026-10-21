"""Packet sender: batches, deduplicates, and uploads BLE sightings."""

import asyncio
import time
import uuid as uuid_mod
from collections.abc import Awaitable, Callable
from typing import Any

import structlog

from hubble_gateway.auth import GatewayAuth
from hubble_gateway.models import BLEPacket, Location

logger = structlog.get_logger(__name__)

_DedupKey = tuple[str, str | None, str]

# Hard cap on remembered dedup keys. Age-based expiry normally keeps the map
# far smaller; the cap only bounds memory if a flood of distinct keys arrives
# inside one window.
MAX_DEDUP_KEYS = 100_000


class _DedupEntry:
    __slots__ = ("packet", "strongest_rssi", "sighting_count")

    def __init__(self, packet: BLEPacket) -> None:
        self.packet = packet
        self.strongest_rssi = packet.rssi
        self.sighting_count = 1

    def merge(self, packet: BLEPacket) -> None:
        self.sighting_count += 1
        if packet.rssi > self.strongest_rssi:
            self.strongest_rssi = packet.rssi
            self.packet = packet


class GatewaySender:
    """Batches and uploads BLE sightings to the gateway API."""

    def __init__(
        self,
        auth: GatewayAuth,
        get_location: Callable[[], Awaitable[Location]] | None = None,
        batch_size: int = 500,
        upload_interval_s: float = 60.0,
        dedup_window_s: float = 300.0,
    ) -> None:
        self._auth = auth
        self._get_location = get_location
        self._local_batch_size = batch_size
        self._local_upload_interval_s = upload_interval_s
        self._local_dedup_window_s = dedup_window_s
        # Sightings waiting for the next upload.
        self._pending: list[_DedupEntry] = []
        # Pending entry per key for the window it opened, so in-window repeats
        # before the upload add to its sighting count.
        self._open: dict[_DedupKey, _DedupEntry] = {}
        # When each key last opened a window. Survives uploads; kept in
        # ascending time order so expiry and the cap pop from the front.
        self._window_start_ms: dict[_DedupKey, int] = {}
        self._dedup_lock = asyncio.Lock()
        self._running = False
        self._stats_sends = 0
        self._stats_total = 0
        self._stats_uploaded = 0
        self._stats_dropped = 0
        self._stats_devices: set[str] = set()

    async def start(self) -> None:
        self._running = True
        asyncio.create_task(self._upload_loop())
        if self._get_location:
            asyncio.create_task(self._location_loop())
        logger.info(
            "Sender started",
            gateway_id=self._auth.gateway_id,
            upload_interval=self.upload_interval_s,
            dedup_window=self.dedup_window_s,
            batch_size=self.batch_size,
        )

    async def stop(self) -> None:
        self._running = False
        await self._flush()
        logger.info(
            "Sender stopped",
            total_packets=self._stats_total,
            uploaded=self._stats_uploaded,
            sends=self._stats_sends,
            unique_devices=len(self._stats_devices),
        )

    def add_packet(self, packet: BLEPacket) -> None:
        self._stats_total += 1
        self._stats_devices.add(packet.device_address)
        key: _DedupKey = (
            packet.device_address,
            packet.service_uuid_16bit,
            packet.service_data_hex,
        )
        now_ms = int(packet.timestamp.timestamp() * 1000)
        window_ms = self.dedup_window_s * 1000
        self._expire_dedup_keys(now_ms, window_ms)

        # The window is anchored at the sighting that opened it, not slid by
        # repeats: a device that beacons nonstop is still reported once per
        # window instead of never again.
        start_ms = self._window_start_ms.get(key)
        if start_ms is not None and now_ms - start_ms < window_ms:
            entry = self._open.get(key)
            if entry is not None:
                entry.merge(packet)
            else:
                self._stats_dropped += 1
            return

        self._window_start_ms.pop(key, None)
        self._window_start_ms[key] = now_ms
        entry = _DedupEntry(packet)
        self._pending.append(entry)
        self._open[key] = entry

    def _expire_dedup_keys(self, now_ms: int, window_ms: float) -> None:
        starts = self._window_start_ms
        while starts:
            key = next(iter(starts))
            if now_ms - starts[key] < window_ms and len(starts) < MAX_DEDUP_KEYS:
                break
            del starts[key]

    # Read the auth's server config on every use rather than caching it, so a
    # new config from any registration, heartbeat or token refresh applies at
    # once, and a cleared config falls back to the local values.
    @property
    def batch_size(self) -> int:
        return self._auth.server_config.get("uploadBatchSize", self._local_batch_size)

    @property
    def upload_interval_s(self) -> float:
        ms = self._auth.server_config.get("uploadIntervalMs")
        return self._local_upload_interval_s if ms is None else ms / 1000

    @property
    def dedup_window_s(self) -> float:
        ms = self._auth.server_config.get("dedupWindowMs")
        return self._local_dedup_window_s if ms is None else ms / 1000

    @property
    def stats(self) -> dict[str, int]:
        return {
            "total_packets": self._stats_total,
            "uploaded_packets": self._stats_uploaded,
            "sends": self._stats_sends,
            "unique_devices": len(self._stats_devices),
            "dropped_duplicates": self._stats_dropped,
            "buffer_size": len(self._pending),
            "dedup_keys": len(self._window_start_ms),
        }

    async def _upload_loop(self) -> None:
        while self._running:
            await asyncio.sleep(self.upload_interval_s)
            if not self._pending:
                continue
            await self._flush()

    async def _location_loop(self) -> None:
        _INTERVAL = 60.0
        while self._running:
            await asyncio.sleep(_INTERVAL)
            if not self._get_location:
                continue
            try:
                location = await self._get_location()
                if location.latitude is not None and location.longitude is not None:
                    await self._upload_location(location)
            except Exception as e:
                logger.warning("Location upload error", error=str(e))

    async def _flush(self) -> None:
        async with self._dedup_lock:
            if not self._pending:
                return
            entries = self._pending
            self._pending = []
            self._open.clear()

        location = Location()
        if self._get_location:
            try:
                location = await self._get_location()
            except Exception as e:
                logger.warning("Failed to get location", error=str(e))

        batch_size = self.batch_size
        for i in range(0, len(entries), batch_size):
            batch = entries[i : i + batch_size]
            await self._upload_batch(batch, location)

    async def _upload_batch(self, entries: list[_DedupEntry], location: Location) -> None:
        gateway_id = self._auth.gateway_id
        if not gateway_id:
            return

        batch_id = str(uuid_mod.uuid4())
        packets_json = []
        for entry in entries:
            pkt = entry.packet.to_gateway_packet(
                location=location,
                sighting_count=entry.sighting_count,
            )
            pkt["rssi"] = entry.strongest_rssi
            packets_json.append(pkt)

        body: dict[str, Any] = {
            "batchId": batch_id,
            "sentAtMillis": int(time.time() * 1000),
            "packets": packets_json,
        }

        try:
            resp = await self._auth.authenticated_request(
                "POST",
                f"/api/v1/gateways/{gateway_id}/packets",
                json_body=body,
            )
            if resp.status_code in (200, 201, 202):
                self._stats_sends += 1
                self._stats_uploaded += len(entries)
                sightings = sum(e.sighting_count for e in entries)
                logger.info(
                    "Batch uploaded",
                    batch_id=batch_id[:8],
                    packets=len(entries),
                    sightings=sightings,
                )
            else:
                logger.warning("Upload failed", status=resp.status_code, body=resp.text[:200])
        except Exception as e:
            logger.error("Upload error", error=str(e))

    async def _upload_location(self, location: Location) -> None:
        gateway_id = self._auth.gateway_id
        if not gateway_id:
            return
        body: dict[str, Any] = {
            "batchId": str(uuid_mod.uuid4()),
            "sentAtMillis": int(time.time() * 1000),
            "locations": [location.to_gateway_dict()],
        }
        try:
            await self._auth.authenticated_request(
                "POST",
                f"/api/v1/gateways/{gateway_id}/locations",
                json_body=body,
            )
        except Exception as e:
            logger.warning("Location upload failed", error=str(e))
