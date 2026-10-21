import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from hubble_gateway.auth import GatewayAuth, sanitize_server_config
from hubble_gateway.config import Settings
from hubble_gateway.models import BLEPacket
from hubble_gateway.sender import GatewaySender

NORMAL = {"uploadIntervalMs": 300_000, "uploadBatchSize": 500, "dedupWindowMs": 300_000}


def _register_body(config):
    return {
        "gatewayId": "gw-1",
        "deviceToken": "dt",
        "refreshToken": "rt",
        "expiresInSeconds": 3600,
        "config": config,
    }


class FakeServer:
    """Stands in for gateway-api; tests set the body each endpoint returns."""

    def __init__(self) -> None:
        self.register_config: object = None
        self.heartbeat_body: dict = {}
        self.refresh_body: dict = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "PUT" and path == "/api/v1/gateways":
            body = json.loads(request.content)
            assert body["platform"]["sdk"] == "hubble-gateway-python"
            return httpx.Response(201, json=_register_body(self.register_config))
        if request.method == "PUT" and path == "/api/v1/gateways/gw-1":
            return httpx.Response(200, json=self.heartbeat_body)
        if request.method == "POST" and path == "/api/v1/auth/refresh":
            return httpx.Response(200, json=self.refresh_body)
        return httpx.Response(404)


@pytest.fixture
def server():
    return FakeServer()


@pytest.fixture
def auth(tmp_path, server):
    a = GatewayAuth("sdk-key", "https://gw.test", token_path=str(tmp_path / "auth.json"))
    a._client = httpx.AsyncClient(transport=httpx.MockTransport(server.handler))
    return a


def _packet(addr: str, ts: datetime) -> BLEPacket:
    return BLEPacket(
        device_address=addr,
        rssi=-60,
        service_data={"0000fca6-0000-1000-8000-00805f9b34fb": b"\x01"},
        service_uuid="0000fca6-0000-1000-8000-00805f9b34fb",
        timestamp=ts,
    )


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (NORMAL, NORMAL),
        ({"uploadIntervalMs": 1_000}, {"uploadIntervalMs": 60_000}),
        ({"uploadIntervalMs": 99_000_000}, {"uploadIntervalMs": 3_600_000}),
        ({"uploadBatchSize": 0}, {"uploadBatchSize": 1}),
        ({"uploadBatchSize": 10_000}, {"uploadBatchSize": 500}),
        ({"dedupWindowMs": 1}, {"dedupWindowMs": 5_000}),
        ({"dedupWindowMs": 99_000_000}, {"dedupWindowMs": 3_600_000}),
        ({"uploadIntervalMs": 120_000.0}, {"uploadIntervalMs": 120_000}),
    ],
)
def test_sanitize_clamps(raw, expected):
    assert sanitize_server_config(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        {"uploadIntervalMs": None},
        {"uploadIntervalMs": "300000"},
        {"uploadBatchSize": True},
        {"dedupWindowMs": float("nan")},
        {"dedupWindowMs": [5_000]},
    ],
)
def test_sanitize_ignores_bad_types(raw):
    assert sanitize_server_config(raw) == {}


@pytest.mark.parametrize("raw", [None, "eco", [], 42])
def test_sanitize_non_object(raw):
    assert sanitize_server_config(raw) == {}


def test_sanitize_drops_unused_keys():
    raw = {
        **NORMAL,
        "scanIntervalMs": 10_000,
        "featureFlags": {"x": True},
        "activeUploadIntervalMs": 60_000,
        "activeDedupWindowMs": 60_000,
        "uploadOnCellular": False,
    }
    assert sanitize_server_config(raw) == NORMAL


async def test_heartbeat_replaces_not_merges(auth, server):
    server.register_config = NORMAL
    assert await auth.ensure_authenticated()
    assert auth.server_config == NORMAL

    server.heartbeat_body = {"config": {"uploadIntervalMs": 900_000}}
    await auth.heartbeat()
    assert auth.server_config == {"uploadIntervalMs": 900_000}


async def test_null_config_clears(auth, server):
    server.register_config = NORMAL
    assert await auth.ensure_authenticated()

    server.heartbeat_body = {"config": None}
    await auth.heartbeat()
    assert auth.server_config == {}


async def test_missing_config_key_keeps_config(auth, server):
    server.register_config = NORMAL
    assert await auth.ensure_authenticated()

    server.heartbeat_body = {}
    await auth.heartbeat()
    assert auth.server_config == NORMAL


async def test_refresh_applies_config(auth, server):
    server.register_config = NORMAL
    assert await auth.ensure_authenticated()

    server.refresh_body = {
        "deviceToken": "dt2",
        "expiresInSeconds": 3600,
        "config": {"uploadIntervalMs": 60_000, "dedupWindowMs": 60_000},
    }
    assert await auth._refresh()
    assert auth.server_config == {"uploadIntervalMs": 60_000, "dedupWindowMs": 60_000}


async def test_heartbeat_persists_config(auth, server, tmp_path):
    server.register_config = NORMAL
    assert await auth.ensure_authenticated()
    server.heartbeat_body = {"config": None}
    await auth.heartbeat()

    reloaded = GatewayAuth("sdk-key", "https://gw.test", token_path=str(tmp_path / "auth.json"))
    assert reloaded.server_config == {}


def test_persisted_stale_keys_dropped(tmp_path):
    path = tmp_path / "auth.json"
    path.write_text(
        json.dumps(
            {
                "gatewayId": "gw-1",
                "serverConfig": {
                    "uploadIntervalMs": 1_000,
                    "scanIntervalMs": 5,
                    "featureFlags": {},
                },
            }
        )
    )
    a = GatewayAuth("sdk-key", "https://gw.test", token_path=str(path))
    assert a.server_config == {"uploadIntervalMs": 60_000}


async def test_sender_reapplies_after_heartbeat(auth, server):
    sender = GatewaySender(auth, batch_size=200, upload_interval_s=5.0, dedup_window_s=30.0)
    assert (sender.batch_size, sender.upload_interval_s, sender.dedup_window_s) == (200, 5.0, 30.0)

    server.register_config = NORMAL
    assert await auth.ensure_authenticated()
    assert (sender.batch_size, sender.upload_interval_s, sender.dedup_window_s) == (500, 300, 300)

    server.heartbeat_body = {"config": {"uploadIntervalMs": 900_000, "dedupWindowMs": 600_000}}
    await auth.heartbeat()
    assert (sender.batch_size, sender.upload_interval_s, sender.dedup_window_s) == (200, 900, 600)

    server.heartbeat_body = {"config": None}
    await auth.heartbeat()
    assert (sender.batch_size, sender.upload_interval_s, sender.dedup_window_s) == (200, 5.0, 30.0)


async def test_sender_applies_dedup_window(auth, server):
    server.register_config = {"dedupWindowMs": 60_000}
    assert await auth.ensure_authenticated()
    sender = GatewaySender(auth, dedup_window_s=1.0)

    t0 = datetime.now(timezone.utc)
    sender.add_packet(_packet("AA", t0))
    sender.add_packet(_packet("AA", t0 + timedelta(seconds=30)))
    assert sender.stats["buffer_size"] == 1
    assert sender._pending[0].sighting_count == 2

    sender.add_packet(_packet("AA", t0 + timedelta(seconds=61)))
    assert sender.stats["buffer_size"] == 2


def _capture_uploads(auth, server) -> list[list[str]]:
    uploads: list[list[str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/packets"):
            packets = json.loads(request.content)["packets"]
            uploads.append([p["deviceAddress"] for p in packets])
            return httpx.Response(202)
        return server.handler(request)

    auth._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return uploads


async def test_duplicate_dropped_across_flush(auth, server):
    server.register_config = {"dedupWindowMs": 60_000}
    assert await auth.ensure_authenticated()
    uploads = _capture_uploads(auth, server)
    sender = GatewaySender(auth)

    t0 = datetime.now(timezone.utc)
    sender.add_packet(_packet("AA", t0))
    await sender._flush()
    assert uploads == [["AA"]]

    sender.add_packet(_packet("AA", t0 + timedelta(seconds=30)))
    assert sender.stats["buffer_size"] == 0
    assert sender.stats["dropped_duplicates"] == 1
    await sender._flush()
    assert uploads == [["AA"]]

    sender.add_packet(_packet("AA", t0 + timedelta(seconds=61)))
    await sender._flush()
    assert uploads == [["AA"], ["AA"]]


async def test_dedup_keys_expire_by_age(auth):
    sender = GatewaySender(auth, dedup_window_s=10.0)
    t0 = datetime.now(timezone.utc)
    for addr in ("A1", "A2", "A3"):
        sender.add_packet(_packet(addr, t0))
    assert sender.stats["dedup_keys"] == 3

    sender.add_packet(_packet("B1", t0 + timedelta(seconds=11)))
    assert sender.stats["dedup_keys"] == 1


async def test_dedup_keys_capped(auth, monkeypatch):
    monkeypatch.setattr("hubble_gateway.sender.MAX_DEDUP_KEYS", 3)
    sender = GatewaySender(auth, dedup_window_s=600.0)
    t0 = datetime.now(timezone.utc)
    for addr in ("A1", "A2", "A3", "A4", "A5"):
        sender.add_packet(_packet(addr, t0))
    assert sender.stats["dedup_keys"] == 3
    assert list(sender._window_start_ms) == [
        ("A3", "FCA6", "01"),
        ("A4", "FCA6", "01"),
        ("A5", "FCA6", "01"),
    ]


def test_default_upload_interval_is_60s(auth, monkeypatch):
    monkeypatch.delenv("HUBBLE_UPLOAD_INTERVAL_SECONDS", raising=False)
    assert Settings(_env_file=None).upload_interval_seconds == 60.0
    assert GatewaySender(auth).upload_interval_s == 60.0


async def test_sender_flush_uses_server_batch_size(auth, server):
    server.register_config = {"uploadBatchSize": 2}
    assert await auth.ensure_authenticated()

    batches: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/packets"):
            batches.append(len(json.loads(request.content)["packets"]))
            return httpx.Response(202)
        return server.handler(request)

    auth._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    sender = GatewaySender(auth, batch_size=500)
    t0 = datetime.now(timezone.utc)
    for addr in ("A1", "A2", "A3", "A4", "A5"):
        sender.add_packet(_packet(addr, t0))
    await sender._flush()
    assert batches == [2, 2, 1]
