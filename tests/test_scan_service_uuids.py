from types import SimpleNamespace

import httpx
import pytest

from hubble_gateway import scanner as scanner_mod
from hubble_gateway.auth import GatewayAuth, sanitize_server_config
from hubble_gateway.config import HUBBLE_SERVICE_UUID, TILE_SERVICE_UUID
from hubble_gateway.models import uuid_to_16bit
from hubble_gateway.scanner import Scanner

FCA6 = HUBBLE_SERVICE_UUID
FEED = TILE_SERVICE_UUID
CUSTOM = "12345678-ABCD-1234-ABCD-1234567890AB"
BASE_180F = "0000180F-0000-1000-8000-00805F9B34FB"


def _scan(raw):
    return sanitize_server_config({"scanServiceUuids": raw}).get("scanServiceUuids")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (["FCA6", "FEED"], [FCA6, FEED]),
        (["feed"], [FCA6, FEED]),
        ([], [FCA6]),
        (["180F", FCA6.lower()], [FCA6, BASE_180F]),
        ([BASE_180F.lower(), "180F"], [FCA6, BASE_180F]),
        ([CUSTOM.lower()], [FCA6, CUSTOM]),
        (["FEED", "nope", 7, None, "FCA", "FEED"], [FCA6, FEED]),
    ],
)
def test_scan_list_normalized(raw, expected):
    assert _scan(raw) == expected


def test_scan_list_capped_at_16():
    raw = [f"{i:04X}" for i in range(1, 40)]
    result = _scan(raw)
    assert len(result) == 16
    assert result[0] == FCA6


@pytest.mark.parametrize("raw", [None, "FCA6,FEED", {"a": 1}])
def test_scan_list_wrong_type_ignored(raw):
    assert _scan(raw) is None


def test_uuid_to_16bit():
    assert uuid_to_16bit(FCA6.lower()) == "FCA6"
    assert uuid_to_16bit(CUSTOM.lower()) == CUSTOM


def _auth(config=None):
    return SimpleNamespace(server_config=config or {})


def _adv(uuid: str, data: bytes = b"\x01"):
    device = SimpleNamespace(address="AA:BB:CC:DD:EE:FF", name=None)
    adv = SimpleNamespace(
        service_uuids=[uuid],
        service_data={uuid: data},
        manufacturer_data={},
        rssi=-50,
        tx_power=None,
        local_name=None,
    )
    return device, adv


def test_scanner_local_list_without_server_config():
    s = Scanner(service_uuids=[FCA6, FEED], auth=_auth())
    assert s.service_uuids == [FCA6.lower(), FEED.lower()]


def test_scanner_server_list_replaces_local_and_uploads_custom_uuid():
    packets = []
    s = Scanner(
        service_uuids=[FCA6, FEED],
        on_packet=packets.append,
        auth=_auth({"scanServiceUuids": [FCA6, CUSTOM]}),
    )
    assert s.service_uuids == [FCA6.lower(), CUSTOM.lower()]

    s._detection_callback(*_adv(FEED.lower()))
    assert packets == []

    s._detection_callback(*_adv(CUSTOM.lower()))
    assert packets[0].to_gateway_packet()["serviceUuid"] == CUSTOM

    s._detection_callback(*_adv("fca6"))
    assert packets[1].to_gateway_packet()["serviceUuid"] == "FCA6"


def test_custom_uuid_has_no_16bit_alias():
    s = Scanner(auth=_auth({"scanServiceUuids": [CUSTOM]}))
    assert s._match_service_uuid(["5678"]) is None


async def test_scanner_applies_new_list_next_cycle(monkeypatch):
    auth = _auth()
    calls: list[list[str]] = []
    s = Scanner(service_uuids=[FCA6, FEED], scan_duration=0, auth=auth)

    class FakeBleak:
        def __init__(self, **kwargs):
            calls.append(list(kwargs["service_uuids"]))

        async def __aenter__(self):
            if len(calls) == 1:
                auth.server_config = {"scanServiceUuids": [FCA6, CUSTOM]}
            elif len(calls) == 2:
                auth.server_config = {}
            else:
                s._running = False
            return self

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(scanner_mod, "BleakScanner", FakeBleak)
    await s.start()
    assert calls == [
        [FCA6.lower(), FEED.lower()],
        [FCA6.lower(), CUSTOM.lower()],
        [FCA6.lower(), FEED.lower()],
    ]


async def test_auth_scan_list_absent_keeps_null_clears(tmp_path):
    bodies = {"heartbeat": {}}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/gateways":
            return httpx.Response(201, json={
                "gatewayId": "gw-1", "deviceToken": "dt", "refreshToken": "rt",
                "expiresInSeconds": 3600, "config": {"scanServiceUuids": ["FEED", CUSTOM]},
            })
        return httpx.Response(200, json=bodies["heartbeat"])

    auth = GatewayAuth("k", "https://gw.test", token_path=str(tmp_path / "a.json"))
    auth._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    assert await auth.ensure_authenticated()
    s = Scanner(service_uuids=[FCA6, FEED], auth=auth)
    assert auth.server_config["scanServiceUuids"] == [FCA6, FEED, CUSTOM]

    await auth.heartbeat()
    assert auth.server_config["scanServiceUuids"] == [FCA6, FEED, CUSTOM]

    bodies["heartbeat"] = {"config": None}
    await auth.heartbeat()
    s._refresh_service_uuids()
    assert s.service_uuids == [FCA6.lower(), FEED.lower()]
