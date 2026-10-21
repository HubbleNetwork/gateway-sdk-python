import json
from types import SimpleNamespace

import httpx
import pytest

from hubble_gateway import scanner as scanner_mod
from hubble_gateway.auth import GatewayAuth, sanitize_server_config
from hubble_gateway.config import HUBBLE_SERVICE_UUID, TILE_SERVICE_UUID, Settings
from hubble_gateway.models import uuid_to_16bit
from hubble_gateway.scanner import Scanner

FCA6 = HUBBLE_SERVICE_UUID.lower()
FEED = TILE_SERVICE_UUID.lower()
CUSTOM = "12345678-ABCD-1234-ABCD-1234567890AB"
BASE_180F = "0000180f-0000-1000-8000-00805f9b34fb"
BASE_181A = "0000181a-0000-1000-8000-00805f9b34fb"


def _payload(raw):
    return sanitize_server_config({"payloadServiceUuids": raw}).get("payloadServiceUuids")


# --- config parsing / validation / clamping ---------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (["FEED"], ["FEED"]),
        (["feed", "180f"], ["FEED", "180F"]),
        ([], []),
        (["FCA6"], []),
        (["FCA6", "FEED", HUBBLE_SERVICE_UUID.lower()], ["FEED"]),
        ([BASE_180F, "180F", "feed"], ["180F", "FEED"]),
        ([BASE_180F.upper()], ["180F"]),
        ([CUSTOM, CUSTOM.lower()], []),
        (["00010000-0000-1000-8000-00805F9B34FB"], []),
        (["FEED", "nope", 7, None, "FCA", "FEEDD", "", "FEED"], ["FEED"]),
        ([" feed "], ["FEED"]),
    ],
)
def test_payload_list_normalized(raw, expected):
    assert _payload(raw) == expected


def test_payload_list_order_kept():
    assert _payload(["181A", "FEED", "180F"]) == ["181A", "FEED", "180F"]


def test_payload_list_capped_at_8_after_filtering():
    raw = ["FCA6", "nope"] + [f"{i:04X}" for i in range(1, 20)]
    assert _payload(raw) == [f"{i:04X}" for i in range(1, 9)]


@pytest.mark.parametrize("raw", [None, "FCA6,FEED", {"a": 1}, 5])
def test_payload_list_wrong_type_dropped(raw):
    assert "payloadServiceUuids" not in sanitize_server_config({"payloadServiceUuids": raw})


def test_legacy_scan_service_uuids_ignored():
    cfg = sanitize_server_config({"scanServiceUuids": ["FCA6", "FEED"], "uploadBatchSize": 10})
    assert cfg == {"uploadBatchSize": 10}


def test_legacy_key_alongside_new_key():
    cfg = sanitize_server_config(
        {"scanServiceUuids": ["FCA6", "180F"], "payloadServiceUuids": ["FEED"]}
    )
    assert cfg == {"payloadServiceUuids": ["FEED"]}


def test_uuid_to_16bit():
    assert uuid_to_16bit(FCA6) == "FCA6"
    assert uuid_to_16bit(CUSTOM.lower()) == CUSTOM


def test_settings_default_has_no_scan_only_uuids():
    assert Settings(_env_file=None).service_uuids == []


# --- scanner: one payload sighting per advertisement ------------------------


def _auth(config=None):
    return SimpleNamespace(server_config=config if config is not None else {})


def _adv(service_data: dict, service_uuids: list | None = None):
    device = SimpleNamespace(address="AA:BB:CC:DD:EE:FF", name=None)
    adv = SimpleNamespace(
        service_uuids=list(service_data) if service_uuids is None else service_uuids,
        service_data=service_data,
        manufacturer_data={},
        rssi=-50,
        tx_power=None,
        local_name=None,
    )
    return device, adv


def _scanner(payload=None, scan_only=None):
    packets, adverts = [], []
    cfg = {} if payload is None else {"payloadServiceUuids": payload}
    s = Scanner(
        service_uuids=scan_only,
        on_packet=packets.append,
        on_advertisement=adverts.append,
        auth=_auth(cfg),
    )
    return s, packets, adverts


def test_fca6_always_scanned_without_config():
    s, _, _ = _scanner()
    assert s.payload_service_uuids == [FCA6]
    assert s.service_uuids == [FCA6]
    assert Scanner().service_uuids == [FCA6]


def test_filter_is_fca6_then_payload_then_scan_only_deduped():
    s, _, _ = _scanner(payload=["FEED", "180F"], scan_only=["180F", CUSTOM, "fca6"])
    assert s.payload_service_uuids == [FCA6, FEED, BASE_180F]
    assert s.service_uuids == [FCA6, FEED, BASE_180F, CUSTOM.lower()]


def test_fca6_only_advert_emits_one():
    s, packets, _ = _scanner(payload=["FEED"])
    s._detection_callback(*_adv({FCA6: b"\x01"}))
    assert [p.to_gateway_packet()["serviceUuid"] for p in packets] == ["FCA6"]
    assert s.stats["multi_payload_advertisements"] == 0


def test_payload_uuid_emits():
    s, packets, _ = _scanner(payload=["FEED"])
    s._detection_callback(*_adv({FEED: b"\x02"}))
    gp = packets[0].to_gateway_packet()
    assert gp["serviceUuid"] == "FEED"
    assert gp["serviceData"] == "Ag=="


def test_two_payloads_in_one_advert_fca6_wins_and_is_counted():
    s, packets, _ = _scanner(payload=["FEED"])
    s._detection_callback(*_adv({FEED: b"\x02", FCA6: b"\x01"}))
    assert len(packets) == 1
    assert packets[0].to_gateway_packet()["serviceUuid"] == "FCA6"
    assert packets[0].to_gateway_packet()["serviceData"] == "AQ=="
    assert s.stats["multi_payload_advertisements"] == 1


def test_two_payloads_list_order_wins():
    s, packets, _ = _scanner(payload=["180F", "FEED"])
    s._detection_callback(*_adv({FEED: b"\x02", BASE_180F: b"\x03"}))
    assert [p.to_gateway_packet()["serviceUuid"] for p in packets] == ["180F"]
    assert s.stats["multi_payload_advertisements"] == 1
    assert s.stats["total_packets"] == 1


def test_empty_service_data_skipped_in_priority():
    s, packets, _ = _scanner(payload=["FEED"])
    s._detection_callback(*_adv({FCA6: b"", FEED: b"\x02"}))
    assert [p.to_gateway_packet()["serviceUuid"] for p in packets] == ["FEED"]
    assert s.stats["multi_payload_advertisements"] == 0


def test_listed_uuid_without_service_data_is_not_a_payload():
    s, packets, adverts = _scanner(payload=["FEED"])
    s._detection_callback(*_adv({}, service_uuids=[FEED]))
    assert packets == []
    assert len(adverts) == 1


def test_payload_not_in_list_is_dropped():
    s, packets, adverts = _scanner(payload=["FEED"])
    s._detection_callback(*_adv({BASE_180F: b"\x03"}))
    assert packets == [] and adverts == []


def test_service_data_only_advert_matches():
    s, packets, _ = _scanner(payload=["FEED"])
    s._detection_callback(*_adv({FEED: b"\x02"}, service_uuids=[]))
    assert [p.to_gateway_packet()["serviceUuid"] for p in packets] == ["FEED"]


def test_scan_only_reaches_listener_not_upload():
    s, packets, adverts = _scanner(payload=["FEED"], scan_only=["180F"])
    s._detection_callback(*_adv({BASE_180F: b"\x03"}))
    assert packets == []
    assert [a.service_uuid for a in adverts] == [BASE_180F]
    assert s.stats["total_packets"] == 0


def test_scan_only_overlapping_payload_list_is_uploaded():
    s, packets, adverts = _scanner(payload=["180F"], scan_only=["180F"])
    s._detection_callback(*_adv({BASE_180F: b"\x03"}))
    assert [p.to_gateway_packet()["serviceUuid"] for p in packets] == ["180F"]
    assert len(adverts) == 1


def test_empty_list_means_fca6_only():
    s, packets, _ = _scanner(payload=[])
    s._detection_callback(*_adv({FEED: b"\x02"}))
    s._detection_callback(*_adv({FCA6: b"\x01"}))
    assert [p.to_gateway_packet()["serviceUuid"] for p in packets] == ["FCA6"]


def test_legacy_scan_list_in_scanner_config_is_ignored():
    s = Scanner(auth=_auth({"scanServiceUuids": [FCA6, FEED]}))
    assert s.service_uuids == [FCA6]


# --- config arrival ---------------------------------------------------------


async def test_scanner_applies_new_list_next_cycle(monkeypatch):
    auth = _auth()
    calls: list[list[str]] = []
    s = Scanner(scan_duration=0, auth=auth)

    class FakeBleak:
        def __init__(self, **kwargs):
            calls.append(list(kwargs["service_uuids"]))

        async def __aenter__(self):
            if len(calls) == 1:
                auth.server_config = {"payloadServiceUuids": ["FEED", "180F"]}
            elif len(calls) == 2:
                auth.server_config = {}
            else:
                s._running = False
            return self

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(scanner_mod, "BleakScanner", FakeBleak)
    await s.start()
    assert calls == [[FCA6], [FCA6, FEED, BASE_180F], [FCA6]]


async def test_auth_three_case_rule(tmp_path):
    bodies = {"heartbeat": {}}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/gateways":
            return httpx.Response(
                201,
                json={
                    "gatewayId": "gw-1",
                    "deviceToken": "dt",
                    "refreshToken": "rt",
                    "expiresInSeconds": 3600,
                    "config": {"payloadServiceUuids": ["FEED", "180F"]},
                },
            )
        return httpx.Response(200, json=bodies["heartbeat"])

    token_path = tmp_path / "a.json"
    auth = GatewayAuth("k", "https://gw.test", token_path=str(token_path))
    auth._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    assert await auth.ensure_authenticated()
    s = Scanner(auth=auth)
    assert s.payload_service_uuids == [FCA6, FEED, BASE_180F]
    assert json.loads(token_path.read_text())["serverConfig"]["payloadServiceUuids"] == [
        "FEED",
        "180F",
    ]

    # No "config" key: keep the current list.
    await auth.heartbeat()
    assert auth.server_config["payloadServiceUuids"] == ["FEED", "180F"]

    # Object without the field: FCA6 only.
    bodies["heartbeat"] = {"config": {"uploadBatchSize": 10}}
    await auth.heartbeat()
    s._refresh_service_uuids()
    assert s.payload_service_uuids == [FCA6]

    # Object with the field again, then config: null clears it.
    bodies["heartbeat"] = {"config": {"payloadServiceUuids": [BASE_181A.upper()]}}
    await auth.heartbeat()
    s._refresh_service_uuids()
    assert s.payload_service_uuids == [FCA6, BASE_181A]

    bodies["heartbeat"] = {"config": None}
    await auth.heartbeat()
    s._refresh_service_uuids()
    assert s.payload_service_uuids == [FCA6]


def test_persisted_legacy_scan_list_dropped_on_load(tmp_path):
    token_path = tmp_path / "a.json"
    token_path.write_text(
        json.dumps(
            {
                "gatewayId": "gw-1",
                "serverConfig": {
                    "scanServiceUuids": [HUBBLE_SERVICE_UUID, TILE_SERVICE_UUID],
                    "payloadServiceUuids": ["feed", "FCA6"],
                },
            }
        )
    )
    auth = GatewayAuth("k", "https://gw.test", token_path=str(token_path))
    assert auth.server_config == {"payloadServiceUuids": ["FEED"]}
