# hubble-gateway

Python SDK for building Hubble Network BLE gateways. Import `hubble_gateway` in your application; this package is a library only (no CLI).

## Server config

gateway-api sends a `config` object (or `null`) in the registration, heartbeat
and token-refresh responses. `GatewayAuth` stores it as `server_config`.
`GatewaySender` reads it on every use, so each new response takes effect
without a restart.

| Key | Range | Overrides |
| --- | --- | --- |
| `uploadIntervalMs` | 60,000 – 3,600,000 | `upload_interval_s` |
| `uploadBatchSize` | 1 – 500 | `batch_size` |
| `dedupWindowMs` | 5,000 – 3,600,000 | `dedup_window_s` |

- Each response replaces the stored config. It does not merge into it.
- `config: null` clears it, and the local values apply again.
- Out-of-range values are clamped. Values of the wrong type are ignored.
- Uploaded packets carry the 16-bit form (`FCA6`) as `serviceUuid`.
- Other keys (`activeUploadIntervalMs`, `activeDedupWindowMs`,
  `uploadOnCellular`) are ignored: this SDK has no motion state or cellular gating.

The local default upload interval is 60 s, the same as the server's floor.

## Scanning

`Scanner` always scans for the Hubble service `FCA6`, plus any configured
payload services.

- One advertisement gives at most one uploaded sighting: the first service, in
  priority order (`FCA6` first), that has non-empty service data.
- `stats["multi_payload_advertisements"]` counts advertisements that carried
  service data for more than one payload service.
- `Scanner(service_uuids=[...])` adds scan-only services. Matching
  advertisements reach the `on_advertisement` callback and are not uploaded.

## Deduplication

The dedup key is `(device address, 16-bit service UUID, service data hex)`.
For a custom 128-bit UUID, the full UUID takes the place of the 16-bit one.

- The first sighting of a key opens a window of `dedup_window_s`.
- Repeats inside the window are dropped. If the first sighting is not uploaded
  yet, a repeat adds to its sighting count and can raise its RSSI.
- The window is fixed at the first sighting. Repeats do not extend it, so a
  device that beacons all the time is reported once per window.
- Windows survive uploads. An upload does not reset them.
- Expired keys are removed. The map is capped at `MAX_DEDUP_KEYS` (100,000);
  past the cap, the oldest key is removed first.
