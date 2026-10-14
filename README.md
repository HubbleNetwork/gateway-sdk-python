# hubble-gateway

Python SDK for building Hubble Network BLE gateways. Import `hubble_gateway` in your application; this package is a library only (no CLI).

## Server config

gateway-api sends a `config` object (or `null`) in the registration, heartbeat
and token-refresh responses. `GatewayAuth` stores it as `server_config`, and
`GatewaySender` reads it on every use, so each new response takes effect at once.

| Key | Range | Overrides |
| --- | --- | --- |
| `uploadIntervalMs` | 60,000 – 3,600,000 | `upload_interval_s` |
| `uploadBatchSize` | 1 – 500 | `batch_size` |
| `dedupWindowMs` | 5,000 – 3,600,000 | `dedup_window_s` |

- Each response replaces the stored config. It does not merge into it.
- `config: null` clears it, and the local values apply again.
- Out-of-range values are clamped. Values that are not numbers are ignored.
- Other keys (`activeUploadIntervalMs`, `activeDedupWindowMs`,
  `uploadOnCellular`) are ignored: this SDK has no motion state or cellular gating.

The local default upload interval is 5 s, but any server config sets at least 60 s.
