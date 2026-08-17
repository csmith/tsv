# Changelog

## 1.2.0 - 2026-08-17

- WireGuard endpoint hostnames are now re-resolved on every health-check-triggered restart, rotating through the resolved addresses so a single dead pool member is routed around instead of being retried indefinitely.
- Added `WG_ENDPOINT_PROTOCOLS` setting to control which IP protocols (and in what preference order) are used for the endpoint (defaults to `4,6`).

## 1.1.0 - 2026-04-04

- Dependency updates

## 1.0.0 - 2025-09-30

_Initial release._
