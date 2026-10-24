# Changelog

## 1.2.1 - 2026-10-24

- Built with Go 1.27.3, fixing vulnerabilities in the standard library including:
  - HTTP/2 server memory exhaustion, CPU exhaustion and crashes (CVE-2026-78659, CVE-2026-78669, CVE-2026-97032)
  - HTTP/1 connection desynchronisation after `CONNECT` requests (CVE-2026-56866, CVE-2026-94439)
  - Compromised intermediate certificates not being distrusted (CVE-2026-111943)
- Dependency updates, including Tailscale 1.102.4

## 1.2.0 - 2026-08-17

- WireGuard endpoint hostnames are now re-resolved on every health-check-triggered restart, rotating through the resolved addresses so a single dead pool member is routed around instead of being retried indefinitely.
- Added `WG_ENDPOINT_PROTOCOLS` setting to control which IP protocols (and in what preference order) are used for the endpoint (defaults to `4,6`).

## 1.1.0 - 2026-04-04

- Dependency updates

## 1.0.0 - 2025-09-30

_Initial release._
