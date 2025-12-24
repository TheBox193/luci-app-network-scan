# LuCI Network Scan

Unified, read-only network scan view for OpenWrt LuCI. The app correlates ARP, DHCP, Wi‑Fi association, and bounded probes into a single table keyed by MAC address. It does not run background services or persist state across reboots.

## Highlights
- One unified device table, one row per MAC address.
- Devices without IPs remain visible (L2‑only).
- Evidence-first: shows how each device was observed.
- Liveness is never “offline”; only evidence-based states.
- Manual scan only; no polling or daemons.
- Optional probes are bounded and user‑triggered.

## Dependencies
Installed automatically with the package:
- `nmap`, `arp-scan`, `iw`, `ip-full`, `ip-bridge`

## Build (Docker SDK / Orbstack)
From repo root:
```sh
docker compose run --rm network-scan-bootstrap
docker compose run --rm network-scan-build
```

The resulting ipk is under:
`./bin/packages/arm_cortex-a15_neon-vfpv4/luci/`

## Install
```sh
opkg install luci-app-network-scan_*.ipk
```

## Use
LuCI → Network → Network Scan

Scan options:
- ARP scan (local L2)
- ICMP sweep (scope‑based)
- TCP probe (ports you choose)
- Scope: LAN subnets (auto) or custom targets
- Filters: hide IPv6/IPv4 link‑local addresses

## Evidence Tabs
Raw inputs are available under tabs for ARP, DHCP, Wi‑Fi, Nmap, and more.
On-device raw files live under:
`/tmp/network-scan/raw/`

## Project layout
`luci-app-network-scan/` contains the LuCI package.
See `luci-app-network-scan/README.md` for package-specific details.
