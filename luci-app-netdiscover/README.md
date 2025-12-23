# LuCI Network Discovery (netdiscover)

Unified, read-only device discovery view for OpenWrt. The package correlates existing system and LuCI data sources into a single table keyed by MAC address. It does not run background services or persist state across reboots.

## Key behaviors
- Single table, one row per MAC address.
- IP addresses are attributes; devices with no IP remain visible.
- Evidence-first: shows which signals observed each device.
- Liveness is never "offline"; only evidence-based states.
- Manual scan only; no polling or daemons.
- Runtime state stored in `/tmp/netdiscover/`.
- ICMP/TCP probes can target auto-detected LAN subnets or a custom range list.

## Data sources used
Tier 1 (preferred):
- `ubus call luci-rpc getHostHints`
- `/tmp/dhcp.leases`
- `iw dev <ifname> station dump`

Tier 2 (optional):
- `ip neigh`
- `bridge fdb show`
- `arp-scan --localnet` (if installed)
- `nmap -sn` (optional ICMP sweep)
- `nmap -p 22,80,443,23 --open` (optional TCP probe)

## Required packages
These are installed as package dependencies:
- `iw` for wireless association + RSSI.
- `arp-scan` for ARP replies and vendor strings.
- `nmap` for ICMP sweep and TCP probe.
- `ip-full` and `ip-bridge` for neighbor/bridge visibility.

## Build (OpenWrt SDK)
From your OpenWrt SDK directory:
```sh
# Add this package to your feeds or copy into package/.
# Then update and install feeds, if needed.

make package/luci-app-netdiscover/compile V=s
```

## Build (Docker SDK / Orbstack)
From this repo root:
```sh
# One-time feed bootstrap (caches feeds under ./feeds and sources under ./dl)
docker compose run --rm netdiscover-bootstrap

# Build the package (reuses cached feeds and downloads)
docker compose run --rm netdiscover-build
```

The resulting ipk is under:
`./bin/packages/arm_cortex-a15_neon-vfpv4/luci/`

### If OpenWrt Git 503s
This repo includes `feeds.conf` pointing at the official GitHub mirrors for the packages + luci feeds on the `openwrt-24.10` branch. The compose file mounts it to `/builder/feeds.conf`, so the SDK uses it instead of the default `git.openwrt.org` URLs.

## Install
- LuCI → System → Software → Upload Package
- or
```sh
opkg install luci-app-netdiscover_*.ipk
```

## Runtime output
- Raw captures: `/tmp/netdiscover/raw/`
- Correlated output: `/tmp/netdiscover/results.json`
- Scan metadata: `/tmp/netdiscover/scan_meta.json`
- Status: `/tmp/netdiscover/status.json`

## Notes
- DHCP lease parsing follows the standard dnsmasq lease file format.
- Liveness is "confirmed" only for active Wi-Fi association or ARP replies; other evidence is marked "possibly stale" or "unknown".
- Action links appear only when the optional TCP probe reports the corresponding port open.
- UI filters can hide IPv6/IPv4 link-local addresses without removing devices from the unified list.
- Evidence tabs expose raw inputs (ARP, DHCP, Wi-Fi, Nmap) via `/tmp/netdiscover/raw/`.
