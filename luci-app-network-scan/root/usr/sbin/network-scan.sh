#!/bin/sh
set -eu

state_root="/tmp/network-scan"
raw_root="$state_root/raw"
lock_file="$state_root/scan.lock"
meta_file="$state_root/scan_meta.json"
status_file="$state_root/status.json"
probe_status_file="$state_root/probe_status.json"

options_specified=0
enable_arp_scan=0
enable_icmp_sweep=0
enable_tcp_probe=0
tcp_ports="22,80,443,23"
scope_mode="auto"
scope_targets_raw=""

for argument in "$@"; do
  options_specified=1
  case "$argument" in
    --arp-scan)
      enable_arp_scan=1
      ;;
    --no-arp-scan)
      enable_arp_scan=0
      ;;
    --icmp-sweep)
      enable_icmp_sweep=1
      ;;
    --tcp-probe)
      enable_tcp_probe=1
      ;;
    --tcp-ports=*)
      tcp_ports="${argument#--tcp-ports=}"
      ;;
    --scope=*)
      scope_mode="${argument#--scope=}"
      ;;
    --scope-targets=*)
      scope_targets_raw="${argument#--scope-targets=}"
      ;;
  esac
done

if [ "$options_specified" -eq 0 ]; then
  enable_arp_scan=1
fi

sanitized_tcp_ports="$(printf "%s" "$tcp_ports" | tr -cd '0-9,')"
if [ -n "$sanitized_tcp_ports" ]; then
  tcp_ports="$sanitized_tcp_ports"
else
  tcp_ports="22,80,443,23"
fi

if [ "$scope_mode" != "custom" ]; then
  scope_mode="auto"
fi

scope_targets_raw="$(printf "%s" "$scope_targets_raw" | tr -cd '0-9./,-')"

mkdir -p "$raw_root"

if [ -f "$lock_file" ]; then
  existing_pid="$(cat "$lock_file" 2>/dev/null || true)"
  if [ -n "$existing_pid" ] && kill -0 "$existing_pid" 2>/dev/null; then
    printf '{"status":"busy"}\n' > "$status_file"
    exit 0
  fi
fi

echo "$$" > "$lock_file"

scan_start_epoch="$(date +%s)"
scan_start_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

printf '{"status":"running","scan_started":"%s"}\n' "$scan_start_iso" > "$status_file"

rm -rf "$raw_root"
mkdir -p "$raw_root"

pids=""

spawn_capture() {
  output_path="$1"
  shift
  ( "$@" > "$output_path" 2>/dev/null || true ) &
  pids="$pids $!"
}

capture_file() {
  source_path="$1"
  output_path="$2"
  if [ -f "$source_path" ]; then
    cp "$source_path" "$output_path"
  fi
}

if command -v ubus >/dev/null 2>&1; then
  spawn_capture "$raw_root/host_hints.json" sh -c "ubus call luci-rpc getHostHints || ubus call luci getHostHints"
  spawn_capture "$raw_root/network_interface_dump.json" ubus call network.interface dump
fi

if command -v bridge >/dev/null 2>&1; then
  spawn_capture "$raw_root/bridge_fdb.txt" bridge fdb show
fi

if command -v iw >/dev/null 2>&1; then
  spawn_capture "$raw_root/iw_dev.txt" iw dev
  iw_interface_list="$(iw dev 2>/dev/null | awk '/Interface/ {print $2}')"
  for interface_name in $iw_interface_list; do
    spawn_capture "$raw_root/iw_station_${interface_name}.txt" iw dev "$interface_name" station dump
  done
fi

capture_file "/tmp/dhcp.leases" "$raw_root/dhcp.leases"

build_scope_targets() {
  target_file="$1"
  : > "$target_file"

  if [ "$scope_mode" = "custom" ] && [ -n "$scope_targets_raw" ]; then
    for token in $(printf "%s" "$scope_targets_raw" | tr ',' ' '); do
      if [ -n "$token" ]; then
        printf "%s\n" "$token" >> "$target_file"
      fi
    done
    if [ -s "$target_file" ]; then
      return 0
    fi
  fi

  scope_mode="auto"
  if command -v ip >/dev/null 2>&1; then
    ip -o -4 addr show up 2>/dev/null | awk '$2 != "lo" {print $4}' | sort -u >> "$target_file"
  fi
}

scope_targets_file="$raw_root/scan_targets.txt"
build_scope_targets "$scope_targets_file"

if [ "$enable_arp_scan" -eq 1 ] && command -v arp-scan >/dev/null 2>&1 && command -v ip >/dev/null 2>&1; then
  arp_interfaces="$(ip -o -4 addr show up 2>/dev/null | awk '{print $2}' | sort -u)"
  for interface_name in $arp_interfaces; do
    if [ "$interface_name" != "lo" ]; then
      spawn_capture "$raw_root/arp_scan_${interface_name}.txt" arp-scan --interface="$interface_name" --localnet
    fi
  done
fi

if [ "$enable_icmp_sweep" -eq 1 ] && command -v nmap >/dev/null 2>&1 && command -v ip >/dev/null 2>&1; then
  if [ -s "$scope_targets_file" ]; then
    spawn_capture "$raw_root/nmap_ping.grep" nmap -sn -n --disable-arp-ping -PE --max-retries 1 --host-timeout 5s -iL "$scope_targets_file" -oG -
  fi
fi

for scan_pid in $pids; do
  wait "$scan_pid"
done

if command -v ip >/dev/null 2>&1; then
  if ip -j neigh >/dev/null 2>&1; then
    ip -j neigh > "$raw_root/ip_neigh.json" 2>/dev/null || true
  else
    ip neigh > "$raw_root/ip_neigh.txt" 2>/dev/null || true
  fi
fi

printf '{"tcp_probe":"%s","icmp_sweep":"%s"}\n' \
  "$enable_tcp_probe" \
  "$enable_icmp_sweep" \
  > "$probe_status_file"

if [ "$enable_tcp_probe" -eq 1 ] && command -v nmap >/dev/null 2>&1; then
  : > "$raw_root/ip_candidates.txt"

  if [ -f "$raw_root/dhcp.leases" ]; then
    awk '{print $3}' "$raw_root/dhcp.leases" >> "$raw_root/ip_candidates.txt"
  fi

  if command -v ip >/dev/null 2>&1; then
    ip -o -4 neigh show 2>/dev/null | awk '$5 != "FAILED" {print $1}' >> "$raw_root/ip_candidates.txt"
  fi

  for arp_scan_file in "$raw_root"/arp_scan_*.txt; do
    if [ -f "$arp_scan_file" ]; then
      awk '{print $1}' "$arp_scan_file" >> "$raw_root/ip_candidates.txt"
    fi
  done

  sort -u "$raw_root/ip_candidates.txt" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '^169\\.254\\.' > "$raw_root/ip_candidates.sorted"

  tcp_targets_file="$raw_root/ip_candidates.sorted"
  if [ "$enable_icmp_sweep" -eq 1 ] && [ -f "$raw_root/nmap_ping.grep" ]; then
    awk '/Status: Up/{print $2}' "$raw_root/nmap_ping.grep" | sort -u > "$raw_root/ip_ping_targets.txt"
    if [ -s "$raw_root/ip_ping_targets.txt" ]; then
      tcp_targets_file="$raw_root/ip_ping_targets.txt"
    fi
  elif [ "$scope_mode" = "custom" ] && [ -s "$scope_targets_file" ]; then
    tcp_targets_file="$scope_targets_file"
  fi

  if [ -s "$tcp_targets_file" ]; then
    nmap -n -Pn --open -p "$tcp_ports" --max-retries 1 --host-timeout 5s -iL "$tcp_targets_file" -oG "$raw_root/nmap_ports.txt" >/dev/null 2>&1 || true
  fi
fi

scan_end_epoch="$(date +%s)"
scan_end_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
scan_duration_seconds=$((scan_end_epoch - scan_start_epoch))

printf '{"scan_started":"%s","scan_finished":"%s","scan_duration_seconds":%s,"scan_options":{"arp_scan":%s,"icmp_sweep":%s,"tcp_probe":%s,"tcp_ports":"%s","scope_mode":"%s","scope_targets":"%s"}}\n' \
  "$scan_start_iso" \
  "$scan_end_iso" \
  "$scan_duration_seconds" \
  "$enable_arp_scan" \
  "$enable_icmp_sweep" \
  "$enable_tcp_probe" \
  "$tcp_ports" \
  "$scope_mode" \
  "$scope_targets_raw" \
  > "$meta_file"

if [ -x "/usr/sbin/network-scan-correlate.lua" ]; then
  /usr/sbin/network-scan-correlate.lua "$state_root" >/dev/null 2>&1 || true
fi

printf '{"status":"complete","scan_started":"%s","scan_finished":"%s"}\n' "$scan_start_iso" "$scan_end_iso" > "$status_file"

rm -f "$lock_file"
