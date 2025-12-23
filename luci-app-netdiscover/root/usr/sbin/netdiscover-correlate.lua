#!/usr/bin/lua

local jsonc = require "luci.jsonc"
local nixio_fs = require "nixio.fs"

local state_root = arg[1] or "/tmp/netdiscover"
local raw_root = state_root .. "/raw"
local output_path = state_root .. "/results.json"
local meta_path = state_root .. "/scan_meta.json"

local function read_file_content(file_path)
  local file_handle = io.open(file_path, "r")
  if not file_handle then
    return nil
  end

  local content = file_handle:read("*a")
  file_handle:close()

  if not content or content == "" then
    return nil
  end

  return content
end

local function parse_json_file(file_path)
  local content = read_file_content(file_path)
  if not content then
    return nil
  end

  local ok, parsed = pcall(jsonc.parse, content)
  if not ok then
    return nil
  end

  return parsed
end

local function normalize_mac(raw_mac)
  if not raw_mac then
    return nil
  end

  local lowered = raw_mac:lower()
  local hyphen_index = lowered:find("-")
  if hyphen_index then
    lowered = lowered:sub(hyphen_index + 1)
  end

  local stripped = lowered:gsub("[^0-9a-f]", "")
  if #stripped ~= 12 then
    return nil
  end

  return string.format(
    "%s:%s:%s:%s:%s:%s",
    stripped:sub(1, 2),
    stripped:sub(3, 4),
    stripped:sub(5, 6),
    stripped:sub(7, 8),
    stripped:sub(9, 10),
    stripped:sub(11, 12)
  )
end

local function normalize_ip(raw_ip)
  if not raw_ip or raw_ip == "" then
    return nil
  end

  local sanitized = raw_ip:match("([^%%]+)")
  return sanitized
end

local function is_link_local(ip_address)
  if not ip_address then
    return false
  end

  local lowered = ip_address:lower()
  if lowered:find(":") then
    return lowered:match("^fe80:") ~= nil
  end

  return lowered:match("^169%.254%.") ~= nil
end

local function add_to_set(set_table, value)
  if not value or value == "" then
    return
  end
  set_table[value] = true
end

local function set_to_sorted_list(set_table)
  local list = {}
  for value in pairs(set_table) do
    table.insert(list, value)
  end
  table.sort(list)
  return list
end

local function is_wireless_interface(interface_name)
  if not interface_name then
    return false
  end
  return interface_name:match("^wlan") or interface_name:match("^phy") or interface_name:match("^mesh")
end

local function is_reachable_state(state_value)
  if not state_value or state_value == "" then
    return false
  end

  local state_text = state_value:upper()
  return state_text:find("REACHABLE") ~= nil
    or state_text:find("DELAY") ~= nil
    or state_text:find("PROBE") ~= nil
end

local function load_scan_meta()
  local meta = parse_json_file(meta_path)
  if type(meta) ~= "table" then
    return {}
  end
  return meta
end

local function directory_iterator(path)
  local iterator = nixio_fs.dir(path)
  if not iterator then
    return function()
      return nil
    end
  end
  return iterator
end

local device_map = {}

local function ensure_device(mac_address)
  local device = device_map[mac_address]
  if device then
    return device
  end

  device = {
    mac = mac_address,
    vendor = nil,
    ip_set = {},
    hostname_set = {},
    interface_set = {},
    seen_set = {},
    connection_set = {},
    rssi = nil,
    dhcp = "unknown",
    liveness = "unknown",
    flags = {}
  }

  device_map[mac_address] = device
  return device
end

local function add_ip_address(device, ip_address)
  local normalized = normalize_ip(ip_address)
  if normalized then
    add_to_set(device.ip_set, normalized)
  end
end

local function add_hostname_to_set(hostname_set, hostname)
  if hostname == "*" or hostname == "-" then
    return
  end
  add_to_set(hostname_set, hostname)
end

local function add_hostname(device, hostname)
  add_hostname_to_set(device.hostname_set, hostname)
end

local function add_interface(device, interface_name)
  add_to_set(device.interface_set, interface_name)
end

local function add_seen_via(device, token)
  add_to_set(device.seen_set, token)
end

local function add_connection(device, connection_type)
  add_to_set(device.connection_set, connection_type)
end

local function mark_confirmed(device)
  device.liveness = "confirmed"
end

local function mark_possible(device)
  if device.liveness ~= "confirmed" then
    device.liveness = "possibly_stale"
  end
end

local function record_vendor(device, vendor_name)
  if not vendor_name or vendor_name == "" then
    return
  end

  if not device.vendor then
    device.vendor = vendor_name
  end
end

local function record_rssi(device, rssi_value)
  if not rssi_value then
    return
  end

  if not device.rssi or rssi_value > device.rssi then
    device.rssi = rssi_value
  end
end

local function parse_host_hints()
  local host_hints = parse_json_file(raw_root .. "/host_hints.json")
  if type(host_hints) ~= "table" then
    return
  end

  local entries = host_hints.hosts or host_hints
  if type(entries) ~= "table" then
    return
  end

  for key, entry in pairs(entries) do
    if type(entry) == "table" then
      local mac_address = normalize_mac(entry.mac or entry.macaddr or entry.mac_address or key)
      if mac_address then
        local device = ensure_device(mac_address)

        add_hostname(device, entry.name or entry.hostname or entry.host)
        add_interface(device, entry.dev or entry.ifname or entry.interface)

        local ip_candidates = {
          entry.ipaddr,
          entry.ip,
          entry.ipv4,
          entry.ip4addr,
          entry.ip6addr,
          entry.ipv6
        }

        for candidate_index, candidate in ipairs(ip_candidates) do
          if type(candidate) == "string" then
            add_ip_address(device, candidate)
          end
        end

        local ip_list_candidates = {
          entry.ipaddrs,
          entry.ip6addrs,
          entry.ipv6addrs
        }

        for list_index, list_candidate in ipairs(ip_list_candidates) do
          if type(list_candidate) == "table" then
            for list_entry_index, list_entry in ipairs(list_candidate) do
              add_ip_address(device, list_entry)
            end
          end
        end

        if type(entry.type) == "string" then
          if entry.type:lower():find("wireless") or entry.type:lower():find("wifi") then
            add_connection(device, "wireless")
          elseif entry.type:lower():find("wired") or entry.type:lower():find("ethernet") then
            add_connection(device, "wired")
          end
        end
      end
    end
  end
end

local function parse_dhcp_leases()
  local content = read_file_content(raw_root .. "/dhcp.leases")
  if not content then
    return {}, false
  end

  local dhcp_entries = {}
  local has_entries = false

  for line in content:gmatch("[^\n]+") do
    local trimmed = line:match("^%s*(.-)%s*$")
    if trimmed ~= "" and trimmed:sub(1, 1) ~= "#" then
      local fields = {}
      for field in trimmed:gmatch("%S+") do
        table.insert(fields, field)
      end

      if #fields >= 5 then
        local mac_address = normalize_mac(fields[2])
        local ip_address = normalize_ip(fields[3])
        local hostname = fields[4]

        if mac_address then
          local entry = dhcp_entries[mac_address]
          if not entry then
            entry = { ip_set = {}, hostname_set = {} }
            dhcp_entries[mac_address] = entry
          end

          if ip_address then
            add_to_set(entry.ip_set, ip_address)
          end

          if hostname then
            add_hostname_to_set(entry.hostname_set, hostname)
          end

          has_entries = true
        end
      end
    end
  end

  return dhcp_entries, has_entries
end

local function parse_ip_neigh()
  local neighbor_entries = parse_json_file(raw_root .. "/ip_neigh.json")
  if type(neighbor_entries) == "table" then
    for entry_index, entry in ipairs(neighbor_entries) do
      if type(entry) == "table" then
        local mac_address = normalize_mac(entry.lladdr)
        local ip_address = normalize_ip(entry.dst)
        if mac_address and ip_address then
          local device = ensure_device(mac_address)
          add_ip_address(device, ip_address)
          add_interface(device, entry.dev)
          add_seen_via(device, "ARP")

          if entry.state then
            local state_value
            if type(entry.state) == "table" then
              state_value = table.concat(entry.state, " ")
            else
              state_value = tostring(entry.state)
            end

            if is_reachable_state(state_value) then
              mark_confirmed(device)
            else
              mark_possible(device)
            end
          else
            mark_possible(device)
          end
        end
      end
    end
    return
  end

  local text_content = read_file_content(raw_root .. "/ip_neigh.txt")
  if not text_content then
    return
  end

  for line in text_content:gmatch("[^\n]+") do
    local ip_address, interface_name, mac_address, state_value = line:match("^(%S+)%s+dev%s+(%S+)%s+lladdr%s+(%S+)%s+(%S+)")
    local normalized_mac = normalize_mac(mac_address)
    if normalized_mac and ip_address then
      local device = ensure_device(normalized_mac)
      add_ip_address(device, ip_address)
      add_interface(device, interface_name)
      add_seen_via(device, "ARP")

      if is_reachable_state(state_value) then
        mark_confirmed(device)
      else
        mark_possible(device)
      end
    end
  end
end

local function parse_bridge_fdb()
  local content = read_file_content(raw_root .. "/bridge_fdb.txt")
  if not content then
    return
  end

  for line in content:gmatch("[^\n]+") do
    local mac_address, interface_name = line:match("^(%S+)%s+dev%s+(%S+)")
    local normalized_mac = normalize_mac(mac_address)
    if normalized_mac and interface_name and not is_wireless_interface(interface_name) then
      local device = ensure_device(normalized_mac)
      add_interface(device, interface_name)
      add_seen_via(device, "Wired")
      add_connection(device, "wired")
      mark_possible(device)
    end
  end
end

local function parse_iw_station_files()
  for file_name in directory_iterator(raw_root) do
    local interface_name = file_name:match("^iw_station_(.+)%.txt$")
    if interface_name then
      local content = read_file_content(raw_root .. "/" .. file_name)
      if content then
        local current_mac = nil
        for line in content:gmatch("[^\n]+") do
          local station_mac = line:match("^Station%s+(%S+)")
          if station_mac then
            current_mac = normalize_mac(station_mac)
            if current_mac then
              local device = ensure_device(current_mac)
              add_interface(device, interface_name)
              add_seen_via(device, "WiFi")
              add_connection(device, "wireless")
              mark_confirmed(device)
            end
          elseif current_mac then
            local signal_value = line:match("signal:%s*(-?%d+)")
            if signal_value then
              local rssi_value = tonumber(signal_value)
              if rssi_value then
                local device = ensure_device(current_mac)
                record_rssi(device, rssi_value)
              end
            end
          end
        end
      end
    end
  end
end

local function parse_arp_scan_files()
  for file_name in directory_iterator(raw_root) do
    local interface_name = file_name:match("^arp_scan_(.+)%.txt$")
    if interface_name then
      local content = read_file_content(raw_root .. "/" .. file_name)
      if content then
        for line in content:gmatch("[^\n]+") do
          local ip_address, mac_address, vendor_name = line:match("^(%d+%.%d+%.%d+%.%d+)%s+(%S+)%s+(.+)$")
          local normalized_mac = normalize_mac(mac_address)
          if normalized_mac and ip_address then
            local device = ensure_device(normalized_mac)
            add_ip_address(device, ip_address)
            add_interface(device, interface_name)
            add_seen_via(device, "ARP")
            record_vendor(device, vendor_name)
            mark_confirmed(device)
          end
        end
      end
    end
  end
end

local function parse_nmap_ping()
  local content = read_file_content(raw_root .. "/nmap_ping.grep")
  if not content then
    return {}
  end

  local ip_set = {}
  for line in content:gmatch("[^\n]+") do
    local ip_address = line:match("^Host:%s+(%S+)")
    local status_value = line:match("Status:%s+(%S+)")
    if ip_address and status_value == "Up" then
      local normalized_ip = normalize_ip(ip_address)
      if normalized_ip then
        ip_set[normalized_ip] = true
      end
    end
  end

  return ip_set
end

local function parse_nmap_ports()
  local content = read_file_content(raw_root .. "/nmap_ports.txt")
  if not content then
    return {}
  end

  local port_map = {}
  for line in content:gmatch("[^\n]+") do
    local ip_address = line:match("^Host:%s+(%S+)")
    local port_block = line:match("Ports:%s+(.+)")
    if ip_address and port_block then
      local port_list = {}
      for port_entry in port_block:gmatch("[^,]+") do
        local port_number = port_entry:match("^(%d+)/open")
        if port_number then
          table.insert(port_list, port_number)
        end
      end
      if #port_list > 0 then
        port_map[normalize_ip(ip_address) or ip_address] = port_list
      end
    end
  end

  return port_map
end

parse_host_hints()
local dhcp_entries, dhcp_available = parse_dhcp_leases()
parse_ip_neigh()
parse_bridge_fdb()
parse_iw_station_files()
parse_arp_scan_files()

local icmp_ip_set = parse_nmap_ping()
local tcp_port_map = parse_nmap_ports()

for mac_address, entry in pairs(dhcp_entries) do
  local device = ensure_device(mac_address)
  for ip_address in pairs(entry.ip_set) do
    add_ip_address(device, ip_address)
  end
  for hostname in pairs(entry.hostname_set) do
    add_hostname(device, hostname)
  end
  add_seen_via(device, "DHCP")
  device.dhcp = "observed"
  mark_possible(device)
end

if dhcp_available then
  for mac_address, device in pairs(device_map) do
    if device.dhcp == "unknown" then
      device.dhcp = "not_observed"
    end
  end
end

local ip_conflict_map = {}
for mac_address, device in pairs(device_map) do
  for ip_address in pairs(device.ip_set) do
    if not is_link_local(ip_address) then
      local mac_set = ip_conflict_map[ip_address]
      if not mac_set then
        mac_set = {}
        ip_conflict_map[ip_address] = mac_set
      end
      mac_set[device.mac] = true
    end
  end
end

local scan_meta = load_scan_meta()
local last_seen = scan_meta.scan_finished or scan_meta.scan_started

local device_list = {}
for mac_address, device in pairs(device_map) do
  local ip_addresses = set_to_sorted_list(device.ip_set)
  local hostnames = set_to_sorted_list(device.hostname_set)
  local interfaces = set_to_sorted_list(device.interface_set)
  local connections = set_to_sorted_list(device.connection_set)
  local open_ports = {}
  local non_link_local_count = 0

  for ip_index, ip_address in ipairs(ip_addresses) do
    if not is_link_local(ip_address) then
      non_link_local_count = non_link_local_count + 1
    end

    if icmp_ip_set[ip_address] then
      add_seen_via(device, "ICMP")
      mark_possible(device)
    end

    local ports_for_ip = tcp_port_map[ip_address]
    if ports_for_ip and #ports_for_ip > 0 then
      add_seen_via(device, "TCP")
      mark_possible(device)
      open_ports[ip_address] = ports_for_ip
    end
  end

  local seen_via = set_to_sorted_list(device.seen_set)

  if #ip_addresses == 0 then
    for token_index, token in ipairs(seen_via) do
      if token == "ARP" or token == "WiFi" or token == "Wired" then
        table.insert(device.flags, { type = "l2_only" })
        break
      end
    end
  end

  if non_link_local_count > 1 then
    table.insert(device.flags, { type = "multiple_ips" })
  end

  if #interfaces > 1 then
    table.insert(device.flags, { type = "multiple_interfaces" })
  end

  if #hostnames > 1 then
    table.insert(device.flags, { type = "multiple_hostnames" })
  end

  if #connections > 1 then
    table.insert(device.flags, { type = "connection_ambiguous" })
  end

  for ip_index, ip_address in ipairs(ip_addresses) do
    local mac_set = ip_conflict_map[ip_address]
    if mac_set then
      local mac_count = 0
      for conflict_mac in pairs(mac_set) do
        mac_count = mac_count + 1
      end
      if mac_count > 1 then
        table.insert(device.flags, { type = "ip_conflict", value = ip_address })
      end
    end
  end

  table.insert(device_list, {
    mac = device.mac,
    vendor = device.vendor,
    ip_addresses = ip_addresses,
    dhcp = device.dhcp,
    hostnames = hostnames,
    connection = connections,
    interfaces = interfaces,
    rssi = device.rssi,
    seen_via = seen_via,
    liveness = device.liveness,
    last_seen = last_seen,
    flags = device.flags,
    ports = next(open_ports) and open_ports or nil
  })
end

table.sort(device_list, function(left, right)
  return left.mac < right.mac
end)

local output = {
  meta = scan_meta,
  devices = device_list
}

local output_content = jsonc.stringify(output, true)
local output_file = io.open(output_path, "w")
if output_file then
  output_file:write(output_content)
  output_file:close()
end
