module("luci.controller.netdiscover", package.seeall)

local function read_json_file(file_path)
  local jsonc = require "luci.jsonc"
  local file_handle = io.open(file_path, "r")
  if not file_handle then
    return nil
  end

  local content = file_handle:read("*a")
  file_handle:close()

  if not content or content == "" then
    return nil
  end

  local ok, parsed = pcall(jsonc.parse, content)
  if not ok then
    return nil
  end

  return parsed
end

local function write_json(payload)
  local jsonc = require "luci.jsonc"
  local http = require "luci.http"

  http.prepare_content("application/json")
  http.write(jsonc.stringify(payload))
end

local function read_text_file(file_path)
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

local function read_directory_matches(directory_path, file_pattern)
  local nixio_fs = require "nixio.fs"
  local iterator = nixio_fs.dir(directory_path)
  if not iterator then
    return nil
  end

  local file_names = {}
  for entry_name in iterator do
    if entry_name:match(file_pattern) then
      file_names[#file_names + 1] = entry_name
    end
  end

  if #file_names == 0 then
    return nil
  end

  table.sort(file_names)

  local output_parts = {}
  for index, entry_name in ipairs(file_names) do
    local content = read_text_file(directory_path .. "/" .. entry_name)
    if content then
      output_parts[#output_parts + 1] = "== " .. entry_name .. " ==\n" .. content
    end
  end

  if #output_parts == 0 then
    return nil
  end

  return table.concat(output_parts, "\n")
end

function index()
  entry({ "admin", "network", "netdiscover" }, call("action_index"), _("Network Discovery"), 60).dependent = false
  entry({ "admin", "network", "netdiscover", "scan" }, call("action_scan")).leaf = true
  entry({ "admin", "network", "netdiscover", "status" }, call("action_status")).leaf = true
  entry({ "admin", "network", "netdiscover", "results" }, call("action_results")).leaf = true
  entry({ "admin", "network", "netdiscover", "raw" }, call("action_raw")).leaf = true
end

function action_index()
  local template = require "luci.template"
  template.render("netdiscover/results")
end

function action_scan()
  local sys = require "luci.sys"
  local http = require "luci.http"

  local enable_arp_scan = http.formvalue("arp_scan") == "1"
  local enable_icmp_sweep = http.formvalue("icmp_sweep") == "1"
  local enable_tcp_probe = http.formvalue("tcp_probe") == "1"
  local scope_mode = http.formvalue("scope") or "auto"
  if scope_mode ~= "custom" then
    scope_mode = "auto"
  end

  local raw_scope_targets = http.formvalue("scope_targets") or ""
  local sanitized_scope_targets = raw_scope_targets:gsub("[^0-9%./,%-]", "")

  local raw_ports = http.formvalue("tcp_ports") or ""
  local allowed_ports = {
    ["22"] = true,
    ["80"] = true,
    ["443"] = true,
    ["23"] = true
  }

  local tcp_ports_list = {}
  for port_value in raw_ports:gmatch("%d+") do
    if allowed_ports[port_value] then
      tcp_ports_list[#tcp_ports_list + 1] = port_value
    end
  end

  if #tcp_ports_list == 0 then
    tcp_ports_list = { "22", "80", "443", "23" }
  end

  local arguments = {}
  if enable_arp_scan then
    arguments[#arguments + 1] = "--arp-scan"
  else
    arguments[#arguments + 1] = "--no-arp-scan"
  end
  if enable_icmp_sweep then
    arguments[#arguments + 1] = "--icmp-sweep"
  end
  if enable_tcp_probe then
    arguments[#arguments + 1] = "--tcp-probe"
    arguments[#arguments + 1] = "--tcp-ports=" .. table.concat(tcp_ports_list, ",")
  end
  arguments[#arguments + 1] = "--scope=" .. scope_mode
  if sanitized_scope_targets ~= "" then
    arguments[#arguments + 1] = "--scope-targets=" .. sanitized_scope_targets
  end

  local command = "/usr/sbin/netdiscover-scan.sh " .. table.concat(arguments, " ") .. " >/dev/null 2>&1 &"
  sys.call(command)

  write_json({
    status = "started",
    options = {
      arp_scan = enable_arp_scan,
      icmp_sweep = enable_icmp_sweep,
      tcp_probe = enable_tcp_probe,
      tcp_ports = tcp_ports_list,
      scope_mode = scope_mode,
      scope_targets = sanitized_scope_targets
    }
  })
end

function action_status()
  local state_root = "/tmp/netdiscover"
  local status = read_json_file(state_root .. "/status.json") or { status = "idle" }
  local meta = read_json_file(state_root .. "/scan_meta.json") or {}

  status.scan_started = status.scan_started or meta.scan_started
  status.scan_finished = status.scan_finished or meta.scan_finished
  status.scan_duration_seconds = status.scan_duration_seconds or meta.scan_duration_seconds

  write_json(status)
end

function action_results()
  local results = read_json_file("/tmp/netdiscover/results.json")
  if type(results) ~= "table" then
    results = { meta = {}, devices = {} }
  end

  write_json(results)
end

function action_raw()
  local http = require "luci.http"
  local raw_root = "/tmp/netdiscover/raw"
  local source_key = http.formvalue("source") or ""
  local content = nil

  local file_map = {
    dhcp_leases = raw_root .. "/dhcp.leases",
    host_hints = raw_root .. "/host_hints.json",
    ip_neigh = raw_root .. "/ip_neigh.txt",
    ip_neigh_json = raw_root .. "/ip_neigh.json",
    bridge_fdb = raw_root .. "/bridge_fdb.txt",
    iw_dev = raw_root .. "/iw_dev.txt",
    nmap_ping = raw_root .. "/nmap_ping.grep",
    nmap_ports = raw_root .. "/nmap_ports.txt",
    scan_targets = raw_root .. "/scan_targets.txt",
    network_interface_dump = raw_root .. "/network_interface_dump.json"
  }

  if source_key == "arp_scan" then
    content = read_directory_matches(raw_root, "^arp_scan_.+%.txt$")
  elseif source_key == "iw_stations" then
    content = read_directory_matches(raw_root, "^iw_station_.+%.txt$")
  else
    local file_path = file_map[source_key]
    if file_path then
      content = read_text_file(file_path)
    end
  end

  http.prepare_content("text/plain")
  if content then
    http.write(content)
  else
    http.write("Not available.")
  end
end
