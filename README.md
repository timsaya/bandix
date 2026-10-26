# Bandix

English| [简体中文](README.zh.md)

Bandix is a network traffic monitoring tool based on eBPF technology, developed in Rust, which can monitor network traffic, connection statistics, and DNS queries of devices in a local area network in real-time.

## Main Features

- **Based on eBPF Technology**: Efficiently monitor network traffic without modifying kernel code
- **Multi-module Monitoring**: Supports traffic monitoring, connection statistics, and DNS monitoring
- **Dual-mode Interface**: Supports both terminal and Web interface display modes
- **Detailed Traffic Statistics**: Real-time display of upload/download rates and total traffic for each IP
- **Multi-level Data Storage**: Hierarchical sampling with day/week/month levels, providing statistical metrics (avg, max, min, percentiles)
- **Connection Statistics**: Monitor TCP/UDP connections per device with state tracking
- **MAC Address Recognition**: Automatically associates IP addresses with MAC addresses
- **Scheduled Rate Limiting**: Set time-based rate limits for devices with flexible scheduling
- **Traffic Quotas**: Set per-minute, hourly, daily, weekly, monthly, and lifetime WAN usage limits per device
- **Hostname Bindings**: Custom device hostname mapping for better device identification
- **High Performance**: Uses Rust and eBPF to ensure minimal impact on system performance during monitoring

## Technical Features

- Uses the aya framework for eBPF program loading and management
- Implements asynchronous web server using tokio
- Supports cross-platform compilation, can be deployed on X86/Arm devices after cross-compilation
- Modular architecture with independent monitoring modules

## System Requirements

- Linux system (kernel version supporting eBPF, 6.0+ recommended)
- Root privileges required to load eBPF programs

## Build Instructions

```shell
./install_dependencies.sh

./build_release.sh
```

## Usage

```shell
sudo ./bandix --iface <network_interface_name> [options]
```

### Command-line Options

- **--iface**: Network interface to monitor (required)
- **--host**: Web server listening IPv4 or IPv6 address. Default: `127.0.0.1` (debug and release). Use `0.0.0.0` or `::` to listen on all IPv4 or IPv6 interfaces.
- **--port**: Web server listening port. Default: `8686`
- **--data-dir**: Data directory (ring files and rate limit configurations will be stored here). Default: `bandix-data`
- **--log-level**: Log level: trace, debug, info, warn, error (default: info). Web and DNS logs are always at DEBUG level.
- **--tc-priority**: TC filter priority (lower number = higher priority, 0 = kernel auto-assign). Default: 0. Use this to control execution order when running alongside other eBPF TC programs.
- **--web-log**: Enable per-request web logging. Default: `false`
- **--enable-traffic**: Enable traffic monitoring module. Default: `false`
- **--traffic-retention-seconds**: Retention duration (seconds) for real-time metrics, i.e., ring file capacity (one slot per second). Default: `600`
- **--traffic-flush-interval-seconds**: Traffic data flush interval (seconds), how often to persist memory ring data to disk. Default: `600`
- **--traffic-persist-history**: Enable traffic history data persistence to disk (disabled by default, data only stored in memory). Default: `false`
- **--enable-dns**: Enable DNS monitoring module. Default: `false`
- **--dns-max-records**: Maximum number of DNS records to keep in memory. Default: `10000`
- **--enable-connection**: Enable connection statistics monitoring module. Default: `false`

### Example Usage

```shell
# Enable traffic monitoring only
sudo ./bandix --iface br-lan --enable-traffic

# Enable both traffic and connection monitoring
sudo ./bandix --iface br-lan --enable-traffic --enable-connection

# Enable DNS monitoring
sudo ./bandix --iface br-lan --enable-dns

# Enable all monitoring modules
sudo ./bandix --iface br-lan --enable-traffic --enable-connection --enable-dns

# Listen on a specific address (the HTTP API has no authentication; restrict access to trusted clients)
sudo ./bandix --iface br-lan --host 192.168.2.1 --enable-connection

# Custom port and data directory
sudo ./bandix --iface br-lan --port 8080 --data-dir /var/lib/bandix --enable-traffic --enable-connection --enable-dns

# Run bandix with higher priority (execute before other TC programs)
sudo ./bandix --iface br-lan --tc-priority 1 --enable-traffic

# Run bandix with lower priority (execute after other TC programs)
sudo ./bandix --iface br-lan --tc-priority 10 --enable-traffic
```

## API Endpoints

### System Information API

#### GET /api/system/info

Read-only endpoint returning only the running Bandix Server version. The version is taken from `bandix/Cargo.toml` at compile time. Available regardless of which monitoring modules are enabled. Other HTTP methods return 405.

```sh
curl http://127.0.0.1:8686/api/system/info
```

```json
{
  "status": "success",
  "data": {
    "version": "0.12.11"
  },
  "message": null
}
```

### Traffic Monitoring API

#### GET /api/traffic/devices
Get real-time traffic statistics for all devices.

**Response:**
```json
{
  "status": "success",
  "data": {
    "d": [
      {
        "ip4": "192.168.1.100",
        "ip6": [],
        "mac": "00:11:22:33:44:55",
        "host": "MyDevice",
        "conn": "wifi",
        "uplink": "phy2-ap0",
        "w_ch": 5,
        "w_freq": 5975,
        "t_rx_b": 1024,
        "t_tx_b": 2048,
        "t_rx_r": 100,
        "t_tx_r": 200,
        "w_rx_l": 0,
        "w_tx_l": 0,
        "l_rx_b": 512,
        "l_tx_b": 1024,
        "l_rx_r": 50,
        "l_tx_r": 100,
        "w_rx_b": 512,
        "w_tx_b": 1024,
        "w_rx_r": 50,
        "w_tx_r": 100,
        "last": 1640995200000
      }
    ]
  }
}
```

**Fields:** `d`=devices; `ip4`=IPv4; `ip6`=IPv6 list; `host`=hostname; `conn`=connection type; `t_rx_b`/`t_tx_b`=total bytes; `t_rx_r`/`t_tx_r`=total rate; `w_rx_l`/`w_tx_l`=WAN limits; `l_*`=LAN; `w_*`=WAN; `last`=last online timestamp (ms).

`uplink` identifies the ingress interface; `w_ch` is the primary Wi-Fi channel; `w_freq` is its actual frequency in MHz, or `0` for non-Wi-Fi/unknown. Both are read from `iw dev <interface> info` and refreshed approximately every 30 seconds. Clients must determine the band from `w_freq`: channel numbers overlap across bands (6 GHz channel 5 is 5975 MHz). Treat the band as unknown when older servers omit `w_freq`.

#### DELETE /api/traffic/devices/batch

Delete devices by MAC address using the same cleanup as `DELETE /api/traffic/devices` (single-device body: `{"mac":"00:11:22:33:44:55"}`). Removes device records, realtime and long-term traffic history, hostname bindings, rate-limit whitelist entries, scheduled limits, quotas and usage, and eBPF traffic/limit state. DNS query records are retained.

```sh
curl -X DELETE http://127.0.0.1:8686/api/traffic/devices/batch \
  -H 'Content-Type: application/json' \
  -d '{"macs":["00:11:22:33:44:55","00:11:22:33:44:66"]}'
```

**Example response (HTTP 200):**

```json
{
  "status": "success",
  "data": {
    "deleted": ["00:11:22:33:44:55"],
    "not_found": ["00:11:22:33:44:66"],
    "failed": []
  },
  "message": null
}
```

- `macs` must contain 1–1000 MAC addresses. Missing bodies, malformed JSON, empty or oversized lists, and invalid MAC addresses return HTTP 400 before any deletion.
- Addresses are deduplicated by their parsed value, including case variants, and returned in lowercase. Each result list preserves request order.
- Valid batches return HTTP 200. `deleted` lists successful deletions, `not_found` lists missing devices, and `failed` contains cleanup errors (`{"mac":"...","message":"..."}`). Top-level `success` means the batch was processed; callers must check `failed`.
- Devices are processed individually; a cleanup failure does not stop subsequent deletions. Cleanup is not transactional: a failed item may already have lost some state.
- Online devices may be rediscovered by background monitoring. Deletion does not block network access.

#### GET /api/traffic/limits/schedule
Get all scheduled rate limits for devices.

**Response:**
```json
{
  "status": "success",
  "data": {
    "limits": [
      {
        "mac": "00:11:22:33:44:55",
        "time_slot": {
          "start": "09:00",
          "end": "18:00",
          "days": [1, 2, 3, 4, 5]
        },
        "wan_rx_rate_limit": 1048576,
        "wan_tx_rate_limit": 1048576
      }
    ]
  }
}
```

#### POST /api/traffic/limits/schedule
Set scheduled rate limits for devices.

**Request Body:**
```json
{
  "mac": "00:11:22:33:44:55",
  "time_slot": {
    "start": "09:00",
    "end": "18:00",
    "days": [1, 2, 3, 4, 5]
  },
  "wan_rx_rate_limit": 1048576,
  "wan_tx_rate_limit": 1048576
}
```

**Time Slot Format:**
- `start`: Start time in "HH:MM" format (24-hour)
- `end`: End time in "HH:MM" format (24-hour, can be "24:00" for end of day)
- `days`: Array of day numbers (1=Monday, 2=Tuesday, ..., 7=Sunday)

#### DELETE /api/traffic/limits/schedule
Delete a scheduled rate limit.

**Request Body:**
```json
{
  "mac": "00:11:22:33:44:55",
  "time_slot": {
    "start": "09:00",
    "end": "18:00",
    "days": [1, 2, 3, 4, 5]
  }
}
```

Traffic sizes and byte rates use binary prefixes (KiB, MiB, GiB and KiB/s, MiB/s, GiB/s), with a factor of 1024 per step. Bit rates use decimal prefixes (kbps, Mbps, Gbps), with a factor of 1000 per step. API values remain raw bytes or bytes per second; existing limits and usage are unchanged.

#### GET /api/traffic/quotas

The response includes `data.supports_directional: true` and `data.supports_quota_modes: true`. The latter advertises mutually exclusive quota modes, including when no quotas exist. Each quota reports `mode` as `combined` or `directional`.

Returns every device quota, current usage, exceeded periods, and blocking state. WAN upload and download are counted independently in `upload` and `download`; the top-level fields retain their legacy combined meaning. Each direction contains limits, `*_used_bytes`, `blocked`, and `exceeded_periods`. Top-level `blocked` means at least one direction is blocked; top-level `exceeded_periods` lists combined limits that were reached. Minute/hour/day/week/month periods follow the router's local calendar (weeks start on Monday); lifetime usage never resets automatically.

#### POST /api/traffic/quotas

Creates or updates a device quota. All values are bytes and `0` means unlimited for that period. Usage begins when the quota is first created and is retained when limits are updated. `PUT` accepts the same request.

The default `mode` is `combined`, including requests from legacy clients that omit it. Set `mode: "directional"` and use `upload` and `download` to configure independent limits. Each accepts `minute_bytes`, `hourly_bytes`, `daily_bytes`, `weekly_bytes`, `monthly_bytes`, and `total_bytes`; omitted fields inside a supplied direction default to zero. For example, allow 1 GiB of uploads and 5 GiB of downloads per day:

```json
{
  "mac": "00:11:22:33:44:55",
  "mode": "directional",
  "upload": { "daily_bytes": 1073741824 },
  "download": { "daily_bytes": 5368709120 }
}
```

Within directional mode, an omitted direction retains its current limits; `{ "mode": "directional", "upload": {} }` clears upload limits without clearing usage. Within combined mode, omitted top-level limits retain their values. Saving either mode clears the inactive mode’s limits, while retaining all usage counters. Modes never apply simultaneously. The following legacy combined configuration remains supported:

```json
{
  "mac": "00:11:22:33:44:55",
  "minute_bytes": 104857600,
  "hourly_bytes": 1073741824,
  "daily_bytes": 5368709120,
  "weekly_bytes": 21474836480,
  "monthly_bytes": 53687091200,
  "total_bytes": 107374182400
}
```

Reaching an upload limit blocks only WAN upload; reaching a download limit blocks only WAN download. A combined limit blocks both directions. Combined and directional limits are mutually exclusive, enforced by the service even if a client submits both sets. IPv4 and IPv6 are covered; LAN traffic is unaffected. Enforcement uses absolute WAN-byte thresholds in the TC eBPF program, so packets are checked in the kernel rather than waiting for the one-second userspace sampling cycle. The packet that crosses a threshold is allowed; subsequent packets are dropped, limiting normal overshoot to roughly one packet (or a small number of concurrently processed packets).

Limits and directional usage survive restarts in quota storage schema version 2. Version 1 files are migrated automatically: existing combined limits and usage are retained, while directional counters start at zero because historical combined usage cannot be split accurately. Existing clients can continue to manage combined limits; independent controls require a client that explicitly selects directional mode and sends the direction objects. Stored quotas without a mode default to combined on load; inactive limits are cleared. Older services support the legacy combined fields; clients must check `supports_quota_modes` before offering directional mode.

#### DELETE /api/traffic/quotas

Deletes the device quota and its accumulated usage. The quota block is removed on the next monitoring cycle (normally within one second).

```json
{
  "mac": "00:11:22:33:44:55"
}
```

#### GET /api/traffic/metrics?mac=<mac_address>
Get real-time historical traffic metrics (1-second sampling).

**Query Parameters:**
- `mac` (optional): MAC address of the device. If omitted or set to "all", returns aggregated data for all devices.

**Response:**
```json
{
  "status": "success",
  "data": {
    "retention_seconds": 600,
    "mac": "00:11:22:33:44:55",
    "metrics": [
      [1640995200000, 100, 200, 50, 100, 50, 100, 1024, 2048, 512, 1024, 512, 1024]
    ]
  }
}
```

**Metrics Array Format (13 values per entry):**
Each array contains: `[ts_ms, total_rx_rate, total_tx_rate, lan_rx_rate, lan_tx_rate, wan_rx_rate, wan_tx_rate, total_rx_bytes, total_tx_bytes, lan_rx_bytes, lan_tx_bytes, wan_rx_bytes, wan_tx_bytes]`

#### GET /api/traffic/metrics/day?mac=<mac_address>
Get day-level traffic metrics with statistics (30-second sampling interval, 1-day retention).

**Query Parameters:**
- `mac` (optional): MAC address of the device. If omitted or set to "all", returns aggregated data for all devices.

**Response:**
```json
{
  "status": "success",
  "data": {
    "retention_seconds": 86400,
    "mac": "00:11:22:33:44:55",
    "metrics": [
      [1640995200000, 1250000, 5000000, 500000, 2000000, 4000000, 4800000, 1500000, 6000000, 800000, 2500000, 4500000, 5500000, 1073741824, 2147483648]
    ]
  }
}
```

**Metrics Array Format (15 values per entry):**
Each array contains: `[ts_ms, wan_rx_rate_avg, wan_rx_rate_max, wan_rx_rate_min, wan_rx_rate_p90, wan_rx_rate_p95, wan_rx_rate_p99, wan_tx_rate_avg, wan_tx_rate_max, wan_tx_rate_min, wan_tx_rate_p90, wan_tx_rate_p95, wan_tx_rate_p99, wan_rx_bytes, wan_tx_bytes]`

#### GET /api/traffic/metrics/week?mac=<mac_address>
Get week-level traffic metrics with statistics (3-minute sampling interval, 1-week retention).

**Query Parameters:**
- `mac` (optional): MAC address of the device. If omitted or set to "all", returns aggregated data for all devices.

**Response Format:** Same as `/api/traffic/metrics/day`

#### GET /api/traffic/metrics/month?mac=<mac_address>
Get month-level traffic metrics with statistics (10-minute sampling interval, 1-month retention).

**Query Parameters:**
- `mac` (optional): MAC address of the device. If omitted or set to "all", returns aggregated data for all devices.

**Response Format:** Same as `/api/traffic/metrics/day`

**Note:** Multi-level metrics (day/week/month) only contain wide network statistics (external traffic) with percentile calculations (avg, max, min, p90, p95, p99) for rate metrics. They do not include local network traffic or total traffic statistics.

#### GET /api/traffic/bindings
Get all hostname bindings for devices.

**Response:**
```json
{
  "status": "success",
  "data": {
    "bindings": [
      {
        "mac": "00:11:22:33:44:55",
        "hostname": "MyDevice"
      }
    ]
  }
}
```

#### POST /api/traffic/bindings
Set or update hostname binding for a device. To remove a binding, send an empty hostname.

**Request Body:**
```json
{
  "mac": "00:11:22:33:44:55",
  "hostname": "MyDevice"
}
```

#### GET /api/traffic/usage/ranking
Get device traffic usage ranking.

**Query Parameters:** `start_ms`, `end_ms`, `network_type` (wan/lan/all)

**Response:** `start`, `end`, `net`, `t_b`, `t_rx_b`, `t_tx_b`, `cnt`, `r` (array with `mac`, `host`, `ip4`, `t_b`, `rx_b`, `tx_b`, `pct`, `r`).

#### GET /api/traffic/usage/increments
Get time-series traffic increments (hourly or daily).

**Query Parameters:** `mac`, `start_ms`, `end_ms`, `aggregation` (hourly/daily), `network_type`

**Response:** `start`, `end`, `agg`, `net`, `inc` (array of increments with `w_rx_avg`/`w_tx_b` etc.), `t_rx_b`, `t_tx_b`, `t_b`.

### Connection Statistics API

#### GET /api/connection/devices
Get connection statistics for all devices.

**Response:**
```json
{
  "status": "success",
  "data": {
    "g": {
      "total": 150,
      "tcp": 120,
      "udp": 30,
      "tcp_est": 80,
      "tcp_tw": 40,
      "tcp_cw": 0,
      "last": 1640995200000
    },
    "d": [
      {
        "mac": "00:11:22:33:44:55",
        "ip4": "192.168.1.100",
        "host": "MyDevice",
        "tcp": 7,
        "udp": 3,
        "tcp_est": 5,
        "tcp_tw": 2,
        "tcp_cw": 0,
        "total": 10,
        "last": 1640995200000
      }
    ],
    "cnt": 1,
    "last": 1640995200000
  }
}
```

**Fields:** `g`=global stats; `d`=devices; `cnt`=device count; `tcp_est`/`tcp_tw`/`tcp_cw`=TCP states; all timestamps in milliseconds.

**Global (g):** `total`, `tcp`, `udp`, `tcp_est`, `tcp_tw`, `tcp_cw`, `last` (ms).

**Device (d):** `mac`, `ip4`, `host`, `tcp`, `udp`, `tcp_est`, `tcp_tw`, `tcp_cw`, `total`, `last` (ms).

**Note:** Device statistics only count outgoing connections. Only devices in the ARP table within the interface subnet are included. All timestamps in milliseconds.

### DNS Monitoring API

#### GET /api/dns/queries
Get DNS query records with filtering and pagination support.

**Query Parameters:**
- `domain` (optional): Filter by domain name (case-insensitive substring match)
- `device` (optional): Filter by device MAC address or hostname (case-insensitive substring match)
- `is_query` (optional): Filter by query type - `true` for queries only, `false` for responses only
- `page` (optional): Page number, default: `1`
- `page_size` (optional): Records per page, default: `20`, max: `1000`

**Response:**
```json
{
  "status": "success",
  "data": {
    "queries": [
      {
        "timestamp": 1762676738185,
        "timestamp_formatted": "2025-11-09 16:25:38.185",
        "domain": "www.baidu.com.",
        "query_type": "A",
        "response_code": "Success",
        "response_time_ms": 15,
        "source_ip": "192.168.2.154",
        "destination_ip": "8.8.8.8",
        "source_port": 53569,
        "destination_port": 53,
        "transaction_id": 62111,
        "is_query": true,
        "response_ips": [],
        "response_records": [],
        "device_mac": "aa:bb:cc:dd:ee:ff",
        "device_name": "MacBook-Pro"
      }
    ],
    "total": 156,
    "page": 1,
    "page_size": 20,
    "total_pages": 8
  }
}
```

**Field Descriptions:**
- `timestamp`: Unix timestamp in milliseconds
- `timestamp_formatted`: Human-readable local time string
- `domain`: Queried domain name
- `query_type`: DNS query type (A, AAAA, CNAME, HTTPS, etc.)
- `response_code`: Response status ("Success", "Domain not found", etc.)
- `response_time_ms`: Response time in milliseconds (0 if no response matched)
- `source_ip`: Source IP address
- `destination_ip`: Destination IP address
- `source_port`: Source port
- `destination_port`: Destination port
- `transaction_id`: DNS transaction ID
- `is_query`: `true` for query, `false` for response
- `response_ips`: IP addresses returned in response (for A/AAAA records)
- `response_records`: All DNS records in response (A, AAAA, CNAME, HTTPS, etc.)
- `device_mac`: Device MAC address (from query source or response destination)
- `device_name`: Device hostname (if available)

**Usage Examples:**
```bash
# Get latest 20 DNS records
GET /api/dns/queries

# Filter by domain
GET /api/dns/queries?domain=baidu.com

# Filter by device
GET /api/dns/queries?device=MacBook

# Get only queries (exclude responses)
GET /api/dns/queries?is_query=true

# Pagination with 50 records per page
GET /api/dns/queries?page=2&page_size=50

# Combined filters
GET /api/dns/queries?domain=google&device=iPhone&page=1&page_size=100
```

**Note:** Records are grouped by transaction (query and response pairs) and sorted by newest first. Within each group, response appears before query.

#### GET /api/dns/stats
Get comprehensive DNS statistics.

**Response:**
```json
{
  "status": "success",
  "data": {
    "stats": {
      "total_queries": 1250,
      "total_responses": 1200,
      "queries_with_response": 1200,
      "queries_without_response": 50,
      
      "avg_response_time_ms": 15.5,
      "min_response_time_ms": 1,
      "max_response_time_ms": 250,
      "response_time_percentiles": {
        "p50": 12,
        "p90": 28,
        "p95": 45,
        "p99": 120
      },
      
      "success_count": 1150,
      "failure_count": 50,
      "success_rate": 0.958,
      "response_codes": [
        {
          "code": "Success",
          "count": 1150,
          "percentage": 0.958
        },
        {
          "code": "Domain not found",
          "count": 30,
          "percentage": 0.025
        }
      ],
      
      "top_domains": [
        { "name": "www.baidu.com.", "count": 156 },
        { "name": "www.google.com.", "count": 98 }
      ],
      
      "top_query_types": [
        { "name": "A", "count": 650 },
        { "name": "AAAA", "count": 400 },
        { "name": "HTTPS", "count": 200 }
      ],
      
      "top_devices": [
        { "name": "MacBook-Pro", "count": 456 },
        { "name": "iPhone-12", "count": 234 }
      ],
      
      "top_dns_servers": [
        { "name": "8.8.8.8", "count": 800 },
        { "name": "192.168.2.1", "count": 450 }
      ],
      
      "unique_devices": 15,
      
      "time_range_start": 1762676738100,
      "time_range_end": 1762680338100,
      "time_range_duration_minutes": 60
    }
  }
}
```

**Statistics Categories:**

**Basic Counts:**
- `total_queries`: Total number of DNS queries
- `total_responses`: Total number of DNS responses
- `queries_with_response`: Queries that received a response
- `queries_without_response`: Queries without response (timeout/lost)

**Performance Metrics:**
- `avg_response_time_ms`: Average response time in milliseconds
- `min_response_time_ms`: Fastest response time
- `max_response_time_ms`: Slowest response time
- `response_time_percentiles`: Response time distribution
  - `p50`: Median (50th percentile)
  - `p90`: 90th percentile
  - `p95`: 95th percentile
  - `p99`: 99th percentile

**Success/Failure Metrics:**
- `success_count`: Number of successful responses (NoError)
- `failure_count`: Number of failed responses (errors)
- `success_rate`: Success rate (0.0 - 1.0)
- `response_codes`: Breakdown by response code with counts and percentages

**Top Rankings:**
- `top_domains`: Most queried domains (top 10)
- `top_query_types`: Most used query types (A, AAAA, HTTPS, etc.)
- `top_devices`: Most active devices (top 10, by hostname or MAC)
- `top_dns_servers`: Most used DNS servers (top 5)

**Device Statistics:**
- `unique_devices`: Number of unique devices making DNS queries

**Time Range:**
- `time_range_start`: Earliest record timestamp (milliseconds)
- `time_range_end`: Latest record timestamp (milliseconds)
- `time_range_duration_minutes`: Time span in minutes

#### GET /api/dns/config
Get DNS monitoring configuration (Not Yet Fully Implemented).

#### POST /api/dns/config
Update DNS monitoring configuration (Not Yet Implemented).

## Field Descriptions

### Traffic Statistics (/api/traffic/devices response keys)
- `ip4`: IPv4 address | `ip6`: IPv6 list | `mac`: MAC | `host`: hostname | `conn`: connection type
- `t_rx_b`/`t_tx_b`: total bytes | `t_rx_r`/`t_tx_r`: total rate | `w_rx_l`/`w_tx_l`: WAN limits
- `l_rx_b`/`l_tx_b`: LAN bytes | `l_rx_r`/`l_tx_r`: LAN rate | `w_rx_b`/`w_tx_b`: WAN bytes | `w_rx_r`/`w_tx_r`: WAN rate
- `last`: last online timestamp (ms)

### Connection Statistics (/api/connection/devices response keys)
- `g`: global stats | `d`: device list | `cnt`: device count
- `total`, `tcp`, `udp`, `tcp_est`, `tcp_tw`, `tcp_cw`, `last` (ms)

## License

This project is licensed under the MIT License.

## Offline IP location databases (GeoIP)

In LuCI, open **Settings → Connection Monitor Settings → IP location database**.
Choose Country, Country + ASN, or City + ASN and click **Download and enable**.
Production databases are optional downloads, not embedded in the Bandix package.
Downloads run in the background and report progress after reopening the page.

Bandix uses the P3TERX GeoLite2 GitHub release, pins the selected release asset,
checks its size and GitHub-provided SHA-256, validates the MMDB structure, and
activates an immutable generation atomically. Failed/cancelled updates retain the
previous database; already-current versions are not downloaded again. First
installation enables lookup; later updates preserve the current enable state.

Country/City/ASN `.mmdb` files can also be uploaded; install location data before
adding ASN. Database readers are memory mapped, lookups are deduplicated after
pagination, and the result cache is bounded to 2048 IPs. Existing flow addresses
and legacy responses retain their semantics.

The default directory is `/usr/share/bandix-geoip`; override it with `--geoip-dir`
or OpenWrt's `bandix.connections.geoip_dir`. Enable state, profile and version are
persisted there. Do not modify or truncate active MMDB files in place. Updates
through the manager do not require restarting the service.

- `GET /api/geoip/status`: installed files, storage, enable state and job progress.
- `POST /api/geoip/manage`: `download` (`profile`: `country`, `country_asn`,
  `city_asn`, or `city`), `cancel`, `enable` (boolean `enabled`), `delete`, `import`.
- Management writes accept only the router itself (loopback or a source IP matching the accepted socket's local IP); LuCI exposes them through its write ACL.
- `import` reads only `/tmp/bandix-geoip-upload.mmdb`, never a client-supplied path.
- `GET /api/connection/flows?page=1&page_size=100&geoip=1`: adds an optional,
  deduplicated `geoip` map to the paged response. No enrichment for legacy arrays.

Source: [P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb).
Data: [MaxMind GeoLite2 terms](https://www.maxmind.com/en/geolite2/eula), separate
from the application license. Production databases are not included in packages.

Run `cargo test -p bandix -p bandix-common` for offline validation. The ignored
`live_country_asn_download` test verifies real downloads in a temporary directory;
set `BANDIX_GEOIP_LIVE_CITY=1` to verify City + ASN instead.
