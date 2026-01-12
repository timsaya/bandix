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
- **--port**: Web server listening port. Default: `8686`
- **--data-dir**: Data directory (ring files and rate limit configurations will be stored here). Default: `bandix-data`
- **--log-level**: Log level: trace, debug, info, warn, error (default: info). Web and DNS logs are always at DEBUG level.
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

# Custom port and data directory
sudo ./bandix --iface br-lan --port 8080 --data-dir /var/lib/bandix --enable-traffic --enable-connection --enable-dns
```

## API Endpoints

### Traffic Monitoring API

#### GET /api/traffic/devices
Get real-time traffic statistics for all devices.

**Response:**
```json
{
  "status": "success",
  "data": {
    "devices": [
      {
        "ip": "192.168.1.100",
        "mac": "00:11:22:33:44:55",
        "total_rx_bytes": 1024,
        "total_tx_bytes": 2048,
        "total_rx_rate": 100,
        "total_tx_rate": 200,
        "lan_rx_bytes": 512,
        "lan_tx_bytes": 1024,
        "lan_rx_rate": 50,
        "lan_tx_rate": 100,
        "wan_rx_bytes": 512,
        "wan_tx_bytes": 1024,
        "wan_rx_rate": 50,
        "wan_tx_rate": 100,
        "wan_rx_rate_limit": 0,
        "wan_tx_rate_limit": 0,
        "last_online_ts": 1640995200000
      }
    ]
  }
}
```

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

### Connection Statistics API

#### GET /api/connection/devices
Get connection statistics for all devices.

**Response:**
```json
{
  "status": "success",
  "data": {
    "global_stats": {
      "total_connections": 150,
      "tcp_connections": 120,
      "udp_connections": 30,
      "established_tcp": 80,
      "time_wait_tcp": 40,
      "close_wait_tcp": 0,
      "last_updated": 1640995200
    },
    "devices": [
      {
        "mac_address": "00:11:22:33:44:55",
        "ip_address": "192.168.1.100",
        "tcp_connections": 7,
        "udp_connections": 3,
        "established_tcp": 5,
        "time_wait_tcp": 2,
        "close_wait_tcp": 0,
        "total_connections": 10,
        "last_updated": 1640995200
      }
    ],
    "total_devices": 1,
    "last_updated": 1640995200
  }
}
```

**Field Descriptions:**

**Global Statistics:**
- `total_connections`: Total number of TCP and UDP connections
- `tcp_connections`: Total number of TCP connections
- `udp_connections`: Total number of UDP connections
- `established_tcp`: Number of active TCP connections (ESTABLISHED state)
- `time_wait_tcp`: Number of TCP connections in TIME_WAIT and similar closing states
- `close_wait_tcp`: Number of TCP connections in CLOSE_WAIT state
- `last_updated`: Unix timestamp of last update

**Device Statistics:**
- `mac_address`: Device MAC address
- `ip_address`: Device IP address
- `tcp_connections`: Total TCP connections initiated by this device
- `udp_connections`: Total UDP connections initiated by this device
- `established_tcp`: Active TCP connections (ESTABLISHED state)
- `time_wait_tcp`: TCP connections in TIME_WAIT and similar closing states
- `close_wait_tcp`: TCP connections in CLOSE_WAIT state
- `total_connections`: Total connections for this device (tcp_connections + udp_connections)
- `last_updated`: Unix timestamp of last update

**Note:** Device statistics only count outgoing connections (where the device is the source). Only devices present in the ARP table and within the same subnet as the specified network interface are included.

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

### Traffic Statistics
- `ip`: Device IP address
- `mac`: Device MAC address
- `total_rx_bytes`: Total bytes received by the device
- `total_tx_bytes`: Total bytes sent by the device
- `total_rx_rate`: Current total receiving rate of the device (bytes/second)
- `total_tx_rate`: Current total sending rate of the device (bytes/second)
- `lan_rx_bytes`: Local network receiving bytes
- `lan_tx_bytes`: Local network sending bytes
- `lan_rx_rate`: Local network receiving rate (bytes/second)
- `lan_tx_rate`: Local network sending rate (bytes/second)
- `wan_rx_bytes`: Wide network receiving bytes
- `wan_tx_bytes`: Wide network sending bytes
- `wan_rx_rate`: Wide network receiving rate (bytes/second)
- `wan_tx_rate`: Wide network sending rate (bytes/second)
- `wan_rx_rate_limit`: Wide network download limit (bytes/second)
- `wan_tx_rate_limit`: Wide network upload limit (bytes/second)
- `last_online_ts`: Last online timestamp (milliseconds since epoch)

### Connection Statistics
- `total_connections`: Total number of connections
- `tcp_connections`: Total number of TCP connections
- `udp_connections`: Total number of UDP connections
- `established_tcp`: Number of established TCP connections
- `time_wait_tcp`: Number of TCP connections in TIME_WAIT state
- `close_wait_tcp`: Number of TCP connections in CLOSE_WAIT state
- `active_tcp`: Number of active TCP connections (ESTABLISHED state)
- `active_udp`: Number of active UDP connections
- `closed_tcp`: Number of closed TCP connections (TIME_WAIT, CLOSE_WAIT, etc.)
- `last_updated`: Last update timestamp (seconds since epoch)

## License

This project is licensed under the MIT License.