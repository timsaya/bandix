# Bandix

English| [简体中文](README.zh.md)

Bandix is a network traffic monitoring tool based on eBPF technology, developed in Rust, which can monitor network traffic, connection statistics, and DNS queries of devices in a local area network in real-time.

## Main Features

- **Based on eBPF Technology**: Efficiently monitor network traffic without modifying kernel code
- **Multi-module Monitoring**: Supports traffic monitoring, connection statistics, and DNS monitoring
- **Dual-mode Interface**: Supports both terminal and Web interface display modes
- **Detailed Traffic Statistics**: Real-time display of upload/download rates and total traffic for each IP
- **Connection Statistics**: Monitor TCP/UDP connections per device with state tracking
- **MAC Address Recognition**: Automatically associates IP addresses with MAC addresses
- **High Performance**: Uses Rust and eBPF to ensure minimal impact on system performance during monitoring

## Technical Features

- Uses the aya framework for eBPF program loading and management
- Implements asynchronous web server using tokio
- Supports cross-platform compilation, can be deployed on X86/Arm devices after cross-compilation
- Modular architecture with independent monitoring modules

## System Requirements

- Linux system (kernel version supporting eBPF, 6.0+ recommended)
- Root privileges required to load eBPF programs

## Usage

```shell
sudo ./bandix --iface <network_interface_name> [options]
```

### Command-line Options

- **--iface**: Network interface to monitor (required)
- **--port**: Web server listening port. Default: `8686`
- **--data-dir**: Data directory (ring files and rate limit configurations will be stored here). Default: `bandix-data`
- **--web-log**: Enable per-request web logging. Default: `false`
- **--enable-traffic**: Enable traffic monitoring module. Default: `false`
- **--traffic-retention-seconds**: Retention duration (seconds), i.e., ring file capacity (one slot per second). Default: `600`
- **--enable-dns**: Enable DNS monitoring module (not yet implemented). Default: `false`
- **--enable-connection**: Enable connection statistics monitoring module. Default: `false`

### Example Usage

```shell
# Enable traffic monitoring only
sudo ./bandix --iface br-lan --enable-traffic

# Enable both traffic and connection monitoring
sudo ./bandix --iface br-lan --enable-traffic --enable-connection

# Custom port and data directory
sudo ./bandix --iface br-lan --port 8080 --data-dir /var/lib/bandix --enable-traffic --enable-connection
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
        "local_rx_bytes": 512,
        "local_tx_bytes": 1024,
        "local_rx_rate": 50,
        "local_tx_rate": 100,
        "wide_rx_bytes": 512,
        "wide_tx_bytes": 1024,
        "wide_rx_rate": 50,
        "wide_tx_rate": 100,
        "wide_rx_rate_limit": 0,
        "wide_tx_rate_limit": 0,
        "last_online_ts": 1640995200000
      }
    ]
  }
}
```

#### GET /api/traffic/limits
Get current rate limits for all devices.

#### POST /api/traffic/limits
Set rate limits for devices.

**Request Body:**
```json
{
  "mac": "00:11:22:33:44:55",
  "wide_rx_rate_limit": 1048576,
  "wide_tx_rate_limit": 1048576
}
```

#### GET /api/traffic/metrics?mac=<mac_address>&duration=<seconds>
Get historical traffic metrics for a specific device.

**Response:**
```json
{
  "status": "success",
  "data": {
    "retention_seconds": 600,
    "mac": "00:11:22:33:44:55",
    "data": [
      {
        "ts_ms": 1640995200000,
        "total_rx_rate": 100,
        "total_tx_rate": 200,
        "local_rx_rate": 50,
        "local_tx_rate": 100,
        "wide_rx_rate": 50,
        "wide_tx_rate": 100,
        "total_rx_bytes": 1024,
        "total_tx_bytes": 2048,
        "local_rx_bytes": 512,
        "local_tx_bytes": 1024,
        "wide_rx_bytes": 512,
        "wide_tx_bytes": 1024
      }
    ]
  }
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
        "active_tcp": 5,
        "active_udp": 3,
        "closed_tcp": 2,
        "total_connections": 10,
        "last_updated": 1640995200
      }
    ],
    "total_devices": 1,
    "last_updated": 1640995200
  }
}
```

### DNS Monitoring API (Not Yet Implemented)

#### GET /api/dns/queries
Get recent DNS queries.

#### GET /api/dns/stats
Get DNS query statistics.

#### GET /api/dns/config
Get DNS monitoring configuration.

#### POST /api/dns/config
Update DNS monitoring configuration.

## Field Descriptions

### Traffic Statistics
- `ip`: Device IP address
- `mac`: Device MAC address
- `total_rx_bytes`: Total bytes received by the device
- `total_tx_bytes`: Total bytes sent by the device
- `total_rx_rate`: Current total receiving rate of the device (bytes/second)
- `total_tx_rate`: Current total sending rate of the device (bytes/second)
- `local_rx_bytes`: Local network receiving bytes
- `local_tx_bytes`: Local network sending bytes
- `local_rx_rate`: Local network receiving rate (bytes/second)
- `local_tx_rate`: Local network sending rate (bytes/second)
- `wide_rx_bytes`: Wide network receiving bytes
- `wide_tx_bytes`: Wide network sending bytes
- `wide_rx_rate`: Wide network receiving rate (bytes/second)
- `wide_tx_rate`: Wide network sending rate (bytes/second)
- `wide_rx_rate_limit`: Wide network download limit (bytes/second)
- `wide_tx_rate_limit`: Wide network upload limit (bytes/second)
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