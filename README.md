# Bandix

English| [简体中文](README.zh.md)

Bandix is a network traffic monitoring tool based on eBPF technology, developed in Rust, which can monitor network traffic and speed of devices in a local area network in real-time.

## Main Features

- **Based on eBPF Technology**: Efficiently monitor network traffic without modifying kernel code
- **Dual-mode Interface**: Supports both terminal and Web interface display modes
- **Detailed Traffic Statistics**: Real-time display of upload/download rates and total traffic for each IP
- **MAC Address Recognition**: Automatically associates IP addresses with MAC addresses
- **High Performance**: Uses Rust and eBPF to ensure minimal impact on system performance during monitoring

## Technical Features

- Uses the aya framework for eBPF program loading and management
- Implements asynchronous web server using tokio
- Supports cross-platform compilation, can be deployed on X86/Arm devices after cross-compilation

## System Requirements

- Linux system (kernel version supporting eBPF, 5.4+ recommended)
- Root privileges required to load eBPF programs

## Usage

```shell
sudo ./bandix --iface <network_interface_name>  --port <port_number>
```
### Command-line options

- **--iface, -i**: Network interface to monitor. Default: `br-lan`.
- **--port, -p**: Web server listening port. Default: `8686`.
- **--data-dir**: Data directory (ring files and rate limit configurations will be stored here). Default: `bandix-data`.
- **--retention-seconds**: Retention duration (seconds), i.e., ring file capacity (one slot per second). Default: `600`.
- **--web-log**: Enable per-request web logging. Default: disabled.


```json
{
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
      "wide_tx_rate_limit": 0
    }
  ]
}
```

**Field Descriptions**:
- `ip`: Device IP address
- `mac`: Device MAC address
- `total_rx_bytes`: Total bytes received by the device
- `total_tx_bytes`: Total bytes sent by the device
- `total_rx_rate`: Current total receiving rate of the device (bytes/second)
- `total_tx_rate`: Current total sending rate of the device (bytes/second)
- `wide_rx_rate_limit`: Wide network download limit (bytes/second)
- `wide_tx_rate_limit`: Wide network upload limit (bytes/second)
- `local_rx_bytes`: Local network receiving bytes
- `local_tx_bytes`: Local network sending bytes
- `local_rx_rate`: Local network receiving rate (bytes/second)
- `local_tx_rate`: Local network sending rate (bytes/second)
- `wide_rx_bytes`: Wide network receiving bytes
- `wide_tx_bytes`: Wide network sending bytes
- `wide_rx_rate`: Wide network receiving rate (bytes/second)
- `wide_tx_rate`: Wide network sending rate (bytes/second) 