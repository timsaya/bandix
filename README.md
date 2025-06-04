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

### Terminal Mode
```shell
sudo ./bandix -i <network_interface_name> --mode tui
```

### Web API Mode
```shell
sudo ./bandix -i <network_interface_name> --mode web --port <port_number>
```
Then access `http://localhost:<port_number>/api/devices` in your browser to get network traffic statistics.

```json
{
  "devices": [
    {
      "ip": "192.168.1.100",
      "mac": "00:11:22:33:44:55",
      "rx_bytes": 1024,
      "tx_bytes": 2048,
      "rx_rate": 100,
      "tx_rate": 200
    }
  ]
}
```

**Field Descriptions**:
- `ip`: Device IP address
- `mac`: Device MAC address
- `rx_bytes`: Total bytes received by the device
- `tx_bytes`: Total bytes sent by the device
- `rx_rate`: Current receiving rate of the device (bytes/second)
- `tx_rate`: Current sending rate of the device (bytes/second) 