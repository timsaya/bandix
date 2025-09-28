# Bandix

[English](README.md) | 简体中文

Bandix 是一个基于 eBPF 技术的网络流量监控工具，使用 Rust 开发，可以实时监控局域网设备的网络流量、连接统计和 DNS 查询。

## 主要功能

- **基于 eBPF 技术**：高效监控网络流量，无需修改内核代码
- **多模块监控**：支持流量监控、连接统计和 DNS 监控
- **双模式界面**：支持终端和 Web 界面显示模式
- **详细流量统计**：实时显示每个 IP 的上传/下载速率和总流量
- **连接统计**：监控每个设备的 TCP/UDP 连接及状态跟踪
- **MAC 地址识别**：自动关联 IP 地址与 MAC 地址
- **高性能**：使用 Rust 和 eBPF 确保监控时对系统性能影响最小

## 技术特性

- 使用 aya 框架进行 eBPF 程序加载和管理
- 使用 tokio 实现异步 Web 服务器
- 支持跨平台编译，可在 X86/Arm 设备上部署
- 模块化架构，各监控模块独立运行

## 系统要求

- Linux 系统（支持 eBPF 的内核版本，推荐 6.0+）
- 需要 root 权限来加载 eBPF 程序

## 使用方法

```shell
sudo ./bandix --iface <网络接口名称> [选项]
```

### 命令行参数

- **--iface**: 要监控的网络接口（必需）
- **--port**: Web 服务器监听端口。默认值：`8686`
- **--data-dir**: 数据目录（环形文件和限速配置将存储在此处）。默认值：`bandix-data`
- **--web-log**: 启用每个请求的 Web 日志记录。默认值：`false`
- **--enable-traffic**: 启用流量监控模块。默认值：`false`
- **--traffic-retention-seconds**: 保留时长（秒），即环形文件容量（每秒一个槽位）。默认值：`600`
- **--enable-dns**: 启用 DNS 监控模块（尚未实现）。默认值：`false`
- **--enable-connection**: 启用连接统计监控模块。默认值：`false`

### 使用示例

```shell
# 仅启用流量监控
sudo ./bandix --iface br-lan --enable-traffic

# 同时启用流量和连接监控
sudo ./bandix --iface br-lan --enable-traffic --enable-connection

# 自定义端口和数据目录
sudo ./bandix --iface br-lan --port 8080 --data-dir /var/lib/bandix --enable-traffic --enable-connection
```

## API 接口

### 流量监控 API

#### GET /api/traffic/devices
获取所有设备的实时流量统计。

**响应：**
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
获取所有设备的当前限速设置。

#### POST /api/traffic/limits
为设备设置限速。

**请求体：**
```json
{
  "mac": "00:11:22:33:44:55",
  "wide_rx_rate_limit": 1048576,
  "wide_tx_rate_limit": 1048576
}
```

#### GET /api/traffic/metrics?mac=<mac地址>&duration=<秒数>
获取特定设备的历史流量指标。

**响应：**
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

### 连接统计 API

#### GET /api/connection/devices
获取所有设备的连接统计。

**响应：**
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

**字段说明：**

**全局统计：**
- `total_connections`: TCP 和 UDP 连接总数
- `tcp_connections`: TCP 连接总数
- `udp_connections`: UDP 连接总数
- `established_tcp`: 活跃的 TCP 连接数（ESTABLISHED 状态）
- `time_wait_tcp`: TIME_WAIT 及类似关闭状态的 TCP 连接数
- `close_wait_tcp`: CLOSE_WAIT 状态的 TCP 连接数
- `last_updated`: 最后更新时间（Unix 时间戳）

**设备统计：**
- `mac_address`: 设备 MAC 地址
- `ip_address`: 设备 IP 地址
- `tcp_connections`: 该设备发起的 TCP 连接总数
- `udp_connections`: 该设备发起的 UDP 连接总数
- `established_tcp`: 活跃的 TCP 连接（ESTABLISHED 状态）
- `time_wait_tcp`: TIME_WAIT 及类似关闭状态的 TCP 连接
- `close_wait_tcp`: CLOSE_WAIT 状态的 TCP 连接
- `total_connections`: 该设备的总连接数（tcp_connections + udp_connections）
- `last_updated`: 最后更新时间（Unix 时间戳）

**注意：** 设备统计只计算出站连接（设备作为源地址的连接）。只包含在 ARP 表中且与指定网络接口在同一子网内的设备。

### DNS 监控 API（尚未实现）

#### GET /api/dns/queries
获取最近的 DNS 查询记录。

#### GET /api/dns/stats
获取 DNS 查询统计信息。

#### GET /api/dns/config
获取 DNS 监控配置。

#### POST /api/dns/config
更新 DNS 监控配置。

## 字段说明

### 流量统计
- `ip`: 设备 IP 地址
- `mac`: 设备 MAC 地址
- `total_rx_bytes`: 设备接收的总字节数
- `total_tx_bytes`: 设备发送的总字节数
- `total_rx_rate`: 设备当前总接收速率（字节/秒）
- `total_tx_rate`: 设备当前总发送速率（字节/秒）
- `local_rx_bytes`: 局域网接收字节数
- `local_tx_bytes`: 局域网发送字节数
- `local_rx_rate`: 局域网接收速率（字节/秒）
- `local_tx_rate`: 局域网发送速率（字节/秒）
- `wide_rx_bytes`: 广域网接收字节数
- `wide_tx_bytes`: 广域网发送字节数
- `wide_rx_rate`: 广域网接收速率（字节/秒）
- `wide_tx_rate`: 广域网发送速率（字节/秒）
- `wide_rx_rate_limit`: 广域网下载限制（字节/秒）
- `wide_tx_rate_limit`: 广域网上传限制（字节/秒）
- `last_online_ts`: 最后在线时间戳（自纪元以来的毫秒数）

### 连接统计
- `total_connections`: 总连接数
- `tcp_connections`: TCP 连接总数
- `udp_connections`: UDP 连接总数
- `established_tcp`: 已建立的 TCP 连接数
- `time_wait_tcp`: TIME_WAIT 状态的 TCP 连接数
- `close_wait_tcp`: CLOSE_WAIT 状态的 TCP 连接数
- `active_tcp`: 活跃的 TCP 连接数（ESTABLISHED 状态）
- `active_udp`: 活跃的 UDP 连接数
- `closed_tcp`: 已关闭的 TCP 连接数（TIME_WAIT、CLOSE_WAIT 等）
- `last_updated`: 最后更新时间戳（自纪元以来的秒数）

## 许可证

本项目采用 MIT 许可证。