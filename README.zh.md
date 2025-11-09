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
- **--enable-dns**: 启用 DNS 监控模块。默认值：`false`
- **--enable-connection**: 启用连接统计监控模块。默认值：`false`

### 使用示例

```shell
# 仅启用流量监控
sudo ./bandix --iface br-lan --enable-traffic

# 同时启用流量和连接监控
sudo ./bandix --iface br-lan --enable-traffic --enable-connection

# 启用 DNS 监控
sudo ./bandix --iface br-lan --enable-dns

# 启用所有监控模块
sudo ./bandix --iface br-lan --enable-traffic --enable-connection --enable-dns

# 自定义端口和数据目录
sudo ./bandix --iface br-lan --port 8080 --data-dir /var/lib/bandix --enable-traffic --enable-connection --enable-dns
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

### DNS 监控 API

#### GET /api/dns/queries
获取 DNS 查询记录，支持过滤和分页。

**查询参数：**
- `domain`（可选）：按域名过滤（不区分大小写的子串匹配）
- `device`（可选）：按设备 MAC 地址或主机名过滤（不区分大小写的子串匹配）
- `is_query`（可选）：按查询类型过滤 - `true` 仅查询，`false` 仅响应
- `page`（可选）：页码，默认值：`1`
- `page_size`（可选）：每页记录数，默认值：`20`，最大值：`1000`

**响应：**
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

**字段说明：**
- `timestamp`：Unix 时间戳（毫秒）
- `timestamp_formatted`：可读的本地时间字符串
- `domain`：查询的域名
- `query_type`：DNS 查询类型（A、AAAA、CNAME、HTTPS 等）
- `response_code`：响应状态码（"Success"、"Domain not found" 等）
- `response_time_ms`：响应时间（毫秒），如果没有匹配的响应则为 0
- `source_ip`：源 IP 地址
- `destination_ip`：目标 IP 地址
- `source_port`：源端口
- `destination_port`：目标端口
- `transaction_id`：DNS 事务 ID
- `is_query`：`true` 表示查询，`false` 表示响应
- `response_ips`：响应中返回的 IP 地址（用于 A/AAAA 记录）
- `response_records`：响应中的所有 DNS 记录（A、AAAA、CNAME、HTTPS 等）
- `device_mac`：设备 MAC 地址（来自查询源或响应目标）
- `device_name`：设备主机名（如果可用）

**使用示例：**
```bash
# 获取最新的 20 条 DNS 记录
GET /api/dns/queries

# 按域名过滤
GET /api/dns/queries?domain=baidu.com

# 按设备过滤
GET /api/dns/queries?device=MacBook

# 仅获取查询记录（不包括响应）
GET /api/dns/queries?is_query=true

# 分页查询，每页 50 条记录
GET /api/dns/queries?page=2&page_size=50

# 组合过滤
GET /api/dns/queries?domain=google&device=iPhone&page=1&page_size=100
```

**注意：** 记录按事务分组（查询和响应配对），并按最新时间排序。在每个组内，响应在查询之前显示。

#### GET /api/dns/stats
获取全面的 DNS 统计信息。

**响应：**
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

**统计分类：**

**基础计数：**
- `total_queries`：DNS 查询总数
- `total_responses`：DNS 响应总数
- `queries_with_response`：收到响应的查询数
- `queries_without_response`：无响应的查询数（超时/丢失）

**性能指标：**
- `avg_response_time_ms`：平均响应时间（毫秒）
- `min_response_time_ms`：最快响应时间
- `max_response_time_ms`：最慢响应时间
- `response_time_percentiles`：响应时间分布
  - `p50`：中位数（第 50 百分位）
  - `p90`：第 90 百分位
  - `p95`：第 95 百分位
  - `p99`：第 99 百分位

**成功/失败指标：**
- `success_count`：成功响应数（NoError）
- `failure_count`：失败响应数（错误）
- `success_rate`：成功率（0.0 - 1.0）
- `response_codes`：按响应码分类的统计（包含数量和百分比）

**Top 排行：**
- `top_domains`：最常查询的域名（前 10）
- `top_query_types`：最常用的查询类型（A、AAAA、HTTPS 等）
- `top_devices`：最活跃的设备（前 10，按主机名或 MAC）
- `top_dns_servers`：最常用的 DNS 服务器（前 5）

**设备统计：**
- `unique_devices`：进行 DNS 查询的唯一设备数

**时间范围：**
- `time_range_start`：最早记录时间戳（毫秒）
- `time_range_end`：最新记录时间戳（毫秒）
- `time_range_duration_minutes`：时间跨度（分钟）

#### GET /api/dns/config
获取 DNS 监控配置（尚未完全实现）。

#### POST /api/dns/config
更新 DNS 监控配置（尚未实现）。

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