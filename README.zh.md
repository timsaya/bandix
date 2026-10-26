# Bandix

[English](README.md) | 简体中文

Bandix 是一个基于 eBPF 技术的网络流量监控工具，使用 Rust 开发，可以实时监控局域网设备的网络流量、连接统计和 DNS 查询。

## 主要功能

- **基于 eBPF 技术**：高效监控网络流量，无需修改内核代码
- **多模块监控**：支持流量监控、连接统计和 DNS 监控
- **双模式界面**：支持终端和 Web 界面显示模式
- **详细流量统计**：实时显示每个 IP 的上传/下载速率和总流量
- **多级数据存储**：分层采样（天/周/月级别），提供统计指标（平均值、最大值、最小值、百分位数）
- **连接统计**：监控每个设备的 TCP/UDP 连接及状态跟踪
- **MAC 地址识别**：自动关联 IP 地址与 MAC 地址
- **定时限速**：为设备设置基于时间的限速规则，支持灵活调度
- **流量配额**：按设备独立设置 WAN 上传、下载的每分钟、每小时、每天、每周、每月和累计流量上限，超限只阻断对应方向，同时兼容合计配额
- **主机名绑定**：自定义设备主机名映射，便于设备识别
- **高性能**：使用 Rust 和 eBPF 确保监控时对系统性能影响最小

## 技术特性

- 使用 aya 框架进行 eBPF 程序加载和管理
- 使用 tokio 实现异步 Web 服务器
- 支持跨平台编译，可在 X86/Arm 设备上部署
- 模块化架构，各监控模块独立运行

## 系统要求

- Linux 系统（支持 eBPF 的内核版本，推荐 6.0+）
- 需要 root 权限来加载 eBPF 程序

## 编译说明

```shell
./install_dependencies.sh

./build_release.sh
```

## 使用方法

```shell
sudo ./bandix --iface <网络接口名称> [选项]
```

### 命令行参数

- **--iface**: 要监控的网络接口（必需）
- **--host**: Web 服务器监听的 IPv4 或 IPv6 地址。调试版和发布版均默认为 `127.0.0.1`。使用 `0.0.0.0` 或 `::` 可监听所有 IPv4 或 IPv6 接口。
- **--port**: Web 服务器监听端口。默认值：`8686`
- **--data-dir**: 数据目录（环形文件和限速配置将存储在此处）。默认值：`bandix-data`
- **--log-level**: 日志级别：trace, debug, info, warn, error（默认：info）。Web 和 DNS 日志始终为 DEBUG 级别。
- **--tc-priority**: TC filter 优先级（数字越小优先级越高，0 = 内核自动分配）。默认值：0。用于控制与其他 eBPF TC 程序共存时的执行顺序。
- **--web-log**: 启用每个请求的 Web 日志记录。默认值：`false`
- **--enable-traffic**: 启用流量监控模块。默认值：`false`
- **--traffic-retention-seconds**: 实时指标的保留时长（秒），即环形文件容量（每秒一个槽位）。默认值：`600`
- **--traffic-flush-interval-seconds**: 流量数据刷新间隔（秒），将内存环形数据持久化到磁盘的频率。默认值：`600`
- **--traffic-persist-history**: 启用流量历史数据持久化到磁盘（默认禁用，数据仅存储在内存中）。默认值：`false`
- **--enable-dns**: 启用 DNS 监控模块。默认值：`false`
- **--dns-max-records**: 内存中保留的最大 DNS 记录数。默认值：`10000`
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

# 以较高优先级运行 bandix（在其他 TC 程序之前执行）
sudo ./bandix --iface br-lan --tc-priority 1 --enable-traffic

# 以较低优先级运行 bandix（在其他 TC 程序之后执行）
sudo ./bandix --iface br-lan --tc-priority 10 --enable-traffic
```

## API 接口

### 系统信息 API

#### GET /api/system/info

只读接口，仅返回当前运行的 Bandix Server 版本号。版本在编译时从 `bandix/Cargo.toml` 获取，不依赖监控模块是否启用。其他 HTTP 方法返回 405。

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

### 流量监控 API

#### GET /api/traffic/devices
获取所有设备的实时流量统计。

**响应：**
```json
{
  "status": "success",
  "data": {
    "d": [
      {
        "ip4": "192.168.1.100",
        "ip6": [],
        "mac": "00:11:22:33:44:55",
        "host": "我的设备",
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

**字段说明：** `d`=设备列表；`ip4`=IPv4；`ip6`=IPv6 地址列表；`host`=主机名；`conn`=连接类型(wifi/wired/router)；`t_rx_b`/`t_tx_b`=总收/发字节；`t_rx_r`/`t_tx_r`=总收/发速率；`w_rx_l`/`w_tx_l`=WAN 限速；`l_rx_b`/`l_tx_b`=LAN 字节；`l_rx_r`/`l_tx_r`=LAN 速率；`w_rx_b`/`w_tx_b`=WAN 字节；`w_rx_r`/`w_tx_r`=WAN 速率；`last`=最后在线时间戳(ms)。

`uplink` 为接入接口名；`w_ch` 为 Wi-Fi 主信道号；`w_freq` 为主信道实际频率（MHz），非 Wi-Fi 或无法读取时为 `0`。频率取自 `iw dev <接口> info`，与信道号一起每约 30 秒刷新。客户端应依据 `w_freq` 判断频段：不同频段的信道号会重叠，例如 6 GHz 的信道 5 为 5975 MHz，不能仅凭 `w_ch=5` 判断为 2.4 GHz。旧服务端缺少 `w_freq` 时应将频段视为未知。

#### DELETE /api/traffic/devices/batch

按 MAC 地址批量删除设备，清理范围与单设备删除接口 `DELETE /api/traffic/devices`（请求体 `{"mac":"00:11:22:33:44:55"}`）相同：设备记录、实时和长期流量历史、主机名绑定、限速白名单、定时限速、流量配额及用量、eBPF 流量和限制状态。DNS 查询记录不在清理范围内。

```sh
curl -X DELETE http://127.0.0.1:8686/api/traffic/devices/batch \
  -H 'Content-Type: application/json' \
  -d '{"macs":["00:11:22:33:44:55","00:11:22:33:44:66"]}'
```

**响应示例（HTTP 200）：**

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

- `macs` 必须包含 1–1000 个 MAC 地址。缺少请求体、JSON 格式错误、空列表、超出上限或任意 MAC 无效时返回 HTTP 400，且不会删除任何设备。
- MAC 地址按解析后的值去重（不区分十六进制字母大小写），响应地址统一为小写；各结果列表保留请求顺序。
- 合法请求返回 HTTP 200；`deleted` 为删除成功的地址，`not_found` 为不存在的地址，`failed` 为清理失败的条目（`{"mac":"...","message":"..."}`）。顶层 `success` 表示批次已处理，调用方需要检查 `failed`。
- 逐项执行，某项失败后继续处理其余设备。删除不具有事务性，失败项可能已有部分数据被清理。
- 在线设备可能被后台监控重新发现；删除操作不会阻止设备联网。

#### GET /api/traffic/limits/schedule
获取所有设备的定时限速设置。

**响应：**
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
为设备设置定时限速。

**请求体：**
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

**时间槽格式：**
- `start`: 开始时间，格式为 "HH:MM"（24小时制）
- `end`: 结束时间，格式为 "HH:MM"（24小时制，可以是 "24:00" 表示一天结束）
- `days`: 星期数组（1=周一，2=周二，...，7=周日）

#### DELETE /api/traffic/limits/schedule
删除设备的定时限速设置。

**请求体：**
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

流量及字节速度按 1024 换算，标为 KiB、MiB、GiB 和 KiB/s、MiB/s、GiB/s；比特速度按 1000 换算，标为 kbps、Mbps、Gbps。API 仍使用原始字节数或字节/秒，已有配额、限速及用量不变。

#### GET /api/traffic/quotas

响应包含 `data.supports_directional: true` 和 `data.supports_quota_modes: true`。后者表示支持互斥的配额模式，无配额记录时也可检测。每条配额的 `mode` 返回 `combined`（合计）或 `directional`（独立）。

获取所有设备的流量配额、当前用量及阻断状态。`upload`、`download` 分别统计 WAN 上传和下载，包含对应的上限、`*_used_bytes` 用量、`blocked` 和 `exceeded_periods`。顶层字段仍表示原有的上传与下载合计；顶层 `blocked` 表示至少一个方向受阻断，顶层 `exceeded_periods` 只列出达到的合计配额。分钟、小时、天、周、月按路由器本地时间重置（每周从周一开始），累计总量不自动重置。

#### POST /api/traffic/quotas

新增或更新设备配额。单位均为字节，`0` 表示该周期不限制。首次为设备创建配额后开始累计用量；更新配额会保留已有用量。

默认使用 `mode: "combined"`（合计模式），旧客户端不传模式时同样按合计处理。要独立配置上传、下载配额，需指定 `mode: "directional"` 并使用 `upload` 和 `download`。两者均支持 `minute_bytes`、`hourly_bytes`、`daily_bytes`、`weekly_bytes`、`monthly_bytes`、`total_bytes`；提供某个方向对象时，其内部未填写的周期默认为 `0`。例如每天允许上传 1 GiB、下载 5 GiB：

```json
{
  "mac": "00:11:22:33:44:55",
  "mode": "directional",
  "upload": { "daily_bytes": 1073741824 },
  "download": { "daily_bytes": 5368709120 }
}
```

独立模式下未提供的方向保留当前上限；`{ "mode": "directional", "upload": {} }` 会清除上传限制，但不清除用量。合计模式下未提供的顶层上限保留原值。保存任一模式都会清除另一模式的上限，并保留全部用量计数，两种模式不会同时生效。以下旧版合计配额请求继续兼容：

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

也可使用 `PUT` 提交相同请求。上传超额只阻断 WAN 上传，下载超额只阻断 WAN 下载；合计配额超额阻断两个方向。服务端强制两种模式互斥，即使客户端同时提交两组上限，也只保留所选模式的上限。IPv4/IPv6 均支持，LAN 通信不受影响。配额通过 TC eBPF 中的 WAN 累计字节绝对阈值逐包检查，不再等待用户态的一秒采样周期。跨过阈值的当前数据包会放行，后续数据包立即丢弃，因此通常只会超出约一个数据包；多队列并发处理时可能是少量同时处理的数据包。

上限和各方向用量以版本 2 格式持久保存，重启后恢复。版本 1 文件会自动迁移，保留原合计上限和用量；由于无法准确拆分历史合计用量，上传、下载独立计数从 `0` 开始。旧版客户端仍可管理合计配额；独立设置需要客户端明确选择独立模式并发送方向对象。未保存模式的旧记录加载时默认合计，并清除非当前模式的上限。旧服务端可继续使用原有合计字段；客户端应先检查 `supports_quota_modes` 再开放独立模式。

#### DELETE /api/traffic/quotas

删除设备配额及其累计用量，设备会在下一次监控周期（通常 1 秒内）解除配额阻断。

```json
{
  "mac": "00:11:22:33:44:55"
}
```

#### GET /api/traffic/metrics?mac=<mac地址>
获取实时历史流量指标（1秒采样间隔）。

**查询参数：**
- `mac`（可选）：设备的 MAC 地址。如果省略或设置为 "all"，则返回所有设备的聚合数据。

**响应：**
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

**指标数组格式（每项13个值）：**
每个数组包含：`[ts_ms, total_rx_rate, total_tx_rate, lan_rx_rate, lan_tx_rate, wan_rx_rate, wan_tx_rate, total_rx_bytes, total_tx_bytes, lan_rx_bytes, lan_tx_bytes, wan_rx_bytes, wan_tx_bytes]`

#### GET /api/traffic/metrics/day?mac=<mac地址>
获取天级别流量指标（包含统计信息，30秒采样间隔，保留1天）。

**查询参数：**
- `mac`（可选）：设备的 MAC 地址。如果省略或设置为 "all"，则返回所有设备的聚合数据。

**响应：**
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

**指标数组格式（每项15个值）：**
每个数组包含：`[ts_ms, wan_rx_rate_avg, wan_rx_rate_max, wan_rx_rate_min, wan_rx_rate_p90, wan_rx_rate_p95, wan_rx_rate_p99, wan_tx_rate_avg, wan_tx_rate_max, wan_tx_rate_min, wan_tx_rate_p90, wan_tx_rate_p95, wan_tx_rate_p99, wan_rx_bytes, wan_tx_bytes]`

#### GET /api/traffic/metrics/week?mac=<mac地址>
获取周级别流量指标（包含统计信息，3分钟采样间隔，保留1周）。

**查询参数：**
- `mac`（可选）：设备的 MAC 地址。如果省略或设置为 "all"，则返回所有设备的聚合数据。

**响应格式：** 与 `/api/traffic/metrics/day` 相同

#### GET /api/traffic/metrics/month?mac=<mac地址>
获取月级别流量指标（包含统计信息，10分钟采样间隔，保留1个月）。

**查询参数：**
- `mac`（可选）：设备的 MAC 地址。如果省略或设置为 "all"，则返回所有设备的聚合数据。

**响应格式：** 与 `/api/traffic/metrics/day` 相同

**注意：** 多级指标（day/week/month）仅包含广域网统计信息（外网流量），提供百分位数计算（平均值、最大值、最小值、p90、p95、p99）用于速率指标。不包含局域网流量或总流量统计。

#### GET /api/traffic/bindings
获取所有设备的主机名绑定。

**响应：**
```json
{
  "status": "success",
  "data": {
    "bindings": [
      {
        "mac": "00:11:22:33:44:55",
        "hostname": "我的设备"
      }
    ]
  }
}
```

#### POST /api/traffic/bindings
设置或更新设备的主机名绑定。要删除绑定，发送空的主机名。

**请求体：**
```json
{
  "mac": "00:11:22:33:44:55",
  "hostname": "我的设备"
}
```

#### GET /api/traffic/usage/ranking
获取设备流量使用排名。

**查询参数：**
- `start_ms`（可选）：开始时间戳（毫秒），默认 365 天前
- `end_ms`（可选）：结束时间戳（毫秒），默认当前
- `network_type`（可选）："wan"、"lan" 或 "all"，默认 "wan"

**响应：**
```json
{
  "status": "success",
  "data": {
    "start": 1710000000000,
    "end": 1710086400000,
    "net": "wan",
    "t_b": 10737418240,
    "t_rx_b": 5368709120,
    "t_tx_b": 5368709120,
    "cnt": 25,
    "r": [
      {
        "mac": "00:11:22:33:44:55",
        "host": "我的设备",
        "ip4": "192.168.1.100",
        "t_b": 1073741824,
        "rx_b": 536870912,
        "tx_b": 536870912,
        "pct": 10.5,
        "r": 1
      }
    ]
  }
}
```

**字段说明：** `start`/`end`=时间范围(ms)；`net`=网络类型；`t_b`=总字节；`t_rx_b`/`t_tx_b`=总收/发；`cnt`=设备数；`r`=排名列表；`rx_b`/`tx_b`=该设备收/发字节；`pct`=占比；`r`(条目内)=排名。

#### GET /api/traffic/usage/increments
获取时间序列流量增量（按小时或按日聚合）。

**查询参数：**
- `mac`（可选）：MAC 地址，省略或 "all" 表示聚合所有设备
- `start_ms`（可选）：开始时间戳（毫秒）
- `end_ms`（可选）：结束时间戳（毫秒）
- `aggregation`（可选）："hourly" 或 "daily"，默认 "hourly"
- `network_type`（可选）："wan"、"lan" 或 "all"

**响应：**
```json
{
  "status": "success",
  "data": {
    "start": 1710000000000,
    "end": 1710086400000,
    "agg": "hourly",
    "mac": "all",
    "net": "wan",
    "inc": [
      {
        "start": 1710000000000,
        "end": 1710003600000,
        "w_rx_avg": 1024,
        "w_rx_max": 2048,
        "w_rx_min": 512,
        "w_rx_p90": 1500,
        "w_rx_p95": 1800,
        "w_rx_p99": 2000,
        "w_tx_avg": 512,
        "w_tx_max": 1024,
        "w_tx_min": 256,
        "w_tx_p90": 800,
        "w_tx_p95": 900,
        "w_tx_p99": 950,
        "w_rx_b": 536870912,
        "w_tx_b": 268435456,
        "l_rx_avg": 512,
        "l_rx_max": 1024,
        "l_rx_min": 256,
        "l_rx_p90": 700,
        "l_rx_p95": 800,
        "l_rx_p99": 900,
        "l_tx_avg": 256,
        "l_tx_max": 512,
        "l_tx_min": 128,
        "l_tx_p90": 400,
        "l_tx_p95": 450,
        "l_tx_p99": 480,
        "l_rx_b": 268435456,
        "l_tx_b": 134217728
      }
    ],
    "t_rx_b": 10737418240,
    "t_tx_b": 5368709120,
    "t_b": 16106127360
  }
}
```

**字段说明：** `agg`=聚合粒度；`inc`=增量列表；`w_*`/`l_*`=WAN/LAN；`_avg`/`_max`/`_min`/`_p90`/`_p95`/`_p99`=速率统计；`_b`=字节增量。

### 连接统计 API

#### GET /api/connection/devices
获取所有设备的连接统计。

**响应：**
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
        "host": "我的设备",
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

**字段说明：**

**g（全局统计）：**
- `total`: TCP 和 UDP 连接总数
- `tcp`: TCP 连接总数
- `udp`: UDP 连接总数
- `tcp_est`: 活跃的 TCP 连接数（ESTABLISHED 状态）
- `tcp_tw`: TIME_WAIT 及类似关闭状态的 TCP 连接数
- `tcp_cw`: CLOSE_WAIT 状态的 TCP 连接数
- `last`: 最后更新时间（Unix 毫秒时间戳）

**d（设备列表）每项：**
- `mac`: 设备 MAC 地址
- `ip4`: 设备 IPv4 地址
- `host`: 主机名
- `tcp`/`udp`: TCP/UDP 连接数
- `tcp_est`/`tcp_tw`/`tcp_cw`: TCP 状态细分
- `total`: 该设备总连接数
- `last`: 最后更新时间（毫秒）

**顶层：** `cnt`=设备数；`last`=全局最后更新时间（毫秒）。

**注意：** 设备统计只计算出站连接。只包含在 ARP 表中且与指定网络接口在同一子网内的设备。所有时间戳均为毫秒。

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

### 流量统计（/api/traffic/devices 响应 key）

| 新 key | 含义 |
|--------|------|
| `ip4` | IPv4 地址 |
| `ip6` | IPv6 地址列表 |
| `mac` | MAC 地址 |
| `host` | 主机名 |
| `conn` | 连接类型（wifi/wired/router）|
| `t_rx_b`/`t_tx_b` | 总收/发字节 |
| `t_rx_r`/`t_tx_r` | 总收/发速率（字节/秒）|
| `w_rx_l`/`w_tx_l` | WAN 限速（字节/秒）|
| `l_rx_b`/`l_tx_b` | LAN 收/发字节 |
| `l_rx_r`/`l_tx_r` | LAN 收/发速率 |
| `w_rx_b`/`w_tx_b` | WAN 收/发字节 |
| `w_rx_r`/`w_tx_r` | WAN 收/发速率 |
| `last` | 最后在线时间戳（毫秒）|

### 连接统计（/api/connection/devices 响应 key）

| 新 key | 含义 |
|--------|------|
| `g` | 全局统计对象 |
| `d` | 设备列表 |
| `cnt` | 设备数量 |
| `total` | 总连接数 |
| `tcp`/`udp` | TCP/UDP 连接数 |
| `tcp_est` | ESTABLISHED 状态 TCP |
| `tcp_tw` | TIME_WAIT 状态 TCP |
| `tcp_cw` | CLOSE_WAIT 状态 TCP |
| `last` | 最后更新时间戳（毫秒）|

## 许可证

本项目采用 MIT 许可证。

## IP 归属地数据库（GeoIP）

连接明细支持在路由器本地查询 IPv4、IPv6 的国家/地区、省市和网络组织。
在 LuCI **设置 → 连接监控设置 → IP 归属地数据库** 中选择内容，点击“下载并启用”。
数据库不会随程序安装包内置，未安装数据库时不影响原有连接监控。

- 国家/地区：Country 数据库；国家/地区和网络组织：Country + ASN；省市和网络组织：City + ASN。
- 下载使用 P3TERX 的 GeoLite2 GitHub 发布版，核对固定版本的文件大小及 GitHub 提供的 SHA-256，并验证 MMDB 结构后再加载。
- 下载、取消、更新、启停、上传和删除均在设置页操作；离开页面后下载继续，重新打开可查看进度。
- 更新失败保留原库；相同版本不会重复下载。首次安装自动启用，后续更新保留已有启停状态。数据库切换无需重启服务。
- 可上传未压缩的 Country、City 或 ASN `.mmdb` 文件。先安装 Country/City，再上传 ASN，会保留原有位置库。
- 默认目录 `/usr/share/bandix-geoip`；可通过 `--geoip-dir` 或 OpenWrt 的 `bandix.connections.geoip_dir` 更改。
  建议使用持久存储或外置磁盘；更改 UCI 目录后先保存并应用。
- 启用状态、当前数据库组合及版本在目录内的 `state.json` 保存，进程重启后恢复。
- 数据库采用只读内存映射，按返回的连接页面去重查询，缓存最多 2048 个 IP；内网、回环、链路本地、共享地址等单独标记。
- 活跃数据库文件不可原地修改或截断。请通过管理接口更新，或停服后处理文件。

数据库来源：[P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb)。
数据提供者：[MaxMind GeoLite2](https://www.maxmind.com/en/geolite2/eula)。
数据库的数据条款与 Bandix 程序许可证分别适用；安装包不包含生产数据库。

### 管理 API

管理写操作仅接受路由器自身连接（loopback，或来源 IP 与接收连接的本地 IP 相同）；LuCI 通过带写权限的 `luci.bandix.manageGeoip` RPC 调用。

```sh
# 下载后校验、启用（后台执行）
curl -H 'Content-Type: application/json' -d '{"action":"download","profile":"country_asn"}' http://127.0.0.1:8686/api/geoip/manage
# 查看数据库及后台任务状态
curl http://127.0.0.1:8686/api/geoip/status
# 对当前页面附加按 IP 去重的 geoip 信息表，原地址及连接字段保持原义
curl 'http://127.0.0.1:8686/api/connection/flows?page=1&page_size=100&geoip=1'
```

`download` 的 `profile` 支持 `country`、`country_asn`、`city_asn` 和 `city`。
其余 action：`cancel`、`enable`（携带 boolean `enabled`）、`delete`、`import`。
`import` 仅接收固定上传暂存路径 `/tmp/bandix-geoip-upload.mmdb`，不接受客户端提供的任意文件路径。
分页响应的可选 `geoip` 字段包含地址范围、国家代码、多语言位置名称、ASN 和网络组织。
旧的不分页响应格式保持兼容；未请求 `geoip=1` 时不附加查询结果。

### 验证

```sh
cargo test -p bandix -p bandix-common
# 可选的真实下载验证（使用独立临时目录，需要访问 GitHub）
cargo test -p bandix --bin bandix live_country_asn_download -- --ignored --nocapture
BANDIX_GEOIP_LIVE_CITY=1 cargo test -p bandix --bin bandix live_country_asn_download -- --ignored --nocapture
```
