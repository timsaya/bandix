# Bandix

简体中文 | [English](README.en.md)

Bandix 是一个基于 eBPF 技术的网络流量监控工具，使用 Rust 语言开发，可以实时监控局域网内各设备的网络流量和速率。

## 主要功能

- **基于 eBPF 技术**：无需修改内核代码，高效监控网络流量
- **双模式界面**：支持终端 (TUI) 和 Web 界面两种显示模式
- **详细的流量统计**：实时显示每个 IP 的上传/下载速率和总流量
- **MAC 地址识别**：自动关联 IP 地址和 MAC 地址
- **高性能**：使用 Rust 和 eBPF 确保监控过程对系统性能影响最小

## 技术特点

- 使用 aya 框架实现 eBPF 程序加载和管理
- 利用 tokio 实现异步 Web 服务器
- 支持跨平台编译，可在交叉编译后部署到 X86/Arm 等设备
## 系统要求

- Linux 系统 (支持 eBPF 的内核版本，推荐 5.4+)
- 需要 root 权限以加载 eBPF 程序

## 使用方法

### 终端模式
```shell
sudo ./bandix -i <网络接口名称> --mode tui
```

### Web API 模式
```shell
sudo ./bandix -i <网络接口名称> --mode web --port <端口号>
```


##### 1. 获取网络流量统计
- **URL**: `http://localhost:<端口号>/api/devices`
- **方法**: GET
- **响应示例**:
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

**字段说明**:
- `ip`: 设备IP地址
- `mac`: 设备MAC地址
- `rx_bytes`: 设备接收的总字节数
- `tx_bytes`: 设备发送的总字节数
- `rx_rate`: 设备当前接收速率（字节/秒）
- `tx_rate`: 设备当前发送速率（字节/秒）

##### 2. 绑定设备名称
- **URL**: `http://localhost:<端口号>/api/bind`
- **方法**: POST
- **请求体**:
```json
{
  "mac": "da:d9:be:02:79:c5",
  "hostname": "ubuntu.local"
}
```

**字段说明**:
- `mac`: 设备MAC地址
- `hostname`: 设备自定义名称

---
