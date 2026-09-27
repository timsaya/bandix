use crate::command::Options;
use crate::utils::network_utils;
use anyhow::Result;
use bandix_common::{ConnectionStats, DeviceConnectionStats};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionFlowDetail {
    pub protocol: String,
    pub state: Option<String>,
    pub orig_src: IpAddr,
    pub orig_dst: IpAddr,
    pub orig_sport: u16,
    pub orig_dport: u16,
    pub repl_src: IpAddr,
    pub repl_dst: IpAddr,
    pub repl_sport: u16,
    pub repl_dport: u16,
    pub orig_packets: u64,
    pub orig_bytes: u64,
    pub repl_packets: u64,
    pub repl_bytes: u64,
    pub flags: Vec<String>,
}

/// 执行 `conntrack -L -f <family>` 并返回标准输出
fn run_conntrack(family: &str) -> Result<String> {
    let output = Command::new("conntrack").arg("-L").arg("-f").arg(family).output()?;
    if !output.status.success() {
        anyhow::bail!(
            "Failed to execute conntrack -L -f {}: {}",
            family,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// 同时取回 IPv4 和 IPv6 的 conntrack 表。
/// `conntrack -L` 不带 `-f` 时 family 缺省为 AF_INET，只会 dump IPv4 表项，
/// 所以 IPv6 必须单独取一次。两个协议族的输出格式一致，拼接后共用同一套解析逻辑。
fn dump_conntrack() -> Result<String> {
    let mut content = run_conntrack("ipv4")?;
    // 内核未启用 IPv6 conntrack 时这里会失败，不影响 IPv4 的统计
    match run_conntrack("ipv6") {
        Ok(ipv6) => content.push_str(&ipv6),
        Err(e) => log::debug!("IPv6 conntrack unavailable: {}", e),
    }
    Ok(content)
}

pub fn parse_connection_flows() -> Result<Vec<ConnectionFlowDetail>> {
    let content = dump_conntrack()?;
    let mut flows = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.contains("flow entries have been shown") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let protocol = parts.get(0).unwrap_or(&"").to_string();
        if protocol != "tcp" && protocol != "udp" {
            continue;
        }
        let mut tcp_state: Option<String> = None;
        if protocol == "tcp" {
            for (i, part) in parts.iter().enumerate() {
                if i >= 3 && !part.contains('=') && !part.starts_with('[') {
                    tcp_state = Some((*part).to_string());
                    break;
                }
            }
            if tcp_state.is_none() && parts.iter().any(|p| p.contains("OFFLOAD")) {
                tcp_state = Some("ESTABLISHED".to_string());
            }
        }
        let mut srcs: Vec<IpAddr> = Vec::new();
        let mut dsts: Vec<IpAddr> = Vec::new();
        let mut sports: Vec<u16> = Vec::new();
        let mut dports: Vec<u16> = Vec::new();
        let mut packets_list: Vec<u64> = Vec::new();
        let mut bytes_list: Vec<u64> = Vec::new();
        let mut flags: Vec<String> = Vec::new();
        for part in &parts {
            if part.starts_with("src=") {
                let s = &part[4..];
                if let Ok(ip) = s.parse::<IpAddr>() {
                    srcs.push(ip);
                }
            } else if part.starts_with("dst=") {
                let s = &part[4..];
                if let Ok(ip) = s.parse::<IpAddr>() {
                    dsts.push(ip);
                }
            } else if part.starts_with("sport=") {
                if let Ok(p) = (&part[6..]).parse::<u16>() {
                    sports.push(p);
                }
            } else if part.starts_with("dport=") {
                if let Ok(p) = (&part[6..]).parse::<u16>() {
                    dports.push(p);
                }
            } else if part.starts_with("packets=") {
                if let Ok(v) = (&part[8..]).parse::<u64>() {
                    packets_list.push(v);
                }
            } else if part.starts_with("bytes=") {
                if let Ok(v) = (&part[6..]).parse::<u64>() {
                    bytes_list.push(v);
                }
            } else if part.starts_with('[') && part.ends_with(']') {
                flags.push((*part).to_string());
            }
        }
        if srcs.len() < 2 || dsts.len() < 2 || sports.len() < 2 || dports.len() < 2 {
            continue;
        }
        let orig_packets = packets_list.get(0).copied().unwrap_or(0);
        let orig_bytes = bytes_list.get(0).copied().unwrap_or(0);
        let repl_packets = packets_list.get(1).copied().unwrap_or(0);
        let repl_bytes = bytes_list.get(1).copied().unwrap_or(0);
        flows.push(ConnectionFlowDetail {
            protocol,
            state: tcp_state,
            orig_src: srcs[0],
            orig_dst: dsts[0],
            orig_sport: sports[0],
            orig_dport: dports[0],
            repl_src: srcs[1],
            repl_dst: dsts[1],
            repl_sport: sports[1],
            repl_dport: dports[1],
            orig_packets,
            orig_bytes,
            repl_packets,
            repl_bytes,
            flags,
        });
    }
    Ok(flows)
}

/// 将子网掩码转换为 CIDR 表示法
fn subnet_mask_to_cidr(mask: [u8; 4]) -> u8 {
    let mut cidr = 0;
    for byte in mask.iter() {
        cidr += byte.count_ones() as u8;
    }
    cidr
}

/// 增强的全局连接统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConnectionStats {
    // 总连接统计（无过滤）
    pub total_stats: ConnectionStats,
    // lan 设备连接统计（基于 ARP 表）
    pub device_stats: HashMap<[u8; 6], DeviceConnectionStats>,
    pub last_updated: u64,
}

impl Default for GlobalConnectionStats {
    fn default() -> Self {
        Self {
            total_stats: ConnectionStats::default(),
            device_stats: HashMap::new(),
            last_updated: 0,
        }
    }
}

/// 构建 LAN 设备地址 → MAC 的查表，并给出每台设备用于展示的 IPv4 地址。
///
/// IPv4 沿用 ARP 表 + 接口子网判定；IPv6 用邻居表，但 `ip -6 neigh` 是全接口的，
/// 必须再用被监控接口自身的前缀过滤掉 WAN 侧邻居。link-local 前缀（fe80::/10）
/// 所有接口共用，区分不了 LAN/WAN，所以只取 GUA 和 ULA 前缀。
fn build_local_device_lookup(
    interface: &str,
    interface_ip: [u8; 4],
    subnet_mask: [u8; 4],
) -> Result<(HashMap<IpAddr, [u8; 6]>, HashMap<[u8; 6], [u8; 4]>)> {
    use crate::utils::network_utils::Ipv6AddressType;

    let mut lookup: HashMap<IpAddr, [u8; 6]> = HashMap::new();
    let mut device_ipv4: HashMap<[u8; 6], [u8; 4]> = HashMap::new();

    for (ip, mac) in network_utils::get_ip_mac_mapping()? {
        if network_utils::is_ip_in_subnet(ip, interface_ip, subnet_mask) {
            lookup.insert(IpAddr::from(ip), mac);
            device_ipv4.entry(mac).or_insert(ip);
        }
    }

    let prefixes: Vec<([u8; 16], u8)> = network_utils::get_interface_ipv6_info(interface)
        .into_iter()
        .filter(|(addr, _)| {
            matches!(
                network_utils::classify_ipv6_address(addr),
                Ipv6AddressType::GlobalUnicast | Ipv6AddressType::UniqueLocal
            )
        })
        .collect();

    if !prefixes.is_empty() {
        match network_utils::get_ipv6_neighbors() {
            Ok(neighbors) => {
                for (mac, addresses) in neighbors {
                    for addr in addresses {
                        if prefixes
                            .iter()
                            .any(|(prefix, prefix_len)| network_utils::is_ipv6_in_prefix(&addr, prefix, *prefix_len))
                        {
                            lookup.insert(IpAddr::from(addr), mac);
                        }
                    }
                }
            }
            Err(e) => log::debug!("Failed to read IPv6 neighbor table: {}", e),
        }
    }

    Ok((lookup, device_ipv4))
}

/// 从 conntrack 表解析连接统计信息（IPv4 + IPv6）
/// 1. 总统计：所有 TCP/UDP 连接（无过滤）
/// 2. 设备统计：源地址能归属到 LAN 设备的连接，IPv4 看 ARP 表 + 子网，IPv6 看邻居表 + 接口前缀
pub fn parse_connection_stats(interface: &str, interface_ip: [u8; 4], subnet_mask: [u8; 4]) -> Result<GlobalConnectionStats> {
    let content = dump_conntrack()?;
    let (device_lookup, device_ipv4) = build_local_device_lookup(interface, interface_ip, subnet_mask)?;

    // 1. 总连接统计（无过滤）
    let mut total_stats = ConnectionStats::default();
    // 2. 本地网络设备连接统计（基于 ARP 表）
    let mut device_stats = HashMap::new();

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    total_stats.last_updated = timestamp;

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        
        if line.contains("flow entries have been shown") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        let protocol = parts.get(0).unwrap_or(&"");

        let mut tcp_state: Option<&str> = None;
        if protocol == &"tcp" {
            for (i, part) in parts.iter().enumerate() {
                if i >= 3 && !part.contains('=') && !part.starts_with('[') {
                    tcp_state = Some(part);
                    break;
                }
            }
            if tcp_state.is_none() && parts.iter().any(|p| p.contains("OFFLOAD")) {
                tcp_state = Some("ESTABLISHED");
            }
        }

        // 提取源和目的 IP 地址（仅使用第一次出现）
        let mut src_ip: Option<IpAddr> = None;
        let mut dst_ip: Option<IpAddr> = None;

        for part in &parts {
            if part.starts_with("src=") && src_ip.is_none() {
                let ip_str = &part[4..]; // Remove "src=" prefix
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    src_ip = Some(ip);
                }
            } else if part.starts_with("dst=") && dst_ip.is_none() {
                let ip_str = &part[4..]; // Remove "dst=" prefix
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    dst_ip = Some(ip);
                }
            }
        }

        // ===== 1. 总连接统计（无过滤，仅 TCP 和 UDP）=====
        let mut total_connection_counted = false;

        match protocol {
            &"tcp" => {
                if let Some(state) = tcp_state {
                    match state {
                        "ESTABLISHED" => {
                            total_stats.tcp_connections += 1;
                            total_stats.established_tcp += 1;
                            total_connection_counted = true;
                        }
                        "TIME_WAIT" => {
                            total_stats.tcp_connections += 1;
                            total_stats.time_wait_tcp += 1;
                            total_connection_counted = true;
                        }
                        "CLOSE_WAIT" => {
                            total_stats.tcp_connections += 1;
                            total_stats.close_wait_tcp += 1;
                            total_connection_counted = true;
                        }
                        "FIN_WAIT_1" | "FIN_WAIT_2" | "CLOSING" | "LAST_ACK" => {
                            total_stats.tcp_connections += 1;
                            total_stats.time_wait_tcp += 1;
                            total_connection_counted = true;
                        }
                        _ => {
                            log::debug!("Unknown TCP state '{}' skipped in global statistics", state);
                        }
                    }
                }
            }
            &"udp" => {
                total_stats.udp_connections += 1;
                total_connection_counted = true;
            }
            _ => {
                // 忽略其他协议
            }
        }

        if total_connection_counted {
            total_stats.total_connections += 1;
        }

        // ===== 2. 本地网络设备连接统计（以设备为 src 的视角）=====
        // 仅当 src 能归属到一台 LAN 设备时计入该设备（IPv4 走 ARP 表，IPv6 走邻居表）
        let device_mac = src_ip.and_then(|ip| device_lookup.get(&ip).copied());

        if let Some(mac) = device_mac {
            // 设备级统计按 MAC 聚合，展示用的 IPv4 地址取自 ARP 表（纯 IPv6 设备为 0.0.0.0）
            let ip_address = device_ipv4.get(&mac).copied().unwrap_or([0, 0, 0, 0]);

            // Update device statistics
            let device_stat = device_stats.entry(mac).or_insert_with(|| DeviceConnectionStats {
                mac_address: mac,
                ip_address,
                tcp_connections: 0,
                udp_connections: 0,
                established_tcp: 0,
                time_wait_tcp: 0,
                close_wait_tcp: 0,
                total_connections: 0,
                last_updated: timestamp,
            });

            // 按协议和状态分类并计数
            let mut device_connection_counted = false;

            match protocol {
                &"tcp" => {
                    if let Some(state) = tcp_state {
                        match state {
                            "ESTABLISHED" => {
                                device_stat.tcp_connections += 1;
                                device_stat.established_tcp += 1;
                                device_connection_counted = true;
                            }
                            "TIME_WAIT" => {
                                device_stat.tcp_connections += 1;
                                device_stat.time_wait_tcp += 1;
                                device_connection_counted = true;
                            }
                            "CLOSE_WAIT" => {
                                device_stat.tcp_connections += 1;
                                device_stat.close_wait_tcp += 1;
                                device_connection_counted = true;
                            }
                            "FIN_WAIT_1" | "FIN_WAIT_2" | "CLOSING" | "LAST_ACK" => {
                                device_stat.tcp_connections += 1;
                                device_stat.time_wait_tcp += 1;
                                device_connection_counted = true;
                            }
                            _ => {
                                log::debug!("Unknown TCP state '{}' skipped for device", state);
                            }
                        }
                    }
                }
                &"udp" => {
                    device_stat.udp_connections += 1;
                    device_connection_counted = true;
                }
                _ => {
                    // 忽略其他协议
                }
            }

            if device_connection_counted {
                device_stat.total_connections += 1;
            }
        }
    }

    Ok(GlobalConnectionStats {
        total_stats,
        device_stats,
        last_updated: timestamp,
    })
}

/// 连接 statistics module context
#[derive(Clone)]
pub struct ConnectionModuleContext {
    pub device_connection_stats: Arc<Mutex<GlobalConnectionStats>>,
    pub hostname_bindings: Arc<Mutex<HashMap<[u8; 6], String>>>,
    pub interface_ip: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub interface: String,
}

impl ConnectionModuleContext {
    /// 创建带有共享主机名绑定和子网信息的连接模块上下文
    pub fn new(
        options: Options,
        hostname_bindings: Arc<Mutex<HashMap<[u8; 6], String>>>,
        interface_ip: [u8; 4],
        subnet_mask: [u8; 4],
    ) -> Self {
        Self {
            device_connection_stats: Arc::new(Mutex::new(GlobalConnectionStats::default())),
            hostname_bindings, // 使用共享的主机名绑定
            interface_ip,
            subnet_mask,
            interface: options.iface().to_string(),
        }
    }
}

/// 连接 statistics monitoring module
pub struct ConnectionMonitor;

impl ConnectionMonitor {
    pub fn new() -> Self {
        ConnectionMonitor
    }

    /// 开始连接监控（包括内部循环）
    pub async fn start(&self, ctx: &mut ConnectionModuleContext, shutdown_notify: std::sync::Arc<tokio::sync::Notify>) -> Result<()> {
        // 开始内部循环
        self.start_monitoring_loop(ctx, shutdown_notify).await
    }

    /// 连接监控内部循环
    async fn start_monitoring_loop(
        &self,
        ctx: &mut ConnectionModuleContext,
        shutdown_notify: std::sync::Arc<tokio::sync::Notify>,
    ) -> Result<()> {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3)); // 每 3 秒更新一次

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // 解析连接统计信息
                    match parse_connection_stats(&ctx.interface, ctx.interface_ip, ctx.subnet_mask) {
                        Ok(new_stats) => {
                            // Update the shared connection statistics
                            {
                                let mut stats = ctx.device_connection_stats.lock().unwrap();
                                *stats = new_stats.clone();
                            }

                            log::debug!(
                                "Connection stats updated: {} devices, total_connections={}, interface={}",
                                new_stats.device_stats.len(),
                                new_stats.total_stats.total_connections,
                                format!("{}.{}.{}.{}/{}",
                                    ctx.interface_ip[0], ctx.interface_ip[1], ctx.interface_ip[2], ctx.interface_ip[3],
                                    subnet_mask_to_cidr(ctx.subnet_mask)
                                )
                            );
                        }
                        Err(e) => {
                            log::error!("Failed to parse connection statistics: {}", e);
                        }
                    }
                }
                _ = shutdown_notify.notified() => {
                    log::info!("Connection monitoring module received shutdown signal, stopping...");
                    break;
                }
            }
        }

        Ok(())
    }
}

