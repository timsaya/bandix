use crate::command::Options;
use crate::utils::network_utils;
use anyhow::Result;
use bandix_common::{ConnectionStats, DeviceConnectionStats};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionFlowDetail {
    pub protocol: String,
    pub state: Option<String>,
    pub orig_src: [u8; 4],
    pub orig_dst: [u8; 4],
    pub orig_sport: u16,
    pub orig_dport: u16,
    pub repl_src: [u8; 4],
    pub repl_dst: [u8; 4],
    pub repl_sport: u16,
    pub repl_dport: u16,
    pub orig_packets: u64,
    pub orig_bytes: u64,
    pub repl_packets: u64,
    pub repl_bytes: u64,
    pub flags: Vec<String>,
}

pub fn parse_connection_flows() -> Result<Vec<ConnectionFlowDetail>> {
    let output = Command::new("conntrack").arg("-L").output()?;
    if !output.status.success() {
        anyhow::bail!(
            "Failed to execute conntrack -L: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let content = String::from_utf8_lossy(&output.stdout);
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
        let mut srcs: Vec<[u8; 4]> = Vec::new();
        let mut dsts: Vec<[u8; 4]> = Vec::new();
        let mut sports: Vec<u16> = Vec::new();
        let mut dports: Vec<u16> = Vec::new();
        let mut packets_list: Vec<u64> = Vec::new();
        let mut bytes_list: Vec<u64> = Vec::new();
        let mut flags: Vec<String> = Vec::new();
        for part in &parts {
            if part.starts_with("src=") {
                let s = &part[4..];
                if let Ok(ip) = s.parse::<std::net::Ipv4Addr>() {
                    srcs.push(ip.octets());
                }
            } else if part.starts_with("dst=") {
                let s = &part[4..];
                if let Ok(ip) = s.parse::<std::net::Ipv4Addr>() {
                    dsts.push(ip.octets());
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

/// 从 conntrack -L 命令解析连接统计信息
/// 1. 总统计：所有 TCP/UDP 连接（无过滤）
/// 2. 设备统计：ARP 表中且与接口在同一子网中的设备的连接
pub fn parse_connection_stats(interface_ip: [u8; 4], subnet_mask: [u8; 4]) -> Result<GlobalConnectionStats> {
    let output = Command::new("conntrack")
        .arg("-L")
        .output()?;
    
    if !output.status.success() {
        anyhow::bail!("Failed to execute conntrack -L: {}", String::from_utf8_lossy(&output.stderr));
    }
    
    let content = String::from_utf8_lossy(&output.stdout);
    let ip_mac_mapping = network_utils::get_ip_mac_mapping()?;

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
        let mut src_ip = None;
        let mut dst_ip = None;

        for part in &parts {
            if part.starts_with("src=") && src_ip.is_none() {
                let ip_str = &part[4..]; // Remove "src=" prefix
                if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                    src_ip = Some(ip.octets());
                }
            } else if part.starts_with("dst=") && dst_ip.is_none() {
                let ip_str = &part[4..]; // Remove "dst=" prefix
                if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                    dst_ip = Some(ip.octets());
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
        // 仅当 src 是 ARP 表中且在相同子网的 LAN 设备时计入该设备
        let valid_device_ip = src_ip.and_then(|ip| {
            if ip_mac_mapping.contains_key(&ip) && network_utils::is_ip_in_subnet(ip, interface_ip, subnet_mask) {
                Some(ip)
            } else {
                None
            }
        });

        if let Some(ip) = valid_device_ip {
            let &mac = ip_mac_mapping.get(&ip).unwrap();

            // Update device statistics
            let device_stat = device_stats.entry(mac).or_insert_with(|| DeviceConnectionStats {
                mac_address: mac,
                ip_address: ip,
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
}

impl ConnectionModuleContext {
    /// 创建带有共享主机名绑定和子网信息的连接模块上下文
    pub fn new(
        _options: Options,
        hostname_bindings: Arc<Mutex<HashMap<[u8; 6], String>>>,
        interface_ip: [u8; 4],
        subnet_mask: [u8; 4],
    ) -> Self {
        Self {
            device_connection_stats: Arc::new(Mutex::new(GlobalConnectionStats::default())),
            hostname_bindings, // 使用共享的主机名绑定
            interface_ip,
            subnet_mask,
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
                    match parse_connection_stats(ctx.interface_ip, ctx.subnet_mask) {
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

