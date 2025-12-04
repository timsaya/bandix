use crate::command::Options;
use crate::utils::network_utils;
use anyhow::Result;
use bandix_common::{ConnectionStats, DeviceConnectionStats};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};

/// Convert subnet mask to CIDR notation
fn subnet_mask_to_cidr(mask: [u8; 4]) -> u8 {
    let mut cidr = 0;
    for byte in mask.iter() {
        cidr += byte.count_ones() as u8;
    }
    cidr
}

/// Enhanced global connection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConnectionStats {
    // Total connection statistics (no filtering)
    pub total_stats: ConnectionStats,
    // Local network device connection statistics (based on ARP table)
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

/// Parse connection statistics from /proc/net/nf_conntrack
/// 1. Total stats: all TCP/UDP connections (no filtering)
/// 2. Device stats: connections for devices in ARP table AND in same subnet as interface
pub fn parse_connection_stats(
    interface_ip: [u8; 4],
    subnet_mask: [u8; 4],
) -> Result<GlobalConnectionStats> {
    let content = fs::read_to_string("/proc/net/nf_conntrack")?;
    let ip_mac_mapping = network_utils::get_ip_mac_mapping()?;

    // 1. Total connection statistics (no filtering)
    let mut total_stats = ConnectionStats::default();
    // 2. Local network device connection statistics (based on ARP table)
    let mut device_stats = HashMap::new();

    // Get current timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    total_stats.last_updated = timestamp;

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }

        // Parse connection line
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        // Extract protocol
        let protocol = parts.get(2).unwrap_or(&"");

        // Extract TCP state (only for TCP connections)
        let mut tcp_state = None;
        if protocol == &"tcp" {
            // For TCP, state is typically at position 5, but let's be more robust
            for (i, part) in parts.iter().enumerate() {
                if i >= 5 && !part.contains('=') && !part.starts_with('[') {
                    // This looks like a TCP state (no '=' and not a flag)
                    tcp_state = Some(*part);
                    break;
                }
            }
        }

        // Extract source and destination IP addresses (use first occurrence only)
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

        // ===== 1. Total connection statistics (no filtering, only TCP and UDP) =====
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
                            total_stats.time_wait_tcp += 1; // Categorized as TIME_WAIT
                            total_connection_counted = true;
                        }
                        _ => {
                            // Other TCP states: skip counting
                            log::debug!("Unknown TCP state '{}' skipped in global stats", state);
                        }
                    }
                } else {
                    // TCP connections without state: skip counting
                    log::debug!("TCP connection without state skipped in global stats");
                }
            }
            &"udp" => {
                total_stats.udp_connections += 1;
                total_connection_counted = true;
            }
            _ => {
                // Ignore other protocols
            }
        }

        if total_connection_counted {
            total_stats.total_connections += 1;
        }

        // ===== 2. Local network device connection statistics (requires ARP table and same subnet) =====
        // Find all IP addresses in ARP table and in same subnet
        let mut valid_device_ips = Vec::new();

        if let Some(ip) = src_ip {
            if ip_mac_mapping.contains_key(&ip)
                && network_utils::is_ip_in_subnet(ip, interface_ip, subnet_mask)
            {
                valid_device_ips.push(ip);
            }
        }
        if let Some(ip) = dst_ip {
            if ip_mac_mapping.contains_key(&ip)
                && network_utils::is_ip_in_subnet(ip, interface_ip, subnet_mask)
            {
                valid_device_ips.push(ip);
            }
        }

        // Skip device statistics if no valid device IPs found
        if valid_device_ips.is_empty() {
            continue;
        }

        // Count connections for each valid device IP
        for ip in valid_device_ips {
            let &mac = ip_mac_mapping.get(&ip).unwrap();

            // Update device statistics
            let device_stat = device_stats
                .entry(mac)
                .or_insert_with(|| DeviceConnectionStats {
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

            // Categorize and count by protocol and state
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
                                device_stat.time_wait_tcp += 1; // Categorized as TIME_WAIT
                                device_connection_counted = true;
                            }
                            _ => {
                                // Other TCP states: skip counting
                                log::debug!("Unknown TCP state '{}' skipped for device", state);
                            }
                        }
                    } else {
                        // TCP connections without state: skip counting
                        log::debug!("TCP connection without state skipped for device");
                    }
                }
                &"udp" => {
                    device_stat.udp_connections += 1;
                    device_connection_counted = true;
                }
                _ => {
                    // Ignore other protocols
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

/// Connection statistics module context
#[derive(Clone)]
pub struct ConnectionModuleContext {
    pub device_connection_stats: Arc<Mutex<GlobalConnectionStats>>,
    pub hostname_bindings: Arc<Mutex<HashMap<[u8; 6], String>>>,
    pub interface_ip: [u8; 4],
    pub subnet_mask: [u8; 4],
}

impl ConnectionModuleContext {
    /// Create connection module context with shared hostname bindings and subnet info
    pub fn new(
        _options: Options,
        hostname_bindings: Arc<Mutex<HashMap<[u8; 6], String>>>,
        interface_ip: [u8; 4],
        subnet_mask: [u8; 4],
    ) -> Self {
        Self {
            device_connection_stats: Arc::new(Mutex::new(GlobalConnectionStats::default())),
            hostname_bindings, // Use the shared hostname_bindings
            interface_ip,
            subnet_mask,
        }
    }
}

/// Connection statistics monitoring module
pub struct ConnectionMonitor;

impl ConnectionMonitor {
    pub fn new() -> Self {
        ConnectionMonitor
    }

    /// Start connection monitoring (includes internal loop)
    pub async fn start(
        &self,
        ctx: &mut ConnectionModuleContext,
        shutdown_notify: std::sync::Arc<tokio::sync::Notify>,
    ) -> Result<()> {
        // Start internal loop
        self.start_monitoring_loop(ctx, shutdown_notify).await
    }

    /// Connection monitoring internal loop
    async fn start_monitoring_loop(
        &self,
        ctx: &mut ConnectionModuleContext,
        shutdown_notify: std::sync::Arc<tokio::sync::Notify>,
    ) -> Result<()> {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3)); // Update every 3 second

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Parse connection statistics
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac_address() {
        let mac_str = "aa:bb:cc:dd:ee:ff";
        let result = network_utils::parse_mac_address(mac_str);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_connection_stats() {
        // This test will only work if /proc/net/nf_conntrack exists
        // and the process has permission to read it
        if std::path::Path::new("/proc/net/nf_conntrack").exists() {
            // Use a test subnet (192.168.1.0/24)
            let interface_ip = [192, 168, 1, 1];
            let subnet_mask = [255, 255, 255, 0];
            let result = parse_connection_stats(interface_ip, subnet_mask);
            assert!(result.is_ok());
        }
    }
}
