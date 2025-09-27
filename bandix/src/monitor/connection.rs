use crate::command::Options;
use crate::utils::network_utils;
use anyhow::Result;
use bandix_common::{ConnectionStats, DeviceConnectionStats};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};

/// Format IP address for display
fn format_ip(ip: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

/// Global connection statistics with device breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConnectionStats {
    pub global_stats: ConnectionStats,
    pub device_stats: HashMap<[u8; 6], DeviceConnectionStats>,
    pub last_updated: u64,
}

impl Default for GlobalConnectionStats {
    fn default() -> Self {
        Self {
            global_stats: ConnectionStats::default(),
            device_stats: HashMap::new(),
            last_updated: 0,
        }
    }
}

/// Parse connection statistics grouped by device from /proc/net/nf_conntrack
/// Only includes connections where source or destination IP is in the same subnet as the interface
/// and the IP has a corresponding MAC address in the ARP table
pub fn parse_device_connection_stats(interface_ip: [u8; 4], subnet_mask: [u8; 4]) -> Result<GlobalConnectionStats> {
    let content = fs::read_to_string("/proc/net/nf_conntrack")?;
    let ip_mac_mapping = network_utils::get_ip_mac_mapping()?;

    let mut global_stats = ConnectionStats::default();
    let mut device_stats = HashMap::new();

    // Get current timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    global_stats.last_updated = timestamp;

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }

        // Parse connection line
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        // Extract protocol and state
        let protocol = parts.get(2).unwrap_or(&"");
        let mut tcp_state = None;

        // Look for TCP state (it's the 6th field in nf_conntrack output)
        if parts.len() > 5 {
            tcp_state = Some(parts[5]);
        }

        // Extract source and destination IP addresses
        let mut src_ip = None;
        let mut dst_ip = None;
        
        for part in &parts {
            if part.starts_with("src=") {
                let ip_str = &part[4..]; // Remove "src=" prefix
                if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                    src_ip = Some(ip.octets());
                }
            } else if part.starts_with("dst=") {
                let ip_str = &part[4..]; // Remove "dst=" prefix
                if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                    dst_ip = Some(ip.octets());
                }
            }
        }

        // Check if both src and dst are local (same as interface IP) - exclude these
        let mut is_local_to_local = false;
        if let (Some(src), Some(dst)) = (src_ip, dst_ip) {
            if src == interface_ip && dst == interface_ip {
                is_local_to_local = true;
            }
        }
        
        // Skip local-to-local connections
        if is_local_to_local {
            continue;
        }
        
        // Find all relevant IPs (non-interface IPs in our subnet)
        let mut relevant_ips = Vec::new();
        
        if let Some(ip) = src_ip {
            if network_utils::is_ip_in_subnet(ip, interface_ip, subnet_mask) && ip != interface_ip {
                relevant_ips.push(ip);
            }
        }
        if let Some(ip) = dst_ip {
            if network_utils::is_ip_in_subnet(ip, interface_ip, subnet_mask) && ip != interface_ip {
                relevant_ips.push(ip);
            }
        }

        // Skip if no relevant IPs found
        if relevant_ips.is_empty() {
            continue;
        }

        // Filter relevant IPs to only include those with MAC addresses in ARP table
        // This ensures consistency between global and device statistics
        let valid_relevant_ips: Vec<[u8; 4]> = relevant_ips
            .iter()
            .filter(|&ip| ip_mac_mapping.contains_key(ip))
            .cloned()
            .collect();

        // Skip if no valid IPs found (no MAC addresses in ARP table)
        if valid_relevant_ips.is_empty() {
            log::debug!(
                "Skipping connection: no MAC addresses found for IPs {:?}",
                relevant_ips.iter().map(format_ip).collect::<Vec<_>>()
            );
            continue;
        }

        // Determine if this is a device-to-device connection or device-to-external connection
        let is_device_to_device = valid_relevant_ips.len() == 2;
        
        // Count this connection once for global statistics (only if we have valid devices)
        let mut global_connection_counted = false;
        
        // Determine connection type for global statistics
        let mut is_tcp_established = false;
        let mut is_tcp_closed = false;
        let mut is_udp = false;
        
        match protocol {
            &"tcp" => {
                if let Some(state) = tcp_state {
                    match state {
                        "ESTABLISHED" => {
                            is_tcp_established = true;
                            global_connection_counted = true;
                        }
                        "TIME_WAIT" | "CLOSE_WAIT" | "FIN_WAIT_1" | "FIN_WAIT_2"
                        | "CLOSING" | "LAST_ACK" => {
                            is_tcp_closed = true;
                            global_connection_counted = true;
                        }
                        _ => {
                            log::debug!("TCP other state '{}' - not counted globally", state);
                        }
                    }
                } else {
                    log::debug!("TCP connection without state - not counted globally");
                }
            }
            &"udp" => {
                is_udp = true;
                global_connection_counted = true;
            }
            _ => {
                log::debug!("Other protocol '{}' - not counted globally", protocol);
            }
        }
        
        // Update global statistics once per connection
        if global_connection_counted {
            global_stats.total_connections += 1;
            if is_tcp_established {
                global_stats.tcp_connections += 1;
                global_stats.established_tcp += 1;
            } else if is_tcp_closed {
                global_stats.tcp_connections += 1;
                global_stats.time_wait_tcp += 1; // Simplified: all closed TCP as TIME_WAIT
            } else if is_udp {
                global_stats.udp_connections += 1;
            }
        }
        
        // In router environment, count for each local device that participates in the connection
        // This reflects each device's network activity level
        log::debug!(
            "Connection processing: protocol={}, valid_relevant_ips={:?}, is_device_to_device={}",
            protocol,
            valid_relevant_ips.iter().map(format_ip).collect::<Vec<_>>(),
            is_device_to_device
        );

        // Process each valid relevant device in the connection
        for ip in valid_relevant_ips {
            // We can safely unwrap here because valid_relevant_ips only contains IPs with MAC addresses
            let &mac = ip_mac_mapping.get(&ip).unwrap();

            // Update device statistics
            let device_stat =
                device_stats
                    .entry(mac)
                    .or_insert_with(|| DeviceConnectionStats {
                        mac_address: mac,
                        ip_address: ip,
                        active_tcp: 0,
                        active_udp: 0,
                        closed_tcp: 0,
                        total_connections: 0,
                        last_updated: timestamp,
                    });

            // Count this connection for the device
            let mut connection_categorized = false;

            match protocol {
                &"tcp" => {
                    if let Some(state) = tcp_state {
                        match state {
                            "ESTABLISHED" => {
                                device_stat.active_tcp += 1;
                                connection_categorized = true;
                                log::debug!("TCP ESTABLISHED for device {}: active_tcp={}", format_ip(&ip), device_stat.active_tcp);
                            }
                            "TIME_WAIT" | "CLOSE_WAIT" | "FIN_WAIT_1" | "FIN_WAIT_2"
                            | "CLOSING" | "LAST_ACK" => {
                                device_stat.closed_tcp += 1;
                                connection_categorized = true;
                                log::debug!("TCP CLOSED for device {}: closed_tcp={}", format_ip(&ip), device_stat.closed_tcp);
                            }
                            _ => {
                                log::debug!("TCP other state '{}' for device {} - not categorized", state, format_ip(&ip));
                            }
                        }
                    } else {
                        log::debug!("TCP connection without state for device {} - not categorized", format_ip(&ip));
                    }
                }
                &"udp" => {
                    device_stat.active_udp += 1;
                    connection_categorized = true;
                    log::debug!("UDP for device {}: active_udp={}", format_ip(&ip), device_stat.active_udp);
                }
                _ => {
                    log::debug!("Other protocol '{}' for device {} - not categorized", protocol, format_ip(&ip));
                }
            }

            // Always increment total_connections if we successfully categorized this connection
            // This ensures total_connections = active_tcp + active_udp + closed_tcp
            if connection_categorized {
                device_stat.total_connections += 1;
            }
        }
    }

    // Global statistics are now calculated directly during parsing to avoid duplicate counting
    Ok(GlobalConnectionStats {
        global_stats,
        device_stats,
        last_updated: timestamp,
    })
}

/// Connection statistics module context
#[derive(Clone)]
pub struct ConnectionModuleContext {
    pub options: Options,
    pub device_connection_stats: Arc<Mutex<GlobalConnectionStats>>,
    pub interface_ip: [u8; 4],
    pub subnet_mask: [u8; 4],
}

impl ConnectionModuleContext {
    /// Create connection module context
    pub fn new(options: Options) -> Result<Self> {
        // Get network interface information
        let (interface_ip, subnet_mask) = network_utils::get_interface_info(&options.iface)
            .ok_or_else(|| anyhow::anyhow!("Failed to get interface info for {}", options.iface))?;
        
        Ok(Self {
            options,
            device_connection_stats: Arc::new(Mutex::new(GlobalConnectionStats::default())),
            interface_ip,
            subnet_mask,
        })
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
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1)); // Update every 1 seconds

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Parse device-level connection statistics
                    match parse_device_connection_stats(ctx.interface_ip, ctx.subnet_mask) {
                        Ok(new_device_stats) => {
                            // Update the shared device statistics
                            {
                                let mut device_stats = ctx.device_connection_stats.lock().unwrap();
                                *device_stats = new_device_stats.clone();
                            }

                            log::debug!(
                                "Device connection stats updated: {} devices, total_connections={}",
                                new_device_stats.device_stats.len(),
                                new_device_stats.global_stats.total_connections
                            );
                        }
                        Err(e) => {
                            log::error!("Failed to parse device connection statistics: {}", e);
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
    fn test_parse_device_connection_stats() {
        // This test will only work if /proc/net/nf_conntrack exists
        // and the process has permission to read it
        if std::path::Path::new("/proc/net/nf_conntrack").exists() {
            // Use a test subnet (192.168.1.0/24)
            let interface_ip = [192, 168, 1, 1];
            let subnet_mask = [255, 255, 255, 0];
            let result = parse_device_connection_stats(interface_ip, subnet_mask);
            assert!(result.is_ok());
        }
    }
}
