use crate::api::{ApiResponse, HttpRequest, HttpResponse};
use crate::monitor::connection::GlobalConnectionStats;
use anyhow::Result;
use bandix_common::ConnectionStats;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// 连接 statistics API handler
#[derive(Clone)]
pub struct ConnectionApiHandler {
    device_connection_stats: Arc<Mutex<GlobalConnectionStats>>,
    hostname_bindings: Arc<Mutex<HashMap<[u8; 6], String>>>,
}

impl ConnectionApiHandler {
    pub fn new(
        device_connection_stats: Arc<Mutex<GlobalConnectionStats>>,
        hostname_bindings: Arc<Mutex<HashMap<[u8; 6], String>>>,
    ) -> Self {
        Self {
            device_connection_stats,
            hostname_bindings,
        }
    }

    /// 获取device-level connection statistics
    fn get_device_connection_stats(&self) -> Result<GlobalConnectionStats> {
        let stats = self.device_connection_stats.lock().unwrap();
        Ok(stats.clone())
    }

    /// 获取device connection statistics with formatted output
    fn get_device_connection_stats_formatted(&self) -> Result<DeviceConnectionStatsResponse> {
        let stats = self.get_device_connection_stats()?;
        let bindings_map = self.hostname_bindings.lock().unwrap();

        // 格式化device statistics for API response and sort by IP address
        let mut devices: Vec<DeviceConnectionInfo> = stats
            .device_stats
            .iter()
            .map(|(mac, device_stats)| {
                // Get hostname from bindings, fallback to empty string if not found
                let hostname = bindings_map.get(mac).cloned().unwrap_or_default();

                DeviceConnectionInfo {
                    mac_address: format_mac(mac),
                    ip_address: format_ip(&device_stats.ip_address),
                    hostname,
                    tcp_connections: device_stats.tcp_connections,
                    udp_connections: device_stats.udp_connections,
                    established_tcp: device_stats.established_tcp,
                    time_wait_tcp: device_stats.time_wait_tcp,
                    close_wait_tcp: device_stats.close_wait_tcp,
                    total_connections: device_stats.total_connections,
                    last_updated: device_stats.last_updated,
                }
            })
            .collect();

        // 排序devices by IP address (ascending order)
        devices.sort_by(|a, b| {
            // Parse IP addresses for comparison
            let ip_a = parse_ip_to_u32(&a.ip_address);
            let ip_b = parse_ip_to_u32(&b.ip_address);
            ip_a.cmp(&ip_b)
        });

        let total_devices = devices.len();
        Ok(DeviceConnectionStatsResponse {
            global_stats: stats.total_stats,
            devices,
            total_devices,
            last_updated: stats.last_updated,
        })
    }
}

/// 设备连接信息，用于 API 响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConnectionInfo {
    pub mac_address: String,
    pub ip_address: String,
    pub hostname: String,
    pub tcp_connections: u32,
    pub udp_connections: u32,
    pub established_tcp: u32,
    pub time_wait_tcp: u32,
    pub close_wait_tcp: u32,
    pub total_connections: u32,
    pub last_updated: u64,
}

/// 设备连接统计响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConnectionStatsResponse {
    pub global_stats: ConnectionStats,
    pub devices: Vec<DeviceConnectionInfo>,
    pub total_devices: usize,
    pub last_updated: u64,
}

/// 格式化 MAC 地址用于显示
fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// 格式化IP address for display
fn format_ip(ip: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

/// 将 IP 地址字符串解析为 u32 用于排序
fn parse_ip_to_u32(ip_str: &str) -> u32 {
    if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
        let octets = ip.octets();
        ((octets[0] as u32) << 24) | ((octets[1] as u32) << 16) | ((octets[2] as u32) << 8) | (octets[3] as u32)
    } else {
        0 // Default to 0 for invalid IP addresses
    }
}

impl ConnectionApiHandler {
    /// 处理HTTP requests for connection statistics
    pub async fn handle_request(&self, request: &HttpRequest) -> Result<HttpResponse> {
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/api/connection/devices") => match self.get_device_connection_stats_formatted() {
                Ok(response) => {
                    let api_response = ApiResponse::success(response);
                    let body = serde_json::to_string(&api_response)?;
                    Ok(HttpResponse::ok(body))
                }
                Err(e) => {
                    log::error!("Failed to get device connection stats: {}", e);
                    Ok(HttpResponse::error(
                        500,
                        format!("Failed to get device connection stats: {}", e),
                    ))
                }
            },
            _ => Ok(HttpResponse::error(404, "Not Found".to_string())),
        }
    }

    /// 获取supported routes for this handler
    pub fn supported_routes(&self) -> Vec<&'static str> {
        vec!["/api/connection/devices"]
    }
}
