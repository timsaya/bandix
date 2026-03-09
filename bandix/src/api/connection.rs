use crate::api::{ApiResponse, HttpRequest, HttpResponse};
use crate::monitor::connection::{parse_connection_flows, ConnectionFlowDetail, GlobalConnectionStats};
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
    #[serde(rename = "mac")]
    pub mac_address: String,
    #[serde(rename = "ip4")]
    pub ip_address: String,
    #[serde(rename = "host")]
    pub hostname: String,
    #[serde(rename = "tcp")]
    pub tcp_connections: u32,
    #[serde(rename = "udp")]
    pub udp_connections: u32,
    #[serde(rename = "tcp_est")]
    pub established_tcp: u32,
    #[serde(rename = "tcp_tw")]
    pub time_wait_tcp: u32,
    #[serde(rename = "tcp_cw")]
    pub close_wait_tcp: u32,
    #[serde(rename = "total")]
    pub total_connections: u32,
    #[serde(rename = "last")]
    pub last_updated: u64,
}

/// 设备连接统计响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConnectionStatsResponse {
    #[serde(rename = "g")]
    pub global_stats: ConnectionStats,
    #[serde(rename = "d")]
    pub devices: Vec<DeviceConnectionInfo>,
    #[serde(rename = "cnt")]
    pub total_devices: usize,
    #[serde(rename = "last")]
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
        0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionFlowResponse {
    pub protocol: String,
    pub state: Option<String>,
    pub orig: FlowEndpoint,
    pub repl: FlowEndpoint,
    pub orig_packets: u64,
    pub orig_bytes: u64,
    pub repl_packets: u64,
    pub repl_bytes: u64,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEndpoint {
    pub src: String,
    pub dst: String,
    pub sport: u16,
    pub dport: u16,
}

fn flow_to_response(f: &ConnectionFlowDetail) -> ConnectionFlowResponse {
    ConnectionFlowResponse {
        protocol: f.protocol.clone(),
        state: f.state.clone(),
        orig: FlowEndpoint {
            src: format_ip(&f.orig_src),
            dst: format_ip(&f.orig_dst),
            sport: f.orig_sport,
            dport: f.orig_dport,
        },
        repl: FlowEndpoint {
            src: format_ip(&f.repl_src),
            dst: format_ip(&f.repl_dst),
            sport: f.repl_sport,
            dport: f.repl_dport,
        },
        orig_packets: f.orig_packets,
        orig_bytes: f.orig_bytes,
        repl_packets: f.repl_packets,
        repl_bytes: f.repl_bytes,
        flags: f.flags.clone(),
    }
}

impl ConnectionApiHandler {
    fn get_connection_flows(
        &self,
        filter_ip: Option<&str>,
        filter_protocol: Option<&str>,
        filter_state: Option<&str>,
    ) -> Result<Vec<ConnectionFlowResponse>> {
        let flows = parse_connection_flows()?;
        let mut result: Vec<ConnectionFlowResponse> = flows
            .iter()
            .filter(|f| {
                filter_ip.map_or(true, |ip| {
                    if let Ok(filter) = ip.parse::<std::net::Ipv4Addr>() {
                        f.orig_src == filter.octets()
                    } else {
                        true
                    }
                })
                    && filter_protocol.map_or(true, |p| f.protocol.eq_ignore_ascii_case(p))
                    && filter_state.map_or(true, |s| {
                        f.state.as_ref().map_or(false, |st| st.eq_ignore_ascii_case(s))
                    })
            })
            .map(flow_to_response)
            .collect();
        result.sort_by(|a, b| {
            let ip_cmp = a.orig.src.cmp(&b.orig.src);
            if ip_cmp != std::cmp::Ordering::Equal {
                return ip_cmp;
            }
            a.orig.dst.cmp(&b.orig.dst).then_with(|| a.orig.sport.cmp(&b.orig.sport))
        });
        Ok(result)
    }

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
            ("GET", "/api/connection/flows") => {
                let filter_ip = request.query_params.get("ip").map(|s| s.as_str());
                let filter_protocol = request.query_params.get("protocol").map(|s| s.as_str());
                let filter_state = request.query_params.get("state").map(|s| s.as_str());
                match self.get_connection_flows(filter_ip, filter_protocol, filter_state) {
                    Ok(flows) => {
                        let api_response = ApiResponse::success(flows);
                        let body = serde_json::to_string(&api_response)?;
                        Ok(HttpResponse::ok(body))
                    }
                    Err(e) => {
                        log::error!("Failed to get connection flows: {}", e);
                        Ok(HttpResponse::error(
                            500,
                            format!("Failed to get connection flows: {}", e),
                        ))
                    }
                }
            }
            _ => Ok(HttpResponse::error(404, "Not Found".to_string())),
        }
    }

    /// 获取supported routes for this handler
    pub fn supported_routes(&self) -> Vec<&'static str> {
        vec!["/api/connection/devices", "/api/connection/flows"]
    }
}
