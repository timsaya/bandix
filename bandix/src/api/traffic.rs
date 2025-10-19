use super::{HttpRequest, HttpResponse, ApiResponse};
use crate::command::Options;
use crate::storage::traffic::{self, MemoryRingManager};
use crate::utils::format_utils::{format_bytes, format_mac};
use bandix_common::MacTrafficStats;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Device information for API response
#[derive(Serialize, Deserialize)]
pub struct DeviceInfo {
    pub ip: String,
    pub ipv6_addresses: Vec<String>,
    pub mac: String,
    pub hostname: String,
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
    pub total_rx_rate: u64,
    pub total_tx_rate: u64,
    pub wide_rx_rate_limit: u64,
    pub wide_tx_rate_limit: u64,
    pub local_rx_bytes: u64,
    pub local_tx_bytes: u64,
    pub local_rx_rate: u64,
    pub local_tx_rate: u64,
    pub wide_rx_bytes: u64,
    pub wide_tx_bytes: u64,
    pub wide_rx_rate: u64,
    pub wide_tx_rate: u64,
    pub last_online_ts: u64,
}

/// Devices response structure
#[derive(Serialize, Deserialize)]
pub struct DevicesResponse {
    pub devices: Vec<DeviceInfo>,
}

/// Rate limit information for API response
#[derive(Serialize, Deserialize)]
pub struct RateLimitInfo {
    pub mac: String,
    pub wide_rx_rate_limit: u64,
    pub wide_tx_rate_limit: u64,
}

/// Rate limits response structure
#[derive(Serialize, Deserialize)]
pub struct RateLimitsResponse {
    pub limits: Vec<RateLimitInfo>,
}

/// Metrics data point for API response
#[derive(Serialize, Deserialize)]
pub struct MetricsDataPoint {
    pub ts_ms: u64,
    pub total_rx_rate: u64,
    pub total_tx_rate: u64,
    pub local_rx_rate: u64,
    pub local_tx_rate: u64,
    pub wide_rx_rate: u64,
    pub wide_tx_rate: u64,
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
    pub local_rx_bytes: u64,
    pub local_tx_bytes: u64,
    pub wide_rx_bytes: u64,
    pub wide_tx_bytes: u64,
}

/// Metrics response structure
#[derive(Serialize, Deserialize)]
pub struct MetricsResponse {
    pub retention_seconds: u64,
    pub mac: String,
    pub metrics: Vec<MetricsDataPoint>,
}

/// Set limit request structure
#[derive(Serialize, Deserialize)]
pub struct SetLimitRequest {
    pub mac: String,
    pub wide_rx_rate_limit: u64,
    pub wide_tx_rate_limit: u64,
}

/// Hostname binding information for API response
#[derive(Serialize, Deserialize)]
pub struct HostnameBinding {
    pub mac: String,
    pub hostname: String,
}

/// Hostname bindings response structure
#[derive(Serialize, Deserialize)]
pub struct HostnameBindingsResponse {
    pub bindings: Vec<HostnameBinding>,
}

/// Set hostname binding request structure
#[derive(Serialize, Deserialize)]
pub struct SetHostnameBindingRequest {
    pub mac: String,
    pub hostname: String,
}

/// Traffic monitoring API handler
#[derive(Clone)]
pub struct TrafficApiHandler {
    mac_stats: Arc<Mutex<HashMap<[u8; 6], MacTrafficStats>>>,
    rate_limits: Arc<Mutex<HashMap<[u8; 6], [u64; 2]>>>,
    hostname_bindings: Arc<Mutex<HashMap<[u8; 6], String>>>,
    memory_ring_manager: Arc<MemoryRingManager>,
    options: Options,
}

impl TrafficApiHandler {
    pub fn new(
        mac_stats: Arc<Mutex<HashMap<[u8; 6], MacTrafficStats>>>,
        rate_limits: Arc<Mutex<HashMap<[u8; 6], [u64; 2]>>>,
        hostname_bindings: Arc<Mutex<HashMap<[u8; 6], String>>>,
        memory_ring_manager: Arc<MemoryRingManager>,
        options: Options,
    ) -> Self {
        Self {
            mac_stats,
            rate_limits,
            hostname_bindings,
            memory_ring_manager,
            options,
        }
    }
}

impl TrafficApiHandler {
    pub fn supported_routes(&self) -> Vec<&'static str> {
        vec![
            "/api/traffic/devices",
            "/api/traffic/limits",
            "/api/traffic/metrics",
            "/api/traffic/bindings",
        ]
    }

    pub async fn handle_request(
        &self,
        request: &HttpRequest,
    ) -> Result<HttpResponse, anyhow::Error> {
        match request.path.as_str() {
            "/api/traffic/devices" => {
                if request.method == "GET" {
                    self.handle_devices().await
                } else {
                    Ok(HttpResponse::error(405, "Method not allowed".to_string()))
                }
            }
            "/api/traffic/limits" => {
                match request.method.as_str() {
                    "GET" => self.handle_limits().await,
                    "POST" => self.handle_set_limit(request).await,
                    // "PUT" => self.handle_set_limit(request).await,
                    // "DELETE" => self.handle_delete_limit(request).await,
                    _ => Ok(HttpResponse::error(405, "Method not allowed".to_string())),
                }
            }
            "/api/traffic/bindings" => {
                match request.method.as_str() {
                    "GET" => self.handle_hostname_bindings().await,
                    "POST" => self.handle_set_hostname_binding(request).await,
                    _ => Ok(HttpResponse::error(405, "Method not allowed".to_string())),
                }
            }
            path if path.starts_with("/api/traffic/metrics") => {
                if request.method == "GET" {
                    self.handle_metrics(request).await
                } else {
                    Ok(HttpResponse::error(405, "Method not allowed".to_string()))
                }
            }
            _ => Ok(HttpResponse::not_found()),
        }
    }
}

impl TrafficApiHandler {
    /// Handle /api/devices endpoint
    async fn handle_devices(&self) -> Result<HttpResponse, anyhow::Error> {
        let stats_map = self.mac_stats.lock().unwrap();
        let bindings_map = self.hostname_bindings.lock().unwrap();

        // Get IPv6 neighbor table from system
        let ipv6_neighbors = crate::utils::network_utils::get_ipv6_neighbors().unwrap_or_default();

        // Only show devices actually collected by eBPF (last_sample_ts > 0)
        let filtered: Vec<(&[u8; 6], &MacTrafficStats)> = stats_map
            .iter()
            .filter(|(_mac, stats)| stats.last_sample_ts > 0)
            .collect();

        let devices: Vec<DeviceInfo> = filtered
            .into_iter()
            .map(|(mac, stats)| {
                // Format MAC address
                let mac_str = format_mac(mac);

                // Format IP address
                let ip_str = format!(
                    "{}.{}.{}.{}",
                    stats.ip_address[0], stats.ip_address[1], stats.ip_address[2], stats.ip_address[3]
                );

                // Get IPv6 addresses for this MAC
                // Combine addresses from both eBPF stats and system neighbor table
                let mut ipv6_addresses_set: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
                
                // First, add IPv6 addresses from eBPF stats
                for i in 0..(stats.ipv6_count as usize) {
                    let addr = stats.ipv6_addresses[i];
                    if addr != [0u8; 16] {
                        ipv6_addresses_set.insert(addr);
                    }
                }
                
                // Then, add IPv6 addresses from system neighbor table
                if let Some(addrs) = ipv6_neighbors.get(mac) {
                    for addr in addrs {
                        if *addr != [0u8; 16] {
                            ipv6_addresses_set.insert(*addr);
                        }
                    }
                }
                
                // Convert to formatted strings and sort lexicographically
                let mut ipv6_addresses: Vec<String> = ipv6_addresses_set
                    .iter()
                    .map(|addr| crate::utils::network_utils::format_ipv6(addr))
                    .collect();
                
                // Sort IPv6 addresses in lexicographic order
                ipv6_addresses.sort();

                // Get hostname from bindings, fallback to empty string if not found
                let hostname = bindings_map.get(mac).cloned().unwrap_or_default();

                DeviceInfo {
                    ip: ip_str,
                    ipv6_addresses,
                    mac: mac_str,
                    hostname,
                    total_rx_bytes: stats.total_rx_bytes,
                    total_tx_bytes: stats.total_tx_bytes,
                    total_rx_rate: stats.total_rx_rate,
                    total_tx_rate: stats.total_tx_rate,
                    wide_rx_rate_limit: stats.wide_rx_rate_limit,
                    wide_tx_rate_limit: stats.wide_tx_rate_limit,
                    local_rx_bytes: stats.local_rx_bytes,
                    local_tx_bytes: stats.local_tx_bytes,
                    local_rx_rate: stats.local_rx_rate,
                    local_tx_rate: stats.local_tx_rate,
                    wide_rx_bytes: stats.wide_rx_bytes,
                    wide_tx_bytes: stats.wide_tx_bytes,
                    wide_rx_rate: stats.wide_rx_rate,
                    wide_tx_rate: stats.wide_tx_rate,
                    last_online_ts: stats.last_online_ts,
                }
            })
            .collect();

        let response = DevicesResponse { devices };
        let api_response = ApiResponse::success(response);
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }

    /// Handle /api/limit endpoint (POST)
    async fn handle_set_limit(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        let body = request
            .body
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing request body"))?;

        // Parse JSON request body using serde
        let set_limit_request: SetLimitRequest = serde_json::from_str(body)?;

        let mac = crate::utils::network_utils::parse_mac_address(&set_limit_request.mac)?;

        // Use the parsed values directly
        let wide_rx_rate_limit = set_limit_request.wide_rx_rate_limit;
        let wide_tx_rate_limit = set_limit_request.wide_tx_rate_limit;

        // Update in-memory rate limits
        {
            let mut rl = self.rate_limits.lock().unwrap();
            rl.insert(mac, [wide_rx_rate_limit, wide_tx_rate_limit]);
        }

        // Sync with mac_stats for UI consistency
        {
            let mut stats_map = self.mac_stats.lock().unwrap();
            if let Some(stats) = stats_map.get_mut(&mac) {
                stats.wide_rx_rate_limit = wide_rx_rate_limit;
                stats.wide_tx_rate_limit = wide_tx_rate_limit;
            }
        }

        // Persist to files
        traffic::upsert_limit(
            &self.options.data_dir,
            &mac,
            wide_rx_rate_limit,
            wide_tx_rate_limit,
        )?;

        // Log the change
        let rx_str = if wide_rx_rate_limit == 0 {
            "Unlimited".to_string()
        } else {
            format!("{}/s", format_bytes(wide_rx_rate_limit))
        };

        let tx_str = if wide_tx_rate_limit == 0 {
            "Unlimited".to_string()
        } else {
            format!("{}/s", format_bytes(wide_tx_rate_limit))
        };

        log::info!(
            "Rate limit set for MAC: {} - Receive: {}, Transmit: {}",
            format_mac(&mac),
            rx_str,
            tx_str
        );

        let api_response = ApiResponse::success(());
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }

    /// Handle /api/limits endpoint
    async fn handle_limits(&self) -> Result<HttpResponse, anyhow::Error> {
        let rl_map = self.rate_limits.lock().unwrap();
        
        let limits: Vec<RateLimitInfo> = rl_map
            .iter()
            .map(|(mac, lim)| {
                let mac_str = format_mac(mac);
                RateLimitInfo {
                    mac: mac_str,
                    wide_rx_rate_limit: lim[0],
                    wide_tx_rate_limit: lim[1],
                }
            })
            .collect();

        let response = RateLimitsResponse { limits };
        let api_response = ApiResponse::success(response);
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }

    /// Handle /api/metrics endpoint
    async fn handle_metrics(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        let mac_opt = request.query_params.get("mac").cloned();

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;
        let start_ms = now_ms.saturating_sub(self.options.traffic_retention_seconds as u64 * 1000);
        let end_ms = now_ms;

        let (rows_result, mac_label) = if let Some(mac_str) = mac_opt {
            if mac_str.to_ascii_lowercase() == "all" || mac_str.trim().is_empty() {
                (
                    self.memory_ring_manager.query_metrics_aggregate_all(start_ms, end_ms),
                    "all".to_string(),
                )
            } else {
                match crate::utils::network_utils::parse_mac_address(&mac_str) {
                    Ok(mac) => (
                        self.memory_ring_manager.query_metrics(&mac, start_ms, end_ms),
                        format_mac(&mac),
                    ),
                    Err(e) => {
                        return Ok(HttpResponse::error(400, format!("Invalid MAC: {}", e)));
                    }
                }
            }
        } else {
            // mac omitted => aggregate all within window
            (
                self.memory_ring_manager.query_metrics_aggregate_all(start_ms, end_ms),
                "all".to_string(),
            )
        };

        match rows_result {
            Ok(rows) => {
                let metrics: Vec<MetricsDataPoint> = rows
                    .iter()
                    .map(|r| MetricsDataPoint {
                        ts_ms: r.ts_ms,
                        total_rx_rate: r.total_rx_rate,
                        total_tx_rate: r.total_tx_rate,
                        local_rx_rate: r.local_rx_rate,
                        local_tx_rate: r.local_tx_rate,
                        wide_rx_rate: r.wide_rx_rate,
                        wide_tx_rate: r.wide_tx_rate,
                        total_rx_bytes: r.total_rx_bytes,
                        total_tx_bytes: r.total_tx_bytes,
                        local_rx_bytes: r.local_rx_bytes,
                        local_tx_bytes: r.local_tx_bytes,
                        wide_rx_bytes: r.wide_rx_bytes,
                        wide_tx_bytes: r.wide_tx_bytes,
                    })
                    .collect();

                let response = MetricsResponse {
                    retention_seconds: self.options.traffic_retention_seconds as u64,
                    mac: mac_label,
                    metrics,
                };

                let api_response = ApiResponse::success(response);
                let body = serde_json::to_string(&api_response)?;
                Ok(HttpResponse::ok(body))
            }
            Err(e) => Ok(HttpResponse::error(500, e.to_string())),
        }
    }

    /// Handle /api/traffic/bindings endpoint (GET)
    async fn handle_hostname_bindings(&self) -> Result<HttpResponse, anyhow::Error> {
        let bindings_map = self.hostname_bindings.lock().unwrap();
        
        let bindings: Vec<HostnameBinding> = bindings_map
            .iter()
            .map(|(mac, hostname)| {
                let mac_str = format_mac(mac);
                HostnameBinding {
                    mac: mac_str,
                    hostname: hostname.clone(),
                }
            })
            .collect();

        let response = HostnameBindingsResponse { bindings };
        let api_response = ApiResponse::success(response);
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }

    /// Handle /api/traffic/bindings endpoint (POST)
    async fn handle_set_hostname_binding(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        let body = request
            .body
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing request body"))?;

        // Parse JSON request body using serde
        let set_binding_request: SetHostnameBindingRequest = serde_json::from_str(body)?;

        let mac = crate::utils::network_utils::parse_mac_address(&set_binding_request.mac)?;

        // Allow empty hostname (for clearing bindings)
        let hostname = set_binding_request.hostname.trim();

        // Update in-memory hostname bindings
        {
            let mut bindings = self.hostname_bindings.lock().unwrap();
            if hostname.is_empty() {
                // Remove binding if hostname is empty
                bindings.remove(&mac);
            } else {
                // Set or update binding
                bindings.insert(mac, hostname.to_string());
            }
        }

        // Persist to file (storage layer handles empty hostname appropriately)
        traffic::upsert_hostname_binding(
            &self.options.data_dir,
            &mac,
            hostname,
        )?;

        // Log the change
        if hostname.is_empty() {
            log::info!(
                "Hostname binding cleared for MAC: {}",
                format_mac(&mac)
            );
        } else {
            log::info!(
                "Hostname binding set for MAC: {} -> {}",
                format_mac(&mac),
                hostname
            );
        }

        let api_response = ApiResponse::success(());
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }

}
