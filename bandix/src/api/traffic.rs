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
    pub mac: String,
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

/// Traffic monitoring API handler
#[derive(Clone)]
pub struct TrafficApiHandler {
    mac_stats: Arc<Mutex<HashMap<[u8; 6], MacTrafficStats>>>,
    rate_limits: Arc<Mutex<HashMap<[u8; 6], [u64; 2]>>>,
    memory_ring_manager: Arc<MemoryRingManager>,
    options: Options,
}

impl TrafficApiHandler {
    pub fn new(
        mac_stats: Arc<Mutex<HashMap<[u8; 6], MacTrafficStats>>>,
        rate_limits: Arc<Mutex<HashMap<[u8; 6], [u64; 2]>>>,
        memory_ring_manager: Arc<MemoryRingManager>,
        options: Options,
    ) -> Self {
        Self {
            mac_stats,
            rate_limits,
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

                DeviceInfo {
                    ip: ip_str,
                    mac: mac_str,
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

}
