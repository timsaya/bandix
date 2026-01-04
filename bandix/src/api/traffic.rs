use super::{ApiResponse, HttpRequest, HttpResponse};
use crate::command::Options;
use crate::storage::traffic::{
    self, MultiLevelRingManager, RealtimeRingManager, ScheduledRateLimit, TimeSlot,
};
use crate::utils::format_utils::{format_bytes, format_mac};
use bandix_common::DeviceTrafficStats;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
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

    pub wan_rx_rate_limit: u64,
    pub wan_tx_rate_limit: u64,

    pub lan_rx_bytes: u64,
    pub lan_tx_bytes: u64,
    pub lan_rx_rate: u64,
    pub lan_tx_rate: u64,

    pub wan_rx_bytes: u64,
    pub wan_tx_bytes: u64,
    pub wan_rx_rate: u64,
    pub wan_tx_rate: u64,

    pub last_online_ts: u64,
}

/// Devices response structure
#[derive(Serialize, Deserialize)]
pub struct DevicesResponse {
    pub devices: Vec<DeviceInfo>,
}

/// Metrics response structure
/// metrics is a Vec of arrays, each array contains:
/// [ts_ms, total_rx_rate, total_tx_rate, lan_rx_rate, lan_tx_rate,
///  wan_rx_rate, wan_tx_rate, total_rx_bytes, total_tx_bytes,
///  lan_rx_bytes, lan_tx_bytes, wan_rx_bytes, wan_tx_bytes]
#[derive(Serialize, Deserialize)]
pub struct MetricsResponse {
    pub retention_seconds: u64,
    pub mac: String,
    pub metrics: Vec<Vec<u64>>,
}

/// Device usage ranking entry
#[derive(Serialize, Deserialize)]
pub struct DeviceUsageRanking {
    pub mac: String,
    pub hostname: String,
    pub ip: String,
    pub total_bytes: u64, // Total bytes (rx + tx) in the time range
    pub rx_bytes: u64,    // Receive bytes
    pub tx_bytes: u64,    // Transmit bytes
    pub percentage: f64,  // Percentage of total usage
    pub rank: usize,      // Ranking position (1-based)
}

/// Device usage ranking response structure
#[derive(Serialize, Deserialize)]
pub struct DeviceUsageRankingResponse {
    pub start_ms: u64,
    pub end_ms: u64,
    pub total_bytes: u64,    // Total bytes across all devices
    pub total_rx_bytes: u64, // Total receive bytes across all devices
    pub total_tx_bytes: u64, // Total transmit bytes across all devices
    pub device_count: usize, // Number of devices
    pub rankings: Vec<DeviceUsageRanking>,
}

/// Time series increment entry (hourly or daily)
#[derive(Serialize, Deserialize)]
pub struct TimeSeriesIncrement {
    pub ts_ms: u64,       // Timestamp (start of hour or day)
    pub rx_bytes: u64,    // Receive bytes increment in this period
    pub tx_bytes: u64,    // Transmit bytes increment in this period
    pub total_bytes: u64, // Total bytes increment (rx + tx)
}

/// Time series increment response structure
#[derive(Serialize, Deserialize)]
pub struct TimeSeriesIncrementResponse {
    pub start_ms: u64,
    pub end_ms: u64,
    pub aggregation: String, // "hourly" or "daily"
    pub mac: String,         // MAC address (or "all" for aggregate)
    pub increments: Vec<TimeSeriesIncrement>,
    pub total_rx_bytes: u64, // Total RX bytes in the range
    pub total_tx_bytes: u64, // Total TX bytes in the range
    pub total_bytes: u64,    // Total bytes in the range
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

/// Time slot for API request/response
#[derive(Serialize, Deserialize, Clone)]
pub struct TimeSlotApi {
    pub start: String, // Format: "HH:MM"
    pub end: String,   // Format: "HH:MM"
    pub days: Vec<u8>, // 1-7 (Monday-Sunday)
}

impl From<&TimeSlot> for TimeSlotApi {
    fn from(slot: &TimeSlot) -> Self {
        let mut days = Vec::new();
        for i in 0..7 {
            if (slot.days_of_week & (1 << i)) != 0 {
                days.push(i + 1); // Convert to 1-7 (Monday-Sunday)
            }
        }
        Self {
            start: TimeSlot::format_time(slot.start_hour, slot.start_minute),
            end: TimeSlot::format_time(slot.end_hour, slot.end_minute),
            days,
        }
    }
}

impl TryFrom<&TimeSlotApi> for TimeSlot {
    type Error = anyhow::Error;

    fn try_from(api: &TimeSlotApi) -> Result<Self, Self::Error> {
        let (start_hour, start_minute) = TimeSlot::parse_time(&api.start)?;
        let (end_hour, end_minute) = TimeSlot::parse_time(&api.end)?;
        let mut days_of_week = 0u8;
        for day in &api.days {
            if *day < 1 || *day > 7 {
                return Err(anyhow::anyhow!("Day must be 1-7 (Monday-Sunday)"));
            }
            days_of_week |= 1 << (day - 1);
        }
        Ok(TimeSlot {
            start_hour,
            start_minute,
            end_hour,
            end_minute,
            days_of_week,
        })
    }
}

/// Scheduled rate limit info for API response
#[derive(Serialize, Deserialize)]
pub struct ScheduledRateLimitInfo {
    pub mac: String,
    pub time_slot: TimeSlotApi,
    pub wan_rx_rate_limit: u64,
    pub wan_tx_rate_limit: u64,
}

/// Scheduled rate limits response structure
#[derive(Serialize, Deserialize)]
pub struct ScheduledRateLimitsResponse {
    pub limits: Vec<ScheduledRateLimitInfo>,
}

/// Set scheduled limit request structure
#[derive(Serialize, Deserialize)]
pub struct SetScheduledLimitRequest {
    pub mac: String,
    pub time_slot: TimeSlotApi,
    pub wan_rx_rate_limit: u64,
    pub wan_tx_rate_limit: u64,
}

/// Delete scheduled limit request structure
#[derive(Serialize, Deserialize)]
pub struct DeleteScheduledLimitRequest {
    pub mac: String,
    pub time_slot: TimeSlotApi,
}

/// Traffic monitoring API handler
#[derive(Clone)]
pub struct TrafficApiHandler {
    mac_stats: Arc<Mutex<HashMap<[u8; 6], DeviceTrafficStats>>>,
    scheduled_rate_limits: Arc<Mutex<Vec<ScheduledRateLimit>>>,
    hostname_bindings: Arc<Mutex<HashMap<[u8; 6], String>>>,
    realtime_manager: Arc<RealtimeRingManager>, // Real-time 1-second sampling (memory-only)
    long_term_manager: Arc<MultiLevelRingManager>, // Long-term sampling (day/week/month/year, persisted)
    device_registry: Arc<crate::storage::device_registry::DeviceRegistry>, // Centralized device registry
    options: Options,
}

impl TrafficApiHandler {
    pub fn new(
        mac_stats: Arc<Mutex<HashMap<[u8; 6], DeviceTrafficStats>>>,
        scheduled_rate_limits: Arc<Mutex<Vec<ScheduledRateLimit>>>,
        hostname_bindings: Arc<Mutex<HashMap<[u8; 6], String>>>,
        realtime_manager: Arc<RealtimeRingManager>,
        long_term_manager: Arc<MultiLevelRingManager>,
        device_registry: Arc<crate::storage::device_registry::DeviceRegistry>,
        options: Options,
    ) -> Self {
        Self {
            mac_stats,
            scheduled_rate_limits,
            hostname_bindings,
            realtime_manager,
            long_term_manager,
            device_registry,
            options,
        }
    }
}

impl TrafficApiHandler {
    pub fn supported_routes(&self) -> Vec<&'static str> {
        vec![
            "/api/traffic/devices",
            "/api/traffic/limits/schedule",
            "/api/traffic/metrics",
            "/api/traffic/metrics/year",
            "/api/traffic/bindings",
            "/api/traffic/usage/ranking",
            "/api/traffic/usage/increments",
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
            "/api/traffic/bindings" => match request.method.as_str() {
                "GET" => self.handle_hostname_bindings().await,
                "POST" => self.handle_set_hostname_binding(request).await,
                _ => Ok(HttpResponse::error(405, "Method not allowed".to_string())),
            },
            "/api/traffic/metrics" => {
                if request.method == "GET" {
                    self.handle_metrics(request).await
                } else {
                    Ok(HttpResponse::error(405, "Method not allowed".to_string()))
                }
            }
            "/api/traffic/metrics/year" => {
                if request.method == "GET" {
                    self.handle_metrics_year(request).await
                } else {
                    Ok(HttpResponse::error(405, "Method not allowed".to_string()))
                }
            }
            "/api/traffic/usage/ranking" => {
                if request.method == "GET" {
                    self.handle_usage_ranking(request).await
                } else {
                    Ok(HttpResponse::error(405, "Method not allowed".to_string()))
                }
            }
            "/api/traffic/usage/increments" => {
                if request.method == "GET" {
                    self.handle_usage_increments(request).await
                } else {
                    Ok(HttpResponse::error(405, "Method not allowed".to_string()))
                }
            }
            "/api/traffic/limits/schedule" => match request.method.as_str() {
                "GET" => self.handle_scheduled_limits().await,
                "POST" => self.handle_set_scheduled_limit(request).await,
                "DELETE" => self.handle_delete_scheduled_limit(request).await,
                _ => Ok(HttpResponse::error(405, "Method not allowed".to_string())),
            },
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

        // Collect all devices from centralized registry (includes historical devices)
        let registry_devices = self.device_registry.get_all_devices();
        let mut all_macs: HashSet<[u8; 6]> = registry_devices.iter().map(|d| d.mac).collect();

        // Also add devices from current stats (baseline already applied during initialization)
        for mac in stats_map.keys() {
            all_macs.insert(*mac);
        }

        let devices: Vec<DeviceInfo> = all_macs
            .into_iter()
            .map(|mac| {
                // Format MAC address
                let mac_str = format_mac(&mac);

                // Get stats from mac_stats (baseline already applied during initialization)
                let (
                    ip_address,
                    total_rx_bytes,
                    total_tx_bytes,
                    total_rx_rate,
                    total_tx_rate,
                    wan_rx_rate_limit,
                    wan_tx_rate_limit,
                    lan_rx_bytes,
                    lan_tx_bytes,
                    lan_rx_rate,
                    lan_tx_rate,
                    wan_rx_bytes,
                    wan_tx_bytes,
                    wan_rx_rate,
                    wan_tx_rate,
                    last_online_ts,
                    ipv6_addresses_from_stats,
                ) = if let Some(stats) = stats_map.get(&mac) {
                    // Device stats (includes baseline for offline devices)
                    (
                        stats.ip_address,
                        stats.total_rx_bytes(),
                        stats.total_tx_bytes(),
                        stats.total_rx_rate(),
                        stats.total_tx_rate(),
                        stats.wan_rx_rate_limit,
                        stats.wan_tx_rate_limit,
                        stats.lan_rx_bytes,
                        stats.lan_tx_bytes,
                        stats.lan_rx_rate,
                        stats.lan_tx_rate,
                        stats.wan_rx_bytes,
                        stats.wan_tx_bytes,
                        stats.wan_rx_rate,
                        stats.wan_tx_rate,
                        stats.last_online_ts,
                        stats.ipv6_addresses,
                    )
                } else {
                    // Should not happen, but provide defaults
                    (
                        [0, 0, 0, 0],
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        [[0u8; 16]; 16],
                    )
                };

                // Get device record from registry (includes historical IP addresses)
                let device_record = self.device_registry.get_device(&mac);

                // Use current IP from stats/baseline, or fallback to registry
                let final_ipv4 = if ip_address != [0, 0, 0, 0] {
                    ip_address
                } else if let Some(record) = &device_record {
                    record.current_ipv4.unwrap_or([0, 0, 0, 0])
                } else {
                    [0, 0, 0, 0]
                };

                // Format IP address
                let ip_str = format!(
                    "{}.{}.{}.{}",
                    final_ipv4[0], final_ipv4[1], final_ipv4[2], final_ipv4[3]
                );

                // Get IPv6 addresses: combine current from stats, registry, and system neighbor table
                let mut ipv6_addresses_set: HashSet<[u8; 16]> = HashSet::new();

                // First, add IPv6 addresses from eBPF stats (if current device)
                for addr in ipv6_addresses_from_stats.iter() {
                    if *addr != [0u8; 16] {
                        ipv6_addresses_set.insert(*addr);
                    }
                }

                // Then, add IPv6 addresses from registry (current and historical)
                if let Some(record) = &device_record {
                    for addr in &record.current_ipv6 {
                        if *addr != [0u8; 16] {
                            ipv6_addresses_set.insert(*addr);
                        }
                    }
                }

                // Finally, add IPv6 addresses from system neighbor table
                if let Some(addrs) = ipv6_neighbors.get(&mac) {
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
                let hostname = bindings_map.get(&mac).cloned().unwrap_or_default();

                DeviceInfo {
                    ip: ip_str,
                    ipv6_addresses,
                    mac: mac_str,
                    hostname,
                    total_rx_bytes,
                    total_tx_bytes,
                    total_rx_rate,
                    total_tx_rate,
                    wan_rx_rate_limit,
                    wan_tx_rate_limit,
                    lan_rx_bytes,
                    lan_tx_bytes,
                    lan_rx_rate,
                    lan_tx_rate,
                    wan_rx_bytes,
                    wan_tx_bytes,
                    wan_rx_rate,
                    wan_tx_rate,
                    last_online_ts,
                }
            })
            .filter(|device| device.last_online_ts > 0)
            .collect();

        let mut devices = devices;
        devices.sort_by(|a, b| {
            let a_ip: std::net::Ipv4Addr =
                a.ip.parse().unwrap_or(std::net::Ipv4Addr::new(0, 0, 0, 0));
            let b_ip: std::net::Ipv4Addr =
                b.ip.parse().unwrap_or(std::net::Ipv4Addr::new(0, 0, 0, 0));
            a_ip.cmp(&b_ip)
        });

        let response = DevicesResponse { devices };
        let api_response = ApiResponse::success(response);
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }

    /// Handle /api/metrics endpoint - Real-time metrics (memory-only, not persisted)
    async fn handle_metrics(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        let mac_opt = request.query_params.get("mac").cloned();

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;
        let start_ms =
            now_ms.saturating_sub(self.options.traffic_retention_seconds() as u64 * 1000);
        let end_ms = now_ms;

        let (rows_result, mac_label) = if let Some(mac_str) = mac_opt {
            if mac_str.to_ascii_lowercase() == "all" || mac_str.trim().is_empty() {
                (
                    self.realtime_manager
                        .query_metrics_aggregate_all(start_ms, end_ms),
                    "all".to_string(),
                )
            } else {
                match crate::utils::network_utils::parse_mac_address(&mac_str) {
                    Ok(mac) => (
                        self.realtime_manager
                            .query_metrics(&mac, start_ms, end_ms),
                        format_mac(&mac),
                    ),
                    Err(e) => {
                        return Ok(HttpResponse::error(400, format!("Invalid MAC: {}", e)));
                    }
                }
            }
        } else {
            (
                self.realtime_manager
                    .query_metrics_aggregate_all(start_ms, end_ms),
                "all".to_string(),
            )
        };

        match rows_result {
            Ok(rows) => {
                let metrics: Vec<Vec<u64>> = rows
                    .iter()
                    .map(|r| {
                        vec![
                            r.ts_ms,
                            r.total_rx_rate,
                            r.total_tx_rate,
                            r.lan_rx_rate,
                            r.lan_tx_rate,
                            r.wan_rx_rate,
                            r.wan_tx_rate,
                            r.total_rx_bytes,
                            r.total_tx_bytes,
                            r.lan_rx_bytes,
                            r.lan_tx_bytes,
                            r.wan_rx_bytes,
                            r.wan_tx_bytes,
                        ]
                    })
                    .collect();

                let response = MetricsResponse {
                    retention_seconds: self.options.traffic_retention_seconds() as u64,
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

    /// Handle /api/traffic/metrics/year endpoint - Year-level statistics (persisted)
    async fn handle_metrics_year(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        let mac_opt = request.query_params.get("mac").cloned();

        let year_manager = match self.long_term_manager.get_manager_by_level("year") {
            Some(manager) => manager,
            None => {
                return Ok(HttpResponse::error(
                    500,
                    "Internal error: year level manager not found".to_string(),
                ));
            }
        };

        // Get year-level sampling configuration
        let sampling_level = match self.long_term_manager.get_level_by_name("year") {
            Some(level) => level,
            None => {
                return Ok(HttpResponse::error(
                    500,
                    "Internal error: year level config not found".to_string(),
                ));
            }
        };

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;

        let retention_seconds = sampling_level.retention_seconds;
        let start_ms = now_ms.saturating_sub(retention_seconds * 1000);
        let end_ms = now_ms;

        let (rows_result, mac_label) = if let Some(mac_str) = mac_opt {
            if mac_str.to_ascii_lowercase() == "all" || mac_str.trim().is_empty() {
                (
                    year_manager.query_stats_aggregate_all(start_ms, end_ms),
                    "all".to_string(),
                )
            } else {
                match crate::utils::network_utils::parse_mac_address(&mac_str) {
                    Ok(mac) => (
                        year_manager.query_stats(&mac, start_ms, end_ms),
                        format_mac(&mac),
                    ),
                    Err(e) => {
                        return Ok(HttpResponse::error(400, format!("Invalid MAC: {}", e)));
                    }
                }
            }
        } else {
            (
                year_manager.query_stats_aggregate_all(start_ms, end_ms),
                "all".to_string(),
            )
        };

        match rows_result {
            Ok(rows) => {
                // Convert to array format with statistics:
                // [ts_ms, wan_rx_rate_avg, wan_rx_rate_max, wan_rx_rate_min, wan_rx_rate_p90, wan_rx_rate_p95, wan_rx_rate_p99,
                //  wan_tx_rate_avg, wan_tx_rate_max, wan_tx_rate_min, wan_tx_rate_p90, wan_tx_rate_p95, wan_tx_rate_p99,
                //  wan_rx_bytes, wan_tx_bytes]
                let metrics: Vec<Vec<u64>> = rows
                    .iter()
                    .map(|r| {
                        vec![
                            r.ts_ms,
                            r.wan_rx_rate_avg,
                            r.wan_rx_rate_max,
                            r.wan_rx_rate_min,
                            r.wan_rx_rate_p90,
                            r.wan_rx_rate_p95,
                            r.wan_rx_rate_p99,
                            r.wan_tx_rate_avg,
                            r.wan_tx_rate_max,
                            r.wan_tx_rate_min,
                            r.wan_tx_rate_p90,
                            r.wan_tx_rate_p95,
                            r.wan_tx_rate_p99,
                            r.wan_rx_bytes,
                            r.wan_tx_bytes,
                        ]
                    })
                    .collect();

                let response = MetricsResponse {
                    retention_seconds: retention_seconds as u64,
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
    async fn handle_set_hostname_binding(
        &self,
        request: &HttpRequest,
    ) -> Result<HttpResponse, anyhow::Error> {
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
        traffic::upsert_hostname_binding(self.options.data_dir(), &mac, hostname)?;

        // Log the change
        if hostname.is_empty() {
            log::info!("Hostname binding cleared for MAC: {}", format_mac(&mac));
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

    /// Handle /api/traffic/limits/schedule endpoint (GET)
    async fn handle_scheduled_limits(&self) -> Result<HttpResponse, anyhow::Error> {
        let scheduled_limits = self.scheduled_rate_limits.lock().unwrap();

        let limits: Vec<ScheduledRateLimitInfo> = scheduled_limits
            .iter()
            .map(|rule| ScheduledRateLimitInfo {
                mac: format_mac(&rule.mac),
                time_slot: TimeSlotApi::from(&rule.time_slot),
                wan_rx_rate_limit: rule.wan_rx_rate_limit,
                wan_tx_rate_limit: rule.wan_tx_rate_limit,
            })
            .collect();

        let response = ScheduledRateLimitsResponse { limits };
        let api_response = ApiResponse::success(response);
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }

    /// Handle /api/traffic/limits/schedule endpoint (POST)
    async fn handle_set_scheduled_limit(
        &self,
        request: &HttpRequest,
    ) -> Result<HttpResponse, anyhow::Error> {
        let body = request
            .body
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing request body"))?;

        // Parse JSON request body
        let set_request: SetScheduledLimitRequest = serde_json::from_str(body)?;

        let mac = crate::utils::network_utils::parse_mac_address(&set_request.mac)?;
        let time_slot = TimeSlot::try_from(&set_request.time_slot)
            .map_err(|e| anyhow::anyhow!("Invalid time slot: {}", e))?;

        let scheduled_limit = ScheduledRateLimit {
            mac,
            time_slot,
            wan_rx_rate_limit: set_request.wan_rx_rate_limit,
            wan_tx_rate_limit: set_request.wan_tx_rate_limit,
        };

        // Update in-memory scheduled rate limits
        {
            let mut srl = self.scheduled_rate_limits.lock().unwrap();
            // Remove existing rule with same MAC and time slot
            srl.retain(|r| {
                !(r.mac == scheduled_limit.mac
                    && r.time_slot.start_hour == scheduled_limit.time_slot.start_hour
                    && r.time_slot.start_minute == scheduled_limit.time_slot.start_minute
                    && r.time_slot.end_hour == scheduled_limit.time_slot.end_hour
                    && r.time_slot.end_minute == scheduled_limit.time_slot.end_minute
                    && r.time_slot.days_of_week == scheduled_limit.time_slot.days_of_week)
            });
            srl.push(scheduled_limit.clone());
        }

        // Persist to file
        traffic::upsert_scheduled_limit(self.options.data_dir(), &scheduled_limit)?;

        // Log the change
        let rx_str = if scheduled_limit.wan_rx_rate_limit == 0 {
            "Unlimited".to_string()
        } else {
            format!("{}/s", format_bytes(scheduled_limit.wan_rx_rate_limit))
        };

        let tx_str = if scheduled_limit.wan_tx_rate_limit == 0 {
            "Unlimited".to_string()
        } else {
            format!("{}/s", format_bytes(scheduled_limit.wan_tx_rate_limit))
        };

        log::info!(
            "Scheduled rate limit set for MAC: {} - Time: {} to {} (days: {}) - Receive: {}, Transmit: {}",
            format_mac(&scheduled_limit.mac),
            TimeSlot::format_time(scheduled_limit.time_slot.start_hour, scheduled_limit.time_slot.start_minute),
            TimeSlot::format_time(scheduled_limit.time_slot.end_hour, scheduled_limit.time_slot.end_minute),
            TimeSlot::format_days(scheduled_limit.time_slot.days_of_week),
            rx_str,
            tx_str
        );

        let api_response = ApiResponse::success(());
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }

    /// Handle /api/traffic/limits/schedule endpoint (DELETE)
    async fn handle_delete_scheduled_limit(
        &self,
        request: &HttpRequest,
    ) -> Result<HttpResponse, anyhow::Error> {
        let body = request
            .body
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing request body"))?;

        // Parse JSON request body
        let delete_request: DeleteScheduledLimitRequest = serde_json::from_str(body)?;

        let mac = crate::utils::network_utils::parse_mac_address(&delete_request.mac)?;
        let time_slot = TimeSlot::try_from(&delete_request.time_slot)
            .map_err(|e| anyhow::anyhow!("Invalid time slot: {}", e))?;

        // Remove from in-memory scheduled rate limits
        {
            let mut srl = self.scheduled_rate_limits.lock().unwrap();
            srl.retain(|r| {
                !(r.mac == mac
                    && r.time_slot.start_hour == time_slot.start_hour
                    && r.time_slot.start_minute == time_slot.start_minute
                    && r.time_slot.end_hour == time_slot.end_hour
                    && r.time_slot.end_minute == time_slot.end_minute
                    && r.time_slot.days_of_week == time_slot.days_of_week)
            });
        }

        // Remove from file
        traffic::delete_scheduled_limit(self.options.data_dir(), &mac, &time_slot)?;

        // Log the change
        log::info!(
            "Scheduled rate limit deleted for MAC: {} - Time: {} to {} (days: {})",
            format_mac(&mac),
            TimeSlot::format_time(time_slot.start_hour, time_slot.start_minute),
            TimeSlot::format_time(time_slot.end_hour, time_slot.end_minute),
            TimeSlot::format_days(time_slot.days_of_week)
        );

        let api_response = ApiResponse::success(());
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }


    /// Handle /api/traffic/usage/ranking endpoint
    /// Query device usage ranking within a specified time range from year-level data
    /// Query parameters:
    ///   - start_ms: Start timestamp in milliseconds (optional, defaults to 365 days ago)
    ///   - end_ms: End timestamp in milliseconds (optional, defaults to now)
    async fn handle_usage_ranking(
        &self,
        request: &HttpRequest,
    ) -> Result<HttpResponse, anyhow::Error> {
        // Get year-level manager
        let year_manager = match self.long_term_manager.get_manager_by_level("year") {
            Some(manager) => manager,
            None => {
                return Ok(HttpResponse::error(
                    500,
                    "Internal error: year level manager not found".to_string(),
                ));
            }
        };

        // Parse time range from query parameters
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;

        let start_ms = request
            .query_params
            .get("start_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or_else(|| {
                // Default to 365 days ago
                now_ms.saturating_sub(365 * 24 * 3600 * 1000)
            });

        let end_ms = request
            .query_params
            .get("end_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(now_ms);

        // Validate time range
        if start_ms >= end_ms {
            return Ok(HttpResponse::error(
                400,
                "Invalid time range: start_ms must be less than end_ms".to_string(),
            ));
        }

        // Query statistics for all devices
        let device_stats = match year_manager.query_stats_by_device(start_ms, end_ms) {
            Ok(stats) => stats,
            Err(e) => {
                return Ok(HttpResponse::error(
                    500,
                    format!("Failed to query stats: {}", e),
                ));
            }
        };

        if device_stats.is_empty() {
            let response = DeviceUsageRankingResponse {
                start_ms,
                end_ms,
                total_bytes: 0,
                total_rx_bytes: 0,
                total_tx_bytes: 0,
                device_count: 0,
                rankings: Vec::new(),
            };
            let api_response = ApiResponse::success(response);
            let body = serde_json::to_string(&api_response)?;
            return Ok(HttpResponse::ok(body));
        }

        let bindings_map = self.hostname_bindings.lock().unwrap();
        let stats_map = self.mac_stats.lock().unwrap();

        let mut rankings: Vec<DeviceUsageRanking> = Vec::new();
        let mut total_bytes = 0u64;
        let mut total_rx_bytes = 0u64;
        let mut total_tx_bytes = 0u64;

        for (mac, stats) in device_stats.iter() {
            let total_device_bytes = stats.wan_rx_bytes + stats.wan_tx_bytes;
            total_bytes = total_bytes.saturating_add(total_device_bytes);
            total_rx_bytes = total_rx_bytes.saturating_add(stats.wan_rx_bytes);
            total_tx_bytes = total_tx_bytes.saturating_add(stats.wan_tx_bytes);

            let mac_str = format_mac(mac);
            let hostname = bindings_map.get(mac).cloned().unwrap_or_default();

            let ip_address = stats_map.get(mac)
                .map(|s| s.ip_address)
                .unwrap_or([0, 0, 0, 0]);

            let ip_str = format!(
                "{}.{}.{}.{}",
                ip_address[0], ip_address[1], ip_address[2], ip_address[3]
            );

            rankings.push(DeviceUsageRanking {
                mac: mac_str,
                hostname,
                ip: ip_str,
                total_bytes: total_device_bytes,
                rx_bytes: stats.wan_rx_bytes,
                tx_bytes: stats.wan_tx_bytes,
                percentage: 0.0, // Will calculate after sorting
                rank: 0,         // Will set after sorting
            });
        }

        // Sort by total_bytes descending
        rankings.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));

        // Calculate percentages and set ranks
        for (idx, ranking) in rankings.iter_mut().enumerate() {
            ranking.rank = idx + 1;
            if total_bytes > 0 {
                ranking.percentage = (ranking.total_bytes as f64 / total_bytes as f64) * 100.0;
            }
        }

        let response = DeviceUsageRankingResponse {
            start_ms,
            end_ms,
            total_bytes,
            total_rx_bytes,
            total_tx_bytes,
            device_count: rankings.len(),
            rankings,
        };

        let api_response = ApiResponse::success(response);
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }

    /// Handle /api/traffic/usage/increments endpoint
    /// Query time series increments (hourly or daily) from year-level data
    /// Query parameters:
    ///   - mac: MAC address (optional, defaults to "all" for aggregate)
    ///   - start_ms: Start timestamp in milliseconds (optional, defaults to 365 days ago)
    ///   - end_ms: End timestamp in milliseconds (optional, defaults to now)
    ///   - aggregation: "hourly" or "daily" (optional, defaults to "hourly")
    async fn handle_usage_increments(
        &self,
        request: &HttpRequest,
    ) -> Result<HttpResponse, anyhow::Error> {
        // Get year-level manager
        let year_manager = match self.long_term_manager.get_manager_by_level("year") {
            Some(manager) => manager,
            None => {
                return Ok(HttpResponse::error(
                    500,
                    "Internal error: year level manager not found".to_string(),
                ));
            }
        };

        // Parse aggregation mode
        let aggregation = request
            .query_params
            .get("aggregation")
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| "hourly".to_string());

        if aggregation != "hourly" && aggregation != "daily" {
            return Ok(HttpResponse::error(
                400,
                "Invalid aggregation: must be 'hourly' or 'daily'".to_string(),
            ));
        }

        // Parse time range
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;

        let start_ms = request
            .query_params
            .get("start_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or_else(|| now_ms.saturating_sub(365 * 24 * 3600 * 1000));

        let end_ms = request
            .query_params
            .get("end_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(now_ms);

        if start_ms >= end_ms {
            return Ok(HttpResponse::error(
                400,
                "Invalid time range: start_ms must be less than end_ms".to_string(),
            ));
        }

        // Query increments
        let hourly_increments = if let Some(mac_str) = request.query_params.get("mac") {
            if mac_str.to_ascii_lowercase() == "all" || mac_str.trim().is_empty() {
                year_manager.query_time_series_increments_aggregate(start_ms, end_ms)?
            } else {
                match crate::utils::network_utils::parse_mac_address(mac_str) {
                    Ok(mac) => year_manager.query_time_series_increments(&mac, start_ms, end_ms)?,
                    Err(e) => {
                        return Ok(HttpResponse::error(400, format!("Invalid MAC: {}", e)));
                    }
                }
            }
        } else {
            year_manager.query_time_series_increments_aggregate(start_ms, end_ms)?
        };

        let mac_label = request
            .query_params
            .get("mac")
            .cloned()
            .unwrap_or_else(|| "all".to_string());

        // Process increments based on aggregation mode
        let increments = if aggregation == "daily" {
            // Aggregate hourly increments into daily totals
            aggregate_to_daily(hourly_increments, start_ms, end_ms)
        } else {
            // Use hourly increments as-is
            hourly_increments
                .into_iter()
                .map(|(ts_ms, rx_bytes, tx_bytes)| TimeSeriesIncrement {
                    ts_ms,
                    rx_bytes,
                    tx_bytes,
                    total_bytes: rx_bytes + tx_bytes,
                })
                .collect()
        };

        // Calculate totals
        let total_rx_bytes: u64 = increments.iter().map(|inc| inc.rx_bytes).sum();
        let total_tx_bytes: u64 = increments.iter().map(|inc| inc.tx_bytes).sum();
        let total_bytes = total_rx_bytes + total_tx_bytes;

        let response = TimeSeriesIncrementResponse {
            start_ms,
            end_ms,
            aggregation: aggregation.clone(),
            mac: mac_label,
            increments,
            total_rx_bytes,
            total_tx_bytes,
            total_bytes,
        };

        let api_response = ApiResponse::success(response);
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }
}

/// Aggregate hourly increments into daily totals
/// Groups increments by day (00:00:00 UTC of each day)
/// Filters out days that are not within the requested time range [start_ms, end_ms)
fn aggregate_to_daily(
    hourly_increments: Vec<(u64, u64, u64)>,
    start_ms: u64,
    end_ms: u64,
) -> Vec<TimeSeriesIncrement> {
    use std::collections::BTreeMap;

    // Group by day (timestamp at 00:00:00 UTC of each day)
    let mut daily_map: BTreeMap<u64, (u64, u64)> = BTreeMap::new();

    for (ts_ms, rx_bytes, tx_bytes) in hourly_increments {
        // Convert timestamp to start of day (00:00:00 UTC) in milliseconds
        // Use chrono to properly handle UTC timezone
        let ts_secs = (ts_ms / 1000) as i64;
        let dt = DateTime::<Utc>::from_timestamp(ts_secs, 0)
            .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).unwrap());

        // Get the date at 00:00:00 UTC
        let day_start_dt = dt.date_naive().and_hms_opt(0, 0, 0).unwrap();
        let day_start_utc = DateTime::<Utc>::from_naive_utc_and_offset(day_start_dt, Utc);
        let day_start_ms = day_start_utc.timestamp_millis() as u64;

        let entry = daily_map.entry(day_start_ms).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(rx_bytes);
        entry.1 = entry.1.saturating_add(tx_bytes);
    }

    // Filter out days that are not within the requested time range
    // A day is included if its start timestamp (00:00:00 UTC) is within [start_ms, end_ms)
    daily_map
        .into_iter()
        .filter(|(ts_ms, _)| *ts_ms >= start_ms && *ts_ms < end_ms)
        .map(|(ts_ms, (rx_bytes, tx_bytes))| TimeSeriesIncrement {
            ts_ms,
            rx_bytes,
            tx_bytes,
            total_bytes: rx_bytes + tx_bytes,
        })
        .collect()
}
