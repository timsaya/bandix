use super::{ApiResponse, HttpRequest, HttpResponse};
use crate::command::Options;
use crate::storage::traffic::{self, MemoryRingManager, ScheduledRateLimit, TimeSlot};
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

/// Metrics response structure
/// metrics is a Vec of arrays, each array contains:
/// [ts_ms, total_rx_rate, total_tx_rate, local_rx_rate, local_tx_rate, 
///  wide_rx_rate, wide_tx_rate, total_rx_bytes, total_tx_bytes, 
///  local_rx_bytes, local_tx_bytes, wide_rx_bytes, wide_tx_bytes]
#[derive(Serialize, Deserialize)]
pub struct MetricsResponse {
    pub retention_seconds: u64,
    pub mac: String,
    pub metrics: Vec<Vec<u64>>,
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
    pub wide_rx_rate_limit: u64,
    pub wide_tx_rate_limit: u64,
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
    pub wide_rx_rate_limit: u64,
    pub wide_tx_rate_limit: u64,
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
    mac_stats: Arc<Mutex<HashMap<[u8; 6], MacTrafficStats>>>,
    scheduled_rate_limits: Arc<Mutex<Vec<ScheduledRateLimit>>>,
    hostname_bindings: Arc<Mutex<HashMap<[u8; 6], String>>>,
    memory_ring_manager: Arc<MemoryRingManager>,
    options: Options,
}

impl TrafficApiHandler {
    pub fn new(
        mac_stats: Arc<Mutex<HashMap<[u8; 6], MacTrafficStats>>>,
        scheduled_rate_limits: Arc<Mutex<Vec<ScheduledRateLimit>>>,
        hostname_bindings: Arc<Mutex<HashMap<[u8; 6], String>>>,
        memory_ring_manager: Arc<MemoryRingManager>,
        options: Options,
    ) -> Self {
        Self {
            mac_stats,
            scheduled_rate_limits,
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
            "/api/traffic/limits/schedule",
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
                    stats.ip_address[0],
                    stats.ip_address[1],
                    stats.ip_address[2],
                    stats.ip_address[3]
                );

                // Get IPv6 addresses for this MAC
                // Combine addresses from both eBPF stats and system neighbor table
                let mut ipv6_addresses_set: std::collections::HashSet<[u8; 16]> =
                    std::collections::HashSet::new();

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

    /// Handle /api/metrics endpoint
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
                    self.memory_ring_manager
                        .query_metrics_aggregate_all(start_ms, end_ms),
                    "all".to_string(),
                )
            } else {
                match crate::utils::network_utils::parse_mac_address(&mac_str) {
                    Ok(mac) => (
                        self.memory_ring_manager
                            .query_metrics(&mac, start_ms, end_ms),
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
                self.memory_ring_manager
                    .query_metrics_aggregate_all(start_ms, end_ms),
                "all".to_string(),
            )
        };

        match rows_result {
            Ok(rows) => {
                // Convert to compact array format: [ts_ms, total_rx_rate, total_tx_rate, 
                // local_rx_rate, local_tx_rate, wide_rx_rate, wide_tx_rate, 
                // total_rx_bytes, total_tx_bytes, local_rx_bytes, local_tx_bytes, 
                // wide_rx_bytes, wide_tx_bytes]
                let metrics: Vec<Vec<u64>> = rows
                    .iter()
                    .map(|r| vec![
                        r.ts_ms,
                        r.total_rx_rate,
                        r.total_tx_rate,
                        r.local_rx_rate,
                        r.local_tx_rate,
                        r.wide_rx_rate,
                        r.wide_tx_rate,
                        r.total_rx_bytes,
                        r.total_tx_bytes,
                        r.local_rx_bytes,
                        r.local_tx_bytes,
                        r.wide_rx_bytes,
                        r.wide_tx_bytes,
                    ])
                    .collect();

                let response = MetricsResponse {
                    retention_seconds: self.options.traffic_retention_seconds() as u64,
                    mac: mac_label,
                    metrics,
                };

                let api_response = ApiResponse::success(response);
                // Use compact JSON serialization (minified, no whitespace)
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
                wide_rx_rate_limit: rule.wide_rx_rate_limit,
                wide_tx_rate_limit: rule.wide_tx_rate_limit,
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
            wide_rx_rate_limit: set_request.wide_rx_rate_limit,
            wide_tx_rate_limit: set_request.wide_tx_rate_limit,
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
        let rx_str = if scheduled_limit.wide_rx_rate_limit == 0 {
            "Unlimited".to_string()
        } else {
            format!("{}/s", format_bytes(scheduled_limit.wide_rx_rate_limit))
        };

        let tx_str = if scheduled_limit.wide_tx_rate_limit == 0 {
            "Unlimited".to_string()
        } else {
            format!("{}/s", format_bytes(scheduled_limit.wide_tx_rate_limit))
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
}
