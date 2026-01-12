use super::{ApiResponse, HttpRequest, HttpResponse};
use crate::command::Options;
use crate::storage::traffic::{self, LongTermRingManager, RealtimeRingManager, ScheduledRateLimit, TimeSlot};
use crate::utils::format_utils::{format_bytes, format_mac};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 设备信息，用于 API 响应
#[derive(Serialize, Deserialize)]
pub struct DeviceInfo {
    pub ip: String,
    pub ipv6_addresses: Vec<String>,
    pub mac: String,
    pub hostname: String,
    pub connection_type: String,

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

/// 设备响应结构
#[derive(Serialize, Deserialize)]
pub struct DevicesResponse {
    pub devices: Vec<DeviceInfo>,
}

/// 指标响应结构
/// 指标是一个数组向量，每个数组包含：
/// [ts_ms, total_rx_rate, total_tx_rate, lan_rx_rate, lan_tx_rate,
///  wan_rx_rate, wan_tx_rate, total_rx_bytes, total_tx_bytes,
///  lan_rx_bytes, lan_tx_bytes, wan_rx_bytes, wan_tx_bytes]
#[derive(Serialize, Deserialize)]
pub struct MetricsResponse {
    pub retention_seconds: u64,
    pub mac: String,
    pub metrics: Vec<Vec<u64>>,
}

/// 设备使用排名条目
#[derive(Serialize, Deserialize)]
pub struct DeviceUsageRanking {
    pub mac: String,
    pub hostname: String,
    pub ip: String,
    pub total_bytes: u64, // 时间范围内总字节数（rx + tx）
    pub rx_bytes: u64,    // 接收字节数
    pub tx_bytes: u64,    // 发送字节数
    pub percentage: f64,  // 总使用量的百分比
    pub rank: usize,      // 排名位置（从1开始）
}

/// 设备使用排名响应结构
#[derive(Serialize, Deserialize)]
pub struct DeviceUsageRankingResponse {
    pub start_ms: u64,
    pub end_ms: u64,
    pub network_type: String, // "wan", "lan", 或 "all"
    pub total_bytes: u64,     // 所有设备的总字节数
    pub total_rx_bytes: u64,  // 所有设备的总接收字节数
    pub total_tx_bytes: u64,  // 所有设备的总发送字节数
    pub device_count: usize,  // 设备数量
    pub rankings: Vec<DeviceUsageRanking>,
}

/// 时间序列增量条目（每小时或每日）
#[derive(Serialize, Deserialize, Clone)]
pub struct TimeSeriesIncrement {
    pub start_ts_ms: u64,
    pub end_ts_ms: u64,
    pub wan_rx_rate_avg: u64,
    pub wan_rx_rate_max: u64,
    pub wan_rx_rate_min: u64,
    pub wan_rx_rate_p90: u64,
    pub wan_rx_rate_p95: u64,
    pub wan_rx_rate_p99: u64,
    pub wan_tx_rate_avg: u64,
    pub wan_tx_rate_max: u64,
    pub wan_tx_rate_min: u64,
    pub wan_tx_rate_p90: u64,
    pub wan_tx_rate_p95: u64,
    pub wan_tx_rate_p99: u64,
    pub wan_rx_bytes_inc: u64,
    pub wan_tx_bytes_inc: u64,
    pub lan_rx_rate_avg: u64,
    pub lan_rx_rate_max: u64,
    pub lan_rx_rate_min: u64,
    pub lan_rx_rate_p90: u64,
    pub lan_rx_rate_p95: u64,
    pub lan_rx_rate_p99: u64,
    pub lan_tx_rate_avg: u64,
    pub lan_tx_rate_max: u64,
    pub lan_tx_rate_min: u64,
    pub lan_tx_rate_p90: u64,
    pub lan_tx_rate_p95: u64,
    pub lan_tx_rate_p99: u64,
    pub lan_rx_bytes_inc: u64,
    pub lan_tx_bytes_inc: u64,
}

/// 时间序列增量响应结构
#[derive(Serialize, Deserialize)]
pub struct TimeSeriesIncrementResponse {
    pub start_ms: u64,
    pub end_ms: u64,
    pub aggregation: String,  // "hourly" 或 "daily"
    pub mac: String,          // MAC 地址（或 "all" 表示聚合）
    pub network_type: String, // "wan" 或 "lan"
    pub increments: Vec<TimeSeriesIncrement>,
    pub total_rx_bytes: u64, // 范围内的总 RX 字节数
    pub total_tx_bytes: u64, // 范围内的总 TX 字节数
    pub total_bytes: u64,    // 范围内的总字节数
}

/// 主机名绑定信息，用于 API 响应
#[derive(Serialize, Deserialize)]
pub struct HostnameBinding {
    pub mac: String,
    pub hostname: String,
}

/// 主机名绑定响应结构
#[derive(Serialize, Deserialize)]
pub struct HostnameBindingsResponse {
    pub bindings: Vec<HostnameBinding>,
}

/// 设置主机名绑定请求结构
#[derive(Serialize, Deserialize)]
pub struct SetHostnameBindingRequest {
    pub mac: String,
    pub hostname: String,
}

/// 时间段，用于 API 请求/响应
#[derive(Serialize, Deserialize, Clone)]
pub struct TimeSlotApi {
    pub start: String, // 格式："HH:MM"
    pub end: String,   // 格式："HH:MM"
    pub days: Vec<u8>, // 1-7（周一到周日）
}

impl From<&TimeSlot> for TimeSlotApi {
    fn from(slot: &TimeSlot) -> Self {
        let mut days = Vec::new();
        for i in 0..7 {
            if (slot.days_of_week & (1 << i)) != 0 {
                days.push(i + 1); // 转换为 1-7（周一到周日）
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

/// 预定速率限制信息，用于 API 响应
#[derive(Serialize, Deserialize)]
pub struct ScheduledRateLimitInfo {
    pub mac: String,
    pub time_slot: TimeSlotApi,
    pub wan_rx_rate_limit: u64,
    pub wan_tx_rate_limit: u64,
}

/// 预定速率限制响应结构
#[derive(Serialize, Deserialize)]
pub struct ScheduledRateLimitsResponse {
    pub limits: Vec<ScheduledRateLimitInfo>,
}

/// 设置预定限制请求结构
#[derive(Serialize, Deserialize)]
pub struct SetScheduledLimitRequest {
    pub mac: String,
    pub time_slot: TimeSlotApi,
    pub wan_rx_rate_limit: u64,
    pub wan_tx_rate_limit: u64,
}

/// 删除预定限制请求结构
#[derive(Serialize, Deserialize)]
pub struct DeleteScheduledLimitRequest {
    pub mac: String,
    pub time_slot: TimeSlotApi,
}

/// 流量 monitoring API handler
#[derive(Clone)]
pub struct TrafficApiHandler {
    scheduled_rate_limits: Arc<Mutex<Vec<ScheduledRateLimit>>>,
    hostname_bindings: Arc<Mutex<HashMap<[u8; 6], String>>>,
    rate_limit_whitelist: Arc<Mutex<HashSet<[u8; 6]>>>,
    rate_limit_whitelist_enabled: Arc<AtomicBool>,
    default_wan_rate_limits: Arc<Mutex<[u64; 2]>>,
    realtime_manager: Arc<RealtimeRingManager>,
    long_term_manager: Arc<LongTermRingManager>,
    device_manager: Arc<crate::device::DeviceManager>,
    options: Options,
}

impl TrafficApiHandler {
    pub fn new_with_rate_limit_whitelist(
        scheduled_rate_limits: Arc<Mutex<Vec<ScheduledRateLimit>>>,
        hostname_bindings: Arc<Mutex<HashMap<[u8; 6], String>>>,
        rate_limit_whitelist: Arc<Mutex<HashSet<[u8; 6]>>>,
        rate_limit_whitelist_enabled: Arc<AtomicBool>,
        default_wan_rate_limits: Arc<Mutex<[u64; 2]>>,
        realtime_manager: Arc<RealtimeRingManager>,
        long_term_manager: Arc<LongTermRingManager>,
        device_manager: Arc<crate::device::DeviceManager>,
        options: Options,
    ) -> Self {
        Self {
            scheduled_rate_limits,
            hostname_bindings,
            rate_limit_whitelist,
            rate_limit_whitelist_enabled,
            default_wan_rate_limits,
            realtime_manager,
            long_term_manager,
            device_manager,
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
            "/api/traffic/usage/ranking",
            "/api/traffic/usage/increments",
            "/api/traffic/rate_limit/whitelist",
            "/api/traffic/rate_limit/whitelist/enabled",
            "/api/traffic/rate_limit/default",
        ]
    }

    pub async fn handle_request(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        match request.path.as_str() {
            "/api/traffic/devices" => {
                if request.method == "GET" {
                    self.handle_devices(request).await
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
            "/api/traffic/rate_limit/whitelist" => match request.method.as_str() {
                "GET" => self.handle_rate_limit_whitelist_get().await,
                "POST" => self.handle_rate_limit_whitelist_add(request).await,
                "DELETE" => self.handle_rate_limit_whitelist_delete(request).await,
                _ => Ok(HttpResponse::error(405, "Method not allowed".to_string())),
            },
            "/api/traffic/rate_limit/whitelist/enabled" => match request.method.as_str() {
                "GET" => self.handle_rate_limit_whitelist_get().await,
                "POST" => self.handle_rate_limit_whitelist_set_enabled(request).await,
                _ => Ok(HttpResponse::error(405, "Method not allowed".to_string())),
            },
            "/api/traffic/rate_limit/default" => match request.method.as_str() {
                "POST" => self.handle_rate_limit_set_default_limits(request).await,
                _ => Ok(HttpResponse::error(405, "Method not allowed".to_string())),
            },
            _ => Ok(HttpResponse::not_found()),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct RateLimitWhitelistStateResponse {
    pub enabled: bool,
    pub default_wan_rx_rate_limit: u64,
    pub default_wan_tx_rate_limit: u64,
    pub macs: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct SetRateLimitWhitelistEnabledRequest {
    pub enabled: bool,
}

#[derive(Serialize, Deserialize)]
pub struct WhitelistMacRequest {
    pub mac: String,
}

#[derive(Serialize, Deserialize)]
pub struct SetDefaultWanRateLimitRequest {
    pub wan_rx_rate_limit: u64,
    pub wan_tx_rate_limit: u64,
}

impl TrafficApiHandler {
    async fn handle_rate_limit_whitelist_get(&self) -> Result<HttpResponse, anyhow::Error> {
        let enabled = self.rate_limit_whitelist_enabled.load(Ordering::Relaxed);
        let default_limits = *self.default_wan_rate_limits.lock().unwrap();
        let wl = self.rate_limit_whitelist.lock().unwrap();
        let mut macs: Vec<String> = wl.iter().map(|m| format_mac(m)).collect();
        macs.sort();
        let response = RateLimitWhitelistStateResponse {
            enabled,
            default_wan_rx_rate_limit: default_limits[0],
            default_wan_tx_rate_limit: default_limits[1],
            macs,
        };
        let api_response = ApiResponse::success(response);
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }

    async fn handle_rate_limit_whitelist_set_enabled(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        let body = request.body.as_ref().ok_or_else(|| anyhow::anyhow!("Missing request body"))?;
        let req: SetRateLimitWhitelistEnabledRequest = serde_json::from_str(body)?;
        self.rate_limit_whitelist_enabled.store(req.enabled, Ordering::Relaxed);
        let wl = self.rate_limit_whitelist.lock().unwrap().clone();
        let default_limits = *self.default_wan_rate_limits.lock().unwrap();
        let policy = crate::storage::traffic::RateLimitPolicy {
            enabled: req.enabled,
            default_wan_limits: default_limits,
            whitelist: wl,
        };
        crate::storage::traffic::save_rate_limit_policy(self.options.data_dir(), &policy)?;
        let api_response = ApiResponse::success(());
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }

    async fn handle_rate_limit_whitelist_add(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        let body = request.body.as_ref().ok_or_else(|| anyhow::anyhow!("Missing request body"))?;
        let req: WhitelistMacRequest = serde_json::from_str(body)?;
        let mac = crate::utils::network_utils::parse_mac_address(&req.mac)?;
        let mut wl = self.rate_limit_whitelist.lock().unwrap();
        wl.insert(mac);
        let enabled = self.rate_limit_whitelist_enabled.load(Ordering::Relaxed);
        let default_limits = *self.default_wan_rate_limits.lock().unwrap();
        let policy = crate::storage::traffic::RateLimitPolicy {
            enabled,
            default_wan_limits: default_limits,
            whitelist: wl.clone(),
        };
        crate::storage::traffic::save_rate_limit_policy(self.options.data_dir(), &policy)?;
        let api_response = ApiResponse::success(());
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }

    async fn handle_rate_limit_whitelist_delete(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        let body = request.body.as_ref().ok_or_else(|| anyhow::anyhow!("Missing request body"))?;
        let req: WhitelistMacRequest = serde_json::from_str(body)?;
        let mac = crate::utils::network_utils::parse_mac_address(&req.mac)?;
        let mut wl = self.rate_limit_whitelist.lock().unwrap();
        wl.remove(&mac);
        let enabled = self.rate_limit_whitelist_enabled.load(Ordering::Relaxed);
        let default_limits = *self.default_wan_rate_limits.lock().unwrap();
        let policy = crate::storage::traffic::RateLimitPolicy {
            enabled,
            default_wan_limits: default_limits,
            whitelist: wl.clone(),
        };
        crate::storage::traffic::save_rate_limit_policy(self.options.data_dir(), &policy)?;
        let api_response = ApiResponse::success(());
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }

    async fn handle_rate_limit_set_default_limits(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        let body = request.body.as_ref().ok_or_else(|| anyhow::anyhow!("Missing request body"))?;
        let req: SetDefaultWanRateLimitRequest = serde_json::from_str(body)?;

        {
            let mut guard = self.default_wan_rate_limits.lock().unwrap();
            *guard = [req.wan_rx_rate_limit, req.wan_tx_rate_limit];
        }

        let enabled = self.rate_limit_whitelist_enabled.load(Ordering::Relaxed);
        let wl = self.rate_limit_whitelist.lock().unwrap().clone();
        let policy = crate::storage::traffic::RateLimitPolicy {
            enabled,
            default_wan_limits: [req.wan_rx_rate_limit, req.wan_tx_rate_limit],
            whitelist: wl,
        };
        crate::storage::traffic::save_rate_limit_policy(self.options.data_dir(), &policy)?;

        let api_response = ApiResponse::success(());
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }
}

impl TrafficApiHandler {
    /// 处理/api/devices endpoint
    /// 查询参数：
    ///   - start_ms: 开始时间戳，毫秒（可选）
    ///   - end_ms: 结束时间戳，毫秒（可选）
    ///   如果都为空，则默认返回所有设备的累积流量（period=all）
    async fn handle_devices(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        let start_ms_param = request.query_params.get("start_ms").and_then(|s| s.parse::<u64>().ok());
        let end_ms_param = request.query_params.get("end_ms").and_then(|s| s.parse::<u64>().ok());

        let time_range = match (start_ms_param, end_ms_param) {
            (Some(start_ms), Some(end_ms)) => {
                if start_ms >= end_ms {
                    return Ok(HttpResponse::error(
                        400,
                        "Invalid time range: start_ms must be less than end_ms".to_string(),
                    ));
                }
                Some((start_ms, end_ms))
            }
            (None, None) => None,
            _ => {
                return Ok(HttpResponse::error(
                    400,
                    "Invalid query: start_ms and end_ms must be provided together".to_string(),
                ));
            }
        };


        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;
        let current_hour_start = (now_ms / (3600 * 1000)) * (3600 * 1000);
        let current_hour_end = current_hour_start + (3600 * 1000);

        let bindings_map = self.hostname_bindings.lock().unwrap();
        let wifi_set = self.device_manager.get_wifi_macs_snapshot();

        // 从设备管理器收集所有设备（包括在线和离线设备）
        let all_devices = self.device_manager.get_all_devices_with_mac();

        let devices: Vec<DeviceInfo> = all_devices
            .into_iter()
            .map(|(mac, device)| {
                let mac = mac;
                let mac_str = format_mac(&mac);

                // 获取 IPv4 和 IPv6 地址
                let final_ipv4 = device.get_current_ipv4();
                let mut ipv6_set: HashSet<[u8; 16]> = HashSet::new();

                for addr in device.get_all_ipv6() {
                    if addr != [0u8; 16] {
                        ipv6_set.insert(addr);
                    }
                }

                let ip_str = format!("{}.{}.{}.{}", final_ipv4[0], final_ipv4[1], final_ipv4[2], final_ipv4[3]);

                let mut ipv6_addresses: Vec<String> = ipv6_set
                    .iter()
                    .map(|addr| crate::utils::network_utils::format_ipv6(addr))
                    .collect();
                ipv6_addresses.sort();

                let hostname = if !device.hostname.is_empty() {
                    device.hostname.clone()
                } else {
                    bindings_map.get(&mac).cloned().unwrap_or_default()
                };

                let connection_type = if wifi_set.contains(&mac) {
                    "wifi".to_string()
                } else {
                    "".to_string()
                };

                // 计算指定时间段的流量
                let (
                    final_total_rx_bytes,
                    final_total_tx_bytes,
                    final_lan_rx_bytes,
                    final_lan_tx_bytes,
                    final_wan_rx_bytes,
                    final_wan_tx_bytes,
                ) = if let Some((start_ms, end_ms)) = time_range {
                    // 查询时间段内的增量（从ring文件累加已保存的增量）
                    let mut period_wan_rx = 0u64;
                    let mut period_wan_tx = 0u64;
                    let mut period_lan_rx = 0u64;
                    let mut period_lan_tx = 0u64;

                    // 从ring文件获取start_ms到end_ms之间已保存的增量
                    let ring_rows = match self.long_term_manager.query_stats_by_mac(&mac, start_ms, end_ms) {
                        Ok(rows) => rows,
                        Err(e) => {
                            log::warn!("Failed to query ring stats for MAC {}: {}", format_mac(&mac), e);
                            Vec::new()
                        }
                    };

                    log::debug!(
                        "MAC {}: ring query returned {} rows in time range",
                        format_mac(&mac),
                        ring_rows.len()
                    );

                    for row in &ring_rows {
                        period_wan_rx = period_wan_rx.saturating_add(row.wan_rx_bytes_inc);
                        period_wan_tx = period_wan_tx.saturating_add(row.wan_tx_bytes_inc);
                        period_lan_rx = period_lan_rx.saturating_add(row.lan_rx_bytes_inc);
                        period_lan_tx = period_lan_tx.saturating_add(row.lan_tx_bytes_inc);
                    }

                    log::debug!(
                        "MAC {}: ring data - WAN: {}/{} bytes, LAN: {}/{} bytes",
                        format_mac(&mac),
                        format_bytes(period_wan_rx),
                        format_bytes(period_wan_tx),
                        format_bytes(period_lan_rx),
                        format_bytes(period_lan_tx)
                    );

                    // 口径与 /api/traffic/usage/ranking 一致：只有当查询范围覆盖当前小时，才加上当前小时增量
                    let query_overlaps_current_hour = start_ms < current_hour_end && end_ms > current_hour_start;
                    if query_overlaps_current_hour {
                        let active_increments = self.long_term_manager.get_active_increments();
                        if let Some(&(wan_rx_inc, wan_tx_inc, lan_rx_inc, lan_tx_inc)) = active_increments.get(&mac) {
                            period_wan_rx = period_wan_rx.saturating_add(wan_rx_inc);
                            period_wan_tx = period_wan_tx.saturating_add(wan_tx_inc);
                            period_lan_rx = period_lan_rx.saturating_add(lan_rx_inc);
                            period_lan_tx = period_lan_tx.saturating_add(lan_tx_inc);

                            log::debug!(
                                "MAC {}: included current-hour increments - WAN: {}/{} bytes, LAN: {}/{} bytes",
                                format_mac(&mac),
                                format_bytes(wan_rx_inc),
                                format_bytes(wan_tx_inc),
                                format_bytes(lan_rx_inc),
                                format_bytes(lan_tx_inc)
                            );
                        } else {
                            log::debug!("MAC {}: no active current-hour increments found", format_mac(&mac));
                        }
                    } else {
                        log::debug!("MAC {}: query does not overlap current hour, skip accumulator", format_mac(&mac));
                    }

                    log::debug!(
                        "MAC {}: final period data - WAN: {}/{} bytes, LAN: {}/{} bytes",
                        format_mac(&mac),
                        format_bytes(period_wan_rx),
                        format_bytes(period_wan_tx),
                        format_bytes(period_lan_rx),
                        format_bytes(period_lan_tx)
                    );

                    (
                        period_wan_rx + period_lan_rx,
                        period_wan_tx + period_lan_tx,
                        period_lan_rx,
                        period_lan_tx,
                        period_wan_rx,
                        period_wan_tx,
                    )
                } else {
                    // period == "all"，使用device的总累积流量（最新最准确）
                    (
                        device.total_rx_bytes(),
                        device.total_tx_bytes(),
                        device.lan_rx_bytes,
                        device.lan_tx_bytes,
                        device.wan_rx_bytes,
                        device.wan_tx_bytes,
                    )
                };

                

                let device_info = DeviceInfo {
                    ip: ip_str,
                    ipv6_addresses,
                    mac: mac_str,
                    hostname,
                    connection_type,
                    total_rx_bytes: final_total_rx_bytes,
                    total_tx_bytes: final_total_tx_bytes,
                    total_rx_rate: device.total_rx_rate(),
                    total_tx_rate: device.total_tx_rate(),
                    wan_rx_rate_limit: device.wan_rx_rate_limit,
                    wan_tx_rate_limit: device.wan_tx_rate_limit,
                    lan_rx_bytes: final_lan_rx_bytes,
                    lan_tx_bytes: final_lan_tx_bytes,
                    lan_rx_rate: device.lan_rx_rate,
                    lan_tx_rate: device.lan_tx_rate,
                    wan_rx_bytes: final_wan_rx_bytes,
                    wan_tx_bytes: final_wan_tx_bytes,
                    wan_rx_rate: device.wan_rx_rate,
                    wan_tx_rate: device.wan_tx_rate,
                    last_online_ts: device.last_online_ts,
                };

                log::debug!(
                    "MAC {}: final device stats - Total: {}/{} bytes, WAN: {}/{} bytes, LAN: {}/{} bytes",
                    format_mac(&mac),
                    format_bytes(final_total_rx_bytes),
                    format_bytes(final_total_tx_bytes),
                    format_bytes(final_wan_rx_bytes),
                    format_bytes(final_wan_tx_bytes),
                    format_bytes(final_lan_rx_bytes),
                    format_bytes(final_lan_tx_bytes)
                );

                device_info
            })
            .collect();

        let mut devices = devices;
        devices.retain(|device| device.ip != "0.0.0.0");

        devices.sort_by(|a, b| {
            let a_ip: std::net::Ipv4Addr = a.ip.parse().unwrap_or(std::net::Ipv4Addr::new(0, 0, 0, 0));
            let b_ip: std::net::Ipv4Addr = b.ip.parse().unwrap_or(std::net::Ipv4Addr::new(0, 0, 0, 0));
            a_ip.cmp(&b_ip)
        });

        let response = DevicesResponse { devices };
        let api_response = ApiResponse::success(response);
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }

    /// 处理/api/traffic/metrics endpoint - 实时指标（仅内存，未持久化）
    async fn handle_metrics(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        let mac_opt = request.query_params.get("mac").cloned();

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;

        let start_ms = now_ms.saturating_sub(self.options.traffic_retention_seconds() as u64 * 1000);

        let end_ms = now_ms;

        let (rows_result, mac_label) = if let Some(mac_str) = mac_opt {
            if mac_str.to_ascii_lowercase() == "all" || mac_str.trim().is_empty() {
                (
                    self.realtime_manager.query_metrics_aggregate_all(start_ms, end_ms),
                    "all".to_string(),
                )
            } else {
                match crate::utils::network_utils::parse_mac_address(&mac_str) {
                    Ok(mac) => (
                        self.realtime_manager.query_metrics_by_mac(&mac, start_ms, end_ms),
                        format_mac(&mac),
                    ),
                    Err(e) => {
                        return Ok(HttpResponse::error(400, format!("Invalid MAC: {}", e)));
                    }
                }
            }
        } else {
            (
                self.realtime_manager.query_metrics_aggregate_all(start_ms, end_ms),
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
                            r.lan_rx_bytes_inc,
                            r.lan_tx_bytes_inc,
                            r.wan_rx_bytes_inc,
                            r.wan_tx_bytes_inc,
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

    /// 处理/api/traffic/bindings endpoint (GET)
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

    /// 处理/api/traffic/bindings endpoint (POST)
    async fn handle_set_hostname_binding(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        let body = request.body.as_ref().ok_or_else(|| anyhow::anyhow!("Missing request body"))?;

        // 解析JSON request body using serde
        let set_binding_request: SetHostnameBindingRequest = serde_json::from_str(body)?;

        let mac = crate::utils::network_utils::parse_mac_address(&set_binding_request.mac)?;

        // Allow empty hostname (for clearing bindings)
        let hostname = set_binding_request.hostname.trim();

        // 更新in-memory hostname bindings
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
            log::info!("Hostname binding set for MAC: {} -> {}", format_mac(&mac), hostname);
        }

        let api_response = ApiResponse::success(());
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }

    /// 处理/api/traffic/limits/schedule endpoint (GET)
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

    /// 处理/api/traffic/limits/schedule endpoint (POST)
    async fn handle_set_scheduled_limit(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        let body = request.body.as_ref().ok_or_else(|| anyhow::anyhow!("Missing request body"))?;

        // 解析JSON request body
        let set_request: SetScheduledLimitRequest = serde_json::from_str(body)?;

        let mac = crate::utils::network_utils::parse_mac_address(&set_request.mac)?;
        let time_slot = TimeSlot::try_from(&set_request.time_slot).map_err(|e| anyhow::anyhow!("Invalid time slot: {}", e))?;

        let scheduled_limit = ScheduledRateLimit {
            mac,
            time_slot,
            wan_rx_rate_limit: set_request.wan_rx_rate_limit,
            wan_tx_rate_limit: set_request.wan_tx_rate_limit,
        };

        // 更新in-memory scheduled rate limits
        {
            let mut srl = self.scheduled_rate_limits.lock().unwrap();
            // 移除existing rule with same MAC and time slot
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

    /// 处理/api/traffic/limits/schedule endpoint (DELETE)
    async fn handle_delete_scheduled_limit(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        let body = request.body.as_ref().ok_or_else(|| anyhow::anyhow!("Missing request body"))?;

        // 解析JSON request body
        let delete_request: DeleteScheduledLimitRequest = serde_json::from_str(body)?;

        let mac = crate::utils::network_utils::parse_mac_address(&delete_request.mac)?;
        let time_slot = TimeSlot::try_from(&delete_request.time_slot).map_err(|e| anyhow::anyhow!("Invalid time slot: {}", e))?;

        // 移除from in-memory scheduled rate limits
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

        // 移除from file
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

    /// 处理/api/traffic/usage/ranking endpoint
    /// 查询参数：
    ///   - start_ms: 开始时间戳，毫秒（可选，默认为 365 天前）
    ///   - end_ms: 结束时间戳，毫秒（可选，默认为现在）
    ///   - network_type: "wan", "lan", 或 "all"（可选，默认为 "wan"）
    async fn handle_usage_ranking(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        // 解析 network_type 参数
        let network_type = request
            .query_params
            .get("network_type")
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| "wan".to_string());

        if network_type != "wan" && network_type != "lan" && network_type != "all" {
            return Ok(HttpResponse::error(
                400,
                "Invalid network_type: must be 'wan', 'lan', or 'all'".to_string(),
            ));
        }

        // 从查询参数解析时间范围
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;

        let start_ms = request
            .query_params
            .get("start_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or_else(|| {
                // 默认为 365 天前
                now_ms.saturating_sub(365 * 24 * 3600 * 1000)
            });

        let end_ms = request
            .query_params
            .get("end_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(now_ms);

        // 验证时间范围
        if start_ms >= end_ms {
            return Ok(HttpResponse::error(
                400,
                "Invalid time range: start_ms must be less than end_ms".to_string(),
            ));
        }

        // 查询所有设备的统计信息
        let mut device_stats = match self.long_term_manager.query_stats_by_device(start_ms, end_ms) {
            Ok(stats) => stats,
            Err(e) => {
                return Ok(HttpResponse::error(500, format!("Failed to query stats: {}", e)));
            }
        };

        // 只有当查询时间范围包含当前小时时，才加上当前小时的增量（从accumulator获取）
        let current_hour_start = (now_ms / (3600 * 1000)) * (3600 * 1000); // 当前小时开始时间
        let current_hour_end = current_hour_start + (3600 * 1000); // 当前小时结束时间

        // 检查查询时间范围是否与当前小时有重叠
        let query_overlaps_current_hour = start_ms < current_hour_end && end_ms > current_hour_start;

        if query_overlaps_current_hour {
            let active_increments = self.long_term_manager.get_active_increments();
            for (mac, (wan_rx_inc, wan_tx_inc, lan_rx_inc, lan_tx_inc)) in active_increments.iter() {
                let entry = device_stats.entry(*mac).or_insert_with(|| {
                    use crate::storage::traffic::MetricsRowWithStats;
                    MetricsRowWithStats {
                        start_ts_ms: start_ms,
                        end_ts_ms: end_ms,
                        wan_rx_rate_avg: 0,
                        wan_rx_rate_max: 0,
                        wan_rx_rate_min: 0,
                        wan_rx_rate_p90: 0,
                        wan_rx_rate_p95: 0,
                        wan_rx_rate_p99: 0,
                        wan_tx_rate_avg: 0,
                        wan_tx_rate_max: 0,
                        wan_tx_rate_min: 0,
                        wan_tx_rate_p90: 0,
                        wan_tx_rate_p95: 0,
                        wan_tx_rate_p99: 0,
                        wan_rx_bytes_inc: 0,
                        wan_tx_bytes_inc: 0,
                        lan_rx_rate_avg: 0,
                        lan_rx_rate_max: 0,
                        lan_rx_rate_min: 0,
                        lan_rx_rate_p90: 0,
                        lan_rx_rate_p95: 0,
                        lan_rx_rate_p99: 0,
                        lan_tx_rate_avg: 0,
                        lan_tx_rate_max: 0,
                        lan_tx_rate_min: 0,
                        lan_tx_rate_p90: 0,
                        lan_tx_rate_p95: 0,
                        lan_tx_rate_p99: 0,
                        lan_rx_bytes_inc: 0,
                        lan_tx_bytes_inc: 0,
                        last_online_ts: 0,
                    }
                });

                // 加上当前小时的增量
                entry.wan_rx_bytes_inc = entry.wan_rx_bytes_inc.saturating_add(*wan_rx_inc);
                entry.wan_tx_bytes_inc = entry.wan_tx_bytes_inc.saturating_add(*wan_tx_inc);
                entry.lan_rx_bytes_inc = entry.lan_rx_bytes_inc.saturating_add(*lan_rx_inc);
                entry.lan_tx_bytes_inc = entry.lan_tx_bytes_inc.saturating_add(*lan_tx_inc);
            }
        }

        if device_stats.is_empty() {
            let response = DeviceUsageRankingResponse {
                start_ms,
                end_ms,
                network_type: network_type.clone(),
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

        let mut rankings: Vec<DeviceUsageRanking> = Vec::new();

        for (mac, stats) in device_stats.iter() {
            // 根据 network_type 选择相应的流量数据
            let (device_rx_bytes, device_tx_bytes) = match network_type.as_str() {
                "wan" => (stats.wan_rx_bytes_inc, stats.wan_tx_bytes_inc),
                "lan" => (stats.lan_rx_bytes_inc, stats.lan_tx_bytes_inc),
                "all" => (
                    stats.wan_rx_bytes_inc + stats.lan_rx_bytes_inc,
                    stats.wan_tx_bytes_inc + stats.lan_tx_bytes_inc,
                ),
                _ => (stats.wan_rx_bytes_inc, stats.wan_tx_bytes_inc), // 默认为 WAN
            };

            let total_device_bytes = device_rx_bytes + device_tx_bytes;

            let mac_str = format_mac(mac);

            // 从设备管理器获取设备信息
            let device = self.device_manager.get_device_by_mac(mac);
            let hostname = device
                .as_ref()
                .map(|d| d.hostname.clone())
                .filter(|h| !h.is_empty())
                .or_else(|| bindings_map.get(mac).cloned())
                .unwrap_or_default();

            let ip_address = device.as_ref().and_then(|d| d.current_ipv4).unwrap_or([0, 0, 0, 0]);

            let ip_str = format!("{}.{}.{}.{}", ip_address[0], ip_address[1], ip_address[2], ip_address[3]);

            rankings.push(DeviceUsageRanking {
                mac: mac_str,
                hostname,
                ip: ip_str,
                total_bytes: total_device_bytes,
                rx_bytes: device_rx_bytes,
                tx_bytes: device_tx_bytes,
                percentage: 0.0, // Will calculate after sorting
                rank: 0,         // Will set after sorting
            });
        }

        // totals 统计所有设备（包括离线设备）
        let total_bytes: u64 = rankings.iter().map(|r| r.total_bytes).sum();
        let total_rx_bytes: u64 = rankings.iter().map(|r| r.rx_bytes).sum();
        let total_tx_bytes: u64 = rankings.iter().map(|r| r.tx_bytes).sum();

        // 排序by total_bytes descending
        rankings.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));

        // 计算percentages and set ranks
        for (idx, ranking) in rankings.iter_mut().enumerate() {
            ranking.rank = idx + 1;
            if total_bytes > 0 {
                ranking.percentage = (ranking.total_bytes as f64 / total_bytes as f64) * 100.0;
            }
        }

        let response = DeviceUsageRankingResponse {
            start_ms,
            end_ms,
            network_type,
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

    /// 处理/api/traffic/usage/increments endpoint
    /// 从长期数据查询时间序列增量（每小时或每日）
    /// 查询参数：
    ///   - mac: MAC 地址（可选，默认为 "all" 表示聚合）
    ///   - start_ms: 开始时间戳，毫秒（可选，默认为 365 天前）
    ///   - end_ms: 结束时间戳，毫秒（可选，默认为现在）
    ///   - aggregation: "hourly" 或 "daily"（可选，默认为 "hourly"）
    ///   - network_type: "wan" 或 "lan"（可选，默认为 "wan"）
    async fn handle_usage_increments(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
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

        let network_type = request
            .query_params
            .get("network_type")
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| "all".to_string());

        if network_type != "wan" && network_type != "lan" && network_type != "all" {
            return Ok(HttpResponse::error(
                400,
                "Invalid network_type: must be 'wan', 'lan', or 'all'".to_string(),
            ));
        }

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

        let mac_param = request.query_params.get("mac");
        let query_mac = if let Some(mac_str) = mac_param {
            if mac_str.to_ascii_lowercase() == "all" || mac_str.trim().is_empty() {
                None
            } else {
                match crate::utils::network_utils::parse_mac_address(mac_str) {
                    Ok(mac) => Some(mac),
                    Err(e) => {
                        return Ok(HttpResponse::error(400, format!("Invalid MAC: {}", e)));
                    }
                }
            }
        } else {
            None
        };

        let rows_result = if let Some(mac) = query_mac {
            self.long_term_manager.query_stats_by_mac(&mac, start_ms, end_ms)
        } else {
            self.long_term_manager.query_stats_aggregate_all(start_ms, end_ms)
        };

        let rows = match rows_result {
            Ok(rows) => rows,
            Err(e) => {
                return Ok(HttpResponse::error(500, format!("Failed to query stats: {}", e)));
            }
        };

        let mut increments: Vec<TimeSeriesIncrement> = rows
            .into_iter()
            .map(|r| TimeSeriesIncrement {
                start_ts_ms: r.start_ts_ms,
                end_ts_ms: r.end_ts_ms,
                wan_rx_rate_avg: r.wan_rx_rate_avg,
                wan_rx_rate_max: r.wan_rx_rate_max,
                wan_rx_rate_min: r.wan_rx_rate_min,
                wan_rx_rate_p90: r.wan_rx_rate_p90,
                wan_rx_rate_p95: r.wan_rx_rate_p95,
                wan_rx_rate_p99: r.wan_rx_rate_p99,
                wan_tx_rate_avg: r.wan_tx_rate_avg,
                wan_tx_rate_max: r.wan_tx_rate_max,
                wan_tx_rate_min: r.wan_tx_rate_min,
                wan_tx_rate_p90: r.wan_tx_rate_p90,
                wan_tx_rate_p95: r.wan_tx_rate_p95,
                wan_tx_rate_p99: r.wan_tx_rate_p99,
                wan_rx_bytes_inc: r.wan_rx_bytes_inc,
                wan_tx_bytes_inc: r.wan_tx_bytes_inc,
                lan_rx_rate_avg: r.lan_rx_rate_avg,
                lan_rx_rate_max: r.lan_rx_rate_max,
                lan_rx_rate_min: r.lan_rx_rate_min,
                lan_rx_rate_p90: r.lan_rx_rate_p90,
                lan_rx_rate_p95: r.lan_rx_rate_p95,
                lan_rx_rate_p99: r.lan_rx_rate_p99,
                lan_tx_rate_avg: r.lan_tx_rate_avg,
                lan_tx_rate_max: r.lan_tx_rate_max,
                lan_tx_rate_min: r.lan_tx_rate_min,
                lan_tx_rate_p90: r.lan_tx_rate_p90,
                lan_tx_rate_p95: r.lan_tx_rate_p95,
                lan_tx_rate_p99: r.lan_tx_rate_p99,
                lan_rx_bytes_inc: r.lan_rx_bytes_inc,
                lan_tx_bytes_inc: r.lan_tx_bytes_inc,
            })
            .collect();

        // 检查查询时间范围是否与当前小时有重叠，如果有则加上当前小时的活跃增量
        let current_hour_start = (now_ms / (3600 * 1000)) * (3600 * 1000); // 当前小时开始时间
        let current_hour_end = current_hour_start + (3600 * 1000); // 当前小时结束时间

        // 检查查询时间范围是否与当前小时有重叠
        let query_overlaps_current_hour = start_ms < current_hour_end && end_ms > current_hour_start;

        if query_overlaps_current_hour {
            // 获取活跃的 accumulator 数据（包含速率统计）
            let active_accumulators = self.long_term_manager.get_active_accumulators_with_stats();

            if let Some(ref mac) = query_mac {
                // 查询特定 MAC 地址
                if let Some(acc) = active_accumulators.get(mac) {
                    // 为当前小时创建 TimeSeriesIncrement 条目（包含速率统计）
                    let current_hour_increment = TimeSeriesIncrement {
                        start_ts_ms: current_hour_start,
                        end_ts_ms: now_ms.min(current_hour_end),
                        wan_rx_rate_avg: acc.wan_rx_rate.avg,
                        wan_rx_rate_max: acc.wan_rx_rate.max,
                        wan_rx_rate_min: acc.wan_rx_rate.min,
                        wan_rx_rate_p90: acc.wan_rx_rate.p90,
                        wan_rx_rate_p95: acc.wan_rx_rate.p95,
                        wan_rx_rate_p99: acc.wan_rx_rate.p99,
                        wan_tx_rate_avg: acc.wan_tx_rate.avg,
                        wan_tx_rate_max: acc.wan_tx_rate.max,
                        wan_tx_rate_min: acc.wan_tx_rate.min,
                        wan_tx_rate_p90: acc.wan_tx_rate.p90,
                        wan_tx_rate_p95: acc.wan_tx_rate.p95,
                        wan_tx_rate_p99: acc.wan_tx_rate.p99,
                        wan_rx_bytes_inc: acc.get_wan_rx_bytes_increment(),
                        wan_tx_bytes_inc: acc.get_wan_tx_bytes_increment(),
                        lan_rx_rate_avg: acc.lan_rx_rate.avg,
                        lan_rx_rate_max: acc.lan_rx_rate.max,
                        lan_rx_rate_min: acc.lan_rx_rate.min,
                        lan_rx_rate_p90: acc.lan_rx_rate.p90,
                        lan_rx_rate_p95: acc.lan_rx_rate.p95,
                        lan_rx_rate_p99: acc.lan_rx_rate.p99,
                        lan_tx_rate_avg: acc.lan_tx_rate.avg,
                        lan_tx_rate_max: acc.lan_tx_rate.max,
                        lan_tx_rate_min: acc.lan_tx_rate.min,
                        lan_tx_rate_p90: acc.lan_tx_rate.p90,
                        lan_tx_rate_p95: acc.lan_tx_rate.p95,
                        lan_tx_rate_p99: acc.lan_tx_rate.p99,
                        lan_rx_bytes_inc: acc.get_lan_rx_bytes_increment(),
                        lan_tx_bytes_inc: acc.get_lan_tx_bytes_increment(),
                    };

                    // 检查是否已经存在当前小时的条目，如果存在则累加字节数和取速率最大值，否则添加新的条目
                    let mut found = false;
                    for inc in &mut increments {
                        if inc.start_ts_ms == current_hour_start {
                            inc.wan_rx_bytes_inc = inc.wan_rx_bytes_inc.saturating_add(acc.get_wan_rx_bytes_increment());
                            inc.wan_tx_bytes_inc = inc.wan_tx_bytes_inc.saturating_add(acc.get_wan_tx_bytes_increment());
                            inc.lan_rx_bytes_inc = inc.lan_rx_bytes_inc.saturating_add(acc.get_lan_rx_bytes_increment());
                            inc.lan_tx_bytes_inc = inc.lan_tx_bytes_inc.saturating_add(acc.get_lan_tx_bytes_increment());

                            // 速率统计：取最大值（因为同一个时间段可能有多个来源的数据）
                            inc.wan_rx_rate_avg = inc.wan_rx_rate_avg.max(acc.wan_rx_rate.avg);
                            inc.wan_rx_rate_max = inc.wan_rx_rate_max.max(acc.wan_rx_rate.max);
                            inc.wan_rx_rate_min = if inc.wan_rx_rate_min == 0 {
                                acc.wan_rx_rate.min
                            } else {
                                inc.wan_rx_rate_min.min(acc.wan_rx_rate.min)
                            };
                            inc.wan_rx_rate_p90 = inc.wan_rx_rate_p90.max(acc.wan_rx_rate.p90);
                            inc.wan_rx_rate_p95 = inc.wan_rx_rate_p95.max(acc.wan_rx_rate.p95);
                            inc.wan_rx_rate_p99 = inc.wan_rx_rate_p99.max(acc.wan_rx_rate.p99);

                            inc.wan_tx_rate_avg = inc.wan_tx_rate_avg.max(acc.wan_tx_rate.avg);
                            inc.wan_tx_rate_max = inc.wan_tx_rate_max.max(acc.wan_tx_rate.max);
                            inc.wan_tx_rate_min = if inc.wan_tx_rate_min == 0 {
                                acc.wan_tx_rate.min
                            } else {
                                inc.wan_tx_rate_min.min(acc.wan_tx_rate.min)
                            };
                            inc.wan_tx_rate_p90 = inc.wan_tx_rate_p90.max(acc.wan_tx_rate.p90);
                            inc.wan_tx_rate_p95 = inc.wan_tx_rate_p95.max(acc.wan_tx_rate.p95);
                            inc.wan_tx_rate_p99 = inc.wan_tx_rate_p99.max(acc.wan_tx_rate.p99);

                            inc.lan_rx_rate_avg = inc.lan_rx_rate_avg.max(acc.lan_rx_rate.avg);
                            inc.lan_rx_rate_max = inc.lan_rx_rate_max.max(acc.lan_rx_rate.max);
                            inc.lan_rx_rate_min = if inc.lan_rx_rate_min == 0 {
                                acc.lan_rx_rate.min
                            } else {
                                inc.lan_rx_rate_min.min(acc.lan_rx_rate.min)
                            };
                            inc.lan_rx_rate_p90 = inc.lan_rx_rate_p90.max(acc.lan_rx_rate.p90);
                            inc.lan_rx_rate_p95 = inc.lan_rx_rate_p95.max(acc.lan_rx_rate.p95);
                            inc.lan_rx_rate_p99 = inc.lan_rx_rate_p99.max(acc.lan_rx_rate.p99);

                            inc.lan_tx_rate_avg = inc.lan_tx_rate_avg.max(acc.lan_tx_rate.avg);
                            inc.lan_tx_rate_max = inc.lan_tx_rate_max.max(acc.lan_tx_rate.max);
                            inc.lan_tx_rate_min = if inc.lan_tx_rate_min == 0 {
                                acc.lan_tx_rate.min
                            } else {
                                inc.lan_tx_rate_min.min(acc.lan_tx_rate.min)
                            };
                            inc.lan_tx_rate_p90 = inc.lan_tx_rate_p90.max(acc.lan_tx_rate.p90);
                            inc.lan_tx_rate_p95 = inc.lan_tx_rate_p95.max(acc.lan_tx_rate.p95);
                            inc.lan_tx_rate_p99 = inc.lan_tx_rate_p99.max(acc.lan_tx_rate.p99);

                            found = true;
                            break;
                        }
                    }

                    if !found {
                        increments.push(current_hour_increment);
                    }
                }
            } else {
                // 聚合所有设备的查询
                // 需要聚合所有设备的活跃 accumulator 数据（包括速率统计）
                let mut current_hour_wan_rx_total = 0u64;
                let mut current_hour_wan_tx_total = 0u64;
                let mut current_hour_lan_rx_total = 0u64;
                let mut current_hour_lan_tx_total = 0u64;

                // 聚合速率统计：累加平均值，取最大值的最大，取最小值的最小
                let mut wan_rx_rate_avg_sum = 0u64;
                let mut wan_rx_rate_max = 0u64;
                let mut wan_rx_rate_min = u64::MAX;
                let mut wan_rx_rate_p90_sum = 0u64;
                let mut wan_rx_rate_p95_sum = 0u64;
                let mut wan_rx_rate_p99_sum = 0u64;

                let mut wan_tx_rate_avg_sum = 0u64;
                let mut wan_tx_rate_max = 0u64;
                let mut wan_tx_rate_min = u64::MAX;
                let mut wan_tx_rate_p90_sum = 0u64;
                let mut wan_tx_rate_p95_sum = 0u64;
                let mut wan_tx_rate_p99_sum = 0u64;

                let mut lan_rx_rate_avg_sum = 0u64;
                let mut lan_rx_rate_max = 0u64;
                let mut lan_rx_rate_min = u64::MAX;
                let mut lan_rx_rate_p90_sum = 0u64;
                let mut lan_rx_rate_p95_sum = 0u64;
                let mut lan_rx_rate_p99_sum = 0u64;

                let mut lan_tx_rate_avg_sum = 0u64;
                let mut lan_tx_rate_max = 0u64;
                let mut lan_tx_rate_min = u64::MAX;
                let mut lan_tx_rate_p90_sum = 0u64;
                let mut lan_tx_rate_p95_sum = 0u64;
                let mut lan_tx_rate_p99_sum = 0u64;

                let device_count = active_accumulators.len() as u64;

                for acc in active_accumulators.values() {
                    current_hour_wan_rx_total = current_hour_wan_rx_total.saturating_add(acc.get_wan_rx_bytes_increment());
                    current_hour_wan_tx_total = current_hour_wan_tx_total.saturating_add(acc.get_wan_tx_bytes_increment());
                    current_hour_lan_rx_total = current_hour_lan_rx_total.saturating_add(acc.get_lan_rx_bytes_increment());
                    current_hour_lan_tx_total = current_hour_lan_tx_total.saturating_add(acc.get_lan_tx_bytes_increment());

                    // 聚合 WAN 速率统计
                    wan_rx_rate_avg_sum = wan_rx_rate_avg_sum.saturating_add(acc.wan_rx_rate.avg);
                    wan_rx_rate_max = wan_rx_rate_max.max(acc.wan_rx_rate.max);
                    wan_rx_rate_min = wan_rx_rate_min.min(acc.wan_rx_rate.min);
                    wan_rx_rate_p90_sum = wan_rx_rate_p90_sum.saturating_add(acc.wan_rx_rate.p90);
                    wan_rx_rate_p95_sum = wan_rx_rate_p95_sum.saturating_add(acc.wan_rx_rate.p95);
                    wan_rx_rate_p99_sum = wan_rx_rate_p99_sum.saturating_add(acc.wan_rx_rate.p99);

                    wan_tx_rate_avg_sum = wan_tx_rate_avg_sum.saturating_add(acc.wan_tx_rate.avg);
                    wan_tx_rate_max = wan_tx_rate_max.max(acc.wan_tx_rate.max);
                    wan_tx_rate_min = wan_tx_rate_min.min(acc.wan_tx_rate.min);
                    wan_tx_rate_p90_sum = wan_tx_rate_p90_sum.saturating_add(acc.wan_tx_rate.p90);
                    wan_tx_rate_p95_sum = wan_tx_rate_p95_sum.saturating_add(acc.wan_tx_rate.p95);
                    wan_tx_rate_p99_sum = wan_tx_rate_p99_sum.saturating_add(acc.wan_tx_rate.p99);

                    // 聚合 LAN 速率统计
                    lan_rx_rate_avg_sum = lan_rx_rate_avg_sum.saturating_add(acc.lan_rx_rate.avg);
                    lan_rx_rate_max = lan_rx_rate_max.max(acc.lan_rx_rate.max);
                    lan_rx_rate_min = lan_rx_rate_min.min(acc.lan_rx_rate.min);
                    lan_rx_rate_p90_sum = lan_rx_rate_p90_sum.saturating_add(acc.lan_rx_rate.p90);
                    lan_rx_rate_p95_sum = lan_rx_rate_p95_sum.saturating_add(acc.lan_rx_rate.p95);
                    lan_rx_rate_p99_sum = lan_rx_rate_p99_sum.saturating_add(acc.lan_rx_rate.p99);

                    lan_tx_rate_avg_sum = lan_tx_rate_avg_sum.saturating_add(acc.lan_tx_rate.avg);
                    lan_tx_rate_max = lan_tx_rate_max.max(acc.lan_tx_rate.max);
                    lan_tx_rate_min = lan_tx_rate_min.min(acc.lan_tx_rate.min);
                    lan_tx_rate_p90_sum = lan_tx_rate_p90_sum.saturating_add(acc.lan_tx_rate.p90);
                    lan_tx_rate_p95_sum = lan_tx_rate_p95_sum.saturating_add(acc.lan_tx_rate.p95);
                    lan_tx_rate_p99_sum = lan_tx_rate_p99_sum.saturating_add(acc.lan_tx_rate.p99);
                }

                // 处理最小值（如果没有数据则设为0）
                if wan_rx_rate_min == u64::MAX {
                    wan_rx_rate_min = 0;
                }
                if wan_tx_rate_min == u64::MAX {
                    wan_tx_rate_min = 0;
                }
                if lan_rx_rate_min == u64::MAX {
                    lan_rx_rate_min = 0;
                }
                if lan_tx_rate_min == u64::MAX {
                    lan_tx_rate_min = 0;
                }

                if device_count > 0 {
                    let current_hour_increment = TimeSeriesIncrement {
                        start_ts_ms: current_hour_start,
                        end_ts_ms: now_ms.min(current_hour_end),
                        wan_rx_rate_avg: wan_rx_rate_avg_sum / device_count,
                        wan_rx_rate_max,
                        wan_rx_rate_min,
                        wan_rx_rate_p90: wan_rx_rate_p90_sum / device_count,
                        wan_rx_rate_p95: wan_rx_rate_p95_sum / device_count,
                        wan_rx_rate_p99: wan_rx_rate_p99_sum / device_count,
                        wan_tx_rate_avg: wan_tx_rate_avg_sum / device_count,
                        wan_tx_rate_max,
                        wan_tx_rate_min,
                        wan_tx_rate_p90: wan_tx_rate_p90_sum / device_count,
                        wan_tx_rate_p95: wan_tx_rate_p95_sum / device_count,
                        wan_tx_rate_p99: wan_tx_rate_p99_sum / device_count,
                        wan_rx_bytes_inc: current_hour_wan_rx_total,
                        wan_tx_bytes_inc: current_hour_wan_tx_total,
                        lan_rx_rate_avg: lan_rx_rate_avg_sum / device_count,
                        lan_rx_rate_max,
                        lan_rx_rate_min,
                        lan_rx_rate_p90: lan_rx_rate_p90_sum / device_count,
                        lan_rx_rate_p95: lan_rx_rate_p95_sum / device_count,
                        lan_rx_rate_p99: lan_rx_rate_p99_sum / device_count,
                        lan_tx_rate_avg: lan_tx_rate_avg_sum / device_count,
                        lan_tx_rate_max,
                        lan_tx_rate_min,
                        lan_tx_rate_p90: lan_tx_rate_p90_sum / device_count,
                        lan_tx_rate_p95: lan_tx_rate_p95_sum / device_count,
                        lan_tx_rate_p99: lan_tx_rate_p99_sum / device_count,
                        lan_rx_bytes_inc: current_hour_lan_rx_total,
                        lan_tx_bytes_inc: current_hour_lan_tx_total,
                    };

                    // 检查是否已经存在当前小时的条目，如果存在则合并数据
                    let mut found = false;
                    for inc in &mut increments {
                        if inc.start_ts_ms == current_hour_start {
                            inc.wan_rx_bytes_inc = inc.wan_rx_bytes_inc.saturating_add(current_hour_wan_rx_total);
                            inc.wan_tx_bytes_inc = inc.wan_tx_bytes_inc.saturating_add(current_hour_wan_tx_total);
                            inc.lan_rx_bytes_inc = inc.lan_rx_bytes_inc.saturating_add(current_hour_lan_rx_total);
                            inc.lan_tx_bytes_inc = inc.lan_tx_bytes_inc.saturating_add(current_hour_lan_tx_total);

                            // 速率统计：取最大值作为聚合结果
                            inc.wan_rx_rate_avg = inc.wan_rx_rate_avg.max(current_hour_increment.wan_rx_rate_avg);
                            inc.wan_rx_rate_max = inc.wan_rx_rate_max.max(current_hour_increment.wan_rx_rate_max);
                            inc.wan_rx_rate_min = if inc.wan_rx_rate_min == 0 {
                                current_hour_increment.wan_rx_rate_min
                            } else {
                                inc.wan_rx_rate_min.min(current_hour_increment.wan_rx_rate_min)
                            };
                            inc.wan_rx_rate_p90 = inc.wan_rx_rate_p90.max(current_hour_increment.wan_rx_rate_p90);
                            inc.wan_rx_rate_p95 = inc.wan_rx_rate_p95.max(current_hour_increment.wan_rx_rate_p95);
                            inc.wan_rx_rate_p99 = inc.wan_rx_rate_p99.max(current_hour_increment.wan_rx_rate_p99);

                            inc.wan_tx_rate_avg = inc.wan_tx_rate_avg.max(current_hour_increment.wan_tx_rate_avg);
                            inc.wan_tx_rate_max = inc.wan_tx_rate_max.max(current_hour_increment.wan_tx_rate_max);
                            inc.wan_tx_rate_min = if inc.wan_tx_rate_min == 0 {
                                current_hour_increment.wan_tx_rate_min
                            } else {
                                inc.wan_tx_rate_min.min(current_hour_increment.wan_tx_rate_min)
                            };
                            inc.wan_tx_rate_p90 = inc.wan_tx_rate_p90.max(current_hour_increment.wan_tx_rate_p90);
                            inc.wan_tx_rate_p95 = inc.wan_tx_rate_p95.max(current_hour_increment.wan_tx_rate_p95);
                            inc.wan_tx_rate_p99 = inc.wan_tx_rate_p99.max(current_hour_increment.wan_tx_rate_p99);

                            inc.lan_rx_rate_avg = inc.lan_rx_rate_avg.max(current_hour_increment.lan_rx_rate_avg);
                            inc.lan_rx_rate_max = inc.lan_rx_rate_max.max(current_hour_increment.lan_rx_rate_max);
                            inc.lan_rx_rate_min = if inc.lan_rx_rate_min == 0 {
                                current_hour_increment.lan_rx_rate_min
                            } else {
                                inc.lan_rx_rate_min.min(current_hour_increment.lan_rx_rate_min)
                            };
                            inc.lan_rx_rate_p90 = inc.lan_rx_rate_p90.max(current_hour_increment.lan_rx_rate_p90);
                            inc.lan_rx_rate_p95 = inc.lan_rx_rate_p95.max(current_hour_increment.lan_rx_rate_p95);
                            inc.lan_rx_rate_p99 = inc.lan_rx_rate_p99.max(current_hour_increment.lan_rx_rate_p99);

                            inc.lan_tx_rate_avg = inc.lan_tx_rate_avg.max(current_hour_increment.lan_tx_rate_avg);
                            inc.lan_tx_rate_max = inc.lan_tx_rate_max.max(current_hour_increment.lan_tx_rate_max);
                            inc.lan_tx_rate_min = if inc.lan_tx_rate_min == 0 {
                                current_hour_increment.lan_tx_rate_min
                            } else {
                                inc.lan_tx_rate_min.min(current_hour_increment.lan_tx_rate_min)
                            };
                            inc.lan_tx_rate_p90 = inc.lan_tx_rate_p90.max(current_hour_increment.lan_tx_rate_p90);
                            inc.lan_tx_rate_p95 = inc.lan_tx_rate_p95.max(current_hour_increment.lan_tx_rate_p95);
                            inc.lan_tx_rate_p99 = inc.lan_tx_rate_p99.max(current_hour_increment.lan_tx_rate_p99);

                            found = true;
                            break;
                        }
                    }

                    if !found {
                        increments.push(current_hour_increment);
                    }
                }
            }
        }

        // 对 increments 按时间排序，确保数据有序
        increments.sort_by_key(|inc| inc.start_ts_ms);

        if network_type == "wan" {
            for inc in &mut increments {
                inc.lan_rx_rate_avg = 0;
                inc.lan_rx_rate_max = 0;
                inc.lan_rx_rate_min = 0;
                inc.lan_rx_rate_p90 = 0;
                inc.lan_rx_rate_p95 = 0;
                inc.lan_rx_rate_p99 = 0;
                inc.lan_tx_rate_avg = 0;
                inc.lan_tx_rate_max = 0;
                inc.lan_tx_rate_min = 0;
                inc.lan_tx_rate_p90 = 0;
                inc.lan_tx_rate_p95 = 0;
                inc.lan_tx_rate_p99 = 0;
                inc.lan_rx_bytes_inc = 0;
                inc.lan_tx_bytes_inc = 0;
            }
        } else if network_type == "lan" {
            for inc in &mut increments {
                inc.wan_rx_rate_avg = 0;
                inc.wan_rx_rate_max = 0;
                inc.wan_rx_rate_min = 0;
                inc.wan_rx_rate_p90 = 0;
                inc.wan_rx_rate_p95 = 0;
                inc.wan_rx_rate_p99 = 0;
                inc.wan_tx_rate_avg = 0;
                inc.wan_tx_rate_max = 0;
                inc.wan_tx_rate_min = 0;
                inc.wan_tx_rate_p90 = 0;
                inc.wan_tx_rate_p95 = 0;
                inc.wan_tx_rate_p99 = 0;
                inc.wan_rx_bytes_inc = 0;
                inc.wan_tx_bytes_inc = 0;
            }
        }

        let increments = if aggregation == "daily" {
            aggregate_to_daily(increments, start_ms, end_ms)
        } else {
            increments
        };

        let mac_label = request.query_params.get("mac").cloned().unwrap_or_else(|| "all".to_string());

        let (total_rx_bytes, total_tx_bytes) = if network_type == "wan" {
            (
                increments.iter().map(|inc| inc.wan_rx_bytes_inc).sum(),
                increments.iter().map(|inc| inc.wan_tx_bytes_inc).sum(),
            )
        } else if network_type == "lan" {
            (
                increments.iter().map(|inc| inc.lan_rx_bytes_inc).sum(),
                increments.iter().map(|inc| inc.lan_tx_bytes_inc).sum(),
            )
        } else {
            (
                increments.iter().map(|inc| inc.wan_rx_bytes_inc + inc.lan_rx_bytes_inc).sum(),
                increments.iter().map(|inc| inc.wan_tx_bytes_inc + inc.lan_tx_bytes_inc).sum(),
            )
        };

        let total_bytes = total_rx_bytes + total_tx_bytes;

        let response = TimeSeriesIncrementResponse {
            start_ms,
            end_ms,
            aggregation: aggregation.clone(),
            mac: mac_label,
            network_type,
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

/// 将每小时增量聚合为每日总数
/// 按日分组增量（每天的 00:00:00 UTC）
/// 过滤掉不在请求时间范围 [start_ms, end_ms) 内的日期
fn aggregate_to_daily(hourly_increments: Vec<TimeSeriesIncrement>, start_ms: u64, end_ms: u64) -> Vec<TimeSeriesIncrement> {
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct DailyAggregate {
        start_ts_ms: u64,
        end_ts_ms: u64,
        wan_rx_rate_avg_sum: u64,
        wan_rx_rate_max: u64,
        wan_rx_rate_min: u64,
        wan_rx_rate_p90_sum: u64,
        wan_rx_rate_p95_sum: u64,
        wan_rx_rate_p99_sum: u64,
        wan_tx_rate_avg_sum: u64,
        wan_tx_rate_max: u64,
        wan_tx_rate_min: u64,
        wan_tx_rate_p90_sum: u64,
        wan_tx_rate_p95_sum: u64,
        wan_tx_rate_p99_sum: u64,
        wan_rx_bytes_inc: u64,
        wan_tx_bytes_inc: u64,
        lan_rx_rate_avg_sum: u64,
        lan_rx_rate_max: u64,
        lan_rx_rate_min: u64,
        lan_rx_rate_p90_sum: u64,
        lan_rx_rate_p95_sum: u64,
        lan_rx_rate_p99_sum: u64,
        lan_tx_rate_avg_sum: u64,
        lan_tx_rate_max: u64,
        lan_tx_rate_min: u64,
        lan_tx_rate_p90_sum: u64,
        lan_tx_rate_p95_sum: u64,
        lan_tx_rate_p99_sum: u64,
        lan_rx_bytes_inc: u64,
        lan_tx_bytes_inc: u64,
        count: u64,
    }

    let mut daily_map: BTreeMap<u64, DailyAggregate> = BTreeMap::new();

    for inc in hourly_increments {
        let ts_secs = (inc.start_ts_ms / 1000) as i64;
        let dt = DateTime::<Utc>::from_timestamp(ts_secs, 0).unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).unwrap());

        let day_start_dt = dt.date_naive().and_hms_opt(0, 0, 0).unwrap();
        let day_start_utc = DateTime::<Utc>::from_naive_utc_and_offset(day_start_dt, Utc);
        let day_start_ms = day_start_utc.timestamp_millis() as u64;

        let entry = daily_map.entry(day_start_ms).or_default();

        if entry.count == 0 {
            entry.start_ts_ms = day_start_ms;
            entry.end_ts_ms = day_start_ms + 24 * 3600 * 1000;
            entry.wan_rx_rate_min = inc.wan_rx_rate_min;
            entry.wan_tx_rate_min = inc.wan_tx_rate_min;
            entry.lan_rx_rate_min = inc.lan_rx_rate_min;
            entry.lan_tx_rate_min = inc.lan_tx_rate_min;
        }

        entry.wan_rx_rate_avg_sum = entry.wan_rx_rate_avg_sum.saturating_add(inc.wan_rx_rate_avg);
        entry.wan_rx_rate_max = entry.wan_rx_rate_max.max(inc.wan_rx_rate_max);
        entry.wan_rx_rate_min = entry.wan_rx_rate_min.min(inc.wan_rx_rate_min);
        entry.wan_rx_rate_p90_sum = entry.wan_rx_rate_p90_sum.saturating_add(inc.wan_rx_rate_p90);
        entry.wan_rx_rate_p95_sum = entry.wan_rx_rate_p95_sum.saturating_add(inc.wan_rx_rate_p95);
        entry.wan_rx_rate_p99_sum = entry.wan_rx_rate_p99_sum.saturating_add(inc.wan_rx_rate_p99);

        entry.wan_tx_rate_avg_sum = entry.wan_tx_rate_avg_sum.saturating_add(inc.wan_tx_rate_avg);
        entry.wan_tx_rate_max = entry.wan_tx_rate_max.max(inc.wan_tx_rate_max);
        entry.wan_tx_rate_min = entry.wan_tx_rate_min.min(inc.wan_tx_rate_min);
        entry.wan_tx_rate_p90_sum = entry.wan_tx_rate_p90_sum.saturating_add(inc.wan_tx_rate_p90);
        entry.wan_tx_rate_p95_sum = entry.wan_tx_rate_p95_sum.saturating_add(inc.wan_tx_rate_p95);
        entry.wan_tx_rate_p99_sum = entry.wan_tx_rate_p99_sum.saturating_add(inc.wan_tx_rate_p99);

        entry.wan_rx_bytes_inc = entry.wan_rx_bytes_inc.saturating_add(inc.wan_rx_bytes_inc);
        entry.wan_tx_bytes_inc = entry.wan_tx_bytes_inc.saturating_add(inc.wan_tx_bytes_inc);

        entry.lan_rx_rate_avg_sum = entry.lan_rx_rate_avg_sum.saturating_add(inc.lan_rx_rate_avg);
        entry.lan_rx_rate_max = entry.lan_rx_rate_max.max(inc.lan_rx_rate_max);
        entry.lan_rx_rate_min = entry.lan_rx_rate_min.min(inc.lan_rx_rate_min);
        entry.lan_rx_rate_p90_sum = entry.lan_rx_rate_p90_sum.saturating_add(inc.lan_rx_rate_p90);
        entry.lan_rx_rate_p95_sum = entry.lan_rx_rate_p95_sum.saturating_add(inc.lan_rx_rate_p95);
        entry.lan_rx_rate_p99_sum = entry.lan_rx_rate_p99_sum.saturating_add(inc.lan_rx_rate_p99);

        entry.lan_tx_rate_avg_sum = entry.lan_tx_rate_avg_sum.saturating_add(inc.lan_tx_rate_avg);
        entry.lan_tx_rate_max = entry.lan_tx_rate_max.max(inc.lan_tx_rate_max);
        entry.lan_tx_rate_min = entry.lan_tx_rate_min.min(inc.lan_tx_rate_min);
        entry.lan_tx_rate_p90_sum = entry.lan_tx_rate_p90_sum.saturating_add(inc.lan_tx_rate_p90);
        entry.lan_tx_rate_p95_sum = entry.lan_tx_rate_p95_sum.saturating_add(inc.lan_tx_rate_p95);
        entry.lan_tx_rate_p99_sum = entry.lan_tx_rate_p99_sum.saturating_add(inc.lan_tx_rate_p99);

        entry.lan_rx_bytes_inc = entry.lan_rx_bytes_inc.saturating_add(inc.lan_rx_bytes_inc);
        entry.lan_tx_bytes_inc = entry.lan_tx_bytes_inc.saturating_add(inc.lan_tx_bytes_inc);

        entry.count += 1;
    }

    daily_map
        .into_iter()
        .filter(|(ts_ms, _)| *ts_ms >= start_ms && *ts_ms < end_ms)
        .map(|(_, agg)| TimeSeriesIncrement {
            start_ts_ms: agg.start_ts_ms,
            end_ts_ms: agg.end_ts_ms,
            wan_rx_rate_avg: if agg.count > 0 { agg.wan_rx_rate_avg_sum / agg.count } else { 0 },
            wan_rx_rate_max: agg.wan_rx_rate_max,
            wan_rx_rate_min: agg.wan_rx_rate_min,
            wan_rx_rate_p90: if agg.count > 0 { agg.wan_rx_rate_p90_sum / agg.count } else { 0 },
            wan_rx_rate_p95: if agg.count > 0 { agg.wan_rx_rate_p95_sum / agg.count } else { 0 },
            wan_rx_rate_p99: if agg.count > 0 { agg.wan_rx_rate_p99_sum / agg.count } else { 0 },
            wan_tx_rate_avg: if agg.count > 0 { agg.wan_tx_rate_avg_sum / agg.count } else { 0 },
            wan_tx_rate_max: agg.wan_tx_rate_max,
            wan_tx_rate_min: agg.wan_tx_rate_min,
            wan_tx_rate_p90: if agg.count > 0 { agg.wan_tx_rate_p90_sum / agg.count } else { 0 },
            wan_tx_rate_p95: if agg.count > 0 { agg.wan_tx_rate_p95_sum / agg.count } else { 0 },
            wan_tx_rate_p99: if agg.count > 0 { agg.wan_tx_rate_p99_sum / agg.count } else { 0 },
            wan_rx_bytes_inc: agg.wan_rx_bytes_inc,
            wan_tx_bytes_inc: agg.wan_tx_bytes_inc,
            lan_rx_rate_avg: if agg.count > 0 { agg.lan_rx_rate_avg_sum / agg.count } else { 0 },
            lan_rx_rate_max: agg.lan_rx_rate_max,
            lan_rx_rate_min: agg.lan_rx_rate_min,
            lan_rx_rate_p90: if agg.count > 0 { agg.lan_rx_rate_p90_sum / agg.count } else { 0 },
            lan_rx_rate_p95: if agg.count > 0 { agg.lan_rx_rate_p95_sum / agg.count } else { 0 },
            lan_rx_rate_p99: if agg.count > 0 { agg.lan_rx_rate_p99_sum / agg.count } else { 0 },
            lan_tx_rate_avg: if agg.count > 0 { agg.lan_tx_rate_avg_sum / agg.count } else { 0 },
            lan_tx_rate_max: agg.lan_tx_rate_max,
            lan_tx_rate_min: agg.lan_tx_rate_min,
            lan_tx_rate_p90: if agg.count > 0 { agg.lan_tx_rate_p90_sum / agg.count } else { 0 },
            lan_tx_rate_p95: if agg.count > 0 { agg.lan_tx_rate_p95_sum / agg.count } else { 0 },
            lan_tx_rate_p99: if agg.count > 0 { agg.lan_tx_rate_p99_sum / agg.count } else { 0 },
            lan_rx_bytes_inc: agg.lan_rx_bytes_inc,
            lan_tx_bytes_inc: agg.lan_tx_bytes_inc,
        })
        .collect()
}
