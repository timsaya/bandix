use super::{ApiResponse, HttpRequest, HttpResponse};
use crate::command::Options;
use crate::storage::traffic::{
    self, LongTermRingManager, RealtimeRingManager, ScheduledRateLimit, TimeSlot,
};
use crate::utils::format_utils::{format_bytes, format_mac};
use chrono::{DateTime, Datelike, Local, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 设备信息，用于 API 响应
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
    pub total_bytes: u64,    // 所有设备的总字节数
    pub total_rx_bytes: u64, // 所有设备的总接收字节数
    pub total_tx_bytes: u64, // 所有设备的总发送字节数
    pub device_count: usize, // 设备数量
    pub rankings: Vec<DeviceUsageRanking>,
}

/// 时间序列增量条目（每小时或每日）
#[derive(Serialize, Deserialize)]
pub struct TimeSeriesIncrement {
    pub ts_ms: u64,       // 时间戳（小时或日的开始）
    pub rx_bytes: u64,    // 此期间的接收字节增量
    pub tx_bytes: u64,    // 此期间的发送字节增量
    pub total_bytes: u64, // 此期间的总字节增量（rx + tx）
}

/// 时间序列增量响应结构
#[derive(Serialize, Deserialize)]
pub struct TimeSeriesIncrementResponse {
    pub start_ms: u64,
    pub end_ms: u64,
    pub aggregation: String, // "hourly" 或 "daily"
    pub mac: String,         // MAC 地址（或 "all" 表示聚合）
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
    realtime_manager: Arc<RealtimeRingManager>, // 实时 1 秒采样（仅内存）
    long_term_manager: Arc<LongTermRingManager>, // 长期采样（1 小时间隔，365 天保留，已持久化）
    device_manager: Arc<crate::device::DeviceManager>, // 统一的设备管理器（包含设备信息和流量统计）
    options: Options,
}

impl TrafficApiHandler {
    pub fn new(
        scheduled_rate_limits: Arc<Mutex<Vec<ScheduledRateLimit>>>,
        hostname_bindings: Arc<Mutex<HashMap<[u8; 6], String>>>,
        realtime_manager: Arc<RealtimeRingManager>,
        long_term_manager: Arc<LongTermRingManager>,
        device_manager: Arc<crate::device::DeviceManager>,
        options: Options,
    ) -> Self {
        Self {
            scheduled_rate_limits,
            hostname_bindings,
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
    /// 计算时间范围的开始和结束时间戳（毫秒）
    /// period: "today" | "week" | "month" | "all"
    fn calculate_time_range(period: &str) -> Option<(u64, u64)> {
        let now = Local::now();
        let now_ms = now.timestamp_millis() as u64;
        
        let start_ms = match period {
            "today" => {
                let today_start = now.date_naive().and_hms_opt(0, 0, 0).unwrap();
                let today_start_local = Local.from_local_datetime(&today_start).unwrap();
                today_start_local.timestamp_millis() as u64
            }
            "week" => {
                let days_from_monday = now.weekday().num_days_from_monday();
                let week_start = now.date_naive()
                    .checked_sub_signed(chrono::Duration::days(days_from_monday as i64))
                    .unwrap()
                    .and_hms_opt(0, 0, 0)
                    .unwrap();
                let week_start_local = Local.from_local_datetime(&week_start).unwrap();
                week_start_local.timestamp_millis() as u64
            }
            "month" => {
                let month_start = now.date_naive()
                    .with_day(1)
                    .unwrap()
                    .and_hms_opt(0, 0, 0)
                    .unwrap();
                let month_start_local = Local.from_local_datetime(&month_start).unwrap();
                month_start_local.timestamp_millis() as u64
            }
            "all" => return None,
            _ => return None,
        };
        
        Some((start_ms, now_ms))
    }

    /// 处理/api/devices endpoint
    /// 查询参数：
    ///   - period: "today" | "week" | "month" | "all" (可选，默认为 "all")
    async fn handle_devices(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        let period = request.query_params
            .get("period")
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| "all".to_string());
        
        let time_range = Self::calculate_time_range(&period);
        
        let bindings_map = self.hostname_bindings.lock().unwrap();

        // 从设备管理器收集所有设备（包括在线和离线设备）
        let all_devices = self.device_manager.get_all_devices();
        let all_macs: HashSet<[u8; 6]> = all_devices.iter().map(|d| d.mac).collect();

        let devices: Vec<DeviceInfo> = all_macs
            .into_iter()
            .map(|mac| {
                // 格式化 MAC 地址
                let mac_str = format_mac(&mac);

                // 从设备管理器获取设备信息（包含所有信息：IP、流量统计等）
                let device = self.device_manager.get_device_by_mac(&mac);
                
                let (final_ipv4, ipv6_addresses_set) = if let Some(device) = &device {
                    let final_ipv4 = device.get_current_ipv4();
                    let mut ipv6_set: HashSet<[u8; 16]> = HashSet::new();
                    
                    // 添加所有 IPv6 地址（当前和历史）
                    for addr in device.get_all_ipv6() {
                        if addr != [0u8; 16] {
                            ipv6_set.insert(addr);
                        }
                    }
                    
                    (final_ipv4, ipv6_set)
                } else {
                    // 设备不存在，使用默认值
                    ([0, 0, 0, 0], HashSet::new())
                };

                // 格式化IP address
                let ip_str = format!(
                    "{}.{}.{}.{}",
                    final_ipv4[0], final_ipv4[1], final_ipv4[2], final_ipv4[3]
                );

                // 转换为格式化的字符串并按字典序排序
                let mut ipv6_addresses: Vec<String> = ipv6_addresses_set
                    .iter()
                    .map(|addr| crate::utils::network_utils::format_ipv6(addr))
                    .collect();
                ipv6_addresses.sort();

                // Get hostname from device or bindings
                let hostname = device.as_ref()
                    .map(|d| d.hostname.clone())
                    .filter(|h| !h.is_empty())
                    .or_else(|| bindings_map.get(&mac).cloned())
                    .unwrap_or_default();

                // 如果指定了时间范围，计算该时间范围内的流量增量
                let (final_total_rx_bytes, final_total_tx_bytes, final_lan_rx_bytes, 
                      final_lan_tx_bytes, final_wan_rx_bytes, final_wan_tx_bytes) = 
                    if let Some((start_ms, end_ms)) = time_range {
                        // 检查结束时间是否在当前小时内（需要从 checkpoint 获取数据）
                        let now_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or(Duration::from_secs(0))
                            .as_millis() as u64;
                        let now_sec = now_ms / 1000;
                        let current_hour_start = (now_sec / 3600) * 3600;
                        let end_sec = end_ms / 1000;
                        let end_hour_start = (end_sec / 3600) * 3600;
                        let is_current_hour = end_hour_start == current_hour_start;

                        // 从长期数据查询该时间范围内的流量增量
                        if let Ok(stats_rows) = self.long_term_manager.query_stats(&mac, start_ms, end_ms) {
                            // 获取开始时间点的数据（作为起始基线）
                            let start_baseline = stats_rows.first().map(|row| {
                                (row.wan_rx_bytes, row.wan_tx_bytes, row.lan_rx_bytes, row.lan_tx_bytes)
                            }).unwrap_or((0, 0, 0, 0));
                            
                            // 获取结束时间点的数据
                            let mut end_baseline = if !stats_rows.is_empty() {
                                stats_rows.last().map(|row| {
                                    (row.wan_rx_bytes, row.wan_tx_bytes, row.lan_rx_bytes, row.lan_tx_bytes)
                                }).unwrap_or((0, 0, 0, 0))
                            } else {
                                (0, 0, 0, 0)
                            };

                            // 如果结束时间在当前小时内，尝试从内存中的累积器获取最新数据
                            if is_current_hour {
                                let active_accumulators = self.long_term_manager.get_active_accumulators();
                                if let Some(&(wan_rx, wan_tx, lan_rx, lan_tx)) = active_accumulators.get(&mac) {
                                    // 使用内存中累积器的数据作为结束值（更准确）
                                    end_baseline = (wan_rx, wan_tx, lan_rx, lan_tx);
                                }
                            }
                            
                            // 计算增量
                            let period_wan_rx = end_baseline.0.saturating_sub(start_baseline.0);
                            let period_wan_tx = end_baseline.1.saturating_sub(start_baseline.1);
                            let period_lan_rx = end_baseline.2.saturating_sub(start_baseline.2);
                            let period_lan_tx = end_baseline.3.saturating_sub(start_baseline.3);
                            
                            (period_wan_rx + period_lan_rx, 
                             period_wan_tx + period_lan_tx,
                             period_lan_rx,
                             period_lan_tx,
                             period_wan_rx,
                             period_wan_tx)
                        } else {
                            // 查询失败，如果是在当前小时内，尝试使用内存中的累积器数据
                            if is_current_hour {
                                let active_accumulators = self.long_term_manager.get_active_accumulators();
                                if let Some(&(wan_rx, wan_tx, lan_rx, lan_tx)) = active_accumulators.get(&mac) {
                                    // 使用内存中累积器的数据，起始基线为 0（因为没有历史数据）
                                    (wan_rx + lan_rx, wan_tx + lan_tx, lan_rx, lan_tx, wan_rx, wan_tx)
                                } else {
                                    // 没有累积器数据，使用当前统计值
                                    if let Some(device) = &device {
                                        (device.total_rx_bytes(), device.total_tx_bytes(), device.lan_rx_bytes, device.lan_tx_bytes, device.wan_rx_bytes, device.wan_tx_bytes)
                                    } else {
                                        (0, 0, 0, 0, 0, 0)
                                    }
                                }
                            } else {
                                // 不在当前小时内，使用当前统计值
                                if let Some(device) = &device {
                                    (device.total_rx_bytes(), device.total_tx_bytes(), device.lan_rx_bytes, device.lan_tx_bytes, device.wan_rx_bytes, device.wan_tx_bytes)
                                } else {
                                    (0, 0, 0, 0, 0, 0)
                                }
                            }
                        }
                    } else {
                        // period == "all"，使用累计流量
                        // 优先使用内存中的累积器数据（如果存在，包含当前小时的累积数据）
                        let active_accumulators = self.long_term_manager.get_active_accumulators();
                        if let Some(&(wan_rx_acc, wan_tx_acc, lan_rx_acc, lan_tx_acc)) = 
                            active_accumulators.get(&mac) {
                            // 使用内存中累积器的数据（更准确，包含当前小时的累积数据）
                            (wan_rx_acc + lan_rx_acc,
                             wan_tx_acc + lan_tx_acc,
                             lan_rx_acc,
                             lan_tx_acc,
                             wan_rx_acc,
                             wan_tx_acc)
                        } else {
                            // 没有累积器数据，使用当前统计值
                            if let Some(device) = &device {
                                (device.total_rx_bytes(), device.total_tx_bytes(), device.lan_rx_bytes, device.lan_tx_bytes, device.wan_rx_bytes, device.wan_tx_bytes)
                            } else {
                                (0, 0, 0, 0, 0, 0)
                            }
                        }
                    };

                // 从 device 获取流量统计信息
                let (total_rx_rate, total_tx_rate, wan_rx_rate_limit, wan_tx_rate_limit,
                     lan_rx_rate, lan_tx_rate, wan_rx_rate, wan_tx_rate, last_online_ts) = 
                    if let Some(device) = &device {
                        (device.total_rx_rate(), device.total_tx_rate(), 
                         device.wan_rx_rate_limit, device.wan_tx_rate_limit,
                         device.lan_rx_rate, device.lan_tx_rate,
                         device.wan_rx_rate, device.wan_tx_rate, device.last_online_ts)
                    } else {
                        (0, 0, 0, 0, 0, 0, 0, 0, 0)
                    };

                DeviceInfo {
                    ip: ip_str,
                    ipv6_addresses,
                    mac: mac_str,
                    hostname,
                    total_rx_bytes: final_total_rx_bytes,
                    total_tx_bytes: final_total_tx_bytes,
                    total_rx_rate,
                    total_tx_rate,
                    wan_rx_rate_limit,
                    wan_tx_rate_limit,
                    lan_rx_bytes: final_lan_rx_bytes,
                    lan_tx_bytes: final_lan_tx_bytes,
                    lan_rx_rate,
                    lan_tx_rate,
                    wan_rx_bytes: final_wan_rx_bytes,
                    wan_tx_bytes: final_wan_tx_bytes,
                    wan_rx_rate,
                    wan_tx_rate,
                    last_online_ts,
                }
            })
            .filter(|device| {
                // 允许显示有流量数据或基线数据的设备
                // 即使 last_online_ts == 0，如果有累计流量，也应该显示
                device.last_online_ts > 0 || 
                device.total_rx_bytes > 0 || 
                device.total_tx_bytes > 0 ||
                device.lan_rx_bytes > 0 ||
                device.lan_tx_bytes > 0 ||
                device.wan_rx_bytes > 0 ||
                device.wan_tx_bytes > 0
            })
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

    /// 处理/api/metrics endpoint - 实时指标（仅内存，未持久化）
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
                        self.realtime_manager.query_metrics(&mac, start_ms, end_ms),
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

    /// 处理/api/traffic/metrics/year endpoint - 年级统计（已持久化）
    async fn handle_metrics_year(
        &self,
        request: &HttpRequest,
    ) -> Result<HttpResponse, anyhow::Error> {
        let mac_opt = request.query_params.get("mac").cloned();


        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;

        const RETENTION_SECONDS: u64 = 365 * 24 * 3600;
        let retention_seconds = RETENTION_SECONDS;
        let start_ms = now_ms.saturating_sub(retention_seconds * 1000);
        let end_ms = now_ms;

        let (rows_result, mac_label) = if let Some(mac_str) = mac_opt {
            if mac_str.to_ascii_lowercase() == "all" || mac_str.trim().is_empty() {
                (
                    self.long_term_manager.query_stats_aggregate_all(start_ms, end_ms),
                    "all".to_string(),
                )
            } else {
                match crate::utils::network_utils::parse_mac_address(&mac_str) {
                    Ok(mac) => (
                        self.long_term_manager.query_stats(&mac, start_ms, end_ms),
                        format_mac(&mac),
                    ),
                    Err(e) => {
                        return Ok(HttpResponse::error(400, format!("Invalid MAC: {}", e)));
                    }
                }
            }
        } else {
            (
                self.long_term_manager.query_stats_aggregate_all(start_ms, end_ms),
                "all".to_string(),
            )
        };

        match rows_result {
            Ok(rows) => {
                // 转换为包含统计信息的数组格式：
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
    async fn handle_set_hostname_binding(
        &self,
        request: &HttpRequest,
    ) -> Result<HttpResponse, anyhow::Error> {
        let body = request
            .body
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing request body"))?;

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
    async fn handle_set_scheduled_limit(
        &self,
        request: &HttpRequest,
    ) -> Result<HttpResponse, anyhow::Error> {
        let body = request
            .body
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing request body"))?;

        // 解析JSON request body
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
    async fn handle_delete_scheduled_limit(
        &self,
        request: &HttpRequest,
    ) -> Result<HttpResponse, anyhow::Error> {
        let body = request
            .body
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing request body"))?;

        // 解析JSON request body
        let delete_request: DeleteScheduledLimitRequest = serde_json::from_str(body)?;

        let mac = crate::utils::network_utils::parse_mac_address(&delete_request.mac)?;
        let time_slot = TimeSlot::try_from(&delete_request.time_slot)
            .map_err(|e| anyhow::anyhow!("Invalid time slot: {}", e))?;

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
    /// 从年级数据查询指定时间范围内的设备使用排名
    /// 查询参数：
    ///   - start_ms: 开始时间戳，毫秒（可选，默认为 365 天前）
    ///   - end_ms: 结束时间戳，毫秒（可选，默认为现在）
    async fn handle_usage_ranking(
        &self,
        request: &HttpRequest,
    ) -> Result<HttpResponse, anyhow::Error> {

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
        let device_stats = match self.long_term_manager.query_stats_by_device(start_ms, end_ms) {
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
            
            // 从设备管理器获取设备信息
            let device = self.device_manager.get_device_by_mac(mac);
            let hostname = device.as_ref()
                .map(|d| d.hostname.clone())
                .filter(|h| !h.is_empty())
                .or_else(|| bindings_map.get(mac).cloned())
                .unwrap_or_default();

            let ip_address = device.as_ref()
                .and_then(|d| d.current_ipv4)
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
    /// 从年级数据查询时间序列增量（每小时或每日）
    /// 查询参数：
    ///   - mac: MAC 地址（可选，默认为 "all" 表示聚合）
    ///   - start_ms: 开始时间戳，毫秒（可选，默认为 365 天前）
    ///   - end_ms: 结束时间戳，毫秒（可选，默认为现在）
    ///   - aggregation: "hourly" 或 "daily"（可选，默认为 "hourly"）
    async fn handle_usage_increments(
        &self,
        request: &HttpRequest,
    ) -> Result<HttpResponse, anyhow::Error> {

        // 解析聚合模式
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

        // 解析time range
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

        // 查询增量
        let hourly_increments = if let Some(mac_str) = request.query_params.get("mac") {
            if mac_str.to_ascii_lowercase() == "all" || mac_str.trim().is_empty() {
                self.long_term_manager.query_time_series_increments_aggregate(start_ms, end_ms)?
            } else {
                match crate::utils::network_utils::parse_mac_address(mac_str) {
                    Ok(mac) => self.long_term_manager.query_time_series_increments(&mac, start_ms, end_ms)?,
                    Err(e) => {
                        return Ok(HttpResponse::error(400, format!("Invalid MAC: {}", e)));
                    }
                }
            }
        } else {
            self.long_term_manager.query_time_series_increments_aggregate(start_ms, end_ms)?
        };

        let mac_label = request
            .query_params
            .get("mac")
            .cloned()
            .unwrap_or_else(|| "all".to_string());

        // 根据聚合模式处理增量
        let increments = if aggregation == "daily" {
            // 将每小时增量聚合为每日总数
            aggregate_to_daily(hourly_increments, start_ms, end_ms)
        } else {
            // 按原样使用每小时增量
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

        // 计算总数
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

/// 将每小时增量聚合为每日总数
/// 按日分组增量（每天的 00:00:00 UTC）
/// 过滤掉不在请求时间范围 [start_ms, end_ms) 内的日期
fn aggregate_to_daily(
    hourly_increments: Vec<(u64, u64, u64)>,
    start_ms: u64,
    end_ms: u64,
) -> Vec<TimeSeriesIncrement> {
    use std::collections::BTreeMap;

    // 按日分组（每天的 00:00:00 UTC 时间戳）
    let mut daily_map: BTreeMap<u64, (u64, u64)> = BTreeMap::new();

    for (ts_ms, rx_bytes, tx_bytes) in hourly_increments {
        // 将时间戳转换为日的开始（00:00:00 UTC），以毫秒为单位
        // 使用 chrono 来正确处理 UTC 时区
        let ts_secs = (ts_ms / 1000) as i64;
        let dt = DateTime::<Utc>::from_timestamp(ts_secs, 0)
            .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).unwrap());

        // 获取 00:00:00 UTC 的日期
        let day_start_dt = dt.date_naive().and_hms_opt(0, 0, 0).unwrap();
        let day_start_utc = DateTime::<Utc>::from_naive_utc_and_offset(day_start_dt, Utc);
        let day_start_ms = day_start_utc.timestamp_millis() as u64;

        let entry = daily_map.entry(day_start_ms).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(rx_bytes);
        entry.1 = entry.1.saturating_add(tx_bytes);
    }

    // 过滤掉不在请求时间范围内的日期
    // 如果一天的开始时间戳（00:00:00 UTC）在 [start_ms, end_ms) 范围内，则包含该天
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
