use super::{ApiResponse, HttpRequest, HttpResponse};
use crate::command::Options;
use crate::monitor::DnsQueryRecord;
use chrono::{Local, TimeZone};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// DNS 查询信息，用于 API 响应
#[derive(Serialize, Deserialize)]
pub struct DnsQueryInfo {
    pub timestamp: u64,              // Unix 时间戳，毫秒
    pub timestamp_formatted: String, // 格式化的时间字符串（例如："2024-01-01 12:00:00"）
    pub domain: String,
    pub query_type: String,
    pub response_code: String,
    pub response_time_ms: Option<u64>, // 响应时间，毫秒；查询为 None，响应为 Some(值)
    pub source_ip: String,
    pub destination_ip: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub transaction_id: u16,
    pub is_query: bool,
    pub response_ips: Vec<String>,
    pub response_records: Vec<String>, // 所有响应记录（A, AAAA, CNAME, HTTPS 等）
    pub device_mac: String,            // 设备 MAC 地址
    pub device_name: String,           // 设备主机名
}

/// DNS 查询响应结构
#[derive(Serialize, Deserialize)]
pub struct DnsQueriesResponse {
    pub queries: Vec<DnsQueryInfo>,
    pub total: usize,       // 分页前的总记录数
    pub page: usize,        // 当前页码
    pub page_size: usize,   // 每页大小
    pub total_pages: usize, // 总页数
}

/// 带有计数的顶级项目（用于顶级域名、设备等）
#[derive(Serialize, Deserialize)]
pub struct TopItem {
    pub name: String,
    pub count: usize,
}

/// 响应时间百分位数
#[derive(Serialize, Deserialize)]
pub struct ResponseTimePercentiles {
    pub p50: u64, // 中位数（第50百分位），毫秒
    pub p90: u64, // 第90百分位，毫秒
    pub p95: u64, // 第95百分位，毫秒
    pub p99: u64, // 第99百分位，毫秒
}

/// 响应代码统计
#[derive(Serialize, Deserialize)]
pub struct ResponseCodeStats {
    pub code: String,
    pub count: usize,
    pub percentage: f64,
}

/// DNS 统计信息，用于 API 响应
#[derive(Serialize, Deserialize)]
pub struct DnsStatsInfo {
    // 基本计数
    pub total_queries: usize,            // DNS 查询总数
    pub total_responses: usize,          // DNS 响应总数
    pub queries_with_response: usize,    // 收到响应的查询数
    pub queries_without_response: usize, // 无响应的查询数（超时/丢失）

    // 性能指标
    pub avg_response_time_ms: f64,            // 平均响应时间，毫秒
    pub min_response_time_ms: u64,            // 最快响应时间
    pub max_response_time_ms: u64,            // 最慢响应时间
    pub latest_response_time_ms: Option<u64>, // 最近响应时间（如果还没有响应则为 None）
    pub response_time_percentiles: ResponseTimePercentiles,

    // 成功/失败指标
    pub success_count: usize,                   // 成功响应数（NoError）
    pub failure_count: usize,                   // 失败响应数（任何错误）
    pub success_rate: f64,                      // 成功率（0.0 - 1.0）
    pub response_codes: Vec<ResponseCodeStats>, // 按响应代码分类

    // 顶级统计
    pub top_domains: Vec<TopItem>,     // 最常查询的域名（前10）
    pub top_query_types: Vec<TopItem>, // 最常用的查询类型（前10）
    pub top_devices: Vec<TopItem>,     // 最活跃的设备（前10）
    pub top_dns_servers: Vec<TopItem>, // 最常用的 DNS 服务器（前10）

    // 设备统计
    pub unique_devices: usize, // 唯一设备数

    // 时间范围
    pub time_range_start: u64,            // 最早记录时间戳（毫秒）
    pub time_range_end: u64,              // 最新记录时间戳（毫秒）
    pub time_range_duration_minutes: u64, // 持续时间，分钟
}

/// DNS 统计响应结构
#[derive(Serialize, Deserialize)]
pub struct DnsStatsResponse {
    pub stats: DnsStatsInfo,
}

/// DNS 配置，用于 API 响应
#[derive(Serialize, Deserialize)]
pub struct DnsConfigInfo {
    pub enabled: bool,
    pub monitored_interfaces: Vec<String>,
    pub log_level: String,
    pub retention_days: u64,
}

/// DNS 配置响应结构
#[derive(Serialize, Deserialize)]
pub struct DnsConfigResponse {
    pub config: DnsConfigInfo,
}

/// DNS 监控 API handler
#[derive(Clone)]
pub struct DnsApiHandler {
    #[allow(dead_code)]
    options: Options,
    dns_queries: Arc<Mutex<Vec<DnsQueryRecord>>>,
    hostname_bindings: Arc<Mutex<std::collections::HashMap<[u8; 6], String>>>,
    boot_time_offset_ns: u64, // 用于将单调时间转换为 Unix 时间戳的偏移量
}

impl DnsApiHandler {
    pub fn new(
        options: Options,
        dns_queries: Arc<Mutex<Vec<DnsQueryRecord>>>,
        hostname_bindings: Arc<Mutex<std::collections::HashMap<[u8; 6], String>>>,
    ) -> Self {
        // 计算启动时间偏移量：Unix 时间 - 单调时间
        // 如果有可用的第一个 DNS 记录的时间戳，则使用它作为参考，
        // 否则从当前时间计算
        let boot_time_offset_ns = Self::calculate_boot_time_offset();

        Self {
            options,
            dns_queries,
            hostname_bindings,
            boot_time_offset_ns,
        }
    }

    /// 计算启动时间偏移量，将单调时间转换为 Unix 时间戳
    /// 读取 /proc/uptime 获取系统运行时间，然后计算启动时间
    fn calculate_boot_time_offset() -> u64 {
        // Method 1: Read /proc/uptime
        if let Ok(content) = std::fs::read_to_string("/proc/uptime") {
            if let Some(uptime_secs_str) = content.split_whitespace().next() {
                if let Ok(uptime_secs) = uptime_secs_str.parse::<f64>() {
                    let uptime_ns = (uptime_secs * 1_000_000_000.0) as u64;
                    let now_unix_ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
                    // Boot time = current Unix time - uptime
                    let boot_time_unix_ns = now_unix_ns.saturating_sub(uptime_ns);
                    // Offset = boot time (we'll add this to monotonic timestamps)
                    // Actually, we need: unix_time = monotonic_time + offset
                    // So: offset = unix_time - monotonic_time
                    // But we don't have monotonic time here, so we use:
                    // offset = boot_time_unix_ns (since monotonic time starts at 0 at boot)
                    return boot_time_unix_ns;
                }
            }
        }

        // 后备方案：使用当前时间作为近似值
        // 精度较低，但如果 /proc/uptime 不可用时可以使用
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
    }

    /// 将单调时间戳（纳秒）转换为 Unix 时间戳（毫秒）
    fn convert_to_unix_timestamp(&self, monotonic_ns: u64) -> u64 {
        // Unix 时间戳 = 单调时间戳 + 启动时间偏移量
        let unix_ns = monotonic_ns.saturating_add(self.boot_time_offset_ns);
        unix_ns / 1_000_000 // 转换为毫秒
    }

    /// 将 MAC 地址字符串解析为 [u8; 6] 字节数组
    fn parse_mac_address(mac_str: &str) -> Result<[u8; 6], anyhow::Error> {
        crate::utils::network_utils::parse_mac_address(mac_str)
    }

    /// 将 Unix 时间戳（毫秒）格式化为可读字符串（本地时间）
    fn format_timestamp(timestamp_ms: u64) -> String {
        let secs = (timestamp_ms / 1000) as i64;
        let nanos = ((timestamp_ms % 1000) * 1_000_000) as u32;

        // 转换为本地时间
        match Local.timestamp_opt(secs, nanos) {
            chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            chrono::LocalResult::None => "无效时间戳".to_string(),
            chrono::LocalResult::Ambiguous(dt1, _dt2) => {
                // 在存在歧义时间的情况下（DST 转换），使用第一个选项
                dt1.format("%Y-%m-%d %H:%M:%S%.3f").to_string()
            }
        }
    }
}

impl DnsApiHandler {
    pub fn supported_routes(&self) -> Vec<&'static str> {
        vec!["/api/dns/queries", "/api/dns/stats", "/api/dns/config"]
    }

    pub async fn handle_request(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        match request.path.as_str() {
            "/api/dns/queries" => {
                if request.method == "GET" {
                    self.handle_queries(request).await
                } else {
                    Ok(HttpResponse::error(405, "Method not allowed".to_string()))
                }
            }
            "/api/dns/stats" => {
                if request.method == "GET" {
                    self.handle_stats().await
                } else {
                    Ok(HttpResponse::error(405, "Method not allowed".to_string()))
                }
            }
            "/api/dns/config" => match request.method.as_str() {
                "GET" => self.handle_get_config().await,
                "POST" => self.handle_set_config(request).await,
                _ => Ok(HttpResponse::error(405, "Method not allowed".to_string())),
            },
            _ => Ok(HttpResponse::not_found()),
        }
    }
}

impl DnsApiHandler {
    fn _generate_test_data(dns_queries: &Arc<Mutex<Vec<crate::monitor::DnsQueryRecord>>>) {
        let mut queries = match dns_queries.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };

        if queries.len() > 100 {
            return;
        }

        let domains = vec![
            "google.com",
            "github.com",
            "stackoverflow.com",
            "reddit.com",
            "youtube.com",
            "facebook.com",
            "twitter.com",
            "amazon.com",
            "microsoft.com",
            "apple.com",
            "baidu.com",
            "taobao.com",
            "qq.com",
            "weibo.com",
            "douyin.com",
            "example.com",
            "test.com",
            "demo.com",
            "localhost",
            "api.example.com",
        ];

        let query_types = vec!["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR"];
        let response_codes = vec!["Success", "NXDomain", "ServFail", "Refused", "NoError"];
        let dns_servers = vec![
            "8.8.8.8",
            "8.8.4.4",
            "1.1.1.1",
            "1.0.0.1",
            "114.114.114.114",
            "223.5.5.5",
            "119.29.29.29",
            "180.76.76.76",
        ];

        // Use a base monotonic timestamp (simulating system boot time)
        // Timestamp is in nanoseconds (monotonic time)
        let base_timestamp_ns = 1_000_000_000_000_000_000u64; // 1e9 seconds in ns

        for i in 0..100_0000 {
            // Simple pseudo-random number generator using index
            let seed = (i as u64).wrapping_mul(1103515245).wrapping_add(12345);
            let r1 = (seed >> 16) & 0x7fff;
            let r2 = (seed >> 8) & 0x7fff;
            let r3 = seed & 0x7fff;
            let r4 = (seed >> 24) & 0x7fff;
            let r5 = (seed >> 32) & 0x7fff;

            let domain_idx = (r1 as usize) % domains.len();
            let query_type_idx = (r2 as usize) % query_types.len();
            let response_code_idx = (r3 as usize) % response_codes.len();
            let dns_server_idx = (r4 as usize) % dns_servers.len();
            let is_query = (i % 2) == 0;

            // Generate client IP (192.168.x.y)
            let client_ip = format!("192.168.{}.{}", (r1 % 255) as u8, (r2 % 255) as u8);

            // Generate MAC address
            let mac = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                (r1 % 255) as u8,
                (r2 % 255) as u8,
                (r3 % 255) as u8,
                (r4 % 255) as u8,
                (r5 % 255) as u8,
                (i % 255) as u8,
            );

            // Generate device name
            let device_name = format!("device-{}", (r1 % 100) as u32);

            // Generate timestamp (monotonic time in nanoseconds, spread over last 24 hours)
            // Each record is spaced by ~0.864 seconds (24 hours / 100k records)
            let timestamp_offset_ns = (i as u64) * 864_000_000; // ~0.864 seconds per record
            let timestamp = base_timestamp_ns + timestamp_offset_ns;

            // Generate transaction ID
            let transaction_id = (r1 % 65535) as u16;

            // Generate response data for responses
            let (response_ips, response_records, response_time_ms) = if !is_query {
                let ip_count = (r2 % 3) + 1;
                let mut ips = Vec::new();
                let mut records = Vec::new();
                for j in 0..ip_count {
                    let ip = format!(
                        "{}.{}.{}.{}",
                        (r1 + j as u64) % 255,
                        (r2 + j as u64) % 255,
                        (r3 + j as u64) % 255,
                        (r4 + j as u64) % 255,
                    );
                    ips.push(ip.clone());
                    records.push(format!("A {}", ip));
                }
                let response_time = (r3 % 500) + 1; // 1-500ms
                (ips, records, Some(response_time))
            } else {
                (Vec::new(), Vec::new(), None)
            };

            queries.push(crate::monitor::DnsQueryRecord {
                timestamp,
                domain: format!("{}.{}", (r1 % 1000), domains[domain_idx]),
                query_type: query_types[query_type_idx].to_string(),
                response_code: response_codes[response_code_idx].to_string(),
                source_ip: if is_query {
                    client_ip.clone()
                } else {
                    dns_servers[dns_server_idx].to_string()
                },
                destination_ip: if is_query {
                    dns_servers[dns_server_idx].to_string()
                } else {
                    client_ip.clone()
                },
                source_port: if is_query { (r1 % 50000 + 1024) as u16 } else { 53 },
                destination_port: if is_query { 53 } else { (r1 % 50000 + 1024) as u16 },
                transaction_id,
                is_query,
                response_ips,
                response_records,
                response_time_ms,
                device_mac: mac,
                device_name,
            });
        }
    }

    /// 处理/api/dns/queries endpoint
    ///
    /// 查询参数：
    /// - domain: 按域名过滤（子串匹配）
    /// - device: 按设备 MAC 或主机名过滤（子串匹配）
    /// - is_query: 按查询类型过滤（true=查询，false=响应）
    /// - query_type: 按 DNS 记录类型过滤（例如：A, AAAA, CNAME, MX, TXT, NS, SOA, PTR）
    /// - dns_server: 按 DNS 服务器 IP 地址过滤（查询时为 destination_ip，响应时为 source_ip）
    /// - page: 页码（默认：1）
    /// - page_size: 每页记录数（默认：20，最大：1000）
    /// - limit: （已弃用，使用 page_size）返回的最大记录数
    async fn handle_queries(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        // Self::_generate_test_data(&self.dns_queries);

        // 获取query parameters
        let domain_filter = request.query_params.get("domain");
        let device_filter = request.query_params.get("device").map(|s| s.to_lowercase());
        let is_query_filter = request.query_params.get("is_query").and_then(|s| s.parse::<bool>().ok());
        let query_type_filter = request.query_params.get("query_type").map(|s| s.to_uppercase());
        let dns_server_filter = request.query_params.get("dns_server");

        // Pagination parameters
        let page = request
            .query_params
            .get("page")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(1)
            .max(1); // Minimum page is 1

        let page_size = request
            .query_params
            .get("page_size")
            .or(request.query_params.get("limit")) // Support legacy 'limit' parameter
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(20)
            .min(1000); // Maximum 1000 records per page

        let queries_guard = if let Ok(guard) = self.dns_queries.lock() {
            guard
        } else {
            return Ok(HttpResponse::error(500, "Failed to lock DNS queries".to_string()));
        };
        let queries = &*queries_guard;

        // 使用索引应用过滤器
        let filtered_indices: Vec<usize> = queries
            .iter()
            .enumerate()
            .filter(|(_, q)| {
                // 按域名过滤
                if let Some(domain) = domain_filter {
                    if !q.domain.contains(domain) {
                        return false;
                    }
                }

                // 按设备过滤（MAC 或主机名，大小写不敏感的子串匹配）
                if let Some(ref device) = device_filter {
                    let mac_match = q.device_mac.to_lowercase().contains(device);
                    let name_match = q.device_name.to_lowercase().contains(device);
                    if !mac_match && !name_match {
                        return false;
                    }
                }

                // 按查询类型过滤（查询 vs 响应）
                if let Some(is_query) = is_query_filter {
                    if q.is_query != is_query {
                        return false;
                    }
                }

                // 按 DNS 记录类型过滤（例如：A, AAAA, CNAME, MX 等）
                // query_type_filter 已经转换为大写，这里也将 q.query_type 转换为大写进行子串匹配
                if let Some(ref query_type) = query_type_filter {
                    if !q.query_type.contains(query_type) {
                        return false;
                    }
                }

                // 按 DNS 服务器 IP 地址过滤（IP 地址都是数字，直接匹配）
                // 对于查询：DNS 服务器是 destination_ip（端口 53）
                // 对于响应：DNS 服务器是 source_ip（端口 53）
                if let Some(dns_server) = dns_server_filter {
                    if q.is_query {
                        // Query: DNS server is destination
                        if !q.destination_ip.contains(dns_server) {
                            return false;
                        }
                    } else {
                        // Response: DNS server is source
                        if !q.source_ip.contains(dns_server) {
                            return false;
                        }
                    }
                }

                true
            })
            .map(|(idx, _)| idx)
            .collect();

        // 按事务分组并排序
        // 策略：按 transaction_id + domain + 源/目的 IP 对分组记录
        // 每个组代表一个查询-响应对（或独立的查询/响应）
        // 按每个组中的最新时间戳排序组（最新的在前）
        // 在每个组内，按时间戳排序（查询在响应之前）

        use std::collections::HashMap;

        // 创建分组：key = (transaction_id, domain, ip_pair_key)
        let mut groups: HashMap<(u16, String, String), Vec<usize>> = HashMap::new();

        for &idx in &filtered_indices {
            let record = &queries[idx];
            // 创建标准化的 IP 对 key（顺序无关）
            // 这确保了查询和响应即使 IP 交换也会被分组在一起
            let ip_pair_key = {
                let mut ips = vec![record.source_ip.as_str(), record.destination_ip.as_str()];
                ips.sort();
                ips.join("_")
            };

            let key = (record.transaction_id, record.domain.clone(), ip_pair_key);
            groups.entry(key).or_insert_with(Vec::new).push(idx);
        }

        // 将分组转换为排序列表
        let mut sorted_groups: Vec<Vec<usize>> = groups.into_values().collect();

        // 按每个组中的最新时间戳排序分组（最新的在前）
        sorted_groups.sort_by(|group_a, group_b| {
            let max_time_a = group_a.iter().map(|&idx| queries[idx].timestamp).max().unwrap_or(0);
            let max_time_b = group_b.iter().map(|&idx| queries[idx].timestamp).max().unwrap_or(0);
            max_time_b.cmp(&max_time_a)
        });

        // 按时间戳排序每个组内的记录（最新的在前）
        // 由于响应通常在查询之后，这意味着响应会排在前面
        for group in &mut sorted_groups {
            group.sort_by(|&idx_a, &idx_b| queries[idx_b].timestamp.cmp(&queries[idx_a].timestamp));
        }

        // 将分组重新展平为单个列表
        let sorted_indices: Vec<usize> = sorted_groups.into_iter().flat_map(|group| group.into_iter()).collect();

        // 计算分页
        let total = sorted_indices.len();
        let total_pages = (total + page_size - 1) / page_size; // Ceiling division
        let start_idx = (page - 1) * page_size;
        let end_idx = (start_idx + page_size).min(total);

        // 应用分页
        let paginated_indices = if start_idx < total {
            &sorted_indices[start_idx..end_idx]
        } else {
            &[] // 页码超出范围
        };

        // 获取最新的主机名绑定以进行动态查找
        let hostname_bindings = if let Ok(bindings) = self.hostname_bindings.lock() {
            bindings.clone()
        } else {
            std::collections::HashMap::new()
        };

        // 转换为 API 响应格式
        let query_infos: Vec<DnsQueryInfo> = paginated_indices
            .iter()
            .map(|&idx| {
                let q = &queries[idx];
                // 将单调时间戳转换为 Unix 时间戳
                let unix_timestamp_ms = self.convert_to_unix_timestamp(q.timestamp);

                // 格式化timestamp
                let timestamp_formatted = Self::format_timestamp(unix_timestamp_ms);

                // 根据 MAC 地址从绑定中获取最新的主机名
                let device_name = if !q.device_mac.is_empty() {
                    // 解析MAC address string to [u8; 6]
                    if let Ok(mac_bytes) = Self::parse_mac_address(&q.device_mac) {
                        hostname_bindings.get(&mac_bytes).cloned().unwrap_or_else(|| {
                            // Fallback to stored hostname if not found in bindings
                            q.device_name.clone()
                        })
                    } else {
                        // 如果MAC parsing fails, use stored hostname
                        q.device_name.clone()
                    }
                } else {
                    q.device_name.clone()
                };

                DnsQueryInfo {
                    timestamp: unix_timestamp_ms,
                    timestamp_formatted,
                    domain: q.domain.clone(),
                    query_type: q.query_type.clone(),
                    response_code: q.response_code.clone(),
                    response_time_ms: q.response_time_ms, // Queries are None, responses may have value
                    source_ip: q.source_ip.clone(),
                    destination_ip: q.destination_ip.clone(),
                    source_port: q.source_port,
                    destination_port: q.destination_port,
                    transaction_id: q.transaction_id,
                    is_query: q.is_query,
                    response_ips: q.response_ips.clone(),
                    response_records: q.response_records.clone(),
                    device_mac: q.device_mac.clone(),
                    device_name,
                }
            })
            .collect();

        let response = DnsQueriesResponse {
            queries: query_infos,
            total,
            page,
            page_size,
            total_pages,
        };

        let api_response = ApiResponse::success(response);
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }

    /// 处理/api/dns/stats endpoint
    async fn handle_stats(&self) -> Result<HttpResponse, anyhow::Error> {
        use std::collections::HashMap;

        // 获取所有 DNS 查询
        let queries = if let Ok(queries) = self.dns_queries.lock() { queries.clone() } else { vec![] };

        // 获取最新的主机名绑定以进行动态查找
        let hostname_bindings = if let Ok(bindings) = self.hostname_bindings.lock() {
            bindings.clone()
        } else {
            std::collections::HashMap::new()
        };

        if queries.is_empty() {
            // 如果没有数据则返回空统计
            let stats = DnsStatsInfo {
                total_queries: 0,
                total_responses: 0,
                queries_with_response: 0,
                queries_without_response: 0,
                avg_response_time_ms: 0.0,
                min_response_time_ms: 0,
                max_response_time_ms: 0,
                latest_response_time_ms: None,
                response_time_percentiles: ResponseTimePercentiles {
                    p50: 0,
                    p90: 0,
                    p95: 0,
                    p99: 0,
                },
                success_count: 0,
                failure_count: 0,
                success_rate: 0.0,
                response_codes: vec![],
                top_domains: vec![],
                top_query_types: vec![],
                top_devices: vec![],
                top_dns_servers: vec![],
                unique_devices: 0,
                time_range_start: 0,
                time_range_end: 0,
                time_range_duration_minutes: 0,
            };

            let response = DnsStatsResponse { stats };
            let api_response = ApiResponse::success(response);
            let body = serde_json::to_string(&api_response)?;
            return Ok(HttpResponse::ok(body));
        }

        // 计算basic counts
        let total_queries = queries.iter().filter(|q| q.is_query).count();
        let total_responses = queries.iter().filter(|q| !q.is_query).count();
        let queries_with_response = queries.iter().filter(|q| q.is_query && q.response_time_ms.is_some()).count();
        let queries_without_response = total_queries - queries_with_response;

        // 计算response time statistics
        let response_times: Vec<u64> = queries.iter().filter_map(|q| q.response_time_ms).filter(|&t| t > 0).collect();

        // 获取latest response time (from the most recent response with response_time_ms)
        let latest_response_time_ms = queries
            .iter()
            .filter(|q| !q.is_query && q.response_time_ms.is_some())
            .max_by_key(|q| q.timestamp)
            .and_then(|q| q.response_time_ms);

        let (avg_response_time_ms, min_response_time_ms, max_response_time_ms, response_time_percentiles) = if !response_times.is_empty() {
            let sum: u64 = response_times.iter().sum();
            let avg = sum as f64 / response_times.len() as f64;
            let min = *response_times.iter().min().unwrap();
            let max = *response_times.iter().max().unwrap();

            // 计算百分位数
            let mut sorted_times = response_times.clone();
            sorted_times.sort();
            let len = sorted_times.len();
            let p50 = sorted_times[len * 50 / 100];
            let p90 = sorted_times[len * 90 / 100];
            let p95 = sorted_times[len * 95 / 100];
            let p99 = sorted_times[len * 99 / 100];

            (avg, min, max, ResponseTimePercentiles { p50, p90, p95, p99 })
        } else {
            (
                0.0,
                0,
                0,
                ResponseTimePercentiles {
                    p50: 0,
                    p90: 0,
                    p95: 0,
                    p99: 0,
                },
            )
        };

        // 计算success/failure metrics
        let success_count = queries.iter().filter(|q| !q.is_query && q.response_code == "Success").count();
        let failure_count = queries
            .iter()
            .filter(|q| !q.is_query && !q.response_code.is_empty() && q.response_code != "Success")
            .count();
        let success_rate = if total_responses > 0 {
            success_count as f64 / total_responses as f64
        } else {
            0.0
        };

        // 响应代码分类
        let mut response_code_map: HashMap<String, usize> = HashMap::new();
        for query in queries.iter().filter(|q| !q.is_query && !q.response_code.is_empty()) {
            *response_code_map.entry(query.response_code.clone()).or_insert(0) += 1;
        }
        let mut response_codes: Vec<ResponseCodeStats> = response_code_map
            .into_iter()
            .map(|(code, count)| ResponseCodeStats {
                code,
                count,
                percentage: if total_responses > 0 { count as f64 / total_responses as f64 } else { 0.0 },
            })
            .collect();
        // 按计数降序排序，然后按代码名称升序排序以保证稳定的顺序
        response_codes.sort_by(|a, b| match b.count.cmp(&a.count) {
            std::cmp::Ordering::Equal => a.code.cmp(&b.code),
            other => other,
        });

        // 顶级域名
        let mut domain_map: HashMap<String, usize> = HashMap::new();
        for query in queries.iter().filter(|q| q.is_query) {
            *domain_map.entry(query.domain.clone()).or_insert(0) += 1;
        }
        let mut top_domains: Vec<TopItem> = domain_map.into_iter().map(|(name, count)| TopItem { name, count }).collect();
        // 按计数降序排序，然后按名称升序排序以保证稳定的顺序
        top_domains.sort_by(|a, b| match b.count.cmp(&a.count) {
            std::cmp::Ordering::Equal => a.name.cmp(&b.name),
            other => other,
        });
        top_domains.truncate(10);

        // 顶级查询类型
        let mut query_type_map: HashMap<String, usize> = HashMap::new();
        for query in queries.iter().filter(|q| q.is_query) {
            *query_type_map.entry(query.query_type.clone()).or_insert(0) += 1;
        }
        let mut top_query_types: Vec<TopItem> = query_type_map
            .into_iter()
            .map(|(name, count)| TopItem { name, count })
            .collect();
        // 按计数降序排序，然后按名称升序排序以保证稳定的顺序
        top_query_types.sort_by(|a, b| match b.count.cmp(&a.count) {
            std::cmp::Ordering::Equal => a.name.cmp(&b.name),
            other => other,
        });
        top_query_types.truncate(10);

        // 顶级设备（按 MAC 或名称）
        // 使用绑定中的最新主机名以获得准确的设备名称
        let mut device_map: HashMap<String, usize> = HashMap::new();
        for query in queries.iter().filter(|q| q.is_query) {
            let device_key = if !query.device_mac.is_empty() {
                // 尝试从绑定中获取最新的主机名
                if let Ok(mac_bytes) = Self::parse_mac_address(&query.device_mac) {
                    if let Some(hostname) = hostname_bindings.get(&mac_bytes) {
                        if !hostname.is_empty() {
                            hostname.clone()
                        } else {
                            query.device_mac.clone()
                        }
                    } else if !query.device_name.is_empty() {
                        query.device_name.clone()
                    } else {
                        query.device_mac.clone()
                    }
                } else if !query.device_name.is_empty() {
                    query.device_name.clone()
                } else {
                    query.device_mac.clone()
                }
            } else if !query.device_name.is_empty() {
                query.device_name.clone()
            } else {
                continue;
            };
            *device_map.entry(device_key).or_insert(0) += 1;
        }
        let mut top_devices: Vec<TopItem> = device_map.into_iter().map(|(name, count)| TopItem { name, count }).collect();
        // 按计数降序排序，然后按名称升序排序以保证稳定的顺序
        top_devices.sort_by(|a, b| match b.count.cmp(&a.count) {
            std::cmp::Ordering::Equal => a.name.cmp(&b.name),
            other => other,
        });
        top_devices.truncate(10);

        // 顶级 DNS 服务器（查询的目的 IP）
        let mut dns_server_map: HashMap<String, usize> = HashMap::new();
        for query in queries.iter().filter(|q| q.is_query) {
            *dns_server_map.entry(query.destination_ip.clone()).or_insert(0) += 1;
        }
        let mut top_dns_servers: Vec<TopItem> = dns_server_map
            .into_iter()
            .map(|(name, count)| TopItem { name, count })
            .collect();
        // 按计数降序排序，然后按名称升序排序以保证稳定的顺序
        top_dns_servers.sort_by(|a, b| match b.count.cmp(&a.count) {
            std::cmp::Ordering::Equal => a.name.cmp(&b.name),
            other => other,
        });
        top_dns_servers.truncate(10);

        // 唯一设备
        let unique_devices: std::collections::HashSet<String> = queries
            .iter()
            .filter(|q| q.is_query && !q.device_mac.is_empty())
            .map(|q| q.device_mac.clone())
            .collect();
        let unique_devices_count = unique_devices.len();

        // 时间范围
        let time_range_start = queries.iter().map(|q| q.timestamp).min().unwrap_or(0);
        let time_range_end = queries.iter().map(|q| q.timestamp).max().unwrap_or(0);
        let time_range_duration_minutes = if time_range_end > time_range_start {
            (time_range_end - time_range_start) / 1_000_000_000 / 60
        } else {
            0
        };

        let stats = DnsStatsInfo {
            total_queries,
            total_responses,
            queries_with_response,
            queries_without_response,
            avg_response_time_ms,
            min_response_time_ms,
            max_response_time_ms,
            latest_response_time_ms,
            response_time_percentiles,
            success_count,
            failure_count,
            success_rate,
            response_codes,
            top_domains,
            top_query_types,
            top_devices,
            top_dns_servers,
            unique_devices: unique_devices_count,
            time_range_start: self.convert_to_unix_timestamp(time_range_start),
            time_range_end: self.convert_to_unix_timestamp(time_range_end),
            time_range_duration_minutes,
        };

        let response = DnsStatsResponse { stats };
        let api_response = ApiResponse::success(response);
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }

    /// 处理/api/dns/config GET endpoint
    async fn handle_get_config(&self) -> Result<HttpResponse, anyhow::Error> {
        // TODO: 实现 DNS 配置检索
        // 这会返回当前的 DNS 监控配置

        let config = DnsConfigInfo {
            enabled: false,
            monitored_interfaces: vec![],
            log_level: "info".to_string(),
            retention_days: 7,
        };

        let response = DnsConfigResponse { config };
        let api_response = ApiResponse::success(response);
        let body = serde_json::to_string(&api_response)?;
        Ok(HttpResponse::ok(body))
    }

    /// 处理/api/dns/config POST endpoint
    async fn handle_set_config(&self, _request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        // TODO: 实现 DNS 配置更新
        // 这会允许更新 DNS 监控设置

        // 现在，只返回未实现的响应
        Ok(HttpResponse::error(
            501,
            "DNS configuration update not yet implemented".to_string(),
        ))
    }
}
