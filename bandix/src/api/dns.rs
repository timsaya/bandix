use super::{ApiResponse, HttpRequest, HttpResponse};
use crate::command::Options;
use crate::monitor::DnsQueryRecord;
use chrono::{Local, TimeZone};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// DNS query information for API response
#[derive(Serialize, Deserialize)]
pub struct DnsQueryInfo {
    pub timestamp: u64,              // Unix timestamp in milliseconds
    pub timestamp_formatted: String, // Formatted time string (e.g., "2024-01-01 12:00:00")
    pub domain: String,
    pub query_type: String,
    pub response_code: String,
    pub response_time_ms: Option<u64>, // Response time in milliseconds, None for queries, Some(value) for responses
    pub source_ip: String,
    pub destination_ip: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub transaction_id: u16,
    pub is_query: bool,
    pub response_ips: Vec<String>,
    pub response_records: Vec<String>, // All response records (A, AAAA, CNAME, HTTPS, etc.)
    pub device_mac: String,            // Device MAC address
    pub device_name: String,           // Device hostname
}

/// DNS queries response structure
#[derive(Serialize, Deserialize)]
pub struct DnsQueriesResponse {
    pub queries: Vec<DnsQueryInfo>,
    pub total: usize,       // Total number of records (before pagination)
    pub page: usize,        // Current page number
    pub page_size: usize,   // Page size
    pub total_pages: usize, // Total number of pages
}

/// Top item with count (for top domains, devices, etc.)
#[derive(Serialize, Deserialize)]
pub struct TopItem {
    pub name: String,
    pub count: usize,
}

/// Response time percentiles
#[derive(Serialize, Deserialize)]
pub struct ResponseTimePercentiles {
    pub p50: u64, // Median (50th percentile) in milliseconds
    pub p90: u64, // 90th percentile in milliseconds
    pub p95: u64, // 95th percentile in milliseconds
    pub p99: u64, // 99th percentile in milliseconds
}

/// Response code statistics
#[derive(Serialize, Deserialize)]
pub struct ResponseCodeStats {
    pub code: String,
    pub count: usize,
    pub percentage: f64,
}

/// DNS statistics for API response
#[derive(Serialize, Deserialize)]
pub struct DnsStatsInfo {
    // Basic counts
    pub total_queries: usize,            // Total number of DNS queries
    pub total_responses: usize,          // Total number of DNS responses
    pub queries_with_response: usize,    // Queries that got a response
    pub queries_without_response: usize, // Queries without response (timeout/lost)

    // Performance metrics
    pub avg_response_time_ms: f64, // Average response time in milliseconds
    pub min_response_time_ms: u64, // Fastest response time
    pub max_response_time_ms: u64, // Slowest response time
    pub latest_response_time_ms: Option<u64>, // Most recent response time (None if no responses yet)
    pub response_time_percentiles: ResponseTimePercentiles,

    // Success/failure metrics
    pub success_count: usize, // Successful responses (NoError)
    pub failure_count: usize, // Failed responses (any error)
    pub success_rate: f64,    // Success rate (0.0 - 1.0)
    pub response_codes: Vec<ResponseCodeStats>, // Breakdown by response code

    // Top statistics
    pub top_domains: Vec<TopItem>,     // Most queried domains (top 10)
    pub top_query_types: Vec<TopItem>, // Most used query types (top 10)
    pub top_devices: Vec<TopItem>,     // Most active devices (top 10)
    pub top_dns_servers: Vec<TopItem>, // Most used DNS servers (top 10)

    // Device statistics
    pub unique_devices: usize, // Number of unique devices

    // Time range
    pub time_range_start: u64,            // Earliest record timestamp (ms)
    pub time_range_end: u64,              // Latest record timestamp (ms)
    pub time_range_duration_minutes: u64, // Duration in minutes
}

/// DNS statistics response structure
#[derive(Serialize, Deserialize)]
pub struct DnsStatsResponse {
    pub stats: DnsStatsInfo,
}

/// DNS configuration for API response
#[derive(Serialize, Deserialize)]
pub struct DnsConfigInfo {
    pub enabled: bool,
    pub monitored_interfaces: Vec<String>,
    pub log_level: String,
    pub retention_days: u64,
}

/// DNS configuration response structure
#[derive(Serialize, Deserialize)]
pub struct DnsConfigResponse {
    pub config: DnsConfigInfo,
}

/// DNS monitoring API handler
#[derive(Clone)]
pub struct DnsApiHandler {
    #[allow(dead_code)]
    options: Options,
    dns_queries: Arc<Mutex<Vec<DnsQueryRecord>>>,
    hostname_bindings: Arc<Mutex<std::collections::HashMap<[u8; 6], String>>>,
    boot_time_offset_ns: u64, // Offset to convert monotonic time to Unix timestamp
}

impl DnsApiHandler {
    pub fn new(
        options: Options,
        dns_queries: Arc<Mutex<Vec<DnsQueryRecord>>>,
        hostname_bindings: Arc<Mutex<std::collections::HashMap<[u8; 6], String>>>,
    ) -> Self {
        // Calculate boot time offset: Unix time - monotonic time
        // We'll use the first DNS record's timestamp as reference if available,
        // otherwise calculate from current time
        let boot_time_offset_ns = Self::calculate_boot_time_offset();

        Self {
            options,
            dns_queries,
            hostname_bindings,
            boot_time_offset_ns,
        }
    }

    /// Calculate boot time offset to convert monotonic time to Unix timestamp
    /// This reads /proc/uptime to get system uptime, then calculates boot time
    fn calculate_boot_time_offset() -> u64 {
        // Method 1: Read /proc/uptime
        if let Ok(content) = std::fs::read_to_string("/proc/uptime") {
            if let Some(uptime_secs_str) = content.split_whitespace().next() {
                if let Ok(uptime_secs) = uptime_secs_str.parse::<f64>() {
                    let uptime_ns = (uptime_secs * 1_000_000_000.0) as u64;
                    let now_unix_ns = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64;
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

        // Fallback: Use current time as approximation
        // This is less accurate but works if /proc/uptime is not available
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }

    /// Convert monotonic timestamp (nanoseconds) to Unix timestamp (milliseconds)
    fn convert_to_unix_timestamp(&self, monotonic_ns: u64) -> u64 {
        // Unix timestamp = monotonic timestamp + boot time offset
        let unix_ns = monotonic_ns.saturating_add(self.boot_time_offset_ns);
        unix_ns / 1_000_000 // Convert to milliseconds
    }

    /// Parse MAC address string to [u8; 6] bytes
    fn parse_mac_address(mac_str: &str) -> Result<[u8; 6], anyhow::Error> {
        crate::utils::network_utils::parse_mac_address(mac_str)
    }

    /// Format Unix timestamp (milliseconds) to readable string (local time)
    fn format_timestamp(timestamp_ms: u64) -> String {
        let secs = (timestamp_ms / 1000) as i64;
        let nanos = ((timestamp_ms % 1000) * 1_000_000) as u32;

        // Convert to local time
        match Local.timestamp_opt(secs, nanos) {
            chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            chrono::LocalResult::None => "Invalid timestamp".to_string(),
            chrono::LocalResult::Ambiguous(dt1, _dt2) => {
                // In case of ambiguous time (DST transition), use the first option
                dt1.format("%Y-%m-%d %H:%M:%S%.3f").to_string()
            }
        }
    }
}

impl DnsApiHandler {
    pub fn supported_routes(&self) -> Vec<&'static str> {
        vec!["/api/dns/queries", "/api/dns/stats", "/api/dns/config"]
    }

    pub async fn handle_request(
        &self,
        request: &HttpRequest,
    ) -> Result<HttpResponse, anyhow::Error> {
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
                source_port: if is_query {
                    (r1 % 50000 + 1024) as u16
                } else {
                    53
                },
                destination_port: if is_query {
                    53
                } else {
                    (r1 % 50000 + 1024) as u16
                },
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

    /// Handle /api/dns/queries endpoint
    ///
    /// Query parameters:
    /// - domain: Filter by domain name (substring match)
    /// - device: Filter by device MAC or hostname (substring match)
    /// - is_query: Filter by query type (true=query, false=response)
    /// - query_type: Filter by DNS record type (e.g., A, AAAA, CNAME, MX, TXT, NS, SOA, PTR)
    /// - dns_server: Filter by DNS server IP address (destination_ip for queries, source_ip for responses)
    /// - page: Page number (default: 1)
    /// - page_size: Number of records per page (default: 20, max: 1000)
    /// - limit: (deprecated, use page_size) Maximum number of records to return
    async fn handle_queries(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {

        // Self::_generate_test_data(&self.dns_queries);
        
        // Get query parameters
        let domain_filter = request.query_params.get("domain");
        let device_filter = request.query_params.get("device").map(|s| s.to_lowercase());
        let is_query_filter = request
            .query_params
            .get("is_query")
            .and_then(|s| s.parse::<bool>().ok());
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

        // Apply filters using indices
        let filtered_indices: Vec<usize> = queries
            .iter()
            .enumerate()
            .filter(|(_, q)| {
                // Filter by domain
                if let Some(domain) = domain_filter {
                    if !q.domain.contains(domain) {
                        return false;
                    }
                }

                // Filter by device (MAC or hostname, case-insensitive substring match)
                if let Some(ref device) = device_filter {
                    let mac_match = q.device_mac.to_lowercase().contains(device);
                    let name_match = q.device_name.to_lowercase().contains(device);
                    if !mac_match && !name_match {
                        return false;
                    }
                }

                // Filter by query type (query vs response)
                if let Some(is_query) = is_query_filter {
                    if q.is_query != is_query {
                        return false;
                    }
                }

                // Filter by DNS record type (e.g., A, AAAA, CNAME, MX, etc.)
                // query_type_filter 已经转换为大写，这里也将 q.query_type 转换为大写进行子串匹配
                if let Some(ref query_type) = query_type_filter {
                    if !q.query_type.contains(query_type) {
                        return false;
                    }
                }

                // Filter by DNS server IP address (IP地址都是数字，直接匹配)
                // For queries: DNS server is destination_ip (port 53)
                // For responses: DNS server is source_ip (port 53)
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

        // Group by transaction and sort
        // Strategy: Group records by transaction_id + domain + source/dest IP pair
        // Each group represents a query-response pair (or standalone query/response)
        // Sort groups by the latest timestamp in each group (newest first)
        // Within each group, sort by timestamp (query before response)

        use std::collections::HashMap;

        // Create groups: key = (transaction_id, domain, ip_pair_key)
        let mut groups: HashMap<(u16, String, String), Vec<usize>> = HashMap::new();

        for &idx in &filtered_indices {
            let record = &queries[idx];
            // Create a normalized IP pair key (order-independent)
            // This ensures query and response with swapped IPs are grouped together
            let ip_pair_key = {
                let mut ips = vec![record.source_ip.as_str(), record.destination_ip.as_str()];
                ips.sort();
                ips.join("_")
            };

            let key = (record.transaction_id, record.domain.clone(), ip_pair_key);
            groups.entry(key).or_insert_with(Vec::new).push(idx);
        }

        // Convert groups to sorted list
        let mut sorted_groups: Vec<Vec<usize>> = groups.into_values().collect();

        // Sort groups by the latest timestamp in each group (newest first)
        sorted_groups.sort_by(|group_a, group_b| {
            let max_time_a = group_a.iter().map(|&idx| queries[idx].timestamp).max().unwrap_or(0);
            let max_time_b = group_b.iter().map(|&idx| queries[idx].timestamp).max().unwrap_or(0);
            max_time_b.cmp(&max_time_a)
        });

        // Sort records within each group by timestamp (newest first)
        // Since responses typically come after queries, this means response will be first
        for group in &mut sorted_groups {
            group.sort_by(|&idx_a, &idx_b| queries[idx_b].timestamp.cmp(&queries[idx_a].timestamp));
        }

        // Flatten groups back to a single list
        let sorted_indices: Vec<usize> = sorted_groups
            .into_iter()
            .flat_map(|group| group.into_iter())
            .collect();

        // Calculate pagination
        let total = sorted_indices.len();
        let total_pages = (total + page_size - 1) / page_size; // Ceiling division
        let start_idx = (page - 1) * page_size;
        let end_idx = (start_idx + page_size).min(total);

        // Apply pagination
        let paginated_indices = if start_idx < total {
            &sorted_indices[start_idx..end_idx]
        } else {
            &[] // Page out of range
        };

        // Get latest hostname bindings for dynamic lookup
        let hostname_bindings = if let Ok(bindings) = self.hostname_bindings.lock() {
            bindings.clone()
        } else {
            std::collections::HashMap::new()
        };

        // Convert to API response format
        let query_infos: Vec<DnsQueryInfo> = paginated_indices
            .iter()
            .map(|&idx| {
                let q = &queries[idx];
                // Convert monotonic timestamp to Unix timestamp
                let unix_timestamp_ms = self.convert_to_unix_timestamp(q.timestamp);

                // Format timestamp
                let timestamp_formatted = Self::format_timestamp(unix_timestamp_ms);

                // Get latest hostname from bindings based on MAC address
                let device_name = if !q.device_mac.is_empty() {
                    // Parse MAC address string to [u8; 6]
                    if let Ok(mac_bytes) = Self::parse_mac_address(&q.device_mac) {
                        hostname_bindings
                            .get(&mac_bytes)
                            .cloned()
                            .unwrap_or_else(|| {
                                // Fallback to stored hostname if not found in bindings
                                q.device_name.clone()
                            })
                    } else {
                        // If MAC parsing fails, use stored hostname
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

    /// Handle /api/dns/stats endpoint
    async fn handle_stats(&self) -> Result<HttpResponse, anyhow::Error> {
        use std::collections::HashMap;

        // Get all DNS queries
        let queries = if let Ok(queries) = self.dns_queries.lock() {
            queries.clone()
        } else {
            vec![]
        };

        // Get latest hostname bindings for dynamic lookup
        let hostname_bindings = if let Ok(bindings) = self.hostname_bindings.lock() {
            bindings.clone()
        } else {
            std::collections::HashMap::new()
        };

        if queries.is_empty() {
            // Return empty stats if no data
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

        // Calculate basic counts
        let total_queries = queries.iter().filter(|q| q.is_query).count();
        let total_responses = queries.iter().filter(|q| !q.is_query).count();
        let queries_with_response = queries
            .iter()
            .filter(|q| q.is_query && q.response_time_ms.is_some())
            .count();
        let queries_without_response = total_queries - queries_with_response;

        // Calculate response time statistics
        let response_times: Vec<u64> = queries
            .iter()
            .filter_map(|q| q.response_time_ms)
            .filter(|&t| t > 0)
            .collect();

        // Get latest response time (from the most recent response with response_time_ms)
        let latest_response_time_ms = queries
            .iter()
            .filter(|q| !q.is_query && q.response_time_ms.is_some())
            .max_by_key(|q| q.timestamp)
            .and_then(|q| q.response_time_ms);

        let (
            avg_response_time_ms,
            min_response_time_ms,
            max_response_time_ms,
            response_time_percentiles,
        ) = if !response_times.is_empty() {
            let sum: u64 = response_times.iter().sum();
            let avg = sum as f64 / response_times.len() as f64;
            let min = *response_times.iter().min().unwrap();
            let max = *response_times.iter().max().unwrap();

            // Calculate percentiles
            let mut sorted_times = response_times.clone();
            sorted_times.sort();
            let len = sorted_times.len();
            let p50 = sorted_times[len * 50 / 100];
            let p90 = sorted_times[len * 90 / 100];
            let p95 = sorted_times[len * 95 / 100];
            let p99 = sorted_times[len * 99 / 100];

            (
                avg,
                min,
                max,
                ResponseTimePercentiles { p50, p90, p95, p99 },
            )
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

        // Calculate success/failure metrics
        let success_count = queries
            .iter()
            .filter(|q| !q.is_query && q.response_code == "Success")
            .count();
        let failure_count = queries
            .iter()
            .filter(|q| !q.is_query && !q.response_code.is_empty() && q.response_code != "Success")
            .count();
        let success_rate = if total_responses > 0 {
            success_count as f64 / total_responses as f64
        } else {
            0.0
        };

        // Response code breakdown
        let mut response_code_map: HashMap<String, usize> = HashMap::new();
        for query in queries
            .iter()
            .filter(|q| !q.is_query && !q.response_code.is_empty())
        {
            *response_code_map
                .entry(query.response_code.clone())
                .or_insert(0) += 1;
        }
        let mut response_codes: Vec<ResponseCodeStats> = response_code_map
            .into_iter()
            .map(|(code, count)| ResponseCodeStats {
                code,
                count,
                percentage: if total_responses > 0 {
                    count as f64 / total_responses as f64
                } else {
                    0.0
                },
            })
            .collect();
        // Sort by count (descending), then by code name (ascending) for stable ordering
        response_codes.sort_by(|a, b| match b.count.cmp(&a.count) {
            std::cmp::Ordering::Equal => a.code.cmp(&b.code),
            other => other,
        });

        // Top domains
        let mut domain_map: HashMap<String, usize> = HashMap::new();
        for query in queries.iter().filter(|q| q.is_query) {
            *domain_map.entry(query.domain.clone()).or_insert(0) += 1;
        }
        let mut top_domains: Vec<TopItem> = domain_map
            .into_iter()
            .map(|(name, count)| TopItem { name, count })
            .collect();
        // Sort by count (descending), then by name (ascending) for stable ordering
        top_domains.sort_by(|a, b| match b.count.cmp(&a.count) {
            std::cmp::Ordering::Equal => a.name.cmp(&b.name),
            other => other,
        });
        top_domains.truncate(10);

        // Top query types
        let mut query_type_map: HashMap<String, usize> = HashMap::new();
        for query in queries.iter().filter(|q| q.is_query) {
            *query_type_map.entry(query.query_type.clone()).or_insert(0) += 1;
        }
        let mut top_query_types: Vec<TopItem> = query_type_map
            .into_iter()
            .map(|(name, count)| TopItem { name, count })
            .collect();
        // Sort by count (descending), then by name (ascending) for stable ordering
        top_query_types.sort_by(|a, b| match b.count.cmp(&a.count) {
            std::cmp::Ordering::Equal => a.name.cmp(&b.name),
            other => other,
        });
        top_query_types.truncate(10);

        // Top devices (by MAC or name)
        // Use latest hostname from bindings for accurate device names
        let mut device_map: HashMap<String, usize> = HashMap::new();
        for query in queries.iter().filter(|q| q.is_query) {
            let device_key = if !query.device_mac.is_empty() {
                // Try to get latest hostname from bindings
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
        let mut top_devices: Vec<TopItem> = device_map
            .into_iter()
            .map(|(name, count)| TopItem { name, count })
            .collect();
        // Sort by count (descending), then by name (ascending) for stable ordering
        top_devices.sort_by(|a, b| match b.count.cmp(&a.count) {
            std::cmp::Ordering::Equal => a.name.cmp(&b.name),
            other => other,
        });
        top_devices.truncate(10);

        // Top DNS servers (destination IP for queries)
        let mut dns_server_map: HashMap<String, usize> = HashMap::new();
        for query in queries.iter().filter(|q| q.is_query) {
            *dns_server_map
                .entry(query.destination_ip.clone())
                .or_insert(0) += 1;
        }
        let mut top_dns_servers: Vec<TopItem> = dns_server_map
            .into_iter()
            .map(|(name, count)| TopItem { name, count })
            .collect();
        // Sort by count (descending), then by name (ascending) for stable ordering
        top_dns_servers.sort_by(|a, b| match b.count.cmp(&a.count) {
            std::cmp::Ordering::Equal => a.name.cmp(&b.name),
            other => other,
        });
        top_dns_servers.truncate(10);

        // Unique devices
        let unique_devices: std::collections::HashSet<String> = queries
            .iter()
            .filter(|q| q.is_query && !q.device_mac.is_empty())
            .map(|q| q.device_mac.clone())
            .collect();
        let unique_devices_count = unique_devices.len();

        // Time range
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

    /// Handle /api/dns/config GET endpoint
    async fn handle_get_config(&self) -> Result<HttpResponse, anyhow::Error> {
        // TODO: Implement DNS configuration retrieval
        // This would return current DNS monitoring configuration

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

    /// Handle /api/dns/config POST endpoint
    async fn handle_set_config(
        &self,
        _request: &HttpRequest,
    ) -> Result<HttpResponse, anyhow::Error> {
        // TODO: Implement DNS configuration update
        // This would allow updating DNS monitoring settings

        // For now, just return a not implemented response
        Ok(HttpResponse::error(
            501,
            "DNS configuration update not yet implemented".to_string(),
        ))
    }
}
