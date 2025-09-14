use bandix_common::MacTrafficStats;
use crate::storage;
use crate::utils::format_utils::{format_bytes, format_mac};
use log::{info, error};
use chrono::Local;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// Simple HTTP server, only depends on tokio
pub async fn start_server(
    port: u16,
    mac_stats: Arc<Mutex<HashMap<[u8; 6], MacTrafficStats>>>,
    rate_limits: Arc<Mutex<HashMap<[u8; 6], [u64; 2]>>>,
    web_log: bool,
) -> Result<(), anyhow::Error> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    info!("HTTP server listening on {}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let mac_stats = Arc::clone(&mac_stats);
        let rate_limits = Arc::clone(&rate_limits);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, mac_stats, rate_limits, web_log).await {
                error!("Error handling connection: {}", e);
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    mac_stats: Arc<Mutex<HashMap<[u8; 6], MacTrafficStats>>>,
    rate_limits: Arc<Mutex<HashMap<[u8; 6], [u64; 2]>>>,
    web_log: bool,
) -> Result<(), anyhow::Error> {
    let mut buffer = [0; 4096]; // Increase buffer size to handle larger requests
    let n = stream.read(&mut buffer).await?;

    // Parse HTTP request to determine path and method
    let request = String::from_utf8_lossy(&buffer[..n]);
    let lines: Vec<&str> = request.lines().collect();

    if lines.is_empty() {
        send_bad_request(&mut stream).await?;
        return Ok(());
    }

    let parts: Vec<&str> = lines[0].split_whitespace().collect();
    if parts.len() < 2 {
        send_bad_request(&mut stream).await?;
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1];

    if web_log {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
        let query = path.splitn(2, '?').nth(1).unwrap_or("");
        if query.is_empty() {
            info!("[{}] {} {}", timestamp, method, path);
        } else {
            info!("[{}] {} {} | params: {}", timestamp, method, path, query);
        }
    }

    if path == "/api/devices" {
        let json = generate_devices_json(&mac_stats);
        send_json_response(&mut stream, &json).await?;
    } else if path.starts_with("/api/limit") && method == "POST" {
        // Parse JSON request body to get MAC address and rate limit settings
        let body = parse_request_body(&request);
        if let Some(body_content) = body {
            match set_device_limit_json(&body_content, &mac_stats, &rate_limits).await {
                Ok(_) => send_json_response(&mut stream, r#"{"status":"success"}"#).await?,
                Err(e) => {
                    let error_json = format!(r#"{{"status":"error","message":"{}"}}"#, e);
                    send_json_response_with_status(&mut stream, &error_json, 400).await?
                }
            }
        } else {
            send_json_response_with_status(
                &mut stream,
                r#"{"status":"error","message":"Invalid request body"}"#,
                400,
            )
            .await?;
        }
    } else if path == "/api/limits" && method == "GET" {
        let json = generate_limits_json(&rate_limits);
        send_json_response(&mut stream, &json).await?;
    } else if path.starts_with("/api/metrics") && method == "GET" {
        // Query string format: /api/metrics?mac=aa:bb:cc:dd:ee:ff|all
        let query = path.splitn(2, '?').nth(1).unwrap_or("");
        let params: std::collections::HashMap<_, _> = query
            .split('&')
            .filter(|s| !s.is_empty())
            .filter_map(|kv| {
                let mut it = kv.splitn(2, '=');
                match (it.next(), it.next()) {
                    (Some(k), Some(v)) => Some((k.to_string(), v.to_string())),
                    _ => None,
                }
            })
            .collect();

        let data_dir = std::env::var("BANDIX_DATA_DIR").unwrap_or_else(|_| "bandix-data".to_string());

        let traffic_retention_seconds: u32 = std::env::var("BANDIX_TRAFFIC_RETENTION_SECONDS")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(3600);
        use std::time::{SystemTime, UNIX_EPOCH, Duration};
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;
        let start_ms = now_ms.saturating_sub(traffic_retention_seconds as u64 * 1000);
        let end_ms = now_ms;

        let mac_opt = params.get("mac").cloned();
        let (rows_result, mac_label) = if let Some(mac_str) = mac_opt {
            if mac_str.to_ascii_lowercase() == "all" || mac_str.trim().is_empty() {
                (
                    crate::storage::query_metrics_aggregate_all_with_window(
                        &data_dir,
                        start_ms,
                        end_ms,
                    ),
                    "all".to_string(),
                )
            } else {
                match parse_mac_address(&mac_str) {
                    Ok(mac) => (
                        crate::storage::query_metrics(&data_dir, &mac, start_ms, end_ms),
                        format_mac(&mac),
                    ),
                    Err(e) => {
                        let error_json = format!(
                            r#"{{"status":"error","message":"invalid mac: {}"}}"#,
                            e
                        );
                        send_json_response_with_status(&mut stream, &error_json, 400).await?;
                        return Ok(());
                    }
                }
            }
        } else {
            // mac omitted => aggregate all within window
            (
                crate::storage::query_metrics_aggregate_all_with_window(
                    &data_dir,
                    start_ms,
                    end_ms,
                ),
                "all".to_string(),
            )
        };

        match rows_result {
            Ok(rows) => {
                // rows 已在存储层按窗口裁剪
                let mut json = format!(
                    "{{\n  \"retention_seconds\": {},\n  \"mac\": \"{}\",\n  \"metrics\": [\n",
                    traffic_retention_seconds,
                    mac_label
                );
                for (i, r) in rows.iter().enumerate() {
                    json.push_str(&format!(
                        "    {{\n      \"ts_ms\": {},\n      \"total_rx_rate\": {},\n      \"total_tx_rate\": {},\n      \"local_rx_rate\": {},\n      \"local_tx_rate\": {},\n      \"wide_rx_rate\": {},\n      \"wide_tx_rate\": {},\n      \"total_rx_bytes\": {},\n      \"total_tx_bytes\": {},\n      \"local_rx_bytes\": {},\n      \"local_tx_bytes\": {},\n      \"wide_rx_bytes\": {},\n      \"wide_tx_bytes\": {}\n    }}",
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
                        r.wide_tx_bytes
                    ));
                    if i + 1 < rows.len() {
                        json.push_str(",\n");
                    } else {
                        json.push_str("\n");
                    }
                }
                json.push_str("  ]\n}");
                send_json_response(&mut stream, &json).await?;
            }
            Err(e) => {
                let error_json = format!(r#"{{"status":"error","message":"{}"}}"#, e);
                send_json_response_with_status(&mut stream, &error_json, 500).await?;
            }
        }
    } else {
        send_not_found(&mut stream).await?;
    }

    Ok(())
}

// Parse request body from request
fn parse_request_body(request: &str) -> Option<String> {
    let parts: Vec<&str> = request.split("\r\n\r\n").collect();
    if parts.len() < 2 {
        return None;
    }
    Some(parts[1].to_string())
}

// Parse MAC address string
fn parse_mac_address(mac_str: &str) -> Result<[u8; 6], anyhow::Error> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return Err(anyhow::anyhow!("Invalid MAC address format"));
    }

    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)?;
    }

    Ok(mac)
}


// Set device rate limit (JSON format)
async fn set_device_limit_json(
    body: &str,
    mac_stats: &Arc<Mutex<HashMap<[u8; 6], MacTrafficStats>>>,
    rate_limits: &Arc<Mutex<HashMap<[u8; 6], [u64; 2]>>>,
) -> Result<(), anyhow::Error> {
    // Parse JSON request body
    let json: Value = serde_json::from_str(body)?;

    let mac_str = json["mac"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing MAC address parameter"))?;

    let mac = parse_mac_address(mac_str)?;

    // Parse cross-network download and upload rate limits (parse numbers directly, unit is bytes)
    let wide_rx_rate_limit = json["wide_rx_rate_limit"].as_u64().unwrap_or(0); // Default unlimited

    let wide_tx_rate_limit = json["wide_tx_rate_limit"].as_u64().unwrap_or(0); // Default unlimited

    // Update in-memory rate limits only (do not create mac_stats entries)
    {
        let mut rl = rate_limits.lock().unwrap();
        rl.insert(mac, [wide_rx_rate_limit, wide_tx_rate_limit]);
    }

    // If the device already exists in mac_stats, sync the limit fields for UI consistency
    {
        let mut stats_map = mac_stats.lock().unwrap();
        if let Some(stats) = stats_map.get_mut(&mac) {
            stats.wide_rx_rate_limit = wide_rx_rate_limit;
            stats.wide_tx_rate_limit = wide_tx_rate_limit;
        }
    }

    // Persist to files (ring files and rate limit configuration)
    // Note: data_dir is currently provided via CLI and used at startup; to avoid passing the
    // path through this module, read the BANDIX_DATA_DIR environment variable, falling back to
    // the default 'bandix-data' if unset.
    let data_dir = std::env::var("BANDIX_DATA_DIR").unwrap_or_else(|_| "bandix-data".to_string());
    storage::upsert_limit(&data_dir, &mac, wide_rx_rate_limit, wide_tx_rate_limit)?;

    // Format rate as readable string
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

    info!(
        "Rate limit set for MAC: {} - Receive: {}, Transmit: {}",
        format_mac(&mac),
        rx_str,
        tx_str
    );

    Ok(())
}



fn generate_devices_json(mac_stats: &Arc<Mutex<HashMap<[u8; 6], MacTrafficStats>>>) -> String {
    let stats_map = mac_stats.lock().unwrap();

    let mut json = String::from("{\n  \"devices\": [\n");

    // 仅展示被 eBPF 实际采集到的设备（last_sample_ts > 0）
    let filtered: Vec<(&[u8; 6], &MacTrafficStats)> = stats_map
        .iter()
        .filter(|(_mac, stats)| stats.last_sample_ts > 0)
        .collect();

    let total_items = filtered.len();
    for (i, (mac, stats)) in filtered.into_iter().enumerate() {
        // Format MAC address
        let mac_str = format_mac(mac);

        // Format IP address
        let ip_str = format!(
            "{}.{}.{}.{}",
            stats.ip_address[0], stats.ip_address[1], stats.ip_address[2], stats.ip_address[3]
        );

        json.push_str(&format!(
            "    {{\n      \"ip\": \"{}\",\n      \"mac\": \"{}\",\n      \"total_rx_bytes\": {},\n      \"total_tx_bytes\": {},\n      \"total_rx_rate\": {},\n      \"total_tx_rate\": {},\n      \"wide_rx_rate_limit\": {},\n      \"wide_tx_rate_limit\": {},\n      \"local_rx_bytes\": {},\n      \"local_tx_bytes\": {},\n      \"local_rx_rate\": {},\n      \"local_tx_rate\": {},\n      \"wide_rx_bytes\": {},\n      \"wide_tx_bytes\": {},\n      \"wide_rx_rate\": {},\n      \"wide_tx_rate\": {},\n      \"last_online_ts\": {}\n    }}",
            ip_str, mac_str,
            stats.total_rx_bytes, stats.total_tx_bytes, stats.total_rx_rate, stats.total_tx_rate,
            stats.wide_rx_rate_limit, stats.wide_tx_rate_limit,
            stats.local_rx_bytes, stats.local_tx_bytes, stats.local_rx_rate, stats.local_tx_rate,
            stats.wide_rx_bytes, stats.wide_tx_bytes, stats.wide_rx_rate, stats.wide_tx_rate,
            stats.last_online_ts
        ));

        if i < total_items - 1 {
            json.push_str(",\n");
        } else {
            json.push_str("\n");
        }
    }

    json.push_str("  ]\n}");
    json
}

fn generate_limits_json(rate_limits: &Arc<Mutex<HashMap<[u8; 6], [u64; 2]>>>) -> String {
    let rl_map = rate_limits.lock().unwrap();
    let mut json = String::from("{\n  \"limits\": [\n");
    let total_items = rl_map.len();
    for (i, (mac, lim)) in rl_map.iter().enumerate() {
        let mac_str = crate::utils::format_utils::format_mac(mac);
        json.push_str(&format!(
            "    {{\n      \"mac\": \"{}\",\n      \"wide_rx_rate_limit\": {},\n      \"wide_tx_rate_limit\": {}\n    }}",
            mac_str, lim[0], lim[1]
        ));
        if i < total_items - 1 {
            json.push_str(",\n");
        } else {
            json.push_str("\n");
        }
    }
    json.push_str("  ]\n}");
    json
}

async fn send_json_response(stream: &mut TcpStream, json: &str) -> Result<(), anyhow::Error> {
    send_json_response_with_status(stream, json, 200).await
}

async fn send_json_response_with_status(
    stream: &mut TcpStream,
    json: &str,
    status: u16,
) -> Result<(), anyhow::Error> {
    let status_text = match status {
        200 => "OK",
        400 => "BAD REQUEST",
        404 => "NOT FOUND",
        500 => "INTERNAL SERVER ERROR",
        _ => "UNKNOWN",
    };

    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        status,
        status_text,
        json.len(),
        json
    );

    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

async fn send_not_found(stream: &mut TcpStream) -> Result<(), anyhow::Error> {
    let response = "HTTP/1.1 404 NOT FOUND\r\nContent-Length: 0\r\n\r\n";
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

async fn send_bad_request(stream: &mut TcpStream) -> Result<(), anyhow::Error> {
    let response = "HTTP/1.1 400 BAD REQUEST\r\nContent-Length: 0\r\n\r\n";
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}
