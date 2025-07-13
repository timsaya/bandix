use bandix_common::MacTrafficStats;
use log::info;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// 简单的HTTP服务器，仅依赖于tokio
pub async fn start_server(
    port: u16,
    mac_stats: Arc<Mutex<HashMap<[u8; 6], MacTrafficStats>>>,
) -> Result<(), anyhow::Error> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    println!("HTTP服务器监听在 {}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let mac_stats = Arc::clone(&mac_stats);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, mac_stats).await {
                eprintln!("处理连接时出错: {}", e);
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    mac_stats: Arc<Mutex<HashMap<[u8; 6], MacTrafficStats>>>,
) -> Result<(), anyhow::Error> {
    let mut buffer = [0; 4096]; // 增加缓冲区大小以处理更大的请求
    let n = stream.read(&mut buffer).await?;

    // 解析HTTP请求以确定路径和方法
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

    if path == "/api/devices" {
        let json = generate_devices_json(&mac_stats);
        send_json_response(&mut stream, &json).await?;
    } else if path.starts_with("/api/limit") && method == "POST" {
        // 解析JSON请求体获取MAC地址和限速设置
        let body = parse_request_body(&request);
        if let Some(body_content) = body {
            match set_device_limit_json(&body_content, &mac_stats).await {
                Ok(_) => send_json_response(&mut stream, r#"{"status":"success"}"#).await?,
                Err(e) => {
                    let error_json = format!(r#"{{"status":"error","message":"{}"}}"#, e);
                    send_json_response_with_status(&mut stream, &error_json, 400).await?
                }
            }
        } else {
            send_json_response_with_status(
                &mut stream,
                r#"{"status":"error","message":"无效的请求体"}"#,
                400,
            )
            .await?;
        }
    } else {
        send_not_found(&mut stream).await?;
    }

    Ok(())
}

// 从请求中解析请求体
fn parse_request_body(request: &str) -> Option<String> {
    let parts: Vec<&str> = request.split("\r\n\r\n").collect();
    if parts.len() < 2 {
        return None;
    }
    Some(parts[1].to_string())
}

// 解析MAC地址字符串
fn parse_mac_address(mac_str: &str) -> Result<[u8; 6], anyhow::Error> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return Err(anyhow::anyhow!("无效的MAC地址格式"));
    }

    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)?;
    }

    Ok(mac)
}


// 设置设备限速（JSON格式）
async fn set_device_limit_json(
    body: &str,
    mac_stats: &Arc<Mutex<HashMap<[u8; 6], MacTrafficStats>>>,
) -> Result<(), anyhow::Error> {
    // 解析JSON请求体
    let json: Value = serde_json::from_str(body)?;

    let mac_str = json["mac"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("缺少MAC地址参数"))?;

    let mac = parse_mac_address(mac_str)?;

    // 解析跨网络下载和上传限速（直接解析数字，单位为字节）
    let wide_rx_rate_limit = json["wide_rx_rate_limit"].as_u64().unwrap_or(0); // 默认无限制

    let wide_tx_rate_limit = json["wide_tx_rate_limit"].as_u64().unwrap_or(0); // 默认无限制

    // 更新用户空间的统计信息
    {
        let mut stats_map = mac_stats.lock().unwrap();
        if let Some(stats) = stats_map.get_mut(&mac) {
            stats.wide_rx_rate_limit = wide_rx_rate_limit;
            stats.wide_tx_rate_limit = wide_tx_rate_limit;
        } else {
            // 如果没有找到MAC地址，创建一个新的记录
            let mut new_stats = MacTrafficStats::default();
            new_stats.wide_rx_rate_limit = wide_rx_rate_limit;
            new_stats.wide_tx_rate_limit = wide_tx_rate_limit;
            stats_map.insert(mac, new_stats);
        }
    }

    // 格式化速率为可读的字符串
    let rx_str = if wide_rx_rate_limit == 0 {
        "无限制".to_string()
    } else {
        format!("{}/s", format_bytes(wide_rx_rate_limit))
    };

    let tx_str = if wide_tx_rate_limit == 0 {
        "无限制".to_string()
    } else {
        format!("{}/s", format_bytes(wide_tx_rate_limit))
    };

    info!(
        "已设置 MAC: {} 的限速 - 接收: {}, 发送: {}",
        format_mac(&mac),
        rx_str,
        tx_str
    );

    Ok(())
}

// 格式化MAC地址
fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

// 格式化字节数
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2}KB", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

fn generate_devices_json(mac_stats: &Arc<Mutex<HashMap<[u8; 6], MacTrafficStats>>>) -> String {
    let stats_map = mac_stats.lock().unwrap();

    let mut json = String::from("{\n  \"devices\": [\n");

    let total_items = stats_map.len();
    for (i, (mac, stats)) in stats_map.iter().enumerate() {
        // 格式化MAC地址
        let mac_str = format_mac(mac);

        // 格式化IP地址
        let ip_str = format!(
            "{}.{}.{}.{}",
            stats.ip_address[0], stats.ip_address[1], stats.ip_address[2], stats.ip_address[3]
        );

        json.push_str(&format!(
            "    {{\n      \"ip\": \"{}\",\n      \"mac\": \"{}\",\n      \"total_rx_bytes\": {},\n      \"total_tx_bytes\": {},\n      \"total_rx_rate\": {},\n      \"total_tx_rate\": {},\n      \"wide_rx_rate_limit\": {},\n      \"wide_tx_rate_limit\": {},\n      \"local_rx_bytes\": {},\n      \"local_tx_bytes\": {},\n      \"local_rx_rate\": {},\n      \"local_tx_rate\": {},\n      \"wide_rx_bytes\": {},\n      \"wide_tx_bytes\": {},\n      \"wide_rx_rate\": {},\n      \"wide_tx_rate\": {}\n    }}",
            ip_str, mac_str, 
            stats.total_rx_bytes, stats.total_tx_bytes, stats.total_rx_rate, stats.total_tx_rate, 
            stats.wide_rx_rate_limit, stats.wide_tx_rate_limit,
            stats.local_rx_bytes, stats.local_tx_bytes, stats.local_rx_rate, stats.local_tx_rate,
            stats.wide_rx_bytes, stats.wide_tx_bytes, stats.wide_rx_rate, stats.wide_tx_rate
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
