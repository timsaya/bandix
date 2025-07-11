use bandix_common::MacTrafficStats;
use log::info;
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
        // 解析请求体获取MAC地址和限速设置
        let body = parse_request_body(&request);
        if let Some(body_content) = body {
            match set_device_limit(&body_content, &mac_stats).await {
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

// 解析速率字符串为字节/秒
fn parse_rate(rate_str: &str) -> Result<u64, anyhow::Error> {
    if rate_str.is_empty() || rate_str == "0" {
        return Ok(0); // 0表示无限制
    }

    let rate_str = rate_str.trim().to_lowercase();
    let rate_str = rate_str.trim_end_matches("/s"); // 移除可能存在的"/s"后缀

    let mut numeric_part = String::new();
    let mut unit_part = String::new();

    for c in rate_str.chars() {
        if c.is_ascii_digit() || c == '.' {
            numeric_part.push(c);
        } else {
            unit_part.push(c);
        }
    }

    let value: f64 = numeric_part.parse()?;
    let bytes_per_second = match unit_part.trim() {
        "" => value as u64, // 无单位，假设为字节/秒
        "b" => value as u64,
        "kb" | "k" => (value * 1024.0) as u64,
        "mb" | "m" => (value * 1024.0 * 1024.0) as u64,
        "gb" | "g" => (value * 1024.0 * 1024.0 * 1024.0) as u64,
        _ => return Err(anyhow::anyhow!("不支持的速率单位: {}", unit_part)),
    };

    Ok(bytes_per_second)
}

// 设置设备限速
async fn set_device_limit(
    body: &str,
    mac_stats: &Arc<Mutex<HashMap<[u8; 6], MacTrafficStats>>>,
) -> Result<(), anyhow::Error> {
    // 解析请求体，格式: mac=00:11:22:33:44:55&download=1MB&upload=500KB
    let params: Vec<&str> = body.split('&').collect();

    let mut mac_str = None;
    let mut download_limit_str = None;
    let mut upload_limit_str = None;

    for param in params {
        let kv: Vec<&str> = param.split('=').collect();
        if kv.len() != 2 {
            continue;
        }

        match kv[0] {
            "mac" => mac_str = Some(kv[1]),
            "download" => download_limit_str = Some(kv[1]),
            "upload" => upload_limit_str = Some(kv[1]),
            _ => {}
        }
    }

    let mac = match mac_str {
        Some(m) => parse_mac_address(m)?,
        None => return Err(anyhow::anyhow!("缺少MAC地址参数")),
    };

    // 默认无限制
    let download_limit = match download_limit_str {
        Some(dl) => parse_rate(dl)?,
        None => 0,
    };

    let upload_limit = match upload_limit_str {
        Some(ul) => parse_rate(ul)?,
        None => 0,
    };

    // 更新用户空间的统计信息
    {
        let mut stats_map = mac_stats.lock().unwrap();
        if let Some(stats) = stats_map.get_mut(&mac) {
            stats.download_limit = download_limit;
            stats.upload_limit = upload_limit;
        } else {
            // 如果没有找到MAC地址，创建一个新的记录
            let mut new_stats = MacTrafficStats::default();
            new_stats.download_limit = download_limit;
            new_stats.upload_limit = upload_limit;
            stats_map.insert(mac, new_stats);
        }
    }

    // 格式化速率为可读的字符串
    let download_str = if download_limit == 0 {
        "无限制".to_string()
    } else {
        format_bytes(download_limit) + "/s"
    };

    let upload_str = if upload_limit == 0 {
        "无限制".to_string()
    } else {
        format_bytes(upload_limit) + "/s"
    };

    info!(
        "已设置 MAC: {} 的限速 - 下载: {}, 上传: {}",
        format_mac(&mac),
        download_str,
        upload_str
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
            "    {{\n      \"ip\": \"{}\",\n      \"mac\": \"{}\",\n      \"rx_bytes\": {},\n      \"tx_bytes\": {},\n      \"rx_rate\": {},\n      \"tx_rate\": {},\n      \"download_limit\": {},\n      \"upload_limit\": {}\n    }}",
            ip_str, mac_str, stats.rx_bytes, stats.tx_bytes, stats.rx_rate, stats.tx_rate, stats.download_limit, stats.upload_limit
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
