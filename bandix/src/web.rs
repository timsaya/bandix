use bandix_common::MacTrafficStats;
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

    let path = parts[1];

    if path == "/api/devices" {
        let json = generate_devices_json(&mac_stats);
        send_json_response(&mut stream, &json).await?;
    }
    {
        send_not_found(&mut stream).await?;
    }

    Ok(())
}

fn generate_devices_json(mac_stats: &Arc<Mutex<HashMap<[u8; 6], MacTrafficStats>>>) -> String {
    let stats_map = mac_stats.lock().unwrap();

    let mut json = String::from("{\n  \"devices\": [\n");

    let total_items = stats_map.len();
    for (i, (mac, stats)) in stats_map.iter().enumerate() {
        // 格式化MAC地址
        let mac_str = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
        
        // 格式化IP地址
        let ip_str = format!(
            "{}.{}.{}.{}", 
            stats.ip_address[0], stats.ip_address[1], stats.ip_address[2], stats.ip_address[3]
        );

        json.push_str(&format!(
            "    {{\n      \"ip\": \"{}\",\n      \"mac\": \"{}\",\n      \"rx_bytes\": {},\n      \"tx_bytes\": {},\n      \"rx_rate\": {},\n      \"tx_rate\": {}\n    }}",
            ip_str, mac_str, stats.rx_bytes, stats.tx_bytes, stats.rx_rate, stats.tx_rate
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
