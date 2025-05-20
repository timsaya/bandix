use bandix_common::IpTrafficStats;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// 简单的HTTP服务器，仅依赖于tokio
pub async fn start_server(
    port: u16,
    ip_stats: Arc<Mutex<HashMap<[u8; 4], IpTrafficStats>>>,
) -> Result<(), anyhow::Error> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    println!("HTTP服务器监听在 {}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let ip_stats = Arc::clone(&ip_stats);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, ip_stats).await {
                eprintln!("处理连接时出错: {}", e);
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    ip_stats: Arc<Mutex<HashMap<[u8; 4], IpTrafficStats>>>,
) -> Result<(), anyhow::Error> {
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer).await?;

    // 解析HTTP请求以确定路径
    let request = String::from_utf8_lossy(&buffer[..n]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    if path == "/api/devices" {
        let json = generate_devices_json(&ip_stats);
        send_json_response(&mut stream, &json).await?;
    } else {
        send_not_found(&mut stream).await?;
    }

    Ok(())
}

fn generate_devices_json(ip_stats: &Arc<Mutex<HashMap<[u8; 4], IpTrafficStats>>>) -> String {
    let stats_map = ip_stats.lock().unwrap();

    let mut json = String::from("{\n  \"devices\": [\n");

    let total_items = stats_map.len();
    for (i, (ip, stats)) in stats_map.iter().enumerate() {
        // 格式化IP地址
        let ip_str = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
        let mac_str = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            stats.mac_address[0],
            stats.mac_address[1],
            stats.mac_address[2],
            stats.mac_address[3],
            stats.mac_address[4],
            stats.mac_address[5]
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
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
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
