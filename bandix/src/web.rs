use bandix_common::IpTrafficStats;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use sqlite::{Connection, State};
use std::path::Path;

// 简单的HTTP服务器，仅依赖于tokio
pub async fn start_server(
    port: u16,
    ip_stats: Arc<Mutex<HashMap<[u8; 4], IpTrafficStats>>>,
) -> Result<(), anyhow::Error> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    println!("HTTP服务器监听在 {}", addr);

    // 初始化数据库
    init_database()?;

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

// 初始化SQLite数据库
fn init_database() -> Result<(), anyhow::Error> {
    let db_path = "bandix.db";
    let _db = if Path::new(db_path).exists() {
        Connection::open(db_path)?
    } else {
        let db = Connection::open(db_path)?;
        db.execute(
            "CREATE TABLE IF NOT EXISTS mac_hostname (
                mac TEXT PRIMARY KEY,
                hostname TEXT NOT NULL
            )",
        )?;
        db
    };
    Ok(())
}

async fn handle_connection(
    mut stream: TcpStream,
    ip_stats: Arc<Mutex<HashMap<[u8; 4], IpTrafficStats>>>,
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
        let json = generate_devices_json(&ip_stats);
        send_json_response(&mut stream, &json).await?;
    } else if path == "/api/bind" && method == "POST" {
        // 处理绑定主机名和MAC地址的请求
        let body = extract_body(&request);
        handle_bind_request(&mut stream, body).await?;
    } else {
        send_not_found(&mut stream).await?;
    }

    Ok(())
}

// 从HTTP请求中提取请求体
fn extract_body(request: &str) -> Option<String> {
    if let Some(pos) = request.find("\r\n\r\n") {
        let body = &request[pos + 4..];
        if !body.is_empty() {
            return Some(body.to_string());
        }
    }
    None
}

// 处理绑定请求
async fn handle_bind_request(stream: &mut TcpStream, body: Option<String>) -> Result<(), anyhow::Error> {
    if let Some(body) = body {
        // 尝试解析JSON
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
            if let (Some(mac), Some(hostname)) = (
                parsed.get("mac").and_then(|v| v.as_str()),
                parsed.get("hostname").and_then(|v| v.as_str()),
            ) {
                // 验证MAC地址格式
                if is_valid_mac(mac) {
                    match save_to_database(mac, hostname) {
                        Ok(_) => {
                            let response = format!(
                                "{{\"success\": true, \"message\": \"成功绑定MAC地址 {} 到主机名 {}\"}}", 
                                mac, hostname
                            );
                            return send_json_response(stream, &response).await;
                        }
                        Err(e) => {
                            let response = format!(
                                "{{\"success\": false, \"message\": \"数据库错误: {}\"}}", 
                                e
                            );
                            return send_json_response_with_status(stream, &response, 500).await;
                        }
                    }
                } else {
                    let response = "{\"success\": false, \"message\": \"无效的MAC地址格式\"}";
                    return send_json_response_with_status(stream, response, 400).await;
                }
            }
        }
    }
    
    let response = "{\"success\": false, \"message\": \"请求格式错误，需要提供mac和hostname字段\"}";
    send_json_response_with_status(stream, response, 400).await
}

// 验证MAC地址格式
fn is_valid_mac(mac: &str) -> bool {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return false;
    }
    
    for part in parts {
        if part.len() != 2 {
            return false;
        }
        if u8::from_str_radix(part, 16).is_err() {
            return false;
        }
    }
    
    true
}

// 将MAC地址和主机名保存到数据库
fn save_to_database(mac: &str, hostname: &str) -> Result<(), anyhow::Error> {
    let db = Connection::open("bandix.db")?;
    
    // 将MAC地址转换为小写
    let mac_lowercase = mac.to_lowercase();
    
    // 使用REPLACE语法，如果已存在则替换
    let mut statement = db.prepare(
        "REPLACE INTO mac_hostname (mac, hostname) VALUES (?, ?)"
    )?;
    
    statement.bind((1, mac_lowercase.as_str()))?;
    statement.bind((2, hostname))?;
    
    while statement.next()? != State::Done {}
    
    Ok(())
}

fn generate_devices_json(ip_stats: &Arc<Mutex<HashMap<[u8; 4], IpTrafficStats>>>) -> String {
    let stats_map = ip_stats.lock().unwrap();
    
    // 获取主机名映射
    let hostnames = get_hostnames().unwrap_or_default();

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
        
        // MAC地址已经是小写格式，因为上面的格式化使用了小写十六进制格式{:02x}
        // 获取主机名（如果有）
        let hostname = hostnames.get(&mac_str).cloned().unwrap_or_default();

        json.push_str(&format!(
            "    {{\n      \"ip\": \"{}\",\n      \"mac\": \"{}\",\n      \"hostname\": \"{}\",\n      \"rx_bytes\": {},\n      \"tx_bytes\": {},\n      \"rx_rate\": {},\n      \"tx_rate\": {}\n    }}",
            ip_str, mac_str, hostname, stats.rx_bytes, stats.tx_bytes, stats.rx_rate, stats.tx_rate
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

// 从数据库获取所有MAC地址与主机名的映射
fn get_hostnames() -> Result<HashMap<String, String>, anyhow::Error> {
    let mut result = HashMap::new();
    let db = Connection::open("bandix.db")?;
    
    let mut statement = db.prepare("SELECT mac, hostname FROM mac_hostname")?;
    
    while let State::Row = statement.next()? {
        let mac: String = statement.read::<String, _>(0)?;
        let hostname: String = statement.read::<String, _>(1)?;
        result.insert(mac, hostname);
    }
    
    Ok(result)
}

async fn send_json_response(stream: &mut TcpStream, json: &str) -> Result<(), anyhow::Error> {
    send_json_response_with_status(stream, json, 200).await
}

async fn send_json_response_with_status(stream: &mut TcpStream, json: &str, status: u16) -> Result<(), anyhow::Error> {
    let status_text = match status {
        200 => "OK",
        400 => "BAD REQUEST",
        404 => "NOT FOUND",
        500 => "INTERNAL SERVER ERROR",
        _ => "UNKNOWN",
    };
    
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        status, status_text, json.len(), json
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
