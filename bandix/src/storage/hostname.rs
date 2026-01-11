use std::fs;
use std::path::{Path, PathBuf};

/// 获取主机名绑定文件的路径
pub fn bindings_path(base_dir: &str) -> PathBuf {
    Path::new(base_dir).join("hostname_bindings.txt")
}

/// 从文件加载主机名绑定
/// 文件格式：每行一个条目 - "mac12 hostname"
pub fn load_hostname_bindings(base_dir: &str) -> Result<Vec<([u8; 6], String)>, anyhow::Error> {
    let path = bindings_path(base_dir);
    let mut out = Vec::new();
    if !path.exists() {
        return Ok(out);
    }
    let content = fs::read_to_string(&path)?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() != 2 {
            continue;
        }
        let mac_str = parts[0];
        let hostname = parts[1];
        if mac_str.len() != 12 {
            continue;
        }
        let mut mac = [0u8; 6];
        let mut ok = true;
        for i in 0..6 {
            if let Ok(v) = u8::from_str_radix(&mac_str[i * 2..i * 2 + 2], 16) {
                mac[i] = v;
            } else {
                ok = false;
                break;
            }
        }
        if ok {
            out.push((mac, hostname.to_string()));
        }
    }
    Ok(out)
}

/// 从 ubus 加载主机名绑定（luci-rpc getHostHints）
/// 执行：ubus call luci-rpc getHostHints
/// 返回包含 MAC 到主机名映射的 JSON
/// 如果命令失败则静默返回空向量（例如，未安装 ubus）
pub fn load_hostname_from_ubus() -> Result<Vec<([u8; 6], String)>, anyhow::Error> {
    use std::process::Command;

    // Try to execute ubus command, silently return empty vec if it fails
    let output = match Command::new("ubus").arg("call").arg("luci-rpc").arg("getHostHints").output() {
        Ok(output) => output,
        Err(_) => {
            // Command failed (e.g., ubus not found), return empty vec silently
            return Ok(Vec::new());
        }
    };

    // 如果command didn't succeed, return empty vec silently
    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Try to parse JSON, if it fails, return empty vec silently
    let json: serde_json::Value = match serde_json::from_str(&stdout) {
        Ok(json) => json,
        Err(_) => return Ok(Vec::new()),
    };

    let mut out = Vec::new();

    // 解析the JSON structure
    // Expected format: { "MAC_ADDRESS": { "name": "hostname", "ipaddrs": [...], "ip6addrs": [...] }, ... }
    // Example: { "06:C9:9D:D2:62:38": { "name": "MacBookAir", ... }, ... }
    if let Some(obj) = json.as_object() {
        for (mac_str, value) in obj {
            // Parse MAC (for both hostname mapping and Wi-Fi cache)
            let parsed_mac = crate::utils::network_utils::parse_mac_address(mac_str).ok().or_else(|| {
                // Try parsing without colons (format: 06C99DD26238)
                if mac_str.len() == 12 {
                    let mut mac = [0u8; 6];
                    let mut ok = true;
                    for i in 0..6 {
                        if let Ok(v) = u8::from_str_radix(&mac_str[i * 2..i * 2 + 2], 16) {
                            mac[i] = v;
                        } else {
                            ok = false;
                            break;
                        }
                    }
                    if ok { Some(mac) } else { None }
                } else {
                    None
                }
            });

            let Some(mac) = parsed_mac else { continue };
            // 获取hostname from "name" field (some devices may not have this field)
            if let Some(name) = value.get("name").and_then(|v| v.as_str()) {
                if name.is_empty() {
                    continue;
                }

                out.push((mac, name.to_string()));
            }
        }
    }

    Ok(out)
}
