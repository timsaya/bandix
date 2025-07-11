pub mod format_utils {
    // 用于将字节数转换为人类可读的格式
    pub fn format_bytes(bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;

        if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} B", bytes)
        }
    }

    // 用于将速率转换为人类可读的格式
    pub fn format_rate(bytes_per_sec: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;

        if bytes_per_sec >= GB {
            format!("{:.2} GB/s", bytes_per_sec as f64 / GB as f64)
        } else if bytes_per_sec >= MB {
            format!("{:.2} MB/s", bytes_per_sec as f64 / MB as f64)
        } else if bytes_per_sec >= KB {
            format!("{:.2} KB/s", bytes_per_sec as f64 / KB as f64)
        } else {
            format!("{} B/s", bytes_per_sec)
        }
    }

    // 格式化IP地址
    pub fn format_ip(ip: &[u8; 4]) -> String {
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    }

    // 格式化MAC地址
    pub fn format_mac(mac: &[u8; 6]) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    }
}

pub mod network_utils {
    
    use std::net::Ipv4Addr;
    use std::process::Command;
    use std::str::FromStr;

    // 判断是否为广播IP地址
    pub fn is_broadcast_ip(ip: &[u8; 4]) -> bool {
        // 255.255.255.255
        if ip[0] == 255 && ip[1] == 255 && ip[2] == 255 && ip[3] == 255 {
            return true;
        }

        // 网段广播地址 (通常是以255结尾的地址)
        if ip[3] == 255 {
            return true;
        }

        // 多播地址 (224.0.0.0 - 239.255.255.255)
        if ip[0] >= 224 && ip[0] <= 239 {
            return true;
        }

        false
    }

    // 检查IP是否在同一子网
    pub fn is_in_same_subnet(ip: &[u8; 4], interface_ip: &[u8; 4], subnet_mask: &[u8; 4]) -> bool {
        for i in 0..4 {
            if (ip[i] & subnet_mask[i]) != (interface_ip[i] & subnet_mask[i]) {
                return false;
            }
        }
        true
    }

    // 获取接口的IP和子网掩码
    pub fn get_interface_info(interface: &str) -> Option<([u8; 4], [u8; 4])> {
        let output = Command::new("ip")
            .args(&["addr", "show", interface])
            .output()
            .ok()?;

        let output_str = String::from_utf8_lossy(&output.stdout);

        // 提取IPv4地址和子网掩码
        for line in output_str.lines() {
            if line.trim().starts_with("inet ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let ip_with_cidr = parts[1];
                    let ip_cidr: Vec<&str> = ip_with_cidr.split('/').collect();

                    if ip_cidr.len() == 2 {
                        if let Ok(ip) = Ipv4Addr::from_str(ip_cidr[0]) {
                            let ip_bytes = ip.octets();

                            if let Ok(cidr) = ip_cidr[1].parse::<u8>() {
                                let mask = get_subnet_mask(cidr);
                                return Some((ip_bytes, mask));
                            }
                        }
                    }
                }
            }
        }

        None
    }

    // 从CIDR计算子网掩码
    pub fn get_subnet_mask(cidr: u8) -> [u8; 4] {
        let mut mask = [0u8; 4];
        let bits = cidr as usize;

        for i in 0..4 {
            let start_bit = i * 8;
            let end_bit = start_bit + 8;

            let mut byte_mask = 0u8;
            for bit in start_bit..end_bit {
                if bit < bits {
                    byte_mask |= 1 << (7 - (bit % 8));
                }
            }

            mask[i] = byte_mask;
        }

        mask
    }
}


