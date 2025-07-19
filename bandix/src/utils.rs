// Only import these formatting functions in debug mode
pub mod format_utils {
    // Convert bytes to human-readable format
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

    // Convert rate to human-readable format
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

    // Format IP address
    pub fn format_ip(ip: &[u8; 4]) -> String {
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    }

    // Format MAC address
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

    // Get interface IP and subnet mask
    pub fn get_interface_info(interface: &str) -> Option<([u8; 4], [u8; 4])> {
        let output = Command::new("ip")
            .args(&["addr", "show", interface])
            .output()
            .ok()?;

        let output_str = String::from_utf8_lossy(&output.stdout);

        // Extract IPv4 address and subnet mask
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

    // Calculate subnet mask from CIDR
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
