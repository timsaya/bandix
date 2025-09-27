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

    use anyhow::Result;
    use std::collections::HashMap;
    use std::fs;
    use std::net::Ipv4Addr;
    use std::process::Command;
    use std::str::FromStr;

    // Get interface IP and subnet mask
    pub fn get_interface_info(interface: &str) -> Option<([u8; 4], [u8; 4])> {
        // Primary: ip addr show <iface>
        if let Ok(output) = Command::new("ip")
            .args(["addr", "show", interface])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
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
        }

        // Fallback: BusyBox ifconfig output (common on OpenWrt)
        if let Ok(output) = Command::new("ifconfig").arg(interface).output() {
            let s = String::from_utf8_lossy(&output.stdout);
            // Two common formats:
            // 1) inet addr:192.168.1.1  Bcast:...  Mask:255.255.255.0
            // 2) inet 192.168.1.1  netmask 255.255.255.0  broadcast 192.168.1.255
            let mut ip_opt: Option<[u8; 4]> = None;
            let mut mask_opt: Option<[u8; 4]> = None;
            for line in s.lines() {
                let line = line.trim();
                if line.contains("inet addr:") || line.starts_with("inet ") {
                    // Try format 1 first
                    if let Some(pos) = line.find("inet addr:") {
                        let rest = &line[pos + "inet addr:".len()..];
                        let ip_part = rest.split_whitespace().next().unwrap_or("");
                        if let Ok(ip) = Ipv4Addr::from_str(ip_part) {
                            ip_opt = Some(ip.octets());
                        }
                    } else {
                        // Try format 2: inet <ip>  ... netmask <mask>
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        for i in 0..parts.len() {
                            if parts[i] == "inet" && i + 1 < parts.len() {
                                if let Ok(ip) = Ipv4Addr::from_str(parts[i + 1]) {
                                    ip_opt = Some(ip.octets());
                                }
                            }
                            if parts[i] == "netmask" && i + 1 < parts.len() {
                                if let Ok(mask_ip) = Ipv4Addr::from_str(parts[i + 1]) {
                                    mask_opt = Some(mask_ip.octets());
                                }
                            }
                        }
                    }

                    // Extract Mask:...
                    if mask_opt.is_none() {
                        if let Some(pos) = line.find("Mask:") {
                            let rest = &line[pos + "Mask:".len()..];
                            let mask_part = rest.split_whitespace().next().unwrap_or("");
                            if let Ok(mask_ip) = Ipv4Addr::from_str(mask_part) {
                                mask_opt = Some(mask_ip.octets());
                            }
                        }
                    }
                }
            }

            if let (Some(ip), Some(mask)) = (ip_opt, mask_opt) {
                return Some((ip, mask));
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

    /// Get IP to MAC address mapping from ARP table
    /// Also includes local machine IP-MAC mapping
    pub fn get_ip_mac_mapping() -> Result<HashMap<[u8; 4], [u8; 6]>> {
        let mut mapping = HashMap::new();

        // Read ARP table from /proc/net/arp
        let content = fs::read_to_string("/proc/net/arp")?;

        for line in content.lines().skip(1) {
            // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                // Parse IP address
                if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                    let ip_bytes = ip.octets();

                    // Parse MAC address
                    if parts[3] != "00:00:00:00:00:00" && parts[3] != "<incomplete>" {
                        if let Ok(mac) = parse_mac_address(parts[3]) {
                            mapping.insert(ip_bytes, mac);
                        }
                    }
                }
            }
        }

        // Add local machine IP-MAC mapping for all network interfaces
        // This ensures that connections from/to the local machine are also counted
        if let Ok(output) = Command::new("ip")
            .args(["addr", "show"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                // Look for lines with "inet " (IPv4 addresses)
                if line.trim().starts_with("inet ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let ip_with_cidr = parts[1];
                        let ip_cidr: Vec<&str> = ip_with_cidr.split('/').collect();
                        if ip_cidr.len() == 2 {
                            if let Ok(ip) = Ipv4Addr::from_str(ip_cidr[0]) {
                                let ip_bytes = ip.octets();
                                
                                // Skip loopback addresses (127.x.x.x)
                                if ip_bytes[0] != 127 {
                                    // Get the MAC address for this interface
                                    if let Some(mac) = get_interface_mac_from_ip_output(&output_str, ip_cidr[0]) {
                                        mapping.insert(ip_bytes, mac);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(mapping)
    }

    /// Extract MAC address for a specific IP from ip addr show output
    fn get_interface_mac_from_ip_output(output: &str, target_ip: &str) -> Option<[u8; 6]> {
        let lines: Vec<&str> = output.lines().collect();
        let mut current_interface = None;
        
        for line in lines {
            // Look for interface name (e.g., "2: enp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP>")
            if line.contains(": <") && line.contains(":") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    current_interface = Some(parts[1].trim());
                }
            }
            // Look for the target IP address
            else if line.contains("inet ") && line.contains(target_ip) {
                // Found the target IP, now look for the MAC address in the same interface block
                if let Some(iface) = current_interface {
                    return get_interface_mac_address(iface);
                }
            }
        }
        None
    }

    /// Get MAC address for a specific network interface
    fn get_interface_mac_address(interface: &str) -> Option<[u8; 6]> {
        // Try to read from /sys/class/net/<interface>/address
        if let Ok(content) = fs::read_to_string(format!("/sys/class/net/{}/address", interface)) {
            if let Ok(mac) = parse_mac_address(content.trim()) {
                return Some(mac);
            }
        }
        None
    }

    /// Parse MAC address from string format (e.g., "aa:bb:cc:dd:ee:ff")
    pub fn parse_mac_address(mac_str: &str) -> Result<[u8; 6]> {
        let parts: Vec<&str> = mac_str.split(':').collect();
        if parts.len() != 6 {
            return Err(anyhow::anyhow!("Invalid MAC address format: {}", mac_str));
        }

        let mut mac = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            mac[i] = u8::from_str_radix(part, 16)?;
        }

        Ok(mac)
    }

    /// Check if an IP address is in the same subnet as the given network interface
    pub fn is_ip_in_subnet(ip: [u8; 4], interface_ip: [u8; 4], subnet_mask: [u8; 4]) -> bool {
        // Calculate network address for both IPs
        let network1 = [
            ip[0] & subnet_mask[0],
            ip[1] & subnet_mask[1],
            ip[2] & subnet_mask[2],
            ip[3] & subnet_mask[3],
        ];
        
        let network2 = [
            interface_ip[0] & subnet_mask[0],
            interface_ip[1] & subnet_mask[1],
            interface_ip[2] & subnet_mask[2],
            interface_ip[3] & subnet_mask[3],
        ];
        
        network1 == network2
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_parse_mac_address() {
            let mac_str = "aa:bb:cc:dd:ee:ff";
            let result = parse_mac_address(mac_str);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        }

        #[test]
        fn test_get_ip_mac_mapping() {
            // This test will only work if /proc/net/arp exists
            // and the process has permission to read it
            if std::path::Path::new("/proc/net/arp").exists() {
                let result = get_ip_mac_mapping();
                assert!(result.is_ok());
            }
        }

        #[test]
        fn test_is_ip_in_subnet() {
            // Test 192.168.1.0/24 subnet
            let interface_ip = [192, 168, 1, 1];
            let subnet_mask = [255, 255, 255, 0];
            
            // IPs in the same subnet
            assert!(is_ip_in_subnet([192, 168, 1, 10], interface_ip, subnet_mask));
            assert!(is_ip_in_subnet([192, 168, 1, 254], interface_ip, subnet_mask));
            
            // IPs not in the same subnet
            assert!(!is_ip_in_subnet([192, 168, 2, 1], interface_ip, subnet_mask));
            assert!(!is_ip_in_subnet([10, 0, 0, 1], interface_ip, subnet_mask));
            assert!(!is_ip_in_subnet([127, 0, 0, 1], interface_ip, subnet_mask));
        }
    }
}
