// 仅在调试模式下导入这些格式化函数
pub mod format_utils {
    // 转换bytes to human-readable format
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

    // 格式化IP address
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
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::process::Command;
    use std::str::FromStr;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};

    // Cache for IP-MAC mapping with expiration
    struct IpMacMappingCache {
        mapping: HashMap<[u8; 4], [u8; 6]>,
        expires_at: SystemTime,
    }

    // Cache for IPv6 neighbor table with expiration
    struct Ipv6NeighborsCache {
        mapping: HashMap<[u8; 6], Vec<[u8; 16]>>,
        expires_at: SystemTime,
    }

    static IP_MAC_MAPPING_CACHE: Mutex<Option<IpMacMappingCache>> = Mutex::new(None);
    static IPV6_NEIGHBORS_CACHE: Mutex<Option<Ipv6NeighborsCache>> = Mutex::new(None);

    // Cache expiration time: 5 seconds
    const CACHE_TTL_SECONDS: u64 = 5;

    // 获取interface IP and subnet mask
    pub fn get_interface_info(interface: &str) -> Option<([u8; 4], [u8; 4])> {
        // Primary: ip addr show <iface>
        if let Ok(output) = Command::new("ip").args(["addr", "show", interface]).output() {
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

    // 计算subnet mask from CIDR
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

    /// 获取IP to MAC address mapping from ARP table (with caching)
    /// Also includes local machine IP-MAC mapping
    /// Results are cached for 5 seconds to reduce system calls
    pub fn get_ip_mac_mapping() -> Result<HashMap<[u8; 4], [u8; 6]>> {
        let now = SystemTime::now();

        // Check cache
        {
            let cache_guard = IP_MAC_MAPPING_CACHE.lock().unwrap();
            if let Some(ref cache) = *cache_guard {
                if now < cache.expires_at {
                    // Cache is valid, return cached data
                    return Ok(cache.mapping.clone());
                }
            }
        }

        // Cache expired or doesn't exist, fetch fresh data
        let mapping = get_ip_mac_mapping_uncached()?;

        // 更新cache
        {
            let expires_at = now + Duration::from_secs(CACHE_TTL_SECONDS);
            let mut cache_guard = IP_MAC_MAPPING_CACHE.lock().unwrap();
            *cache_guard = Some(IpMacMappingCache {
                mapping: mapping.clone(),
                expires_at,
            });
        }

        Ok(mapping)
    }

    /// 获取IP to MAC address mapping from neighbor table (uncached, internal implementation)
    /// Also includes local machine IP-MAC mapping
    fn get_ip_mac_mapping_uncached() -> Result<HashMap<[u8; 4], [u8; 6]>> {
        let mut mapping = HashMap::new();

        // Read neighbor table using ip -4 neigh show
        if let Ok(output) = Command::new("ip").args(["-4", "neigh", "show"]).output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 {
                    continue;
                }

                let state = parts.get(parts.len() - 1).unwrap_or(&"");
                if matches!(*state, "FAILED" | "INCOMPLETE" | "INVALID") {
                    continue;
                }

                if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                    let ip_bytes = ip.octets();

                    if let Some(lladdr_pos) = parts.iter().position(|&x| x == "lladdr") {
                        if lladdr_pos + 1 < parts.len() {
                            if let Ok(mac) = parse_mac_address(parts[lladdr_pos + 1]) {
                                mapping.insert(ip_bytes, mac);
                            }
                        }
                    }
                }
            }
        }

        // 添加local machine IP-MAC mapping for all network interfaces
        if let Ok(output) = Command::new("ip").args(["addr", "show"]).output() {
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

                                if ip_bytes[0] != 127 {
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

    /// 解析MAC address from string format (e.g., "aa:bb:cc:dd:ee:ff")
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

    /// 检查是否an IP address is in the same subnet as the given network interface
    pub fn is_ip_in_subnet(ip: [u8; 4], interface_ip: [u8; 4], subnet_mask: [u8; 4]) -> bool {
        // 计算network address for both IPs
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

    /// 获取IPv6 address information for a specific interface
    /// Returns a list of (IPv6 address, prefix length) tuples
    pub fn get_interface_ipv6_info(interface: &str) -> Vec<([u8; 16], u8)> {
        let mut ipv6_addresses = Vec::new();

        if let Ok(output) = Command::new("ip").args(["-6", "addr", "show", interface]).output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                // Look for "inet6 <addr>/<prefix_len> scope ..."
                if line.trim().starts_with("inet6 ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let addr_with_prefix = parts[1];
                        let addr_parts: Vec<&str> = addr_with_prefix.split('/').collect();
                        if addr_parts.len() == 2 {
                            if let Ok(ipv6) = Ipv6Addr::from_str(addr_parts[0]) {
                                if let Ok(prefix_len) = addr_parts[1].parse::<u8>() {
                                    ipv6_addresses.push((ipv6.octets(), prefix_len));
                                }
                            }
                        }
                    }
                }
            }
        }

        ipv6_addresses
    }

    /// 获取IPv6 neighbor table (similar to ARP for IPv4) (with caching)
    /// Returns mapping from MAC address to list of IPv6 addresses
    /// Results are cached for 5 seconds to reduce system calls
    pub fn get_ipv6_neighbors() -> Result<HashMap<[u8; 6], Vec<[u8; 16]>>> {
        let now = SystemTime::now();

        // Check cache
        {
            let cache_guard = IPV6_NEIGHBORS_CACHE.lock().unwrap();
            if let Some(ref cache) = *cache_guard {
                if now < cache.expires_at {
                    // Cache is valid, return cached data
                    return Ok(cache.mapping.clone());
                }
            }
        }

        // Cache expired or doesn't exist, fetch fresh data
        let mapping = get_ipv6_neighbors_uncached()?;

        // 更新cache
        {
            let expires_at = now + Duration::from_secs(CACHE_TTL_SECONDS);
            let mut cache_guard = IPV6_NEIGHBORS_CACHE.lock().unwrap();
            *cache_guard = Some(Ipv6NeighborsCache {
                mapping: mapping.clone(),
                expires_at,
            });
        }

        Ok(mapping)
    }

    /// 获取IPv6 neighbor table (uncached, internal implementation)
    /// Returns mapping from MAC address to list of IPv6 addresses
    fn get_ipv6_neighbors_uncached() -> Result<HashMap<[u8; 6], Vec<[u8; 16]>>> {
        let mut mapping: HashMap<[u8; 6], Vec<[u8; 16]>> = HashMap::new();

        // Method 1: Parse ip -6 neigh show
        if let Ok(output) = Command::new("ip").args(["-6", "neigh", "show"]).output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 {
                    continue;
                }

                let state = parts.get(parts.len() - 1).unwrap_or(&"");
                if matches!(*state, "FAILED" | "INCOMPLETE" | "INVALID") {
                    continue;
                }

                if let Ok(ipv6) = Ipv6Addr::from_str(parts[0]) {
                    if let Some(lladdr_pos) = parts.iter().position(|&x| x == "lladdr") {
                        if lladdr_pos + 1 < parts.len() {
                            if let Ok(mac) = parse_mac_address(parts[lladdr_pos + 1]) {
                                mapping.entry(mac).or_insert_with(Vec::new).push(ipv6.octets());
                            }
                        }
                    }
                }
            }
        }

        // Method 2: Add local interface IPv6 addresses
        // 获取all network interfaces and their IPv6 addresses
        if let Ok(output) = Command::new("ip").args(["-6", "addr", "show"]).output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = output_str.lines().collect();
            let mut current_interface: Option<String> = None;

            for line in lines {
                // Look for interface name line
                if !line.starts_with(' ') && line.contains(": <") {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 2 {
                        current_interface = Some(parts[1].trim().to_string());
                    }
                } else if line.trim().starts_with("inet6 ") {
                    // 解析IPv6 address
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let addr_with_prefix = parts[1];
                        let addr_parts: Vec<&str> = addr_with_prefix.split('/').collect();
                        if let Ok(ipv6) = Ipv6Addr::from_str(addr_parts[0]) {
                            // Skip loopback and link-local addresses for now
                            // (can be included if needed)
                            let ipv6_bytes = ipv6.octets();
                            // Skip ::1 (loopback)
                            if ipv6_bytes == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] {
                                continue;
                            }

                            // Get MAC address for this interface
                            if let Some(ref iface) = current_interface {
                                if let Some(mac) = get_interface_mac_address(iface) {
                                    mapping.entry(mac).or_insert_with(Vec::new).push(ipv6_bytes);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(mapping)
    }

    /// 格式化IPv6 address from bytes
    pub fn format_ipv6(bytes: &[u8; 16]) -> String {
        let ipv6 = Ipv6Addr::from(*bytes);
        ipv6.to_string()
    }

    /// 格式化IPv6 address with privacy protection for public addresses
    /// LAN addresses (ULA, Link-Local) are shown in full
    /// WAN addresses (GUA) are partially masked with asterisks
    pub fn format_ipv6_with_privacy(bytes: &[u8; 16]) -> String {
        let addr_type = classify_ipv6_address(bytes);
        let ipv6 = Ipv6Addr::from(*bytes);
        let full_addr = ipv6.to_string();

        match addr_type {
            // 对于WAN addresses (Global Unicast), mask the middle part
            Ipv6AddressType::GlobalUnicast => {
                // 解析the address into segments
                let segments: Vec<&str> = full_addr.split(':').collect();

                if segments.len() >= 4 {
                    // Show first 2 segments and last 1 segment, mask the middle
                    // Example: 2408:820c:a93d:44b0:e251:d8ff:fe11:b45c
                    //       -> 2408:820c:****:****:****:****:****:b45c
                    let first_part = segments[..2].join(":");
                    let last_part = segments[segments.len() - 1];
                    format!("{}:****:****:****:****:****:{}", first_part, last_part)
                } else {
                    // Fallback: mask everything except first and last
                    format!("{}:****:****", segments[0])
                }
            }
            // 对于LAN addresses, show in full
            _ => full_addr,
        }
    }

    /// IPv6 address type and network classification
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Ipv6AddressType {
        LinkLocal,     // fe80::/10 - Link-Local
        UniqueLocal,   // fc00::/7 (fd00::/8) - ULA
        GlobalUnicast, // 2000::/3 - Global Unicast
        Loopback,      // ::1/128
        Multicast,     // ff00::/8
        Unspecified,   // ::/128
        Other,
    }

    impl Ipv6AddressType {
        pub fn type_name(&self) -> &'static str {
            match self {
                Ipv6AddressType::LinkLocal => "Link-Local",
                Ipv6AddressType::UniqueLocal => "ULA",
                Ipv6AddressType::GlobalUnicast => "GUA",
                Ipv6AddressType::Loopback => "Loopback",
                Ipv6AddressType::Multicast => "Multicast",
                Ipv6AddressType::Unspecified => "Unspecified",
                Ipv6AddressType::Other => "Other",
            }
        }

        pub fn network_scope(&self) -> &'static str {
            match self {
                Ipv6AddressType::LinkLocal => "LAN",
                Ipv6AddressType::UniqueLocal => "LAN",
                Ipv6AddressType::GlobalUnicast => "WAN",
                Ipv6AddressType::Loopback => "Local",
                Ipv6AddressType::Multicast => "Special",
                Ipv6AddressType::Unspecified => "Special",
                Ipv6AddressType::Other => "Unknown",
            }
        }
    }

    /// Classify IPv6 address type based on RFC standards
    pub fn classify_ipv6_address(bytes: &[u8; 16]) -> Ipv6AddressType {
        // Check for unspecified address ::/128
        if bytes == &[0u8; 16] {
            return Ipv6AddressType::Unspecified;
        }

        // Check for loopback address ::1/128
        if bytes[0..15] == [0u8; 15] && bytes[15] == 1 {
            return Ipv6AddressType::Loopback;
        }

        // Check for multicast ff00::/8
        if bytes[0] == 0xff {
            return Ipv6AddressType::Multicast;
        }

        // Check for link-local fe80::/10
        // fe80::/10 means first 10 bits are 1111111010
        // fe80 = 1111 1110 1000 0000
        // feb0 = 1111 1110 1011 1111 (upper boundary)
        if bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80 {
            return Ipv6AddressType::LinkLocal;
        }

        // Check for unique local address fc00::/7 (actually fd00::/8 in practice)
        // fc00::/7 means first 7 bits are 1111110
        if (bytes[0] & 0xfe) == 0xfc {
            return Ipv6AddressType::UniqueLocal;
        }

        // Check for global unicast 2000::/3
        // 2000::/3 means first 3 bits are 001
        if (bytes[0] & 0xe0) == 0x20 {
            return Ipv6AddressType::GlobalUnicast;
        }

        Ipv6AddressType::Other
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
            // 这test will only work if /proc/net/arp exists
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

        #[test]
        fn test_classify_ipv6_address() {
            use std::net::Ipv6Addr;
            use std::str::FromStr;

            // Test Global Unicast (GUA) - 2000::/3
            let gua = Ipv6Addr::from_str("2408:820c:a93d:44b0::1").unwrap();
            assert_eq!(classify_ipv6_address(&gua.octets()), Ipv6AddressType::GlobalUnicast);
            assert_eq!(Ipv6AddressType::GlobalUnicast.network_scope(), "WAN");

            // Test Unique Local (ULA) - fd00::/8
            let ula = Ipv6Addr::from_str("fd00:1234:5678::1").unwrap();
            assert_eq!(classify_ipv6_address(&ula.octets()), Ipv6AddressType::UniqueLocal);
            assert_eq!(Ipv6AddressType::UniqueLocal.network_scope(), "LAN");

            let ula2 = Ipv6Addr::from_str("fd76:3d06:2ad2::882").unwrap();
            assert_eq!(classify_ipv6_address(&ula2.octets()), Ipv6AddressType::UniqueLocal);

            // Test Link-Local - fe80::/10
            let link_local = Ipv6Addr::from_str("fe80::1").unwrap();
            assert_eq!(classify_ipv6_address(&link_local.octets()), Ipv6AddressType::LinkLocal);
            assert_eq!(Ipv6AddressType::LinkLocal.network_scope(), "LAN");

            // Test Loopback - ::1
            let loopback = Ipv6Addr::from_str("::1").unwrap();
            assert_eq!(classify_ipv6_address(&loopback.octets()), Ipv6AddressType::Loopback);

            // Test Unspecified - ::
            let unspecified = Ipv6Addr::from_str("::").unwrap();
            assert_eq!(classify_ipv6_address(&unspecified.octets()), Ipv6AddressType::Unspecified);

            // Test Multicast - ff00::/8
            let multicast = Ipv6Addr::from_str("ff02::1").unwrap();
            assert_eq!(classify_ipv6_address(&multicast.octets()), Ipv6AddressType::Multicast);
        }

        #[test]
        fn test_format_ipv6_with_privacy() {
            use std::net::Ipv6Addr;
            use std::str::FromStr;

            // Test WAN address (GUA) - should be masked
            let gua = Ipv6Addr::from_str("2408:820c:a93d:44b0:e251:d8ff:fe11:b45c").unwrap();
            let formatted = format_ipv6_with_privacy(&gua.octets());
            assert!(formatted.contains("****"), "WAN address should contain asterisks");
            assert!(formatted.starts_with("2408:820c:"), "Should preserve first two segments");
            assert!(formatted.ends_with(":b45c"), "Should preserve last segment");

            // Test LAN address (ULA) - should be shown in full
            let ula = Ipv6Addr::from_str("fd37:c22a:b039:0:e251:d8ff:fe11:b45c").unwrap();
            let formatted_ula = format_ipv6_with_privacy(&ula.octets());
            assert!(!formatted_ula.contains("****"), "LAN address should not contain asterisks");
            assert!(formatted_ula.contains("fd37:c22a:b039"), "LAN address should be shown in full");

            // Test Link-Local - should be shown in full
            let link_local = Ipv6Addr::from_str("fe80::61c6:f554:bf4b:2e2d").unwrap();
            let formatted_ll = format_ipv6_with_privacy(&link_local.octets());
            assert!(
                !formatted_ll.contains("****"),
                "Link-Local address should not contain asterisks"
            );
        }
    }
}
