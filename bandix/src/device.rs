use crate::command::SubnetInfo;
use crate::storage::device_registry::DeviceRegistry;
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime};

/// 来自 ARP 表的设备信息
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpLine {
    pub mac: [u8; 6],
    pub ip: [u8; 4],
    pub ipv6_addresses: Vec<[u8; 16]>,
}

pub struct DeviceManager {
    /// 当前 ARP table snapshot (online devices)
    arp_table: Arc<Mutex<Vec<ArpLine>>>,
    /// Central device registry (maintains historical IP addresses)
    device_registry: Arc<DeviceRegistry>,
    /// 网络接口 name
    iface: String,
    /// Subnet information for the monitored interface
    subnet_info: SubnetInfo,
    /// 最后一个 refresh timestamp
    last_refresh: Arc<Mutex<SystemTime>>,
    /// Refresh interval (default: 30 seconds)
    refresh_interval: Duration,
    /// Shutdown flag for interruptible operations
    shutdown_flag: Option<Arc<AtomicBool>>,
}

impl DeviceManager {
    /// 创建a new device manager with interface and subnet info
    pub fn new(
        iface: String,
        subnet_info: SubnetInfo,
        device_registry: Arc<DeviceRegistry>,
        shutdown_flag: Option<Arc<AtomicBool>>,
    ) -> Self {
        Self {
            arp_table: Arc::new(Mutex::new(Vec::new())),
            device_registry,
            iface,
            subnet_info,
            last_refresh: Arc::new(Mutex::new(SystemTime::UNIX_EPOCH)),
            refresh_interval: Duration::from_secs(30),
            shutdown_flag,
        }
    }

    /// 获取mutable reference to device by MAC address
    fn get_device_by_mac_mut<'a>(
        devices: &'a mut Vec<ArpLine>,
        mac: &[u8; 6],
    ) -> Option<&'a mut ArpLine> {
        devices.iter_mut().find(|device| device.mac == *mac)
    }

    /// 获取reference to device registry
    pub fn get_registry(&self) -> Arc<DeviceRegistry> {
        Arc::clone(&self.device_registry)
    }

    pub fn load_initial_devices(&self, data_dir: &str) -> Result<()> {
        let registry_path = Path::new(data_dir).join("devices.json");

        if let Err(e) = self.device_registry.load_from_file(registry_path) {
            log::warn!("Failed to load device registry: {}", e);
        }

        log::info!(
            "Waiting for neighbor rediscovery and loading initial devices from ARP table..."
        );
        self.refresh_arp_cache()?;
        let arp_table = self.read_arp_table()?;
        let arp_table_clone = arp_table.clone();

        {
            let mut devices_list = self.arp_table.lock().unwrap();
            *devices_list = arp_table;

            let mut last_refresh = self.last_refresh.lock().unwrap();
            *last_refresh = SystemTime::now();
        }

        for arp_line in arp_table_clone.iter() {
            self.device_registry.register_device(
                arp_line.mac,
                Some(arp_line.ip),
                &arp_line.ipv6_addresses.clone(),
            );
        }

        log::info!(
            "Loaded {} valid devices from ARP table, total devices in registry: {}",
            arp_table_clone.len(),
            self.device_registry.device_count()
        );
        Ok(())
    }

    fn read_arp_table(&self) -> Result<Vec<ArpLine>> {
        let mut devices = Vec::new();

        let mut ipv6_neighbors: HashMap<[u8; 6], Vec<[u8; 16]>> = std::collections::HashMap::new();

        if let Ok(output) = std::process::Command::new("ip")
            .args(["-6", "neigh", "show", "dev", &self.iface])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                // Format: <ipv6> dev <iface> lladdr <mac> <state>
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    // Find "lladdr" keyword and parse MAC
                    if let Some(lladdr_pos) = parts.iter().position(|&x| x == "lladdr") {
                        if lladdr_pos + 1 < parts.len() {
                            if let Ok(mac) = crate::utils::network_utils::parse_mac_address(
                                parts[lladdr_pos + 1],
                            ) {
                                // Try to parse IPv6 address
                                if let Ok(ipv6) = parts[0].parse::<std::net::Ipv6Addr>() {
                                    ipv6_neighbors
                                        .entry(mac)
                                        .or_insert_with(Vec::new)
                                        .push(ipv6.octets());
                                }
                            }
                        }
                    }
                }
            }
        }

        // Read ARP table from /proc/net/arp
        let content = fs::read_to_string("/proc/net/arp")?;

        for line in content.lines().skip(1) {
            // Skip header line
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }

            // 解析IP address
            let ip = match parts[0].parse::<Ipv4Addr>() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            let ip_bytes = ip.octets();

            // 解析hardware type (should be 0x01 for Ethernet)
            let hw_type = parts[1];
            if hw_type != "0x1" && hw_type != "0x01" && hw_type != "1" {
                continue;
            }

            // 解析flags (ARP entry state)
            // Flags: 0x2 = incomplete, 0x0 = no entry, others = valid
            let flags = parts[2];
            if flags == "0x0" || flags == "0x00" || flags == "0" {
                // No ARP entry
                continue;
            }

            // 解析MAC address
            let mac_str = parts[3];
            if mac_str == "00:00:00:00:00:00" || mac_str == "<incomplete>" {
                // Invalid or incomplete entry
                continue;
            }

            let mac = match crate::utils::network_utils::parse_mac_address(mac_str) {
                Ok(mac) => mac,
                Err(_) => continue,
            };

            // 检查是否MAC is special (broadcast, multicast, etc.)
            if self::is_special_mac_address(&mac) {
                continue;
            }

            // 解析device name (interface) - last column in ARP table
            let device_name = parts[5];
            if device_name != self.iface {
                log::debug!(
                    "Skipping ARP entry for device {} (monitoring {})",
                    device_name,
                    self.iface
                );
                continue;
            }

            // 获取IPv6 addresses for this MAC
            let ipv6_addresses = ipv6_neighbors.get(&mac).cloned().unwrap_or_default();

            // 添加to devices list
            devices.push(ArpLine {
                mac,
                ip: ip_bytes,
                ipv6_addresses,
            });
        }

        // Also add local machine IP-MAC mappings from the monitored interface
        let interface_mac = self.subnet_info.interface_mac;
        let interface_ipv4 = self.subnet_info.interface_ip;
        let interface_ipv6_addresses = ipv6_neighbors
            .get(&interface_mac)
            .cloned()
            .unwrap_or_default();

        devices.push(ArpLine {
            mac: interface_mac,
            ip: interface_ipv4,
            ipv6_addresses: interface_ipv6_addresses,
        });

        Ok(devices)
    }

    /// Refresh ARP table cache
    /// 这should be called when eBPF detects a new MAC/IP combination
    /// 这method performs incremental update: adds new devices and updates existing ones,
    /// but does not remove devices that are temporarily offline
    pub fn refresh_arp_table(&self) -> Result<usize> {
        // Refresh ARP/neighbor cache before reading to remove stale entries
        self.refresh_arp_cache()?;

        let new_devices = self.read_arp_table()?;
        let mut added_count = 0;
        let mut updated_count = 0;

        // Incremental update: add new devices and update existing ones
        {
            let mut devices_list = self.arp_table.lock().unwrap();

            for device in new_devices.iter() {
                if let Some(existing_device) =
                    Self::get_device_by_mac_mut(&mut devices_list, &device.mac)
                {
                    // Device exists, update its information if changed
                    let mut changed = false;
                    if existing_device.ip != device.ip {
                        existing_device.ip = device.ip;
                        changed = true;
                    }
                    // 更新IPv6 addresses if changed
                    if existing_device.ipv6_addresses != device.ipv6_addresses {
                        existing_device.ipv6_addresses = device.ipv6_addresses.clone();
                        changed = true;
                    }
                    if changed {
                        updated_count += 1;
                    }
                } else {
                    // New device, add it
                    devices_list.push(device.clone());
                    added_count += 1;
                }

                // 更新registry with current ARP table data
                let ipv6_array: Vec<[u8; 16]> = device.ipv6_addresses.clone();
                self.device_registry
                    .register_device(device.mac, Some(device.ip), &ipv6_array);
            }
        }

        {
            let mut last_refresh = self.last_refresh.lock().unwrap();
            *last_refresh = SystemTime::now();
        }

        log::debug!(
            "Refreshed ARP table: added {} new devices, updated {} existing devices, total devices: {}",
            added_count,
            updated_count,
            self.device_count()
        );
        Ok(added_count + updated_count)
    }

    /// 检查是否a MAC address is in the device list
    #[allow(dead_code)]
    pub fn is_valid_mac(&self, mac: &[u8; 6]) -> bool {
        let devices = self.arp_table.lock().unwrap();
        devices.iter().any(|device| device.mac == *mac)
    }

    /// 检查是否a MAC-IP combination is valid
    /// Returns true if both MAC and IP are in the device list and match
    pub fn is_valid_device(&self, mac: &[u8; 6], ip: &[u8; 4]) -> bool {
        let devices = self.arp_table.lock().unwrap();
        devices
            .iter()
            .any(|device| device.mac == *mac && device.ip == *ip)
    }

    /// 获取device info by MAC address
    #[allow(dead_code)]
    pub fn get_device_by_mac(&self, mac: &[u8; 6]) -> Option<ArpLine> {
        let devices = self.arp_table.lock().unwrap();
        devices.iter().find(|device| device.mac == *mac).cloned()
    }

    /// 获取all devices
    #[allow(dead_code)]
    pub fn get_all_devices(&self) -> Vec<ArpLine> {
        let devices = self.arp_table.lock().unwrap();
        devices.clone()
    }

    /// 获取device count
    pub fn device_count(&self) -> usize {
        let devices = self.arp_table.lock().unwrap();
        devices.len()
    }

    /// 检查是否refresh is needed (based on refresh interval)
    pub fn should_refresh(&self) -> bool {
        let last_refresh = self.last_refresh.lock().unwrap();
        if let Ok(elapsed) = last_refresh.elapsed() {
            elapsed >= self.refresh_interval
        } else {
            // System time went backwards, refresh anyway
            true
        }
    }

    /// Force refresh ARP table if enough time has passed since last refresh
    /// Returns true if refresh was performed, false if skipped due to recent refresh
    pub fn force_refresh_if_needed(&self) -> Result<bool> {
        let should_refresh = {
            let last_refresh = self.last_refresh.lock().unwrap();
            if let Ok(elapsed) = last_refresh.elapsed() {
                elapsed >= self.refresh_interval
            } else {
                // System time went backwards, refresh anyway
                true
            }
        };

        if should_refresh {
            self.refresh_arp_table()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Refresh ARP/neighbor cache by flushing old entries
    fn refresh_arp_cache(&self) -> Result<()> {
        log::debug!("Refreshing ARP/neighbor cache by flushing old entries...");

        if let Err(e) = std::process::Command::new("ip")
            .args(["-s", "-s", "neigh", "flush", "all"])
            .output()
        {
            log::warn!("Failed to flush IPv4 neighbor cache: {}", e);
        }

        log::debug!("Waiting for neighbor rediscovery...");
        let wait_duration = Duration::from_secs(5);
        let check_interval = Duration::from_millis(100);
        let mut elapsed = Duration::ZERO;

        while elapsed < wait_duration {
            if let Some(ref shutdown_flag) = self.shutdown_flag {
                if shutdown_flag.load(Ordering::Relaxed) {
                    log::debug!("ARP cache refresh interrupted by shutdown signal");
                    return Err(anyhow::anyhow!("Operation interrupted by shutdown signal"));
                }
            }
            thread::sleep(check_interval);
            elapsed += check_interval;
        }

        log::debug!("ARP/neighbor cache refreshed");
        Ok(())
    }

    /// 设置refresh interval
    #[allow(dead_code)]
    pub fn set_refresh_interval(&mut self, interval: Duration) {
        self.refresh_interval = interval;
    }
}

// 注意：DeviceManager 不再实现 Default，因为它需要 hostname_bindings

/// 检查 MAC 地址是否特殊（广播、多播等）
fn is_special_mac_address(mac: &[u8; 6]) -> bool {
    // Broadcast address FF:FF:FF:FF:FF:FF
    if mac == &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] {
        return true;
    }

    // Multicast address (lowest bit of first byte is 1)
    if (mac[0] & 0x01) == 0x01 {
        return true;
    }

    // Zero address 00:00:00:00:00:00
    if mac == &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00] {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_special_mac_address() {
        assert!(is_special_mac_address(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        ]));
        assert!(is_special_mac_address(&[
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00
        ]));
        assert!(is_special_mac_address(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ]));
        assert!(!is_special_mac_address(&[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55
        ]));
    }
}
