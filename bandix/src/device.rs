use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

/// Subnet information for interface reuse
#[derive(Debug, Clone)]
pub struct SubnetInfo {
    pub interface_ip: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub interface_mac: [u8; 6],
    pub ipv6_addresses: Vec<([u8; 16], u8)>,
}

/// Device information from ARP table
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub mac: [u8; 6],
    pub ip: [u8; 4],                   // IPv4 address
    pub ipv6_addresses: Vec<[u8; 16]>, // IPv6 addresses (can have multiple)
}

/// Device manager that maintains a list of valid devices from ARP table
/// Only includes devices with valid ARP entries (REACHABLE, STALE, etc.)
/// Excludes incomplete or invalid entries
pub struct DeviceManager {
    /// Mapping from MAC address to DeviceInfo
    devices: Arc<Mutex<HashMap<[u8; 6], DeviceInfo>>>,
    /// Network interface name
    iface: String,
    /// Subnet information for the monitored interface
    subnet_info: SubnetInfo,
    /// Last refresh timestamp
    last_refresh: Arc<Mutex<SystemTime>>,
    /// Refresh interval (default: 30 seconds)
    refresh_interval: Duration,
}

impl DeviceManager {
    /// Create a new device manager with interface and subnet info
    pub fn new(iface: String, subnet_info: SubnetInfo) -> Self {
        Self {
            devices: Arc::new(Mutex::new(HashMap::new())),
            iface,
            subnet_info,
            last_refresh: Arc::new(Mutex::new(SystemTime::UNIX_EPOCH)),
            refresh_interval: Duration::from_secs(30),
        }
    }

    /// Load devices from ARP table at startup
    /// Only loads valid entries (excludes incomplete and invalid entries)
    pub fn load_initial_devices(&self) -> Result<usize> {
        // Refresh ARP/neighbor cache before reading to remove stale entries
        self.refresh_arp_cache()?;

        let devices = self.read_arp_table()?;
        let count = devices.len();

        // Update internal cache
        {
            let mut devices_map = self.devices.lock().unwrap();
            devices_map.clear();

            for device in devices.iter() {
                devices_map.insert(device.mac, device.clone());
            }
        }

        {
            let mut last_refresh = self.last_refresh.lock().unwrap();
            *last_refresh = SystemTime::now();
        }

        log::info!("Loaded {} valid devices from ARP table", count);
        Ok(count)
    }

    /// Read ARP table from /proc/net/arp
    /// Only includes valid entries (excludes incomplete, 00:00:00:00:00:00, etc.)
    fn read_arp_table(&self) -> Result<Vec<DeviceInfo>> {
        let mut devices = Vec::new();

        // Get IPv6 neighbor table (MAC -> IPv6 addresses) filtered by interface
        let mut ipv6_neighbors = std::collections::HashMap::new();

        // Filter IPv6 neighbors by our interface
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

            // Parse IP address
            let ip = match parts[0].parse::<Ipv4Addr>() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            let ip_bytes = ip.octets();

            // Parse hardware type (should be 0x01 for Ethernet)
            let hw_type = parts[1];
            if hw_type != "0x1" && hw_type != "0x01" && hw_type != "1" {
                continue;
            }

            // Parse flags (ARP entry state)
            // Flags: 0x2 = incomplete, 0x0 = no entry, others = valid
            let flags = parts[2];
            if flags == "0x0" || flags == "0x00" || flags == "0" {
                // No ARP entry
                continue;
            }

            // Parse MAC address
            let mac_str = parts[3];
            if mac_str == "00:00:00:00:00:00" || mac_str == "<incomplete>" {
                // Invalid or incomplete entry
                continue;
            }

            let mac = match crate::utils::network_utils::parse_mac_address(mac_str) {
                Ok(mac) => mac,
                Err(_) => continue,
            };

            // Check if MAC is special (broadcast, multicast, etc.)
            if self::is_special_mac_address(&mac) {
                continue;
            }

            // Parse device name (interface) - last column in ARP table
            let device_name = parts[5];
            if device_name != self.iface {
                log::debug!(
                    "Skipping ARP entry for device {} (monitoring {})",
                    device_name,
                    self.iface
                );
                continue;
            }

            // Get IPv6 addresses for this MAC
            let ipv6_addresses = ipv6_neighbors.get(&mac).cloned().unwrap_or_default();

            // Add to devices list
            devices.push(DeviceInfo {
                mac,
                ip: ip_bytes,
                ipv6_addresses,
            });
        }

        // Also add local machine IP-MAC mappings from the monitored interface
        // This ensures that connections from/to the local machine are also counted
        let mac = self.subnet_info.interface_mac;
        let ip_bytes = self.subnet_info.interface_ip;

        // Skip loopback addresses (127.x.x.x)
        if ip_bytes[0] != 127 {
            // Check if this device is already in the list
            let mut found = false;
            for device in devices.iter() {
                if device.mac == mac {
                    found = true;
                    break;
                }
            }

            if !found {
                // Get IPv6 addresses for this MAC
                let ipv6_addresses = ipv6_neighbors
                    .get(&mac)
                    .cloned()
                    .unwrap_or_default();

                devices.push(DeviceInfo {
                    mac,
                    ip: ip_bytes,
                    ipv6_addresses,
                });
            }
        }

        Ok(devices)
    }

    /// Refresh ARP table cache
    /// This should be called when eBPF detects a new MAC/IP combination
    /// This method performs incremental update: adds new devices and updates existing ones,
    /// but does not remove devices that are temporarily offline
    pub fn refresh_arp_table(&self) -> Result<usize> {
        // Refresh ARP/neighbor cache before reading to remove stale entries
        self.refresh_arp_cache()?;

        let new_devices = self.read_arp_table()?;
        let mut added_count = 0;
        let mut updated_count = 0;

        // Incremental update: add new devices and update existing ones
        {
            let mut devices_map = self.devices.lock().unwrap();

            for device in new_devices.iter() {
                if let Some(existing_device) = devices_map.get_mut(&device.mac) {
                    // Device exists, update its information if changed
                    let mut changed = false;
                    if existing_device.ip != device.ip {
                        existing_device.ip = device.ip;
                        changed = true;
                    }
                    // Update IPv6 addresses if changed
                    if existing_device.ipv6_addresses != device.ipv6_addresses {
                        existing_device.ipv6_addresses = device.ipv6_addresses.clone();
                        changed = true;
                    }
                    if changed {
                        updated_count += 1;
                    }
                } else {
                    // New device, add it
                    devices_map.insert(device.mac, device.clone());
                    added_count += 1;
                }
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

    /// Check if a MAC address is in the device list
    #[allow(dead_code)]
    pub fn is_valid_mac(&self, mac: &[u8; 6]) -> bool {
        let devices = self.devices.lock().unwrap();
        devices.contains_key(mac)
    }

    /// Check if a MAC-IP combination is valid
    /// Returns true if both MAC and IP are in the device list and match
    pub fn is_valid_device(&self, mac: &[u8; 6], ip: &[u8; 4]) -> bool {
        let devices = self.devices.lock().unwrap();
        if let Some(device) = devices.get(mac) {
            device.ip == *ip
        } else {
            false
        }
    }

    /// Get device info by MAC address
    #[allow(dead_code)]
    pub fn get_device_by_mac(&self, mac: &[u8; 6]) -> Option<DeviceInfo> {
        let devices = self.devices.lock().unwrap();
        devices.get(mac).cloned()
    }

    /// Get all devices
    #[allow(dead_code)]
    pub fn get_all_devices(&self) -> Vec<DeviceInfo> {
        let devices = self.devices.lock().unwrap();
        devices.values().cloned().collect()
    }

    /// Get device count
    pub fn device_count(&self) -> usize {
        let devices = self.devices.lock().unwrap();
        devices.len()
    }

    /// Check if refresh is needed (based on refresh interval)
    pub fn should_refresh(&self) -> bool {
        let last_refresh = self.last_refresh.lock().unwrap();
        if let Ok(elapsed) = last_refresh.elapsed() {
            elapsed >= self.refresh_interval
        } else {
            // System time went backwards, refresh anyway
            true
        }
    }

    /// Refresh ARP/neighbor cache by flushing old entries
    /// This forces the system to rediscover neighbors and removes stale entries
    fn refresh_arp_cache(&self) -> Result<()> {
        log::debug!("Refreshing ARP/neighbor cache by flushing old entries...");

        // Flush all neighbor cache entries (both IPv4 and IPv6)
        // Note: This will temporarily disrupt network connectivity until neighbors are rediscovered
        if let Err(e) = std::process::Command::new("ip")
            .args(["-s", "-s", "neigh", "flush", "all"])
            .output()
        {
            log::warn!("Failed to flush IPv4 neighbor cache: {}", e);
        }

        // Wait for neighbors to be rediscovered
        // ARP requests are typically sent immediately, but we give some time for responses
        log::debug!("Waiting for neighbor rediscovery...");
        thread::sleep(Duration::from_secs(5));

        log::debug!("ARP/neighbor cache refreshed");
        Ok(())
    }

    /// Set refresh interval
    #[allow(dead_code)]
    pub fn set_refresh_interval(&mut self, interval: Duration) {
        self.refresh_interval = interval;
    }
}

// Note: DeviceManager no longer implements Default because it requires hostname_bindings

/// Check if MAC address is special (broadcast, multicast, etc.)
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
