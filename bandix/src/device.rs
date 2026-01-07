use crate::command::SubnetInfo;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 统一的设备结构，包含设备信息和流量统计
#[derive(Debug, Clone)]
pub struct UnifiedDevice {
    pub mac: [u8; 6],
    
    // 设备基本信息
    pub current_ipv4: Option<[u8; 4]>,
    pub historical_ipv4: Vec<[u8; 4]>,
    pub current_ipv6: Vec<[u8; 16]>,
    pub historical_ipv6: Vec<[u8; 16]>,
    pub hostname: String,
    
    // 流量统计数据（从 DeviceTrafficStats 拆分而来）
    // 速率限制
    pub wan_rx_rate_limit: u64,
    pub wan_tx_rate_limit: u64,
    
    // LAN 流量
    pub lan_rx_bytes: u64,
    pub lan_tx_bytes: u64,
    pub lan_rx_rate: u64,
    pub lan_tx_rate: u64,
    
    // WAN 流量
    pub wan_rx_bytes: u64,
    pub wan_tx_bytes: u64,
    pub wan_rx_rate: u64,
    pub wan_tx_rate: u64,
    
    // 上次采样值（用于计算增量）
    pub lan_last_rx_bytes: u64,
    pub lan_last_tx_bytes: u64,
    pub wan_last_rx_bytes: u64,
    pub wan_last_tx_bytes: u64,
    
    // 设备最后在线时间（前后2次流量对比，如果有差异，说明在线）
    pub last_online_ts: u64,

    // 最后采样时间，即从 eBPF 中获取流量的时间
    pub last_sample_ts: u64,
}

impl UnifiedDevice {
    pub fn new(mac: [u8; 6]) -> Self {
        Self {
            mac,
            current_ipv4: None,
            historical_ipv4: Vec::new(),
            current_ipv6: Vec::new(),
            historical_ipv6: Vec::new(),
            hostname: String::new(),
            wan_rx_rate_limit: 0,
            wan_tx_rate_limit: 0,
            lan_rx_bytes: 0,
            lan_tx_bytes: 0,
            lan_rx_rate: 0,
            lan_tx_rate: 0,
            wan_rx_bytes: 0,
            wan_tx_bytes: 0,
            wan_rx_rate: 0,
            wan_tx_rate: 0,
            lan_last_rx_bytes: 0,
            lan_last_tx_bytes: 0,
            wan_last_rx_bytes: 0,
            wan_last_tx_bytes: 0,
            last_online_ts: 0,
            last_sample_ts: 0,
        }
    }
    
    /// 计算总接收字节数（LAN + WAN）
    pub fn total_rx_bytes(&self) -> u64 {
        self.lan_rx_bytes + self.wan_rx_bytes
    }
    
    /// 计算总发送字节数（LAN + WAN）
    pub fn total_tx_bytes(&self) -> u64 {
        self.lan_tx_bytes + self.wan_tx_bytes
    }
    
    /// 计算总接收速率（LAN + WAN）
    pub fn total_rx_rate(&self) -> u64 {
        self.lan_rx_rate + self.wan_rx_rate
    }
    
    /// 计算总发送速率（LAN + WAN）
    pub fn total_tx_rate(&self) -> u64 {
        self.lan_tx_rate + self.wan_tx_rate
    }

    pub fn update_ipv4(&mut self, ip: [u8; 4]) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if let Some(current) = self.current_ipv4 {
            if current != ip {
                if !self.historical_ipv4.contains(&current) {
                    self.historical_ipv4.push(current);
                }
                self.current_ipv4 = Some(ip);
            }
        } else {
            self.current_ipv4 = Some(ip);
        }
        
        self.last_online_ts = now;
    }

    pub fn update_ipv6(&mut self, ipv6_list: &[[u8; 16]]) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let new_set: HashSet<[u8; 16]> = ipv6_list.iter().copied().collect();

        for old_ipv6 in &self.current_ipv6 {
            if !new_set.contains(old_ipv6) && !self.historical_ipv6.contains(old_ipv6) {
                self.historical_ipv6.push(*old_ipv6);
            }
        }

        self.current_ipv6 = ipv6_list.to_vec();
        
        self.last_online_ts = now;
    }

    pub fn update_hostname(&mut self, hostname: String) {
        if !hostname.is_empty() {
            self.hostname = hostname;
        }
    }

    pub fn touch(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.last_online_ts = now;
    }
    
    pub fn get_current_ipv4(&self) -> [u8; 4] {
        self.current_ipv4.unwrap_or([0, 0, 0, 0])
    }
    
    pub fn get_all_ipv6(&self) -> Vec<[u8; 16]> {
        self.current_ipv6.clone()
    }
}

pub struct DeviceManager {
    devices: Arc<Mutex<HashMap<[u8; 6], UnifiedDevice>>>,
    iface: String,
    subnet_info: SubnetInfo,
    hostname_bindings: Arc<Mutex<HashMap<[u8; 6], String>>>,
}

impl DeviceManager {
    pub fn new(
        iface: String,
        subnet_info: SubnetInfo,
        hostname_bindings: Arc<Mutex<HashMap<[u8; 6], String>>>,
    ) -> Self {
        Self {
            devices: Arc::new(Mutex::new(HashMap::new())),
            iface,
            subnet_info,
            hostname_bindings,
        }
    }

    pub fn start_background_task(
        self: Arc<Self>,
        refresh_interval: Duration,
        shutdown_notify: Arc<tokio::sync::Notify>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(refresh_interval);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = self.refresh_devices() {
                            log::warn!("Failed to refresh devices: {}", e);
                        }
                    }
                    _ = shutdown_notify.notified() => {
                        log::info!("Device manager background task received shutdown signal, stopping...");
                        break;
                    }
                }
            }
        })
    }

    fn read_arp_table(&self) -> Result<Vec<( [u8; 6], Option<[u8; 4]>, Vec<[u8; 16]> )>> {
        let mut devices = Vec::new();
        let mut ipv6_neighbors: HashMap<[u8; 6], Vec<[u8; 16]>> = HashMap::new();

        if let Ok(output) = std::process::Command::new("ip")
            .args(["-6", "neigh", "show", "dev", &self.iface])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    if let Some(lladdr_pos) = parts.iter().position(|&x| x == "lladdr") {
                        if lladdr_pos + 1 < parts.len() {
                            if let Ok(mac) = crate::utils::network_utils::parse_mac_address(
                                parts[lladdr_pos + 1],
                            ) {
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

        let content = fs::read_to_string("/proc/net/arp")?;

        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }

            let ip = match parts[0].parse::<Ipv4Addr>() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            let ip_bytes = ip.octets();

            let hw_type = parts[1];
            if hw_type != "0x1" && hw_type != "0x01" && hw_type != "1" {
                continue;
            }

            let flags = parts[2];
            if flags == "0x0" || flags == "0x00" || flags == "0" {
                continue;
            }

            let mac_str = parts[3];
            if mac_str == "00:00:00:00:00:00" || mac_str == "<incomplete>" {
                continue;
            }

            let mac = match crate::utils::network_utils::parse_mac_address(mac_str) {
                Ok(mac) => mac,
                Err(_) => continue,
            };

            if Self::is_special_mac_address(&mac) {
                continue;
            }

            let device_name = parts[5];
            if device_name != self.iface {
                continue;
            }

            let ipv6_addresses = ipv6_neighbors.get(&mac).cloned().unwrap_or_default();

            devices.push((mac, Some(ip_bytes), ipv6_addresses));
        }

        let interface_mac = self.subnet_info.interface_mac;
        let interface_ipv4 = self.subnet_info.interface_ip;
        let interface_ipv6_addresses = ipv6_neighbors
            .get(&interface_mac)
            .cloned()
            .unwrap_or_default();

        devices.push((interface_mac, Some(interface_ipv4), interface_ipv6_addresses));

        Ok(devices)
    }

    pub fn refresh_devices(&self) -> Result<()> {
        let arp_devices = self.read_arp_table()?;
        let hostname_bindings = self.hostname_bindings.lock().unwrap();

        let mut devices = self.devices.lock().unwrap();

        for (mac, ipv4, ipv6_list) in arp_devices {
            let device = devices.entry(mac).or_insert_with(|| UnifiedDevice::new(mac));

            if let Some(ip) = ipv4 {
                device.update_ipv4(ip);
            }

            if !ipv6_list.is_empty() {
                device.update_ipv6(&ipv6_list);
            }

            if let Some(hostname) = hostname_bindings.get(&mac) {
                device.update_hostname(hostname.clone());
            }

            device.touch();
        }

        Ok(())
    }

    pub fn get_device_by_mac(&self, mac: &[u8; 6]) -> Option<UnifiedDevice> {
        let devices = self.devices.lock().unwrap();
        devices.get(mac).cloned()
    }

    pub fn get_all_devices(&self) -> Vec<UnifiedDevice> {
        let devices = self.devices.lock().unwrap();
        devices.values().cloned().collect()
    }
    
    pub fn update_device_traffic_stats<F>(&self, mac: &[u8; 6], updater: F) -> Result<()>
    where
        F: FnOnce(&mut UnifiedDevice),
    {
        let mut devices = self.devices.lock().unwrap();
        if let Some(device) = devices.get_mut(mac) {
            updater(device);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Device not found: {:?}", mac))
        }
    }
    
    pub fn get_all_devices_for_snapshot(&self) -> Vec<([u8; 6], UnifiedDevice)> {
        let devices = self.devices.lock().unwrap();
        devices.iter().map(|(mac, device)| (*mac, device.clone())).collect()
    }

    /// 添加离线设备（从 ring 文件恢复的设备）
    /// 如果设备已存在，则只更新主机名；如果不存在，则创建新设备
    pub fn add_offline_device(&self, mac: [u8; 6]) {
        let hostname_bindings = self.hostname_bindings.lock().unwrap();
        let mut devices = self.devices.lock().unwrap();
        
        let device = devices.entry(mac).or_insert_with(|| UnifiedDevice::new(mac));
        
        if let Some(hostname) = hostname_bindings.get(&mac) {
            device.update_hostname(hostname.clone());
        }
        
        // 不更新 last_seen_ts，保持设备为离线状态
    }

    fn is_special_mac_address(mac: &[u8; 6]) -> bool {
        if mac == &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] {
            return true;
        }

        if (mac[0] & 0x01) == 0x01 {
            return true;
        }

        if mac == &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00] {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_special_mac_address() {
        assert!(DeviceManager::is_special_mac_address(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        ]));
        assert!(DeviceManager::is_special_mac_address(&[
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00
        ]));
        assert!(DeviceManager::is_special_mac_address(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ]));
        assert!(!DeviceManager::is_special_mac_address(&[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55
        ]));
    }
}
