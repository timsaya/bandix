use crate::command::SubnetInfo;
use anyhow::Result;
use log;
use std::collections::{HashMap, HashSet};
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
        self.current_ipv4
            .or_else(|| self.historical_ipv4.last().copied())
            .unwrap_or([0, 0, 0, 0])
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
                        let shutdown_notify_clone = shutdown_notify.clone();
                        tokio::select! {
                            result = self.refresh_devices(shutdown_notify_clone) => {
                                if let Err(e) = result {
                                    log::warn!("Failed to refresh devices: {}", e);
                                }
                            }
                            _ = shutdown_notify.notified() => {
                                log::info!("Device refresh cancelled by shutdown signal");
                                break;
                            }
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

    fn read_neighbor_table(&self) -> Result<Vec<([u8; 6], Option<[u8; 4]>, Vec<[u8; 16]>)>> {
        let mut devices_map: HashMap<[u8; 6], (Option<[u8; 4]>, Vec<[u8; 16]>)> = HashMap::new();

        // 读取 IPv4 邻居表
        if let Ok(output) = std::process::Command::new("ip")
            .args(["-4", "neigh", "show", "dev", &self.iface])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 {
                    continue;
                }

                // 检查邻居状态，只保留有效状态
                let state = parts.get(parts.len() - 1).unwrap_or(&"");
                if matches!(
                    *state,
                    "FAILED" | "NOARP" | "INCOMPLETE" | "INVALID"
                ) {
                    continue;
                }

                // 解析 IPv4 地址
                let ipv4 = match parts[0].parse::<std::net::Ipv4Addr>() {
                    Ok(ip) => ip,
                    Err(_) => continue,
                };

                // 查找 MAC 地址 (lladdr)
                if let Some(lladdr_pos) = parts.iter().position(|&x| x == "lladdr") {
                    if lladdr_pos + 1 < parts.len() {
                        if let Ok(mac) = crate::utils::network_utils::parse_mac_address(
                            parts[lladdr_pos + 1],
                        ) {
                            if Self::is_special_mac_address(&mac) {
                                continue;
                            }

                            devices_map
                                .entry(mac)
                                .or_insert_with(|| (None, Vec::new()))
                                .0 = Some(ipv4.octets());
                        }
                    }
                }
            }
        }

        // 读取 IPv6 邻居表
        if let Ok(output) = std::process::Command::new("ip")
            .args(["-6", "neigh", "show", "dev", &self.iface])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 {
                    continue;
                }

                // 检查邻居状态，只保留有效状态
                let state = parts.get(parts.len() - 1).unwrap_or(&"");
                if matches!(
                    *state,
                    "FAILED" | "NOARP" | "INCOMPLETE" | "INVALID"
                ) {
                    continue;
                }

                // 解析 IPv6 地址
                let ipv6 = match parts[0].parse::<std::net::Ipv6Addr>() {
                    Ok(ip) => ip,
                    Err(_) => continue,
                };

                // 查找 MAC 地址 (lladdr)
                if let Some(lladdr_pos) = parts.iter().position(|&x| x == "lladdr") {
                    if lladdr_pos + 1 < parts.len() {
                        if let Ok(mac) = crate::utils::network_utils::parse_mac_address(
                            parts[lladdr_pos + 1],
                        ) {
                            if Self::is_special_mac_address(&mac) {
                                continue;
                            }

                            devices_map
                                .entry(mac)
                                .or_insert_with(|| (None, Vec::new()))
                                .1
                                .push(ipv6.octets());
                        }
                    }
                }
            }
        }

        // 添加接口本身
        let interface_mac = self.subnet_info.interface_mac;
        let interface_ipv4 = self.subnet_info.interface_ip;
        let interface_ipv6_addresses = devices_map
            .get(&interface_mac)
            .map(|(_, ipv6)| ipv6.clone())
            .unwrap_or_default();

        devices_map.insert(
            interface_mac,
            (Some(interface_ipv4), interface_ipv6_addresses),
        );

        // 转换为向量格式
        let devices: Vec<([u8; 6], Option<[u8; 4]>, Vec<[u8; 16]>)> = devices_map
            .into_iter()
            .map(|(mac, (ipv4, ipv6))| (mac, ipv4, ipv6))
            .collect();

        Ok(devices)
    }

    pub async fn refresh_devices(&self, _shutdown_notify: Arc<tokio::sync::Notify>) -> Result<()> {
        log::debug!("Starting device refresh for interface: {}", self.iface);

        let neighbor_devices = self.read_neighbor_table()?;
        log::debug!("Found {} devices in neighbor table", neighbor_devices.len());

        let hostname_bindings = self.hostname_bindings.lock().unwrap();

        let mut devices = self.devices.lock().unwrap();
        let mut updated_count = 0;
        let mut new_count = 0;

        for (mac, ipv4, ipv6_list) in neighbor_devices {
            let is_new = !devices.contains_key(&mac);
            let device = devices
                .entry(mac)
                .or_insert_with(|| UnifiedDevice::new(mac));

            if is_new {
                new_count += 1;
            } else {
                updated_count += 1;
            }

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

        log::debug!(
            "Device refresh completed: {} total devices ({} new, {} updated)",
            devices.len(),
            new_count,
            updated_count
        );

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
        devices
            .iter()
            .map(|(mac, device)| (*mac, device.clone()))
            .collect()
    }

    /// 添加离线设备（从 ring 文件恢复的设备）
    /// 如果设备已存在，则只更新主机名；如果不存在，则创建新设备
    pub fn add_offline_device(&self, mac: [u8; 6], ipv4: Option<[u8; 4]>) {
        let hostname_bindings = self.hostname_bindings.lock().unwrap();
        let mut devices = self.devices.lock().unwrap();

        let device = devices
            .entry(mac)
            .or_insert_with(|| UnifiedDevice::new(mac));

        if let Some(hostname) = hostname_bindings.get(&mac) {
            device.update_hostname(hostname.clone());
        }

        if let Some(ip) = ipv4 {
            if device.current_ipv4.is_none() && !device.historical_ipv4.contains(&ip) {
                device.historical_ipv4.push(ip);
            }
        }
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
