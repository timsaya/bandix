use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct DeviceRecord {
    pub mac: [u8; 6],
    pub current_ipv4: Option<[u8; 4]>,
    pub historical_ipv4: Vec<[u8; 4]>,
    pub current_ipv6: Vec<[u8; 16]>,
    pub historical_ipv6: Vec<[u8; 16]>,
    pub first_seen_ts: u64,
    pub last_seen_ts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeviceRecordJson {
    mac: String,
    current_ipv4: Option<String>,
    historical_ipv4: Vec<String>,
    current_ipv6: Vec<String>,
    historical_ipv6: Vec<String>,
    first_seen_ts: u64,
    last_seen_ts: u64,
}

impl From<&DeviceRecord> for DeviceRecordJson {
    fn from(record: &DeviceRecord) -> Self {
        Self {
            mac: crate::utils::format_utils::format_mac(&record.mac),
            current_ipv4: record
                .current_ipv4
                .map(|ip| crate::utils::format_utils::format_ip(&ip)),
            historical_ipv4: record
                .historical_ipv4
                .iter()
                .map(|ip| crate::utils::format_utils::format_ip(ip))
                .collect(),
            current_ipv6: record
                .current_ipv6
                .iter()
                .map(|ip| crate::utils::network_utils::format_ipv6(ip))
                .collect(),
            historical_ipv6: record
                .historical_ipv6
                .iter()
                .map(|ip| crate::utils::network_utils::format_ipv6(ip))
                .collect(),
            first_seen_ts: record.first_seen_ts,
            last_seen_ts: record.last_seen_ts,
        }
    }
}

fn parse_ipv4_string(ip_str: &str) -> Result<[u8; 4]> {
    let parts: Vec<&str> = ip_str.split('.').collect();
    if parts.len() == 4 {
        Ok([
            parts[0]
                .parse::<u8>()
                .map_err(|e| anyhow::anyhow!("Invalid IPv4 octet '{}': {}", parts[0], e))?,
            parts[1]
                .parse::<u8>()
                .map_err(|e| anyhow::anyhow!("Invalid IPv4 octet '{}': {}", parts[1], e))?,
            parts[2]
                .parse::<u8>()
                .map_err(|e| anyhow::anyhow!("Invalid IPv4 octet '{}': {}", parts[2], e))?,
            parts[3]
                .parse::<u8>()
                .map_err(|e| anyhow::anyhow!("Invalid IPv4 octet '{}': {}", parts[3], e))?,
        ])
    } else {
        Err(anyhow::anyhow!("Invalid IPv4 format: {}", ip_str))
    }
}

fn parse_ipv6_string(ip_str: &str) -> Result<[u8; 16]> {
    let ipv6 = ip_str
        .parse::<std::net::Ipv6Addr>()
        .map_err(|e| anyhow::anyhow!("Invalid IPv6 format {}: {}", ip_str, e))?;
    Ok(ipv6.octets())
}

impl TryFrom<DeviceRecordJson> for DeviceRecord {
    type Error = anyhow::Error;

    fn try_from(json: DeviceRecordJson) -> Result<Self> {
        let mac = crate::utils::network_utils::parse_mac_address(&json.mac)?;

        let current_ipv4 = json
            .current_ipv4
            .map(|ip_str| parse_ipv4_string(&ip_str))
            .transpose()?;

        let historical_ipv4: Result<Vec<[u8; 4]>> = json
            .historical_ipv4
            .iter()
            .map(|ip_str| parse_ipv4_string(ip_str))
            .collect();

        let current_ipv6: Result<Vec<[u8; 16]>> = json
            .current_ipv6
            .iter()
            .map(|ip_str| parse_ipv6_string(ip_str))
            .collect();

        let historical_ipv6: Result<Vec<[u8; 16]>> = json
            .historical_ipv6
            .iter()
            .map(|ip_str| parse_ipv6_string(ip_str))
            .collect();

        Ok(Self {
            mac,
            current_ipv4,
            historical_ipv4: historical_ipv4?,
            current_ipv6: current_ipv6?,
            historical_ipv6: historical_ipv6?,
            first_seen_ts: json.first_seen_ts,
            last_seen_ts: json.last_seen_ts,
        })
    }
}

impl DeviceRecord {
    pub fn new(mac: [u8; 6]) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            mac,
            current_ipv4: None,
            historical_ipv4: Vec::new(),
            current_ipv6: Vec::new(),
            historical_ipv6: Vec::new(),
            first_seen_ts: now,
            last_seen_ts: now,
        }
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
        self.last_seen_ts = now;
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
        self.last_seen_ts = now;
    }

    pub fn touch(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.last_seen_ts = now;
    }
}

pub struct DeviceRegistry {
    devices: Arc<Mutex<Vec<DeviceRecord>>>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self {
            devices: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn get_device_by_mac_mut<'a>(
        devices: &'a mut Vec<DeviceRecord>,
        mac: &[u8; 6],
    ) -> Option<&'a mut DeviceRecord> {
        devices.iter_mut().find(|record| record.mac == *mac)
    }

    pub fn register_device(&self, mac: [u8; 6], ipv4: Option<[u8; 4]>, ipv6_list: &[[u8; 16]]) {
        let mut devices = self.devices.lock().unwrap();

        if let Some(record) = Self::get_device_by_mac_mut(&mut devices, &mac) {
            if let Some(ip) = ipv4 {
                record.update_ipv4(ip);
            }
            if !ipv6_list.is_empty() {
                record.update_ipv6(ipv6_list);
            }
        } else {
            let mut record = DeviceRecord::new(mac);
            if let Some(ip) = ipv4 {
                record.update_ipv4(ip);
            }
            if !ipv6_list.is_empty() {
                record.update_ipv6(ipv6_list);
            }
            devices.push(record);
        }
    }

    pub fn update_device_ipv4(&self, mac: [u8; 6], ipv4: [u8; 4]) {
        let mut devices = self.devices.lock().unwrap();
        if let Some(record) = Self::get_device_by_mac_mut(&mut devices, &mac) {
            record.update_ipv4(ipv4);
        } else {
            let mut record = DeviceRecord::new(mac);
            record.update_ipv4(ipv4);
            devices.push(record);
        }
    }

    pub fn update_device_ipv6(&self, mac: [u8; 6], ipv6_list: &[[u8; 16]]) {
        let mut devices = self.devices.lock().unwrap();
        if let Some(record) = Self::get_device_by_mac_mut(&mut devices, &mac) {
            record.update_ipv6(ipv6_list);
        } else {
            let mut record = DeviceRecord::new(mac);
            record.update_ipv6(ipv6_list);
            devices.push(record);
        }
    }

    pub fn touch_device(&self, mac: [u8; 6]) {
        let mut devices = self.devices.lock().unwrap();
        if let Some(record) = Self::get_device_by_mac_mut(&mut devices, &mac) {
            record.touch();
        }
    }

    pub fn get_device(&self, mac: &[u8; 6]) -> Option<DeviceRecord> {
        let devices = self.devices.lock().unwrap();
        devices.iter().find(|record| record.mac == *mac).cloned()
    }

    pub fn get_all_devices(&self) -> Vec<DeviceRecord> {
        let devices = self.devices.lock().unwrap();
        devices.clone()
    }

    pub fn get_all_macs(&self) -> Vec<[u8; 6]> {
        let devices = self.devices.lock().unwrap();
        devices.iter().map(|record| record.mac).collect()
    }

    pub fn device_count(&self) -> usize {
        let devices = self.devices.lock().unwrap();
        devices.len()
    }

    pub fn load_from_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(&path)?;

        if let Ok(json_records) = serde_json::from_str::<Vec<DeviceRecordJson>>(&content) {
            let mut devices = self.devices.lock().unwrap();
            let mut loaded_count = 0;
            for json_record in json_records {
                match DeviceRecord::try_from(json_record) {
                    Ok(record) => {
                        if Self::get_device_by_mac_mut(&mut devices, &record.mac).is_none() {
                            devices.push(record);
                            loaded_count += 1;
                        }
                    }
                    Err(e) => {
                        log::warn!("Failed to parse device record: {}, skipping", e);
                    }
                }
            }
            log::info!(
                "Loaded {} devices from registry file (new format)",
                loaded_count
            );
            return Ok(());
        }

        Err(anyhow::anyhow!(
            "Failed to parse device registry file: invalid format"
        ))
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let devices = self.devices.lock().unwrap();
        let json_records: Vec<DeviceRecordJson> =
            devices.iter().map(|r| DeviceRecordJson::from(r)).collect();
        let content = serde_json::to_string_pretty(&json_records)
            .map_err(|e| anyhow::anyhow!("Failed to serialize device registry: {}", e))?;

        fs::write(&path, content)?;
        log::debug!("Saved {} devices to registry file", json_records.len());
        Ok(())
    }

    pub fn get_inner(&self) -> Arc<Mutex<Vec<DeviceRecord>>> {
        Arc::clone(&self.devices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_record_ipv4_history() {
        let mut record = DeviceRecord::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        record.update_ipv4([192, 168, 1, 100]);
        assert_eq!(record.current_ipv4, Some([192, 168, 1, 100]));
        assert_eq!(record.historical_ipv4.len(), 0);

        record.update_ipv4([192, 168, 1, 101]);
        assert_eq!(record.current_ipv4, Some([192, 168, 1, 101]));
        assert_eq!(record.historical_ipv4.len(), 1);
        assert!(record.historical_ipv4.contains(&[192, 168, 1, 100]));

        record.update_ipv4([192, 168, 1, 101]);
        assert_eq!(record.historical_ipv4.len(), 1);
    }

    #[test]
    fn test_device_record_ipv6_history() {
        let mut record = DeviceRecord::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let ipv6_1 = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let ipv6_2 = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
        ];
        let ipv6_3 = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03,
        ];

        record.update_ipv6(&[ipv6_1, ipv6_2]);
        assert_eq!(record.current_ipv6.len(), 2);
        assert_eq!(record.historical_ipv6.len(), 0);

        record.update_ipv6(&[ipv6_2, ipv6_3]);
        assert_eq!(record.current_ipv6.len(), 2);
        assert_eq!(record.historical_ipv6.len(), 1);
        assert!(record.historical_ipv6.contains(&ipv6_1));
    }
}
