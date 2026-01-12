#![no_std]

#[cfg(feature = "serde")]
extern crate serde;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Packet header for eBPF to userspace communication
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PacketHeader {
    pub timestamp: u64,    // Timestamp (nanoseconds)
    pub packet_len: u32,   // Total packet length (bytes)
    pub captured_len: u32, // Actual bytes copied to ringbuf (usually equals packet_len)
    pub ifindex: u32,      // 网络接口 index (may be 0 in TC scenario)
    pub direction: u32,    // Direction: 0=Ingress, 1=Egress
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketHeader {}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DeviceTrafficStats {
    pub ip_address: [u8; 4],
    pub ipv6_addresses: [[u8; 16]; 16],

    pub wan_rx_rate_limit: u64,
    pub wan_tx_rate_limit: u64,

    pub lan_rx_bytes: u64,
    pub lan_tx_bytes: u64,
    pub lan_rx_rate: u64,
    pub lan_tx_rate: u64,

    pub wan_rx_bytes: u64,
    pub wan_tx_bytes: u64,
    pub wan_rx_rate: u64,
    pub wan_tx_rate: u64,

    pub lan_last_rx_bytes: u64,
    pub lan_last_tx_bytes: u64,
    pub wan_last_rx_bytes: u64,
    pub wan_last_tx_bytes: u64,

    pub last_online_ts: u64,
    pub last_sample_ts: u64,
}

impl DeviceTrafficStats {
    /// Count the number of valid IPv6 addresses (non-zero addresses)
    pub fn ipv6_count(&self) -> u8 {
        self.ipv6_addresses.iter().filter(|addr| **addr != [0u8; 16]).count() as u8
    }

    /// 计算total receive bytes (lan + wan)
    pub fn total_rx_bytes(&self) -> u64 {
        self.lan_rx_bytes + self.wan_rx_bytes
    }

    /// 计算total send bytes (lan + wan)
    pub fn total_tx_bytes(&self) -> u64 {
        self.lan_tx_bytes + self.wan_tx_bytes
    }

    /// 计算total receive rate (lan + wan)
    pub fn total_rx_rate(&self) -> u64 {
        self.lan_rx_rate + self.wan_rx_rate
    }

    /// 计算total send rate (lan + wan)
    pub fn total_tx_rate(&self) -> u64 {
        self.lan_tx_rate + self.wan_tx_rate
    }

    /// 创建a new DeviceTrafficStats with only IP addresses set, all other fields are zero
    pub fn from_ip(ip_address: [u8; 4], ipv6_addresses: [[u8; 16]; 16]) -> Self {
        Self {
            ip_address,
            ipv6_addresses,
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
            last_online_ts: 0,
            lan_last_rx_bytes: 0,
            lan_last_tx_bytes: 0,
            wan_last_rx_bytes: 0,
            wan_last_tx_bytes: 0,
            last_sample_ts: 0,
        }
    }
}

/// 连接 statistics data structure
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ConnectionStats {
    pub total_connections: u32,
    pub tcp_connections: u32,
    pub udp_connections: u32,
    pub established_tcp: u32,
    pub time_wait_tcp: u32,
    pub close_wait_tcp: u32,
    pub last_updated: u64,
}

/// 设备-level connection statistics
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DeviceConnectionStats {
    pub mac_address: [u8; 6],
    pub ip_address: [u8; 4],
    pub tcp_connections: u32,   // Total TCP connections
    pub udp_connections: u32,   // Total UDP connections
    pub established_tcp: u32,   // TCP connections in ESTABLISHED state
    pub time_wait_tcp: u32,     // TCP connections in TIME_WAIT state
    pub close_wait_tcp: u32,    // TCP connections in CLOSE_WAIT state
    pub total_connections: u32, // Total connections (tcp_connections + udp_connections)
    pub last_updated: u64,
}

impl Default for DeviceTrafficStats {
    fn default() -> Self {
        Self {
            ip_address: [0; 4],
            ipv6_addresses: [[0; 16]; 16],
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
            last_online_ts: 0,
            lan_last_rx_bytes: 0,
            lan_last_tx_bytes: 0,
            wan_last_rx_bytes: 0,
            wan_last_tx_bytes: 0,
            last_sample_ts: 0,
        }
    }
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            total_connections: 0,
            tcp_connections: 0,
            udp_connections: 0,
            established_tcp: 0,
            time_wait_tcp: 0,
            close_wait_tcp: 0,
            last_updated: 0,
        }
    }
}

impl Default for DeviceConnectionStats {
    fn default() -> Self {
        Self {
            mac_address: [0, 0, 0, 0, 0, 0],
            ip_address: [0, 0, 0, 0],
            tcp_connections: 0,
            udp_connections: 0,
            established_tcp: 0,
            time_wait_tcp: 0,
            close_wait_tcp: 0,
            total_connections: 0,
            last_updated: 0,
        }
    }
}
