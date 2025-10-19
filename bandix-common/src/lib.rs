#![no_std]

#[cfg(feature = "serde")]
extern crate serde;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MacTrafficStats {
    pub ip_address: [u8; 4], // IPv4 address
    
    // IPv6 addresses (a device may have multiple IPv6 addresses)
    // Support up to 16 IPv6 addresses (matches Linux kernel default: net.ipv6.conf.*.max_addresses = 16)
    // Including: GUA, ULA, Link-Local, temporary/privacy addresses, etc.
    pub ipv6_addresses: [[u8; 16]; 16],
    pub ipv6_count: u8, // Number of valid IPv6 addresses (0-16)

    // Total traffic statistics
    pub total_rx_bytes: u64,      // Total receive bytes
    pub total_tx_bytes: u64,      // Total send bytes
    pub total_rx_packets: u64,    // Total receive packets
    pub total_tx_packets: u64,    // Total send packets
    pub total_last_rx_bytes: u64, // Last total receive bytes
    pub total_last_tx_bytes: u64, // Last total send bytes
    pub total_rx_rate: u64,       // Total receive rate (bytes/sec)
    pub total_tx_rate: u64,       // Total send rate (bytes/sec)

    // Local network traffic statistics
    pub local_rx_bytes: u64,      // Local network receive bytes
    pub local_tx_bytes: u64,      // Local network send bytes
    pub local_rx_rate: u64,       // Local network receive rate (bytes/sec)
    pub local_tx_rate: u64,       // Local network send rate (bytes/sec)
    pub local_last_rx_bytes: u64, // Last local network receive bytes
    pub local_last_tx_bytes: u64, // Last local network send bytes

    // Cross-network traffic statistics
    pub wide_rx_bytes: u64,      // Cross-network receive bytes
    pub wide_tx_bytes: u64,      // Cross-network send bytes
    pub wide_rx_rate: u64,       // Cross-network receive rate (bytes/sec)
    pub wide_tx_rate: u64,       // Cross-network send rate (bytes/sec)
    pub wide_last_rx_bytes: u64, // Last cross-network receive bytes
    pub wide_last_tx_bytes: u64, // Last cross-network send bytes
    // Cross-network rate limits
    pub wide_rx_rate_limit: u64, // Cross-network download limit (bytes/sec)
    pub wide_tx_rate_limit: u64, // Cross-network upload limit (bytes/sec)

    pub last_online_ts: u64, // Last online timestamp (ms since epoch; updated only when traffic increases)
    pub last_sample_ts: u64, // Last sample timestamp (ms since epoch)
}

/// Connection statistics data structure
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

/// Device-level connection statistics
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DeviceConnectionStats {
    pub mac_address: [u8; 6],
    pub ip_address: [u8; 4],
    pub tcp_connections: u32,     // TCP连接总数
    pub udp_connections: u32,     // UDP连接总数
    pub established_tcp: u32,     // ESTABLISHED状态的TCP连接
    pub time_wait_tcp: u32,       // TIME_WAIT状态的TCP连接
    pub close_wait_tcp: u32,      // CLOSE_WAIT状态的TCP连接
    pub total_connections: u32,   // 总连接数 (tcp_connections + udp_connections)
    pub last_updated: u64,
}

impl Default for MacTrafficStats {
    fn default() -> Self {
        Self {
            ip_address: [0; 4],
            ipv6_addresses: [[0; 16]; 16],
            ipv6_count: 0,
            total_rx_bytes: 0,
            total_tx_bytes: 0,
            total_rx_packets: 0,
            total_tx_packets: 0,
            total_last_rx_bytes: 0,
            total_last_tx_bytes: 0,
            total_rx_rate: 0,
            total_tx_rate: 0,
            wide_rx_rate_limit: 0,
            wide_tx_rate_limit: 0,
            // Local network traffic statistics
            local_rx_bytes: 0,
            local_tx_bytes: 0,
            local_rx_rate: 0,
            local_tx_rate: 0,
            local_last_rx_bytes: 0,
            local_last_tx_bytes: 0,
            // Cross-network traffic statistics
            wide_rx_bytes: 0,
            wide_tx_bytes: 0,
            wide_rx_rate: 0,
            wide_tx_rate: 0,
            wide_last_rx_bytes: 0,
            wide_last_tx_bytes: 0,
            last_online_ts: 0,
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
