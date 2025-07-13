#![no_std]

#[cfg(feature = "serde")]
extern crate serde;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MacTrafficStats {
    pub ip_address: [u8; 4], // IP地址

    // 总流量统计
    pub total_rx_bytes: u64,      // 总接收字节数
    pub total_tx_bytes: u64,      // 总发送字节数
    pub total_rx_packets: u64,    // 总接收数据包数
    pub total_tx_packets: u64,    // 总发送数据包数
    pub total_last_rx_bytes: u64, // 上一次统计的总接收字节数
    pub total_last_tx_bytes: u64, // 上一次统计的总发送字节数
    pub total_rx_rate: u64,       // 总接收速率 (字节/秒)
    pub total_tx_rate: u64,       // 总发送速率 (字节/秒)

    // 局域网内部流量统计
    pub local_rx_bytes: u64,      // 局域网内部接收字节数
    pub local_tx_bytes: u64,      // 局域网内部发送字节数
    pub local_rx_rate: u64,       // 局域网内部接收速率 (字节/秒)
    pub local_tx_rate: u64,       // 局域网内部发送速率 (字节/秒)
    pub local_last_rx_bytes: u64, // 上一次统计的局域网内部接收字节数
    pub local_last_tx_bytes: u64, // 上一次统计的局域网内部发送字节数

    // 跨网络流量统计
    pub wide_rx_bytes: u64,      // 跨网络接收字节数
    pub wide_tx_bytes: u64,      // 跨网络发送字节数
    pub wide_rx_rate: u64,       // 跨网络接收速率 (字节/秒)
    pub wide_tx_rate: u64,       // 跨网络发送速率 (字节/秒)
    pub wide_last_rx_bytes: u64, // 上一次统计的跨网络接收字节数
    pub wide_last_tx_bytes: u64, // 上一次统计的跨网络发送字节数
    // 跨网络速率限制
    pub wide_rx_rate_limit: u64, // 跨网络下载限制 (字节/秒)
    pub wide_tx_rate_limit: u64, // 跨网络上传限制 (字节/秒)

    pub last_update: u64, // 上次更新时间戳
}

impl Default for MacTrafficStats {
    fn default() -> Self {
        Self {
            ip_address: [0; 4],
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
            // 局域网内部流量统计
            local_rx_bytes: 0,
            local_tx_bytes: 0,
            local_rx_rate: 0,
            local_tx_rate: 0,
            local_last_rx_bytes: 0,
            local_last_tx_bytes: 0,
            // 跨网络流量统计
            wide_rx_bytes: 0,
            wide_tx_bytes: 0,
            wide_rx_rate: 0,
            wide_tx_rate: 0,
            wide_last_rx_bytes: 0,
            wide_last_tx_bytes: 0,
            last_update: 0,
        }
    }
}
