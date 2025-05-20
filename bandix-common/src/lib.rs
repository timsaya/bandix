#![no_std]

#[cfg(feature = "serde")]
extern crate serde;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// 保留旧的结构体以保持兼容性
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IpTrafficStats {
    pub rx_bytes: u64,      // 接收的字节数
    pub tx_bytes: u64,      // 发送的字节数
    pub rx_packets: u64,    // 接收的数据包数
    pub tx_packets: u64,    // 发送的数据包数
    pub last_rx_bytes: u64, // 上一次统计的接收字节数
    pub last_tx_bytes: u64, // 上一次统计的发送字节数
    pub rx_rate: u64,       // 接收速率 (字节/秒)
    pub tx_rate: u64,       // 发送速率 (字节/秒)
    pub last_update: u64,   // 上次更新时间戳
    pub download_limit: u64, // 下载限制 (字节/秒)
    pub upload_limit: u64,  // 上传限制 (字节/秒)
    pub mac_address: [u8; 6], // MAC地址
}

impl Default for IpTrafficStats {
    fn default() -> Self {
        Self {
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            last_rx_bytes: 0,
            last_tx_bytes: 0,
            rx_rate: 0,
            tx_rate: 0,
            last_update: 0,
            download_limit: 0,
            upload_limit: 0,
            mac_address: [0; 6],
        }
    }
}
