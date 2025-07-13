use crate::utils::format_utils::format_bytes;
use crate::utils::format_utils::format_ip;
use crate::utils::format_utils::format_mac;
use crate::utils::format_utils::format_rate;
use bandix_common::MacTrafficStats;
use std::collections::HashMap as StdHashMap;
use std::sync::{Arc, Mutex};

// 显示终端用户界面
pub fn display_tui_interface(mac_stats: &Arc<Mutex<StdHashMap<[u8; 6], MacTrafficStats>>>) {
    // 清屏
    print!("\x1B[2J\x1B[1;1H");

    // 打印表头
    println!(
        "{:<16} | {:<16} | {:<12} | {:<11} | {:<11} | {:<12} | {:<10} | {:<11} | {:<12} | {:<11} | {:<11} | {:<11} |",
        "IP地址", "MAC地址", "总上传速率", "总下载速率", "总上传", "总下载", "上传限制", "下载限制", "局域网上传", "局域网下载", "跨网上传", "跨网下载"
    );
    println!("{:-<180}", "");

    // 重新获取锁以读取数据进行显示
    let stats_map = mac_stats.lock().unwrap();

    // 打印每个IP的统计信息
    let mut mac_stats_data = stats_map.iter().collect::<Vec<_>>();

    // 按 IP 地址从小到大排序
    mac_stats_data.sort_by(|(_, a), (_, b)| {
        // 将 IP 地址转换为 u32 便于比较
        let a_ip = u32::from_be_bytes(a.ip_address);
        let b_ip = u32::from_be_bytes(b.ip_address);
        a_ip.cmp(&b_ip)
    });

    for (mac, stats) in mac_stats_data {
        // 打印当前 MAC 的统计信息
        println!(
            "{:<18} | {:<18} | {:<16} | {:<15} | {:<14} | {:<15} | {:<14} | {:<15} | {:<16} | {:<15} | {:<14} | {:<15} |",
            format_ip(&stats.ip_address),
            format_mac(mac),
            format_rate(stats.total_tx_rate),
            format_rate(stats.total_rx_rate),
            format_bytes(stats.total_tx_bytes),
            format_bytes(stats.total_rx_bytes),
            format_rate(stats.wide_tx_rate_limit),
            format_rate(stats.wide_rx_rate_limit),
            format_rate(stats.local_tx_rate),
            format_rate(stats.local_rx_rate),
            format_rate(stats.wide_tx_rate),
            format_rate(stats.wide_rx_rate),
        );
    }
}
