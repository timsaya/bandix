// Only import these formatting functions in debug mode
use crate::utils::format_utils::format_bytes;
use crate::utils::format_utils::format_ip;
use crate::utils::format_utils::format_mac;
use crate::utils::format_utils::format_rate;
use bandix_common::MacTrafficStats;
use std::collections::HashMap as StdHashMap;
use std::sync::{Arc, Mutex};

// Display terminal user interface
pub fn display_tui_interface(mac_stats: &Arc<Mutex<StdHashMap<[u8; 6], MacTrafficStats>>>) {
    // Clear screen
    print!("\x1B[2J\x1B[1;1H");

    // Print table header
    println!(
        "{:<16} | {:<16} | {:<12} | {:<11} | {:<11} | {:<12} | {:<10} | {:<11} | {:<12} | {:<11} | {:<11} | {:<11} |",
        "IP Address", "MAC Address", "Total TX Rate", "Total RX Rate", "Total TX", "Total RX", "TX Limit", "RX Limit", "Local TX", "Local RX", "Wide TX", "Wide RX"
    );
    println!("{:-<180}", "");

    // Re-acquire lock to read data for display
    let stats_map = mac_stats.lock().unwrap();

    // Print statistics for each IP
    let mut mac_stats_data = stats_map.iter().collect::<Vec<_>>();

    // Sort by IP address from small to large
    mac_stats_data.sort_by(|(_, a), (_, b)| {
        // Convert IP address to u32 for comparison
        let a_ip = u32::from_be_bytes(a.ip_address);
        let b_ip = u32::from_be_bytes(b.ip_address);
        a_ip.cmp(&b_ip)
    });

    for (mac, stats) in mac_stats_data {
        // Print current MAC statistics
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
