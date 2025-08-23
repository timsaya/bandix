// Only import these formatting functions in debug mode
use crate::utils::format_utils::format_bytes;
use crate::utils::format_utils::format_ip;
use crate::utils::format_utils::format_mac;
use crate::utils::format_utils::format_rate;
use bandix_common::MacTrafficStats;
use std::collections::HashMap as StdHashMap;
use std::sync::{Arc, Mutex};
use comfy_table::{Table, ContentArrangement, presets::UTF8_FULL};
use chrono::{Local, TimeZone};

// Display terminal user interface
pub fn display_tui_interface(mac_stats: &Arc<Mutex<StdHashMap<[u8; 6], MacTrafficStats>>>) {
    // Clear screen
    print!("\x1B[2J\x1B[1;1H");

    // Read data
    let stats_map = mac_stats.lock().unwrap();
    let mut mac_stats_data = stats_map.iter().collect::<Vec<_>>();

    // Sort by IP ascending
    mac_stats_data.sort_by(|(_, a), (_, b)| {
        let a_ip = u32::from_be_bytes(a.ip_address);
        let b_ip = u32::from_be_bytes(b.ip_address);
        a_ip.cmp(&b_ip)
    });

    // Build table
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            "IP Address",
            "MAC Address",
            "Total TX Rate",
            "Total RX Rate",
            "Total TX",
            "Total RX",
            "TX Limit",
            "RX Limit",
            "Local TX",
            "Local RX",
            "Wide TX",
            "Wide RX",
            "Last Online",
        ]);

    for (mac, stats) in mac_stats_data {
        let last_online_str = if stats.last_online_ts == 0 {
            "-".to_string()
        } else {
            Local
                .timestamp_millis_opt(stats.last_online_ts as i64)
                .single()
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| stats.last_online_ts.to_string())
        };

        table.add_row(vec![
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
            last_online_str,
        ]);
    }

    println!("{}", table);
}
