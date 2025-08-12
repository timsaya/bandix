// Only import display functions in debug mode
#[cfg(debug_assertions)]
use crate::display::display_tui_interface;
use anyhow::Ok;
use aya::maps::HashMap;
use aya::maps::MapData;
use bandix_common::MacTrafficStats;
use crate::storage::BaselineTotals;
use std::collections::HashMap as StdHashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Check if MAC address is special address (broadcast, multicast, etc.)
fn is_special_mac_address(mac: &[u8; 6]) -> bool {
    // Broadcast address FF:FF:FF:FF:FF:FF
    if mac == &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] {
        return true;
    }

    // Multicast address (lowest bit of first byte is 1)
    if (mac[0] & 0x01) == 0x01 {
        return true;
    }

    // Zero address 00:00:00:00:00:00
    if mac == &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00] {
        return true;
    }

    false
}

fn collect_mac_ip_mapping(
    ingress_ebpf: &aya::Ebpf,
    egress_ebpf: &aya::Ebpf,
) -> Result<StdHashMap<[u8; 6], [u8; 4]>, anyhow::Error> {
    let mut mac_ip_mapping = StdHashMap::new();

    let ingress_mac_ip_mapping = HashMap::<&MapData, [u8; 6], [u8; 4]>::try_from(
        ingress_ebpf
            .map("MAC_IP_MAPPING")
            .ok_or(anyhow::anyhow!("Cannot find ingress MAC_IP_MAPPING map"))?,
    )?;

    let egress_mac_ip_mapping = HashMap::<&MapData, [u8; 6], [u8; 4]>::try_from(
        egress_ebpf
            .map("MAC_IP_MAPPING")
            .ok_or(anyhow::anyhow!("Cannot find MAC_IP_MAPPING map"))?,
    )?;

    for entry in ingress_mac_ip_mapping.iter() {
        let (key, value) = entry.unwrap();
        mac_ip_mapping.insert(key, value);
    }

    for entry in egress_mac_ip_mapping.iter() {
        let (key, value) = entry.unwrap();
        mac_ip_mapping.insert(key, value);
    }

    Ok(mac_ip_mapping)
}

fn collect_traffic_data(
    ingress_ebpf: &aya::Ebpf,
    egress_ebpf: &aya::Ebpf,
) -> Result<StdHashMap<[u8; 6], [u64; 4]>, anyhow::Error> {
    let mut traffic_data = StdHashMap::new();

    let ingress_traffic = HashMap::<&MapData, [u8; 6], [u64; 4]>::try_from(
        ingress_ebpf
            .map("MAC_TRAFFIC")
            .ok_or(anyhow::anyhow!("Cannot find ingress MAC_TRAFFIC map"))?,
    )?;

    let egress_traffic = HashMap::<&MapData, [u8; 6], [u64; 4]>::try_from(
        egress_ebpf
            .map("MAC_TRAFFIC")
            .ok_or(anyhow::anyhow!("Cannot find egress MAC_TRAFFIC map"))?,
    )?;

    // Process ingress direction traffic data
    for entry in ingress_traffic.iter() {
        let (key, value) = entry.unwrap();
        // Exclude broadcast and multicast addresses
        if is_special_mac_address(&key) {
            continue;
        }
        traffic_data.insert(key, value);
    }

    // Merge egress direction traffic data
    for entry in egress_traffic.iter() {
        let (key, value) = entry.unwrap();

        // Exclude broadcast and multicast addresses
        if is_special_mac_address(&key) {
            continue;
        }

        if let Some(existing) = traffic_data.get_mut(&key) {
            // Merge local network and cross-network traffic
            existing[0] = existing[0].saturating_add(value[0]); // Local network send
            existing[1] = existing[1].saturating_add(value[1]); // Local network receive
            existing[2] = existing[2].saturating_add(value[2]); // Cross-network send
            existing[3] = existing[3].saturating_add(value[3]); // Cross-network receive
        } else {
            traffic_data.insert(key, value);
        }
    }

    Ok(traffic_data)
}

struct TrafficData {
    pub ip_address: [u8; 4],
    pub local_tx_bytes: u64,    // Local network send bytes
    pub local_rx_bytes: u64,    // Local network receive bytes
    pub wide_tx_bytes: u64, // Cross-network send bytes
    pub wide_rx_bytes: u64, // Cross-network receive bytes
}

fn merge(
    traffic_data: &StdHashMap<[u8; 6], [u64; 4]>,
    mac_ip_mapping: &StdHashMap<[u8; 6], [u8; 4]>,
) -> Result<StdHashMap<[u8; 6], TrafficData>, anyhow::Error> {
    let mut traffic = StdHashMap::new();

    for (mac, ip) in mac_ip_mapping.iter() {
        if let Some(data) = traffic_data.get(mac) {
            traffic.insert(
                *mac,
                TrafficData {
                    ip_address: *ip,
                    local_tx_bytes: data[0],    // Local network send
                    local_rx_bytes: data[1],    // Local network receive
                    wide_tx_bytes: data[2], // Cross-network send
                    wide_rx_bytes: data[3], // Cross-network receive
                },
            );
        }
    }

    Ok(traffic)
}

fn update_traffic_stats(
    mac_stats: &Arc<Mutex<StdHashMap<[u8; 6], MacTrafficStats>>>,
    device_traffic_stats: &StdHashMap<[u8; 6], TrafficData>,
    baselines: &Arc<Mutex<StdHashMap<[u8; 6], BaselineTotals>>>,
) -> Result<(), anyhow::Error> {
    // Get current timestamp
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64;

    let mut stats_map = mac_stats.lock().unwrap();
    let baseline_map = baselines.lock().unwrap();

    for (mac, traffic_data) in device_traffic_stats.iter() {
        let stats = stats_map.entry(*mac).or_insert_with(|| MacTrafficStats {
            ip_address: traffic_data.ip_address,
            // Total traffic statistics
            total_rx_bytes: 0,
            total_tx_bytes: 0,
            total_rx_packets: 0,
            total_tx_packets: 0,
            total_last_rx_bytes: 0,
            total_last_tx_bytes: 0,
            total_rx_rate: 0,
            total_tx_rate: 0,
            // Cross-network rate limits
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
            last_update: now,
        });

        // If the entry already exists (e.g., created earlier due to rate limit config and IP is still default),
        // overwrite with the latest IP collected by eBPF to avoid staying at 0.0.0.0.
        if traffic_data.ip_address != [0, 0, 0, 0] && stats.ip_address != traffic_data.ip_address {
            stats.ip_address = traffic_data.ip_address;
        }

        // Calculate total traffic
        let total_rx_bytes = traffic_data.local_rx_bytes + traffic_data.wide_rx_bytes;
        let total_tx_bytes = traffic_data.local_tx_bytes + traffic_data.wide_tx_bytes;

        // Lookup baseline for current MAC (default zeros)
        let b = baseline_map
            .get(mac)
            .copied()
            .unwrap_or(BaselineTotals {
                total_rx_bytes: 0,
                total_tx_bytes: 0,
                local_rx_bytes: 0,
                local_tx_bytes: 0,
                wide_rx_bytes: 0,
                wide_tx_bytes: 0,
            });

        // Update total bytes with baseline added
        stats.total_rx_bytes = total_rx_bytes + b.total_rx_bytes;
        stats.total_tx_bytes = total_tx_bytes + b.total_tx_bytes;

        // Update local network traffic with baseline added
        stats.local_rx_bytes = traffic_data.local_rx_bytes + b.local_rx_bytes;
        stats.local_tx_bytes = traffic_data.local_tx_bytes + b.local_tx_bytes;

        // Update cross-network traffic with baseline added
        stats.wide_rx_bytes = traffic_data.wide_rx_bytes + b.wide_rx_bytes;
        stats.wide_tx_bytes = traffic_data.wide_tx_bytes + b.wide_tx_bytes;

        // Calculate rate (bytes/sec)
        if stats.last_update > 0 {
            let time_diff = now.saturating_sub(stats.last_update);
            if time_diff > 0 {
                // Calculate total receive rate
                let rx_diff = stats.total_rx_bytes.saturating_sub(stats.total_last_rx_bytes);
                stats.total_rx_rate = (rx_diff * 1000) / time_diff; // Convert to bytes/sec

                // Calculate total send rate
                let tx_diff = stats.total_tx_bytes.saturating_sub(stats.total_last_tx_bytes);
                stats.total_tx_rate = (tx_diff * 1000) / time_diff; // Convert to bytes/sec

                // Calculate local network receive rate
                let local_rx_diff = stats.local_rx_bytes.saturating_sub(stats.local_last_rx_bytes);
                stats.local_rx_rate = (local_rx_diff * 1000) / time_diff;

                // Calculate local network send rate
                let local_tx_diff = stats.local_tx_bytes.saturating_sub(stats.local_last_tx_bytes);
                stats.local_tx_rate = (local_tx_diff * 1000) / time_diff;

                // Calculate cross-network receive rate
                let wide_rx_diff = stats.wide_rx_bytes.saturating_sub(stats.wide_last_rx_bytes);
                stats.wide_rx_rate = (wide_rx_diff * 1000) / time_diff;

                // Calculate cross-network send rate
                let wide_tx_diff = stats.wide_tx_bytes.saturating_sub(stats.wide_last_tx_bytes);
                stats.wide_tx_rate = (wide_tx_diff * 1000) / time_diff;
            }
        }

        // Save current values as basis for next calculation
        stats.total_last_rx_bytes = stats.total_rx_bytes;
        stats.total_last_tx_bytes = stats.total_tx_bytes;
        stats.local_last_rx_bytes = stats.local_rx_bytes;
        stats.local_last_tx_bytes = stats.local_tx_bytes;
        stats.wide_last_rx_bytes = stats.wide_rx_bytes;
        stats.wide_last_tx_bytes = stats.wide_tx_bytes;
        stats.last_update = now;
    }

    Ok(())
}

fn update_rate_limit(
    mac_stats: &Arc<Mutex<StdHashMap<[u8; 6], MacTrafficStats>>>,
    ingress_ebpf: &mut aya::Ebpf,
    egress_ebpf: &mut aya::Ebpf,
) -> Result<(), anyhow::Error> {
    let mut stats_map = mac_stats.lock().unwrap();

    let mut ingress_mac_rate_limits: HashMap<_, [u8; 6], [u64; 2]> = HashMap::try_from(
        ingress_ebpf
            .map_mut("MAC_RATE_LIMITS")
            .ok_or(anyhow::anyhow!("Cannot find ingress MAC_RATE_LIMITS"))?,
    )?;

    let mut egress_mac_rate_limits: HashMap<_, [u8; 6], [u64; 2]> = HashMap::try_from(
        egress_ebpf
            .map_mut("MAC_RATE_LIMITS")
            .ok_or(anyhow::anyhow!("Cannot find egress MAC_RATE_LIMITS"))?,
    )?;

    for (mac, traffic_data) in stats_map.iter_mut() {
        ingress_mac_rate_limits
            .insert(
                mac,
                &[traffic_data.wide_rx_rate_limit, traffic_data.wide_tx_rate_limit],
                0,
            )
            .unwrap();

        egress_mac_rate_limits
            .insert(
                mac,
                &[traffic_data.wide_rx_rate_limit, traffic_data.wide_tx_rate_limit],
                0,
            )
            .unwrap();
    }

    Ok(())
}

// Update data
pub async fn update(
    mac_stats: &Arc<Mutex<StdHashMap<[u8; 6], MacTrafficStats>>>,
    ingress_ebpf: &mut aya::Ebpf,
    egress_ebpf: &mut aya::Ebpf,
    baselines: &Arc<Mutex<StdHashMap<[u8; 6], BaselineTotals>>>,
) -> Result<(), anyhow::Error> {
    let mac_ip_mapping = collect_mac_ip_mapping(ingress_ebpf, egress_ebpf)?;
    let traffic_data = collect_traffic_data(ingress_ebpf, egress_ebpf)?;
    let device_traffic_stats = merge(&traffic_data, &mac_ip_mapping)?;

    update_traffic_stats(mac_stats, &device_traffic_stats, baselines)?;

    update_rate_limit(mac_stats, ingress_ebpf, egress_ebpf)?;

    // Only call display function in debug mode
    #[cfg(debug_assertions)]
    {
        display_tui_interface(mac_stats);
    }

    Ok(())
}
