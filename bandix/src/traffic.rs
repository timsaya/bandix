use crate::display::display_tui_interface;
use crate::utils::network_utils::is_broadcast_ip;
use crate::utils::network_utils::is_in_same_subnet;
use aya::maps::HashMap;
use aya::maps::MapData;
use bandix_common::MacTrafficStats;
use std::collections::HashMap as StdHashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// 判断MAC地址是否应该被过滤
fn should_filter_mac(
    mac: &[u8; 6],
    mac_ip_mapping: &StdHashMap<[u8; 6], [u8; 4]>,
    interface_ip: &[u8; 4],
    subnet_mask: &[u8; 4],
) -> bool {
    // 检查是否有对应的IP
    if let Some(ip) = mac_ip_mapping.get(mac) {
        // 检查是否为广播IP
        if is_broadcast_ip(ip) {
            return true;
        }

        // 检查是否在当前子网
        if !is_in_same_subnet(ip, interface_ip, subnet_mask) {
            return true;
        }

        // 通过所有检查，不应该过滤
        return false;
    }

    // 没有对应的IP，应该过滤
    true
}

// 从eBPF映射中收集数据
fn collect_traffic_data(
    ingress_traffic: &HashMap<&MapData, [u8; 6], [u64; 2]>,
    egress_traffic: &HashMap<&MapData, [u8; 6], [u64; 2]>,
    mac_ip_mapping: &StdHashMap<[u8; 6], [u8; 4]>,
    interface_ip: &[u8; 4],
    subnet_mask: &[u8; 4],
) -> (
    Vec<[u8; 6]>,
    StdHashMap<[u8; 6], [u64; 2]>,
    StdHashMap<[u8; 6], [u64; 2]>,
) {
    // 收集入站流量数据
    let ingress_data: StdHashMap<[u8; 6], [u64; 2]> = ingress_traffic
        .iter()
        .filter_map(|entry| entry.ok())
        .collect();

    // 收集出站流量数据
    let egress_data: StdHashMap<[u8; 6], [u64; 2]> = egress_traffic
        .iter()
        .filter_map(|entry| entry.ok())
        .collect();

    // 合并所有 mac 地址
    let mut all_macs = Vec::<[u8; 6]>::new();

    for mac in ingress_data.keys() {
        // 使用封装的函数检查是否应该过滤
        if should_filter_mac(mac, mac_ip_mapping, interface_ip, subnet_mask) {
            continue;
        }
        all_macs.push(*mac);
    }

    for mac in egress_data.keys() {
        // 如果该MAC已经添加，则跳过
        if all_macs.contains(mac) {
            continue;
        }

        // 使用封装的函数检查是否应该过滤
        if should_filter_mac(mac, mac_ip_mapping, interface_ip, subnet_mask) {
            continue;
        }
        all_macs.push(*mac);
    }

    (all_macs, ingress_data, egress_data)
}

// 更新流量统计数据
fn update_traffic_stats(
    mac_stats: &Arc<Mutex<StdHashMap<[u8; 6], MacTrafficStats>>>,
    mac: &[u8; 6],
    ingress_data: &StdHashMap<[u8; 6], [u64; 2]>,
    egress_data: &StdHashMap<[u8; 6], [u64; 2]>,
    mac_ip_mapping: &StdHashMap<[u8; 6], [u8; 4]>,
    now: u64,
) {
    // 获取 mac_stats 的锁，准备更新数据
    let mut stats_map = mac_stats.lock().unwrap();

    // 更新指定MAC的统计信息
    let stats: &mut MacTrafficStats = stats_map
        .entry(*mac)
        .or_insert_with(MacTrafficStats::default);

    // 从入站和出站数据中获取流量信息（从终端设备角度）
    if let Some(ingress) = ingress_data.get(mac) {
        stats.tx_bytes = ingress[0]; // 终端设备发送的数据是路由器接收到的
    }

    if let Some(egress) = egress_data.get(mac) {
        stats.rx_bytes = egress[1]; // 终端设备接收的数据是路由器发送的
    }

    // 更新 IP 地址
    if let Some(ip) = mac_ip_mapping.get(mac) {
        stats.ip_address = *ip;
    }

    // 计算速率 - 使用实际时间间隔
    if stats.last_update > 0 {
        // 计算时间间隔（毫秒）
        let time_diff_ms = now - stats.last_update;
        if time_diff_ms > 0 {
            // 转换为秒（浮点数精度）
            let time_diff_sec = time_diff_ms as f64 / 1000.0;

            stats.rx_rate = if stats.rx_bytes > stats.last_rx_bytes {
                ((stats.rx_bytes - stats.last_rx_bytes) as f64 / time_diff_sec) as u64
            } else {
                0
            };

            stats.tx_rate = if stats.tx_bytes > stats.last_tx_bytes {
                ((stats.tx_bytes - stats.last_tx_bytes) as f64 / time_diff_sec) as u64
            } else {
                0
            };
        }
    }

    // 更新上次的统计数据
    stats.last_rx_bytes = stats.rx_bytes;
    stats.last_tx_bytes = stats.tx_bytes;
    stats.last_update = now;
}

// 批量更新所有设备的流量统计
fn update_all_devices_stats(
    mac_stats: &Arc<Mutex<StdHashMap<[u8; 6], MacTrafficStats>>>,
    all_macs: &Vec<[u8; 6]>,
    ingress_data: &StdHashMap<[u8; 6], [u64; 2]>,
    egress_data: &StdHashMap<[u8; 6], [u64; 2]>,
    mac_ip_mapping: &StdHashMap<[u8; 6], [u8; 4]>,
    now: u64,
) {
    // 对于每个 mac，更新其统计信息
    for mac in all_macs {
        update_traffic_stats(
            mac_stats,
            mac,
            ingress_data,
            egress_data,
            mac_ip_mapping,
            now,
        );
    }
}

// 更新数据并显示界面
pub async fn update_and_display(
    mac_stats: &Arc<Mutex<StdHashMap<[u8; 6], MacTrafficStats>>>,
    ingress_traffic: &HashMap<&MapData, [u8; 6], [u64; 2]>,
    egress_traffic: &HashMap<&MapData, [u8; 6], [u64; 2]>,
    mac_ip_mapping: &HashMap<&MapData, [u8; 6], [u8; 4]>,
    interface_ip: &[u8; 4],
    subnet_mask: &[u8; 4],
) {
    // 获取当前时间戳
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64;

    // 收集MAC和IP映射关系
    let mac_ip_mapping: StdHashMap<[u8; 6], [u8; 4]> = mac_ip_mapping
        .iter()
        .filter_map(|entry| entry.ok())
        .collect();

    // 收集流量数据
    let (all_macs, ingress_data, egress_data) = collect_traffic_data(
        &ingress_traffic,
        &egress_traffic,
        &mac_ip_mapping,
        &interface_ip,
        &subnet_mask,
    );

    // 更新所有设备的统计信息
    update_all_devices_stats(
        &mac_stats,
        &all_macs,
        &ingress_data,
        &egress_data,
        &mac_ip_mapping,
        now,
    );

    // 显示终端用户界面
    display_tui_interface(&mac_stats, &mac_ip_mapping);
}
