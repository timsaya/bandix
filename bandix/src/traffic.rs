use crate::display::display_tui_interface;
use anyhow::Ok;
use aya::maps::HashMap;
use aya::maps::MapData;
use bandix_common::MacTrafficStats;
use std::collections::HashMap as StdHashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// 检查 MAC 地址是否为特殊地址（广播、多播等）
fn is_special_mac_address(mac: &[u8; 6]) -> bool {
    // 广播地址 FF:FF:FF:FF:FF:FF
    if mac == &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] {
        return true;
    }

    // 多播地址 (第一个字节的最低位为1)
    if (mac[0] & 0x01) == 0x01 {
        return true;
    }

    // 零地址 00:00:00:00:00:00
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
            .ok_or(anyhow::anyhow!("找不到ingress MAC_IP_MAPPING映射"))?,
    )?;

    let egress_mac_ip_mapping = HashMap::<&MapData, [u8; 6], [u8; 4]>::try_from(
        egress_ebpf
            .map("MAC_IP_MAPPING")
            .ok_or(anyhow::anyhow!("找不到MAC_IP_MAPPING映射"))?,
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
            .ok_or(anyhow::anyhow!("找不到ingress MAC_TRAFFIC映射"))?,
    )?;

    let egress_traffic = HashMap::<&MapData, [u8; 6], [u64; 4]>::try_from(
        egress_ebpf
            .map("MAC_TRAFFIC")
            .ok_or(anyhow::anyhow!("找不到egress MAC_TRAFFIC映射"))?,
    )?;

    // 处理ingress方向的流量数据
    for entry in ingress_traffic.iter() {
        let (key, value) = entry.unwrap();
        // 排除广播地址和多播地址等特殊地址
        if is_special_mac_address(&key) {
            continue;
        }
        traffic_data.insert(key, value);
    }

    // 合并egress方向的流量数据
    for entry in egress_traffic.iter() {
        let (key, value) = entry.unwrap();

        // 排除广播地址和多播地址等特殊地址
        if is_special_mac_address(&key) {
            continue;
        }

        if let Some(existing) = traffic_data.get_mut(&key) {
            // 合并局域网内部和跨网络的流量
            existing[0] = existing[0].saturating_add(value[0]); // 局域网内部发送
            existing[1] = existing[1].saturating_add(value[1]); // 局域网内部接收
            existing[2] = existing[2].saturating_add(value[2]); // 跨网络发送
            existing[3] = existing[3].saturating_add(value[3]); // 跨网络接收
        } else {
            traffic_data.insert(key, value);
        }
    }

    Ok(traffic_data)
}

struct TrafficData {
    pub ip_address: [u8; 4],
    pub local_tx_bytes: u64,    // 局域网内部发送字节数
    pub local_rx_bytes: u64,    // 局域网内部接收字节数
    pub wide_tx_bytes: u64, // 跨网络发送字节数
    pub wide_rx_bytes: u64, // 跨网络接收字节数
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
                    local_tx_bytes: data[0],    // 局域网内部发送
                    local_rx_bytes: data[1],    // 局域网内部接收
                    wide_tx_bytes: data[2], // 跨网络发送
                    wide_rx_bytes: data[3], // 跨网络接收
                },
            );
        }
    }

    Ok(traffic)
}

fn update_traffic_stats(
    mac_stats: &Arc<Mutex<StdHashMap<[u8; 6], MacTrafficStats>>>,
    device_traffic_stats: &StdHashMap<[u8; 6], TrafficData>,
) -> Result<(), anyhow::Error> {
    // 获取当前时间戳
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64;

    let mut stats_map = mac_stats.lock().unwrap();

    for (mac, traffic_data) in device_traffic_stats.iter() {
        let stats = stats_map.entry(*mac).or_insert_with(|| MacTrafficStats {
            ip_address: traffic_data.ip_address,
            // 总流量统计
            total_rx_bytes: 0,
            total_tx_bytes: 0,
            total_rx_packets: 0,
            total_tx_packets: 0,
            total_last_rx_bytes: 0,
            total_last_tx_bytes: 0,
            total_rx_rate: 0,
            total_tx_rate: 0,
            // 跨网络速率限制
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
            last_update: now,
        });

        // 计算总流量
        let total_rx_bytes = traffic_data.local_rx_bytes + traffic_data.wide_rx_bytes;
        let total_tx_bytes = traffic_data.local_tx_bytes + traffic_data.wide_tx_bytes;

        // 更新总字节数
        stats.total_rx_bytes = total_rx_bytes;
        stats.total_tx_bytes = total_tx_bytes;

        // 更新局域网内部流量
        stats.local_rx_bytes = traffic_data.local_rx_bytes;
        stats.local_tx_bytes = traffic_data.local_tx_bytes;

        // 更新跨网络流量
        stats.wide_rx_bytes = traffic_data.wide_rx_bytes;
        stats.wide_tx_bytes = traffic_data.wide_tx_bytes;

        // 计算速率（字节/秒）
        if stats.last_update > 0 {
            let time_diff = now.saturating_sub(stats.last_update);
            if time_diff > 0 {
                // 计算总接收速率
                let rx_diff = stats.total_rx_bytes.saturating_sub(stats.total_last_rx_bytes);
                stats.total_rx_rate = (rx_diff * 1000) / time_diff; // 转换为字节/秒

                // 计算总发送速率
                let tx_diff = stats.total_tx_bytes.saturating_sub(stats.total_last_tx_bytes);
                stats.total_tx_rate = (tx_diff * 1000) / time_diff; // 转换为字节/秒

                // 计算局域网内部接收速率
                let local_rx_diff = stats.local_rx_bytes.saturating_sub(stats.local_last_rx_bytes);
                stats.local_rx_rate = (local_rx_diff * 1000) / time_diff;

                // 计算局域网内部发送速率
                let local_tx_diff = stats.local_tx_bytes.saturating_sub(stats.local_last_tx_bytes);
                stats.local_tx_rate = (local_tx_diff * 1000) / time_diff;

                // 计算跨网络接收速率
                let wide_rx_diff = stats.wide_rx_bytes.saturating_sub(stats.wide_last_rx_bytes);
                stats.wide_rx_rate = (wide_rx_diff * 1000) / time_diff;

                // 计算跨网络发送速率
                let wide_tx_diff = stats.wide_tx_bytes.saturating_sub(stats.wide_last_tx_bytes);
                stats.wide_tx_rate = (wide_tx_diff * 1000) / time_diff;
            }
        }

        // 保存当前值作为下次计算的基础
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
            .ok_or(anyhow::anyhow!("找不到ingress MAC_RATE_LIMITS"))?,
    )?;

    let mut egress_mac_rate_limits: HashMap<_, [u8; 6], [u64; 2]> = HashMap::try_from(
        egress_ebpf
            .map_mut("MAC_RATE_LIMITS")
            .ok_or(anyhow::anyhow!("找不到egress MAC_RATE_LIMITS"))?,
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

// 更新数据
pub async fn update(
    mac_stats: &Arc<Mutex<StdHashMap<[u8; 6], MacTrafficStats>>>,
    ingress_ebpf: &mut aya::Ebpf,
    egress_ebpf: &mut aya::Ebpf,
) -> Result<(), anyhow::Error> {
    let mac_ip_mapping = collect_mac_ip_mapping(ingress_ebpf, egress_ebpf)?;
    let traffic_data = collect_traffic_data(ingress_ebpf, egress_ebpf)?;
    let device_traffic_stats = merge(&traffic_data, &mac_ip_mapping)?;

    update_traffic_stats(mac_stats, &device_traffic_stats)?;

    update_rate_limit(mac_stats, ingress_ebpf, egress_ebpf)?;

    display_tui_interface(mac_stats);

    Ok(())
}
