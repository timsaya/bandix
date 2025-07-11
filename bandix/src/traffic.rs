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
) -> Result<StdHashMap<[u8; 6], [u64; 2]>, anyhow::Error> {
    let mut traffic_data = StdHashMap::new();

    let ingress_traffic = HashMap::<&MapData, [u8; 6], [u64; 2]>::try_from(
        ingress_ebpf
            .map("MAC_TRAFFIC")
            .ok_or(anyhow::anyhow!("找不到ingress MAC_TRAFFIC映射"))?,
    )?;

    let egress_traffic = HashMap::<&MapData, [u8; 6], [u64; 2]>::try_from(
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
            // 合并上传和下载流量
            existing[0] = existing[0].saturating_add(value[0]);
            existing[1] = existing[1].saturating_add(value[1]);
        } else {
            traffic_data.insert(key, value);
        }
    }

    

    Ok(traffic_data)
}

struct TrafficData {
    pub ip_address: [u8; 4],
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

fn merge(
    traffic_data: &StdHashMap<[u8; 6], [u64; 2]>,
    mac_ip_mapping: &StdHashMap<[u8; 6], [u8; 4]>,
) -> Result<StdHashMap<[u8; 6], TrafficData>, anyhow::Error> {
    let mut traffic = StdHashMap::new();

    for (mac, ip) in mac_ip_mapping.iter() {
        if let Some(data) = traffic_data.get(mac) {
            traffic.insert(
                *mac,
                TrafficData {
                    ip_address: *ip,
                    tx_bytes: data[0],
                    rx_bytes: data[1],
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
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            last_rx_bytes: 0,
            last_tx_bytes: 0,
            rx_rate: 0,
            tx_rate: 0,
            last_update: now,
            download_limit: 0,
            upload_limit: 0,
        });

        // 更新总字节数
        stats.rx_bytes = traffic_data.rx_bytes;
        stats.tx_bytes = traffic_data.tx_bytes;

        // 计算速率（字节/秒）
        if stats.last_update > 0 {
            let time_diff = now.saturating_sub(stats.last_update);
            if time_diff > 0 {
                // 计算接收速率
                let rx_diff = stats.rx_bytes.saturating_sub(stats.last_rx_bytes);
                stats.rx_rate = (rx_diff * 1000) / time_diff; // 转换为字节/秒

                // 计算发送速率
                let tx_diff = stats.tx_bytes.saturating_sub(stats.last_tx_bytes);
                stats.tx_rate = (tx_diff * 1000) / time_diff; // 转换为字节/秒
            }
        }

        // 保存当前值作为下次计算的基础
        stats.last_rx_bytes = stats.rx_bytes;
        stats.last_tx_bytes = stats.tx_bytes;
        stats.last_update = now;
    }

    Ok(())
}

// 更新数据并显示界面
pub async fn update(
    mac_stats: &Arc<Mutex<StdHashMap<[u8; 6], MacTrafficStats>>>,
    ingress_ebpf: &aya::Ebpf,
    egress_ebpf: &aya::Ebpf,
) -> Result<(), anyhow::Error> {
    let mac_ip_mapping = collect_mac_ip_mapping(ingress_ebpf, egress_ebpf)?;
    let traffic_data = collect_traffic_data(ingress_ebpf, egress_ebpf)?;
    let device_traffic_stats = merge(&traffic_data, &mac_ip_mapping)?;

    update_traffic_stats(mac_stats, &device_traffic_stats)?;

    display_tui_interface(mac_stats, &mac_ip_mapping);

    Ok(())
}
