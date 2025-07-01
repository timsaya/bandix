use crate::ebpf::egress::load_egress;
use crate::ebpf::ingress::load_ingress;
use crate::web;
use aya::maps::HashMap;
use aya::maps::MapData;
use bandix_common::MacTrafficStats;
use clap::Parser;
use log::info;
use log::LevelFilter;
use std::collections::HashMap as StdHashMap;
use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::signal;
use tokio::time::interval;

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "wlo1")]
    pub iface: String,

    #[clap(long, default_value = "8686")]
    pub port: u16,
}

// 用于将字节数转换为人类可读的格式
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

// 用于将速率转换为人类可读的格式
fn format_rate(bytes_per_sec: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes_per_sec >= GB {
        format!("{:.2} GB/s", bytes_per_sec as f64 / GB as f64)
    } else if bytes_per_sec >= MB {
        format!("{:.2} MB/s", bytes_per_sec as f64 / MB as f64)
    } else if bytes_per_sec >= KB {
        format!("{:.2} KB/s", bytes_per_sec as f64 / KB as f64)
    } else {
        format!("{} B/s", bytes_per_sec)
    }
}

// 格式化IP地址
fn format_ip(ip: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

// 格式化MAC地址
fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

// 判断是否为广播IP地址
fn is_broadcast_ip(ip: &[u8; 4]) -> bool {
    // 255.255.255.255
    if ip[0] == 255 && ip[1] == 255 && ip[2] == 255 && ip[3] == 255 {
        return true;
    }

    // 网段广播地址 (通常是以255结尾的地址)
    if ip[3] == 255 {
        return true;
    }

    // 多播地址 (224.0.0.0 - 239.255.255.255)
    if ip[0] >= 224 && ip[0] <= 239 {
        return true;
    }

    false
}

// 检查IP是否在同一子网
fn is_in_same_subnet(ip: &[u8; 4], interface_ip: &[u8; 4], subnet_mask: &[u8; 4]) -> bool {
    for i in 0..4 {
        if (ip[i] & subnet_mask[i]) != (interface_ip[i] & subnet_mask[i]) {
            return false;
        }
    }
    true
}

// 获取接口的IP和子网掩码
fn get_interface_info(interface: &str) -> Option<([u8; 4], [u8; 4])> {
    let output = Command::new("ip")
        .args(&["addr", "show", interface])
        .output()
        .ok()?;

    let output_str = String::from_utf8_lossy(&output.stdout);

    // 提取IPv4地址和子网掩码
    for line in output_str.lines() {
        if line.trim().starts_with("inet ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let ip_with_cidr = parts[1];
                let ip_cidr: Vec<&str> = ip_with_cidr.split('/').collect();

                if ip_cidr.len() == 2 {
                    if let Ok(ip) = Ipv4Addr::from_str(ip_cidr[0]) {
                        let ip_bytes = ip.octets();

                        if let Ok(cidr) = ip_cidr[1].parse::<u8>() {
                            let mask = get_subnet_mask(cidr);
                            return Some((ip_bytes, mask));
                        }
                    }
                }
            }
        }
    }

    None
}

// 从CIDR计算子网掩码
fn get_subnet_mask(cidr: u8) -> [u8; 4] {
    let mut mask = [0u8; 4];
    let bits = cidr as usize;

    for i in 0..4 {
        let start_bit = i * 8;
        let end_bit = start_bit + 8;

        let mut byte_mask = 0u8;
        for bit in start_bit..end_bit {
            if bit < bits {
                byte_mask |= 1 << (7 - (bit % 8));
            }
        }

        mask[i] = byte_mask;
    }

    mask
}

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

// 初始化eBPF程序和映射
async fn init_ebpf_programs(iface: String) -> Result<(aya::Ebpf, aya::Ebpf), anyhow::Error> {
    let ingress_ebpf = load_ingress(iface.clone()).await?;
    let egress_ebpf = load_egress(iface.clone()).await?;

    Ok((ingress_ebpf, egress_ebpf))
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

// 显示终端用户界面
fn display_tui_interface(
    mac_stats: &Arc<Mutex<StdHashMap<[u8; 6], MacTrafficStats>>>,
    mac_ip_mapping: &StdHashMap<[u8; 6], [u8; 4]>,
) {
    // 清屏
    print!("\x1B[2J\x1B[1;1H");

    // 打印表头
    println!(
        "{:<16} | {:<16} | {:<12} | {:<11} | {:<11} | {:<11} ",
        "IP地址", "MAC地址", "下载速率", "上传速率", "总下载", "总上传"
    );
    println!("{:-<120}", "");

    // 重新获取锁以读取数据进行显示
    let stats_map = mac_stats.lock().unwrap();

    // 打印每个IP的统计信息
    let mac_stats_data = stats_map.iter().collect::<Vec<_>>();
    for (mac, stats) in mac_stats_data {
        // 获取MAC地址对应的IP
        let ip_str = match mac_ip_mapping.get(mac) {
            Some(ip) => format_ip(ip),
            None => "未知IP".to_string(),
        };

        let mac_str = format_mac(mac);

        // 打印当前 MAC 的统计信息
        println!(
            "{:<18} | {:<18} | {:<16} | {:<15} | {:<14} | {:<15} ",
            ip_str,
            mac_str,
            format_rate(stats.rx_rate),
            format_rate(stats.tx_rate),
            format_bytes(stats.rx_bytes),
            format_bytes(stats.tx_bytes),
        );
    }
}

// 运行服务，同时启动Web服务器和提供TUI输出
async fn run_service(
    port: u16,
    mac_stats: Arc<Mutex<StdHashMap<[u8; 6], MacTrafficStats>>>,
    ingress_ebpf: &mut aya::Ebpf,
    egress_ebpf: &mut aya::Ebpf,
    interface_ip: [u8; 4],
    subnet_mask: [u8; 4],
) -> Result<(), anyhow::Error> {
    info!("启动服务，Web端口: {}", port);

    // 获取映射
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

    let mac_ip_map = HashMap::<&MapData, [u8; 6], [u8; 4]>::try_from(
        egress_ebpf
            .map("MAC_IP_MAPPING")
            .ok_or(anyhow::anyhow!("找不到MAC_IP_MAPPING映射"))?,
    )?;

    // 创建定时器，每秒更新一次
    let mut interval = interval(Duration::from_secs(1));

    // 创建一个控制退出的变量
    let running = Arc::new(Mutex::new(true));
    let r = running.clone();

    // 处理 Ctrl+C 信号
    tokio::spawn(async move {
        if signal::ctrl_c().await.is_ok() {
            info!("正在退出...");
            let mut r = r.lock().unwrap();
            *r = false;
        }
    });

    // 启动Web服务器（在后台运行）
    let web_stats = Arc::clone(&mac_stats);
    tokio::spawn(async move {
        if let Err(e) = web::start_server(port, web_stats).await {
            eprintln!("Web服务器错误: {}", e);
        }
    });

    // 数据收集和TUI显示循环
    while *running.lock().unwrap() {
        interval.tick().await;

        // 更新并显示数据
        update_and_display(
            &mac_stats,
            &ingress_traffic,
            &egress_traffic,
            &mac_ip_map,
            &interface_ip,
            &subnet_mask,
        )
        .await;
    }

    Ok(())
}

// 更新数据并显示界面
async fn update_and_display(
    mac_stats: &Arc<Mutex<StdHashMap<[u8; 6], MacTrafficStats>>>,
    ingress_traffic: &HashMap<&MapData, [u8; 6], [u64; 2]>,
    egress_traffic: &HashMap<&MapData, [u8; 6], [u64; 2]>,
    mac_ip_map: &HashMap<&MapData, [u8; 6], [u8; 4]>,
    interface_ip: &[u8; 4],
    subnet_mask: &[u8; 4],
) {
    // 获取当前时间戳
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64;

    // 收集MAC和IP映射关系
    let mac_ip_mapping: StdHashMap<[u8; 6], [u8; 4]> =
        mac_ip_map.iter().filter_map(|entry| entry.ok()).collect();

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

pub async fn run(opt: Opt) -> Result<(), anyhow::Error> {
    // 设置日志
    env_logger::Builder::new()
        .filter(None, LevelFilter::Info)
        .init();

    let Opt { iface, port } = opt;

    // 初始化eBPF程序
    let (mut ingress_ebpf, mut egress_ebpf) = init_ebpf_programs(iface.clone()).await?;

    // 创建设备统计信息共享数据结构
    let mac_stats = Arc::new(Mutex::new(StdHashMap::<[u8; 6], MacTrafficStats>::new()));

    // 获取接口的IP和子网掩码
    let interface_info = get_interface_info(&iface);
    let (interface_ip, subnet_mask) = interface_info.unwrap_or(([0, 0, 0, 0], [0, 0, 0, 0]));

    // 运行服务（同时启动Web和TUI）
    run_service(
        port,
        mac_stats,
        &mut ingress_ebpf,
        &mut egress_ebpf,
        interface_ip,
        subnet_mask,
    )
    .await?;

    Ok(())
}
