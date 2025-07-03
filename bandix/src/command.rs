use crate::ebpf::egress::load_egress;
use crate::ebpf::ingress::load_ingress;
use crate::traffic::update_and_display;
use crate::utils::network_utils::get_interface_info;
use crate::web;
use aya::maps::HashMap;
use aya::maps::MapData;
use bandix_common::MacTrafficStats;
use clap::Parser;
use log::info;
use log::LevelFilter;
use std::collections::HashMap as StdHashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::signal;
use tokio::time::interval;

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "wlo1")]
    pub iface: String,

    #[clap(long, default_value = "8686")]
    pub port: u16,
}

// 初始化eBPF程序和映射
async fn init_ebpf_programs(iface: String) -> Result<(aya::Ebpf, aya::Ebpf), anyhow::Error> {
    let ingress_ebpf = load_ingress(iface.clone()).await?;
    let egress_ebpf = load_egress(iface.clone()).await?;

    Ok((ingress_ebpf, egress_ebpf))
}

// 运行服务，同时启动Web服务器和提供TUI输出
async fn run_service(
    iface: String,
    port: u16,
    ingress_ebpf: &mut aya::Ebpf,
    egress_ebpf: &mut aya::Ebpf,
) -> Result<(), anyhow::Error> {
    // 创建设备统计信息共享数据结构
    let mac_stats = Arc::new(Mutex::new(StdHashMap::<[u8; 6], MacTrafficStats>::new()));

    // 获取接口的IP和子网掩码
    let interface_info = get_interface_info(&iface);
    let (interface_ip, subnet_mask) = interface_info.unwrap_or(([0, 0, 0, 0], [0, 0, 0, 0]));

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

    let mac_ip_mapping = HashMap::<&MapData, [u8; 6], [u8; 4]>::try_from(
        egress_ebpf
            .map("MAC_IP_MAPPING")
            .ok_or(anyhow::anyhow!("找不到MAC_IP_MAPPING映射"))?,
    )?;

    // 创建定时器，每0.1秒更新一次
    let mut interval = interval(Duration::from_millis(100));

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
    let mac_stats_clone = Arc::clone(&mac_stats);
    tokio::spawn(async move {
        if let Err(e) = web::start_server(port, mac_stats_clone).await {
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
            &mac_ip_mapping,
            &interface_ip,
            &subnet_mask,
        )
        .await;
    }

    Ok(())
}

pub async fn run(opt: Opt) -> Result<(), anyhow::Error> {
    // 设置日志
    env_logger::Builder::new()
        .filter(None, LevelFilter::Info)
        .init();

    let Opt { iface, port } = opt;

    // 初始化eBPF程序
    let (mut ingress_ebpf, mut egress_ebpf) = init_ebpf_programs(iface.clone()).await?;

    // 运行服务（同时启动Web和TUI）
    run_service(iface, port, &mut ingress_ebpf, &mut egress_ebpf).await?;

    Ok(())
}
