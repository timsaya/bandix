use crate::ebpf::egress::load_egress;
use crate::ebpf::ingress::load_ingress;
use crate::traffic::update;
use crate::utils::network_utils::get_interface_info;
use crate::web;
use aya::maps::Array;
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
    let egress_ebpf = load_egress(iface.clone()).await?;
    let ingress_ebpf = load_ingress(iface.clone()).await?;

    Ok((ingress_ebpf, egress_ebpf))
}

// 初始化子网配置
async fn init_subnet_info(
    egress_ebpf: &mut aya::Ebpf,
    ingress_ebpf: &mut aya::Ebpf,
    iface: String,
) -> Result<(), anyhow::Error> {
    // 子网配置
    let interface_info = get_interface_info(&iface);
    let (interface_ip, subnet_mask) = interface_info.unwrap_or(([0, 0, 0, 0], [0, 0, 0, 0]));

    let mut subnet_info: Array<_, [u8; 4]> =
        Array::try_from(ingress_ebpf.take_map("SUBNET_INFO").unwrap())?;

    subnet_info.set(0, &interface_ip, 0)?;
    subnet_info.set(1, &subnet_mask, 0)?;

    let mut subnet_info: Array<_, [u8; 4]> =
        Array::try_from(egress_ebpf.take_map("SUBNET_INFO").unwrap())?;
    subnet_info.set(0, &interface_ip, 0)?;
    subnet_info.set(1, &subnet_mask, 0)?;

    Ok(())
}

// 运行服务，同时启动Web服务器和提供TUI输出
async fn run_service(
    _iface: String,
    port: u16,
    mut ingress_ebpf: aya::Ebpf,
    mut egress_ebpf: aya::Ebpf,
) -> Result<(), anyhow::Error> {
    let mac_stats = Arc::new(Mutex::new(StdHashMap::<[u8; 6], MacTrafficStats>::new()));

    let running = Arc::new(Mutex::new(true));
    let r: Arc<Mutex<bool>> = running.clone();

    tokio::spawn(async move {
        if signal::ctrl_c().await.is_ok() {
            info!("正在退出...");
            let mut r = r.lock().unwrap();
            *r = false;
        }
    });

    let mac_stats_clone = Arc::clone(&mac_stats);
    tokio::spawn(async move {
        if let Err(e) = web::start_server(port, mac_stats_clone).await {
            eprintln!("Web服务器错误: {}", e);
        }
    });

    let mut interval = interval(Duration::from_millis(1000));
    while *running.lock().unwrap() {
        interval.tick().await;
        update(&mac_stats, &mut ingress_ebpf, &mut egress_ebpf).await?;
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

    // 初始化子网配置
    init_subnet_info(&mut ingress_ebpf, &mut egress_ebpf, iface.clone()).await?;

    // 运行服务（同时启动Web和TUI）
    run_service(iface, port, ingress_ebpf, egress_ebpf).await?;

    Ok(())
}
