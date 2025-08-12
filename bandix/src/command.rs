use crate::ebpf::egress::load_egress;
use crate::ebpf::ingress::load_ingress;
use crate::storage;
use crate::traffic::update;
use std::collections::HashMap as StdHashMap;
use crate::storage::BaselineTotals;
use crate::utils::network_utils::get_interface_info;
use crate::web;
use aya::maps::Array;
use bandix_common::MacTrafficStats;
use clap::Parser;
use log::info;
use log::LevelFilter;

use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::signal;
use tokio::time::interval;

#[derive(Debug, Parser)]
#[clap(name = "bandix")]
#[clap(author = "github.com/timsaya")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
#[clap(about = "Network traffic monitoring based on eBPF for OpenWrt")]
pub struct Opt {
    #[clap(short, long, default_value = "br-lan", help = "Network interface to monitor")]
    pub iface: String,

    #[clap(short, long, default_value = "8686", help = "Web server listening port")]
    pub port: u16,

    #[clap(
        long,
        default_value = "bandix-data",
        help = "Data directory (ring files and rate limit configurations will be stored here)"
    )]
    pub data_dir: String,

    #[clap(
        long,
        default_value = "3600",
        help = "Retention duration (seconds), i.e., ring file capacity (one slot per second)"
    )]
    pub retention_seconds: u32,
}

// Initialize eBPF programs and maps
async fn init_ebpf_programs(iface: String) -> Result<(aya::Ebpf, aya::Ebpf), anyhow::Error> {
    let egress_ebpf = load_egress(iface.clone()).await?;
    let ingress_ebpf = load_ingress(iface.clone()).await?;

    Ok((ingress_ebpf, egress_ebpf))
}

// Initialize subnet configuration
async fn init_subnet_info(
    egress_ebpf: &mut aya::Ebpf,
    ingress_ebpf: &mut aya::Ebpf,
    iface: String,
) -> Result<(), anyhow::Error> {
    // Subnet configuration
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

// Run service, start web server and provide TUI output
async fn run_service(
    _iface: String,
    port: u16,
    data_dir: String,
    retention_seconds: u32,
    mut ingress_ebpf: aya::Ebpf,
    mut egress_ebpf: aya::Ebpf,
) -> Result<(), anyhow::Error> {
    let mac_stats = Arc::new(Mutex::new(StdHashMap::<[u8; 6], MacTrafficStats>::new()));
    let baseline_totals = Arc::new(Mutex::new(StdHashMap::<[u8; 6], BaselineTotals>::new()));

    let running = Arc::new(Mutex::new(true));
    let r: Arc<Mutex<bool>> = running.clone();

    tokio::spawn(async move {
        if signal::ctrl_c().await.is_ok() {
            info!("Exiting...");
            let mut r = r.lock().unwrap();
            *r = false;
        }
    });

    // Initialize data directory and load rate limits and baseline traffic
    {
        storage::ensure_schema(&data_dir)?;
        let limits = storage::load_all_limits(&data_dir)?;
        let latest = storage::load_latest_totals(&data_dir)?;

        // Rate limits
        {
            let mut stats_map = mac_stats.lock().unwrap();
            for (mac, rx, tx) in limits {
                let entry = stats_map.entry(mac).or_default();
                entry.wide_rx_rate_limit = rx;
                entry.wide_tx_rate_limit = tx;
            }
        }

        // Baseline totals
        {
            let mut b = baseline_totals.lock().unwrap();
            for (mac, base) in latest {
                b.insert(mac, base);
            }
        }
    }

    // Provide data directory for the web interface (via environment variable to avoid passing through everywhere)
    std::env::set_var("BANDIX_DATA_DIR", &data_dir);

    let mac_stats_clone = Arc::clone(&mac_stats);
    tokio::spawn(async move {
        if let Err(e) = web::start_server(port, mac_stats_clone).await {
            eprintln!("Web server error: {}", e);
        }
    });

    // Metrics persistence task
    {
        let mac_stats_for_metrics = Arc::clone(&mac_stats);
        let data_dir_for_metrics = data_dir.clone();
        let retention_seconds_for_metrics = retention_seconds;
        tokio::spawn(async move {
            let mut metrics_interval = interval(Duration::from_secs(1));
            loop {
                metrics_interval.tick().await;
                use std::time::{SystemTime, UNIX_EPOCH};
                let ts_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::from_secs(0))
                    .as_millis() as u64;
                let snapshot: Vec<([u8; 6], MacTrafficStats)> = {
                    let stats = mac_stats_for_metrics.lock().unwrap();
                    stats.iter().map(|(k, v)| (*k, *v)).collect()
                };
                if let Err(e) = storage::insert_metrics_batch(
                    &data_dir_for_metrics,
                    ts_ms,
                    &snapshot,
                    retention_seconds_for_metrics,
                )
                {
                    eprintln!("metrics persist error: {}", e);
                }
            }
        });
    }

    let mut interval = interval(Duration::from_millis(1000));
    while *running.lock().unwrap() {
        interval.tick().await;
        update(&mac_stats, &mut ingress_ebpf, &mut egress_ebpf, &baseline_totals).await?;
    }

    Ok(())
}

pub async fn run(opt: Opt) -> Result<(), anyhow::Error> {
    // Set up logging
    env_logger::Builder::new()
        .filter(None, LevelFilter::Info)
        .init();

    let Opt { iface, port, data_dir, retention_seconds } = opt;

    // Initialize eBPF programs
    let (mut ingress_ebpf, mut egress_ebpf) = init_ebpf_programs(iface.clone()).await?;

    // Initialize subnet configuration
    init_subnet_info(&mut ingress_ebpf, &mut egress_ebpf, iface.clone()).await?;

    // Run service (start web and TUI)
    run_service(
        iface,
        port,
        data_dir,
        retention_seconds,
        ingress_ebpf,
        egress_ebpf,
    )
    .await?;

    Ok(())
}
