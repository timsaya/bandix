use crate::ebpf::egress::load_egress;
use crate::ebpf::ingress::load_ingress;
use crate::monitor::{MonitorConfig, MonitorManager};
use crate::storage;
use crate::storage::BaselineTotals;
use crate::system::log_startup_info;
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
#[clap(name = "bandix")]
#[clap(author = "github.com/timsaya")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
#[clap(about = "Network traffic monitoring based on eBPF for OpenWrt")]
pub struct Opt {
    #[clap(long, help = "Network interface to monitor (required)")]
    pub iface: String,

    #[clap(long, default_value = "8686", help = "Web server listening port")]
    pub port: u16,

    #[clap(
        long,
        default_value = "bandix-data",
        help = "Data directory (ring files and rate limit configurations will be stored here)"
    )]
    pub data_dir: String,

    #[clap(
        long,
        default_value = "600",
        help = "Retention duration (seconds), i.e., ring file capacity (one slot per second)"
    )]
    pub traffic_retention_seconds: u32,

    #[clap(
        long,
        default_value = "false",
        help = "Enable web request logging (per-HTTP-request line)"
    )]
    pub web_log: bool,

    #[clap(
        long,
        default_value = "false",
        help = "Enable traffic monitoring module"
    )]
    pub enable_traffic: bool,

    #[clap(
        long,
        default_value = "false",
        help = "Enable DNS monitoring module (not yet implemented)"
    )]
    pub enable_dns: bool,
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
    // Configure subnet information for eBPF maps
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
    traffic_retention_seconds: u32,
    web_log: bool,
    monitor_config: MonitorConfig,
    preloaded_baselines: Vec<([u8; 6], BaselineTotals)>,
    ebpf_programs: Option<(aya::Ebpf, aya::Ebpf)>,
) -> Result<(), anyhow::Error> {
    let mac_stats = Arc::new(Mutex::new(StdHashMap::<[u8; 6], MacTrafficStats>::new()));
    let baseline_totals = Arc::new(Mutex::new(StdHashMap::<[u8; 6], BaselineTotals>::new()));
    let rate_limits = Arc::new(Mutex::new(StdHashMap::<[u8; 6], [u64; 2]>::new()));

    let running = Arc::new(Mutex::new(true));
    let r: Arc<Mutex<bool>> = running.clone();

    tokio::spawn(async move {
        if signal::ctrl_c().await.is_ok() {
            info!("Exiting...");
            let mut r = r.lock().unwrap();
            *r = false;
        }
    });

    // Initialize data directory and load rate limits, apply preloaded baselines
    {
        storage::ensure_schema(&data_dir)?;
        let limits = storage::load_all_limits(&data_dir)?;

        // Load rate limits into dedicated map; do NOT write mac_stats
        {
            let mut rl = rate_limits.lock().unwrap();
            for (mac, rx, tx) in limits {
                rl.insert(mac, [rx, tx]);
            }
        }

        // Baseline totals (use preloaded values from before potential rebuild)
        {
            let mut b = baseline_totals.lock().unwrap();
            for (mac, base) in preloaded_baselines {
                b.insert(mac, base);
            }
        }
    }

    // Provide data directory and retention for the web interface (via environment variables to avoid passing through everywhere)
    std::env::set_var("BANDIX_DATA_DIR", &data_dir);
    std::env::set_var(
        "BANDIX_TRAFFIC_RETENTION_SECONDS",
        traffic_retention_seconds.to_string(),
    );

    let mac_stats_clone = Arc::clone(&mac_stats);
    let rate_limits_clone = Arc::clone(&rate_limits);
    tokio::spawn(async move {
        if let Err(e) = web::start_server(port, mac_stats_clone, rate_limits_clone, web_log).await {
            log::error!("Web server error: {}", e);
        }
    });

    // Metrics persistence task
    {
        let mac_stats_for_metrics = Arc::clone(&mac_stats);
        let data_dir_for_metrics = data_dir.clone();
        let traffic_retention_seconds_for_metrics = traffic_retention_seconds;
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
                    traffic_retention_seconds_for_metrics,
                ) {
                    log::error!("metrics persist error: {}", e);
                }
            }
        });
    }

    // At least one monitoring module is guaranteed to be enabled (checked in run function)

    // If eBPF programs are available, start monitoring loop
    if let Some((mut ingress_ebpf, mut egress_ebpf)) = ebpf_programs {
        // Create monitor manager
        let monitor_manager = MonitorManager::new(monitor_config.clone());

        let mut interval = interval(Duration::from_millis(1000));
        while *running.lock().unwrap() {
            interval.tick().await;

            // Start monitors (at least one monitoring module is guaranteed to be enabled)
            monitor_manager
                .start_monitors(
                    &mac_stats,
                    &mut ingress_ebpf,
                    &mut egress_ebpf,
                    &baseline_totals,
                    &rate_limits,
                )
                .await?;
        }
    } else {
        // No eBPF programs needed but monitoring modules are enabled (e.g., DNS-only monitoring)
        log::info!("Current monitoring modules don't require eBPF programs, running with web service only");
        while *running.lock().unwrap() {
            tokio::time::sleep(Duration::from_millis(1000)).await;
        }
    }

    Ok(())
}

pub async fn run(opt: Opt) -> Result<(), anyhow::Error> {
    // Set up logging
    env_logger::Builder::new()
        .filter(None, LevelFilter::Info)
        .target(env_logger::Target::Stdout)
        .init();

    let Opt {
        iface,
        port,
        data_dir,
        traffic_retention_seconds,
        web_log,
        enable_traffic,
        enable_dns,
    } = opt;

    // Create monitoring configuration
    let mut monitor_config = MonitorConfig::new();
    if enable_traffic {
        monitor_config = monitor_config.enable_traffic();
    }
    if enable_dns {
        monitor_config = monitor_config.enable_dns();
    }

    // Exit if no monitoring modules are enabled
    if !monitor_config.is_any_enabled() {
        return Err(anyhow::anyhow!(
            "No monitoring modules enabled. Use --enable-traffic to enable traffic monitoring, or --enable-dns to enable DNS monitoring"
        ));
    }

    // Startup diagnostics
    log_startup_info(
        &iface,
        port,
        &data_dir,
        traffic_retention_seconds,
        web_log,
        &monitor_config,
    );

    // Ensure data schema, and rebuild ring files if retention mismatch before eBPF init
    storage::ensure_schema(&data_dir)?;
    let rebuilt =
        storage::rebuild_all_ring_files_if_mismatch(&data_dir, traffic_retention_seconds)?;
    // Decide baseline: if rebuilt, start from zero; otherwise load latest totals
    let preloaded_baselines = if rebuilt {
        Vec::new()
    } else {
        storage::load_latest_totals(&data_dir)?
    };

    // Initialize eBPF programs only if traffic monitoring is enabled
    let ebpf_programs = if monitor_config.enable_traffic {
        log::info!("Traffic monitoring enabled, initializing eBPF programs...");
        let (mut ingress, mut egress) = init_ebpf_programs(iface.clone()).await?;
        // Initialize subnet configuration
        init_subnet_info(&mut ingress, &mut egress, iface.clone()).await?;
        Some((ingress, egress))
    } else {
        log::info!("No eBPF-required monitoring modules enabled, skipping eBPF initialization");
        None
    };

    // Run service (start web and TUI)
    run_service(
        iface,
        port,
        data_dir,
        traffic_retention_seconds,
        web_log,
        monitor_config,
        preloaded_baselines,
        ebpf_programs,
    )
    .await?;

    Ok(())
}
