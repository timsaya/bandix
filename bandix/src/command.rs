use crate::ebpf::egress::load_egress;
use crate::ebpf::ingress::load_ingress;
use crate::storage;
use crate::storage::BaselineTotals;
use crate::traffic::update;
use crate::utils::network_utils::get_interface_info;
use crate::web;
use aya::maps::Array;
use bandix_common::MacTrafficStats;
use clap::Parser;
use log::LevelFilter;
use log::{info, warn};
use std::collections::HashMap as StdHashMap;

use crate::utils::format_utils::format_ip;
use std::env;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::signal;
use tokio::time::interval;

// ---- Startup diagnostics ----
fn read_first_line(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.lines().next().map(|l| l.trim().to_string()))
}

fn kernel_version() -> Option<String> {
    // Prefer concise output first
    if let Ok(out) = std::process::Command::new("uname").args(["-sr"]).output() {
        if let Ok(s) = String::from_utf8(out.stdout) {
            return Some(s.trim().to_string());
        }
    }
    // Fallback to /proc/version (verbose)
    read_first_line("/proc/version")
}

fn hostname() -> Option<String> {
    if let Some(h) = read_first_line("/proc/sys/kernel/hostname") {
        return Some(h);
    }
    if let Some(h) = read_first_line("/etc/hostname") {
        return Some(h);
    }
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
}

fn loadavg() -> Option<String> {
    fs::read_to_string("/proc/loadavg").ok().map(|s| {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.len() >= 3 {
            format!("{} {} {}", parts[0], parts[1], parts[2])
        } else {
            s.trim().to_string()
        }
    })
}

fn mem_total_mb() -> Option<u64> {
    // Parse MemTotal: kB
    if let Ok(content) = fs::read_to_string("/proc/meminfo") {
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                let kb: u64 = rest
                    .split_whitespace()
                    .find_map(|t| t.parse().ok())
                    .unwrap_or(0);
                return Some(kb / 1024);
            }
        }
    }
    None
}

fn cpu_model_and_cores() -> Option<(String, usize)> {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    if let Ok(content) = fs::read_to_string("/proc/cpuinfo") {
        for line in content.lines() {
            if let Some(model) = line.strip_prefix("model name\t: ") {
                return Some((model.trim().to_string(), cores));
            }
            if let Some(hardware) = line.strip_prefix("Hardware\t: ") {
                // arm
                return Some((hardware.trim().to_string(), cores));
            }
        }
    }
    Some(("Unknown CPU".to_string(), cores))
}

fn current_user_ids() -> (u32, u32) {
    unsafe {
        let uid = libc::geteuid();
        let gid = libc::getegid();
        (uid as u32, gid as u32)
    }
}

fn parse_openwrt_from_os_release() -> Option<Vec<(String, String)>> {
    let content = fs::read_to_string("/etc/os-release").ok()?;
    let mut pairs: Vec<(String, String)> = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with("OPENWRT_") {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let mut val = v.trim().to_string();
            if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
                val = val[1..val.len() - 1].to_string();
            }
            pairs.push((k.to_string(), val));
        }
    }
    if pairs.is_empty() {
        None
    } else {
        Some(pairs)
    }
}

fn log_startup_info(
    iface: &str,
    port: u16,
    data_dir: &str,
    retention_seconds: u32,
    web_log: bool,
) {
    let app_version = env!("CARGO_PKG_VERSION");
    let (uid, gid) = current_user_ids();
    let cwd = env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
        .unwrap_or_default();
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;

    // Network info
    let iface_info = get_interface_info(iface);
    let (ip_str, mask_str) = if let Some((ip, mask)) = iface_info {
        (format_ip(&ip), format_ip(&mask))
    } else {
        ("0.0.0.0".to_string(), "0.0.0.0".to_string())
    };

    // System info
    let kver = kernel_version().unwrap_or_else(|| "unknown".to_string());
    let host = hostname().unwrap_or_else(|| "unknown".to_string());
    let load = loadavg().unwrap_or_else(|| "unknown".to_string());
    let mem_mb = mem_total_mb().unwrap_or(0);
    let (cpu_model, cores) = cpu_model_and_cores().unwrap_or(("Unknown CPU".to_string(), 1));

    info!("bandix v{} started", app_version);
    info!("Host: {} (uid={}, gid={})", host, uid, gid);
    info!("OS: {}", os);
    info!("Kernel: {}", kver);
    info!("Arch: {}", arch);
    info!("CPU: {} ({} cores)", cpu_model, cores);
    info!("Memory: {} MiB", mem_mb);
    info!("Load: {}", load);
    info!("Working directory: {}", cwd);
    if uid != 0 {
        warn!("It is recommended to run as root to enable eBPF capabilities");
    }
    info!("Listening port: {}", port);
    info!("Data directory: {}", data_dir);
    info!("Retention seconds: {}", retention_seconds);
    info!(
        "Web request logging: {}",
        if web_log { "enabled" } else { "disabled" }
    );
    info!("Interface: {} (IP: {}, Mask: {})", iface, ip_str, mask_str);
    if let Some(kvs) = parse_openwrt_from_os_release() {
        info!("OpenWrt identifiers (/etc/os-release):");
        for (k, v) in kvs {
            info!("{}=\"{}\"", k, v);
        }
    }
    if !Path::new(data_dir).exists() {
        warn!(
            "Data directory does not exist and will be created during runtime: {}",
            data_dir
        );
    }
}

#[derive(Debug, Parser)]
#[clap(name = "bandix")]
#[clap(author = "github.com/timsaya")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
#[clap(about = "Network traffic monitoring based on eBPF for OpenWrt")]
pub struct Opt {
    #[clap(
        short,
        long,
        default_value = "br-lan",
        help = "Network interface to monitor"
    )]
    pub iface: String,

    #[clap(
        short,
        long,
        default_value = "8686",
        help = "Web server listening port"
    )]
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
    pub retention_seconds: u32,

    #[clap(
        long,
        help = "Enable web request logging (per-HTTP-request line)"
    )]
    pub web_log: bool,
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
    web_log: bool,
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
        // 启动时若发现与当前 retention 不一致，立刻重建所有 ring 文件（在读取基线之后执行，避免丢失基线）
        storage::rebuild_all_ring_files_if_mismatch(&data_dir, retention_seconds)?;

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

    // Provide data directory and retention for the web interface (via environment variables to avoid passing through everywhere)
    std::env::set_var("BANDIX_DATA_DIR", &data_dir);
    std::env::set_var("BANDIX_RETENTION_SECONDS", retention_seconds.to_string());

    let mac_stats_clone = Arc::clone(&mac_stats);
    tokio::spawn(async move {
        if let Err(e) = web::start_server(port, mac_stats_clone, web_log).await {
            log::error!("Web server error: {}", e);
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
                ) {
                    log::error!("metrics persist error: {}", e);
                }
            }
        });
    }

    let mut interval = interval(Duration::from_millis(1000));
    while *running.lock().unwrap() {
        interval.tick().await;
        update(
            &mac_stats,
            &mut ingress_ebpf,
            &mut egress_ebpf,
            &baseline_totals,
        )
        .await?;
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
        retention_seconds,
        web_log,
    } = opt;

    // Startup diagnostics
    log_startup_info(&iface, port, &data_dir, retention_seconds, web_log);

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
        web_log,
        ingress_ebpf,
        egress_ebpf,
    )
    .await?;

    Ok(())
}
