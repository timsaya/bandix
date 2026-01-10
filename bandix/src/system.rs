use crate::command::Options;
use crate::utils::format_utils::format_ip;
use crate::utils::network_utils::get_interface_info;
use log::{info, warn};
use std::env;
use std::fs;
use std::path::Path;

// ---- 启动诊断信息 ----
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
    // 解析MemTotal: kB
    if let Ok(content) = fs::read_to_string("/proc/meminfo") {
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                let kb: u64 = rest.split_whitespace().find_map(|t| t.parse().ok()).unwrap_or(0);
                return Some(kb / 1024);
            }
        }
    }
    None
}

fn cpu_model_and_cores() -> Option<(String, usize)> {
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
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

pub fn log_startup_info(options: &Options) {
    let app_version = env!("CARGO_PKG_VERSION");
    let (uid, gid) = current_user_ids();
    let cwd = env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
        .unwrap_or_default();
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;

    // Network info
    let iface_info = get_interface_info(options.iface());
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
    info!("Listening port: {}", options.port());
    info!("Data directory: {}", options.data_dir());
    info!("Log level: {}", options.log_level());
    info!("Retention seconds: {}", options.traffic_retention_seconds());
    info!("Interface: {} (IP: {}, Mask: {})", options.iface(), ip_str, mask_str);

    // Display enabled monitoring modules with their configurations
    let mut enabled_count = 0;

    if options.enable_traffic() {
        enabled_count += 1;
    }
    if options.enable_dns() {
        enabled_count += 1;
    }
    if options.enable_connection() {
        enabled_count += 1;
    }

    if enabled_count == 0 {
        info!("Enabled monitoring modules: None");
    } else {
        info!("Enabled monitoring modules ({}):", enabled_count);

        if options.enable_traffic() {
            info!("  • Traffic monitoring (retention: {}s)", options.traffic_retention_seconds());
        }

        if options.enable_dns() {
            info!("  • DNS monitoring");
        }

        if options.enable_connection() {
            info!("  • Connection statistics monitoring");
        }
    }

    if let Some(kvs) = parse_openwrt_from_os_release() {
        info!("OpenWrt identifiers (/etc/os-release):");
        for (k, v) in kvs {
            info!("{}=\"{}\"", k, v);
        }
    }
    if !Path::new(options.data_dir()).exists() {
        warn!(
            "Data directory does not exist and will be created during runtime: {}",
            options.data_dir()
        );
    }
}
