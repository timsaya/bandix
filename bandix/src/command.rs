use crate::device::DeviceManager;
use crate::storage::device_registry::DeviceRegistry;
use std::path::Path;

use crate::ebpf::shared::load_shared;
use crate::monitor::{
    ConnectionModuleContext, DnsModuleContext, ModuleContext, MonitorManager, TrafficModuleContext,
};
use crate::system::log_startup_info;
use crate::utils::network_utils::get_interface_info;
use crate::web;
use aya::maps::Array;
use clap::{Args, Parser};
use log::info;
use log::LevelFilter;
use std::sync::Arc;
use tokio::signal;

/// 所有命令共享的通用参数
#[derive(Debug, Args, Clone)]
pub struct CommonArgs {
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
        default_value = "info",
        help = "Log level: trace, debug, info, warn, error (default: info). Web and DNS logs are always at DEBUG level."
    )]
    pub log_level: String,
}

/// 流量模块参数
#[derive(Debug, Args, Clone)]
#[clap(group = clap::ArgGroup::new("traffic").multiple(false))]
pub struct TrafficArgs {
    #[clap(
        long,
        default_value = "false",
        help = "Enable traffic monitoring module"
    )]
    pub enable_traffic: bool,

    #[clap(
        long,
        default_value = "600",
        help = "Retention duration (seconds), i.e., ring file capacity (one slot per second)"
    )]
    pub traffic_retention_seconds: u32,

    #[clap(
        long,
        default_value = "600",
        help = "Traffic data flush interval (seconds), how often to persist memory ring data to disk"
    )]
    pub traffic_flush_interval_seconds: u32,

    #[clap(
        long,
        default_value = "false",
        help = "Enable traffic history data persistence to disk (disabled by default, data only stored in memory)"
    )]
    pub traffic_persist_history: bool,
}

/// DNS 模块参数
#[derive(Debug, Args, Clone)]
pub struct DnsArgs {
    #[clap(long, default_value = "false", help = "Enable DNS monitoring module")]
    pub enable_dns: bool,

    #[clap(
        long,
        default_value = "10000",
        help = "Maximum number of DNS records to keep in memory (default: 10000)"
    )]
    pub dns_max_records: usize,
}

/// 连接模块参数
#[derive(Debug, Args, Clone)]
pub struct ConnectionArgs {
    #[clap(
        long,
        default_value = "false",
        help = "Enable connection statistics monitoring module"
    )]
    pub enable_connection: bool,
}

#[derive(Debug, Parser, Clone)]
#[clap(name = "bandix")]
#[clap(author = "github.com/timsaya")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
#[clap(about = "Network traffic monitoring based on eBPF for OpenWrt")]
pub struct Options {
    #[clap(flatten)]
    pub common: CommonArgs,

    #[clap(flatten)]
    pub traffic: TrafficArgs,

    #[clap(flatten)]
    pub dns: DnsArgs,

    #[clap(flatten)]
    pub connection: ConnectionArgs,
}

impl Options {
    /// 从通用参数获取接口
    pub fn iface(&self) -> &str {
        &self.common.iface
    }

    /// 从通用参数获取端口
    pub fn port(&self) -> u16 {
        self.common.port
    }

    /// 从通用参数获取数据目录
    pub fn data_dir(&self) -> &str {
        &self.common.data_dir
    }

    /// 从通用参数获取日志级别
    pub fn log_level(&self) -> &str {
        &self.common.log_level
    }

    /// 从流量参数获取启用流量
    pub fn enable_traffic(&self) -> bool {
        self.traffic.enable_traffic
    }

    /// 从流量参数获取流量保留秒数
    pub fn traffic_retention_seconds(&self) -> u32 {
        self.traffic.traffic_retention_seconds
    }

    /// 从流量参数获取流量刷新间隔秒数
    pub fn traffic_flush_interval_seconds(&self) -> u32 {
        self.traffic.traffic_flush_interval_seconds
    }

    /// 从流量参数获取流量持久化历史
    pub fn traffic_persist_history(&self) -> bool {
        self.traffic.traffic_persist_history
    }

    /// 从 DNS 参数获取启用 DNS
    pub fn enable_dns(&self) -> bool {
        self.dns.enable_dns
    }

    /// 从 DNS 参数获取 DNS 最大记录数
    pub fn dns_max_records(&self) -> usize {
        self.dns.dns_max_records
    }

    /// 从连接参数获取启用连接
    pub fn enable_connection(&self) -> bool {
        self.connection.enable_connection
    }
}

// 验证参数
fn validate_arguments(opt: &Options) -> Result<(), anyhow::Error> {
    // 检查网络接口是否存在
    if get_interface_info(opt.iface()).is_none() {
        return Err(anyhow::anyhow!(
            "Network interface '{}' does not exist",
            opt.iface()
        ));
    }

    // 检查端口是否有效（0-65535）
    if opt.port() == 0 {
        return Err(anyhow::anyhow!("Port number cannot be 0"));
    }

    // 仅在启用流量模块时验证流量特定参数
    if opt.enable_traffic() {
        if opt.traffic_retention_seconds() == 0 {
            return Err(anyhow::anyhow!(
                "traffic_retention_seconds must be greater than 0"
            ));
        }

        if opt.traffic_flush_interval_seconds() == 0 {
            return Err(anyhow::anyhow!(
                "traffic_flush_interval_seconds must be greater than 0"
            ));
        }
    }

    Ok(())
}

fn load_hostname_bindings(
    data_dir: &str,
) -> std::sync::Arc<std::sync::Mutex<std::collections::HashMap<[u8; 6], String>>> {
    let bindings = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    // 从文件加载现有主机名绑定（优先来源）
    let mut bindings_count = 0;
    if let Ok(loaded_bindings) = crate::storage::hostname::load_hostname_bindings(data_dir) {
        let mut bindings_map = bindings.lock().unwrap();
        for (mac, hostname) in loaded_bindings {
            bindings_map.insert(mac, hostname);
            bindings_count += 1;
        }
        log::info!(
            "Loaded {} hostname bindings from saved file",
            bindings_count
        );
    } else {
        log::warn!("Failed to load hostname bindings from saved file");
    }

    // 从 ubus 加载额外的主机名绑定（备用来源）
    if let Ok(ubus_bindings) = crate::storage::hostname::load_hostname_from_ubus() {
        let mut bindings_map = bindings.lock().unwrap();
        let mut ubus_count = 0;
        for (mac, hostname) in ubus_bindings {
            if !bindings_map.contains_key(&mac) {
                bindings_map.insert(mac, hostname);
                ubus_count += 1;
            }
        }
        if ubus_count > 0 {
            log::info!(
                "Loaded {} additional hostname bindings from ubus",
                ubus_count
            );
        }
    }

    bindings
}

// 初始化共享的 eBPF 程序（被流量和 DNS 模块共同使用）
async fn init_shared_ebpf(options: &Options) -> Result<aya::Ebpf, anyhow::Error> {
    load_shared(options.iface().to_string()).await
}

// 子网信息结构体（跨模块共享）
#[derive(Debug, Clone)]
pub struct SubnetInfo {
    pub interface_ip: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub interface_mac: [u8; 6],
    pub ipv6_addresses: Vec<([u8; 16], u8)>,
}

impl SubnetInfo {
    pub fn from_interface(iface: &str) -> Result<Self, anyhow::Error> {
        let interface_info = get_interface_info(iface);

        let (interface_ip, subnet_mask) = interface_info.ok_or_else(|| {
            anyhow::anyhow!("Failed to get interface information for '{}'", iface)
        })?;

        let interface_mac = std::fs::read_to_string(format!("/sys/class/net/{}/address", iface))
            .ok()
            .and_then(|content| crate::utils::network_utils::parse_mac_address(content.trim()).ok())
            .unwrap_or([0, 0, 0, 0, 0, 0]);

        let ipv6_addresses = crate::utils::network_utils::get_interface_ipv6_info(iface);

        Ok(SubnetInfo {
            interface_ip,
            subnet_mask,
            interface_mac,
            ipv6_addresses,
        })
    }
}

// 创建模块上下文：加载 eBPF 程序，配置内核映射，并创建上下文对象
async fn create_module_contexts(
    options: &Options,
    subnet_info: &SubnetInfo,
    shared_hostname_bindings: &std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<[u8; 6], String>>,
    >,
    device_manager: Arc<DeviceManager>,
) -> Result<Vec<ModuleContext>, anyhow::Error> {
    let mut module_contexts = Vec::new();

    // 如果启用了流量或 DNS 模块，则加载共享的 eBPF 程序
    let shared_ebpf = if options.enable_traffic() || options.enable_dns() {
        log::info!("Loading shared eBPF programs (ingress and egress)...");
        let mut ebpf = init_shared_ebpf(options).await?;

        // 如果启用了流量模块，则配置子网信息映射
        if options.enable_traffic() {
            log::info!("Configuring subnet info maps for traffic module...");

            // 配置 IPv4 子网信息映射
            let mut ipv4_subnet_info: Array<_, [u8; 4]> =
                Array::try_from(ebpf.take_map("IPV4_SUBNET_INFO").unwrap())?;
            ipv4_subnet_info.set(0, &subnet_info.interface_ip, 0)?;
            ipv4_subnet_info.set(1, &subnet_info.subnet_mask, 0)?;

            // 配置 IPv6 子网信息映射
            let mut ipv6_subnet_info: Array<_, [u8; 32]> =
                Array::try_from(ebpf.take_map("IPV6_SUBNET_INFO").unwrap())?;

            for i in 0..16 {
                ipv6_subnet_info.set(i, &[0u8; 32], 0)?;
            }

            for (idx, (ipv6_addr, prefix_len)) in
                subnet_info.ipv6_addresses.iter().enumerate().take(16)
            {
                let mut subnet_data = [0u8; 32];
                subnet_data[0..16].copy_from_slice(ipv6_addr);
                subnet_data[16] = *prefix_len;
                subnet_data[17] = 1;
                ipv6_subnet_info.set(idx as u32, &subnet_data, 0)?;

                let addr_type = crate::utils::network_utils::classify_ipv6_address(ipv6_addr);
                log::info!(
                    "Configured IPv6 subnet {}: {}/{} [Type: {}, Network: {}]",
                    idx,
                    crate::utils::network_utils::format_ipv6_with_privacy(ipv6_addr),
                    prefix_len,
                    addr_type.type_name(),
                    addr_type.network_scope()
                );
            }
        }

        Some(ebpf)
    } else {
        None
    };

    // 配置模块启用标志，如果需要则获取 DNS 映射
    // 这需要对 eBPF 对象的独占访问，因此我们在创建上下文之前完成
    if let Some(mut ebpf) = shared_ebpf {
        // 配置模块启用标志
        log::info!("Configuring module enable flags...");
        let mut module_flags: Array<_, u8> = Array::try_from(
            ebpf.take_map("MODULE_ENABLE_FLAGS")
                .ok_or_else(|| anyhow::anyhow!("Cannot find MODULE_ENABLE_FLAGS map"))?,
        )?;

        // 设置traffic module flag (index 0)
        let traffic_flag = if options.enable_traffic() { 1u8 } else { 0u8 };
        module_flags.set(0, &traffic_flag, 0)?;
        log::info!("Traffic module enabled: {}", traffic_flag != 0);

        // 设置DNS module flag (index 1)
        let dns_flag = if options.enable_dns() { 1u8 } else { 0u8 };
        module_flags.set(1, &dns_flag, 0)?;
        log::info!("DNS module enabled: {}", dns_flag != 0);

        let dns_map = if options.enable_dns() {
            // 在包装到 Arc 之前获取 DNS_DATA RingBuf 映射
            // 这是必要的，因为 take_map 需要独占访问
            log::info!("Acquiring DNS RingBuf map...");
            Some(ebpf.take_map("DNS_DATA").ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot find DNS_DATA map. Make sure DNS eBPF programs are loaded correctly."
                )
            })?)
        } else {
            None
        };

        // 现在包装到 Arc 中，以便两个模块可以共享
        let shared_ebpf_arc = Arc::new(ebpf);

        // 初始化流量模块
        if options.enable_traffic() {
            log::info!("Initializing traffic module...");

            // 创建对共享 eBPF 对象的引用
            let ingress = Arc::clone(&shared_ebpf_arc);
            let egress = Arc::clone(&shared_ebpf_arc);

            // 创建流量模块上下文（使用共享的 device_manager）
            let mut traffic_ctx = TrafficModuleContext::new(
                options.clone(),
                ingress,
                egress,
                Arc::clone(&device_manager),
            );
            traffic_ctx.hostname_bindings = std::sync::Arc::clone(shared_hostname_bindings);

            module_contexts.push(ModuleContext::Traffic(traffic_ctx));
        }

        // 初始化 DNS 模块
        if options.enable_dns() {
            log::info!("Initializing DNS module...");

            // 创建对共享 eBPF 对象的引用
            let ingress = Arc::clone(&shared_ebpf_arc);
            let egress = Arc::clone(&shared_ebpf_arc);

            // 使用预获取的映射创建 DNS 模块上下文
            let dns_ctx = DnsModuleContext::new_with_map(
                options.clone(),
                ingress,
                egress,
                dns_map.unwrap(),
                std::sync::Arc::clone(shared_hostname_bindings),
            );
            module_contexts.push(ModuleContext::Dns(dns_ctx));
        }
    }

    // 初始化连接模块
    if options.enable_connection() {
        log::info!("Initializing connection module...");

        // 创建连接模块上下文
        let connection_ctx = ConnectionModuleContext::new(
            options.clone(),
            std::sync::Arc::clone(shared_hostname_bindings),
            subnet_info.interface_ip,
            subnet_info.subnet_mask,
        );
        module_contexts.push(ModuleContext::Connection(connection_ctx));
    }

    Ok(module_contexts)
}

// 启动设备刷新任务：定期刷新 ARP 表并更新设备注册表
fn start_device_refresh_task(
    device_manager: Arc<DeviceManager>,
    device_registry: Arc<DeviceRegistry>,
    data_dir: String,
    shutdown_notify: Arc<tokio::sync::Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // 定期 ARP 表刷新（每30秒）
                    if let Err(e) = device_manager.refresh_arp_table() {
                        log::warn!("Failed to refresh ARP table: {}", e);
                    } else {
                        log::debug!("Periodic ARP table refresh completed");
                    }

                    // 定期保存设备注册表
                    let registry_path = Path::new(&data_dir).join("devices.json");
                    if let Err(e) = device_registry.save_to_file(&registry_path) {
                        log::warn!("Failed to save device registry: {}", e);
                    }
                }
                _ = shutdown_notify.notified() => {
                    log::info!("Device refresh task received shutdown signal, stopping...");
                    // 关闭前的最终保存
                    let registry_path = Path::new(&data_dir).join("devices.json");
                    if let Err(e) = device_registry.save_to_file(&registry_path) {
                        log::error!("Failed to save device registry during shutdown: {}", e);
                    }
                    break;
                }
            }
        }
    })
}

// 启动主机名刷新任务：定期从 ubus 更新主机名绑定
fn start_hostname_refresh_task(
    shared_hostname_bindings: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<[u8; 6], String>>,
    >,
    options: Options,
    shutdown_notify: Arc<tokio::sync::Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(600));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // 从 ubus 加载主机名绑定（如果 ubus 不可用则静默失败）
                    if let Ok(ubus_bindings) = crate::storage::hostname::load_hostname_from_ubus() {
                        let mut bindings_map = shared_hostname_bindings.lock().unwrap();
                        let mut updated_count = 0;

                        // 加载保存的绑定以检查优先级
                        let saved_bindings = crate::storage::hostname::load_hostname_bindings(options.data_dir())
                            .unwrap_or_default();
                        let saved_macs: std::collections::HashSet<[u8; 6]> =
                            saved_bindings.iter().map(|(mac, _)| *mac).collect();

                        for (mac, hostname) in ubus_bindings {
                            // 仅在未手动设置时更新（不在保存的绑定中）
                            if !saved_macs.contains(&mac) {
                                if let Some(existing) = bindings_map.get(&mac) {
                                    if existing != &hostname {
                                        bindings_map.insert(mac, hostname);
                                        updated_count += 1;
                                    }
                                } else {
                                    bindings_map.insert(mac, hostname);
                                    updated_count += 1;
                                }
                            }
                        }

                        if updated_count > 0 {
                            log::debug!("Updated {} hostname bindings from ubus", updated_count);
                        }
                    }
                }
                _ = shutdown_notify.notified() => {
                    log::info!("Hostname refresh task received shutdown signal, stopping...");
                    break;
                }
            }
        }
    })
}

// 运行服务，启动 Web 服务器
async fn run_service(options: &Options) -> Result<(), anyhow::Error> {
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());
    let shutdown_notify_clone = shutdown_notify.clone();
    let shutdown_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_flag_clone = shutdown_flag.clone();

    tokio::spawn(async move {
        if signal::ctrl_c().await.is_ok() {
            info!("Received shutdown signal, gracefully shutting down...");
            shutdown_flag_clone.store(true, std::sync::atomic::Ordering::Relaxed);
            shutdown_notify_clone.notify_waiters();
        }
    });

    let subnet_info = SubnetInfo::from_interface(options.iface())?;

    let shared_hostname_bindings = load_hostname_bindings(options.data_dir());

    let device_registry = Arc::new(DeviceRegistry::new());
    let device_manager = Arc::new(DeviceManager::new(
        options.iface().to_string(),
        subnet_info.clone(),
        Arc::clone(&device_registry),
        Some(shutdown_flag.clone()),
    ));

    if let Err(e) = device_manager.load_initial_devices(options.data_dir()) {
        if shutdown_flag.load(std::sync::atomic::Ordering::Relaxed) {
            log::info!("Initial device loading interrupted by shutdown signal");
            shutdown_notify.notify_waiters();
            return Ok(());
        } else {
            log::warn!("Failed to load initial devices: {}", e);
        }
    }

    // 创建模块上下文：加载 eBPF 程序并配置内核映射
    let module_contexts = create_module_contexts(
        options,
        &subnet_info,
        &shared_hostname_bindings,
        Arc::clone(&device_manager),
    )
    .await?;

    // 初始化模块
    let mut monitor_manager = MonitorManager::from_contexts(&module_contexts);
    monitor_manager.init_modules(&module_contexts).await?;

    // 使用 API 路由器启动 Web 服务器
    let api_router = monitor_manager.get_api_router().clone();
    let options_for_web = options.clone();
    let shutdown_notify_for_web = shutdown_notify.clone();
    let web_task = tokio::spawn(async move {
        if let Err(e) =
            web::start_server(options_for_web, api_router, shutdown_notify_for_web).await
        {
            log::error!("Web server error: {}", e);
        }
    });

    // 启动主机名刷新任务
    let hostname_refresh_task = start_hostname_refresh_task(
        Arc::clone(&shared_hostname_bindings),
        options.clone(),
        shutdown_notify.clone(),
    );

    // 启动设备刷新任务
    // let device_refresh_task = start_device_refresh_task(
    //     device_manager,
    //     device_registry,
    //     options.data_dir().to_string(),
    //     shutdown_notify.clone(),
    // );

    // 通过 MonitorManager 为所有模块启动内部循环
    let mut tasks = monitor_manager
        .start_modules(module_contexts, shutdown_notify.clone())
        .await?;

    tasks.push(web_task);

    tasks.push(hostname_refresh_task);

    // tasks.push(device_refresh_task);

    // 等待关闭信号
    shutdown_notify.notified().await;
    info!("Stopping all modules...");

    // 等待所有任务完成
    for task in tasks {
        if let Err(e) = task.await {
            log::error!("Module task error: {}", e);
        }
    }

    info!("All modules stopped, program exiting");

    Ok(())
}

pub async fn run(options: Options) -> Result<(), anyhow::Error> {
    validate_arguments(&options)?;

    let log_level = match options.log_level().to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => {
            return Err(anyhow::anyhow!(
                "Invalid log level: {}. Valid values: trace, debug, info, warn, error",
                options.log_level()
            ));
        }
    };

    env_logger::Builder::new()
        .filter(None, log_level)
        .filter_module("aya::bpf", LevelFilter::Error)
        .target(env_logger::Target::Stdout)
        .init();

    log_startup_info(&options);

    // 检查是否至少启用了 一个模块
    if !options.enable_traffic() && !options.enable_dns() && !options.enable_connection() {
        return Err(anyhow::anyhow!(
            "No monitoring modules enabled. At least one module must be enabled: --enable-traffic, --enable-dns, or --enable-connection"
        ));
    }

    run_service(&options).await?;

    Ok(())
}
