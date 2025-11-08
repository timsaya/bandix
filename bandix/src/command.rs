use crate::ebpf::dns::load_dns;
use crate::ebpf::traffic::load_traffic;
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

/// Common arguments shared by all commands
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
        default_value = "false",
        help = "Enable web request logging (per-HTTP-request line)"
    )]
    pub web_log: bool,
}

/// Traffic module arguments
#[derive(Debug, Args, Clone)]
#[clap(group = clap::ArgGroup::new("traffic").multiple(false))]
pub struct TrafficArgs {
    #[clap(
        long,
        default_value = "true",
        help = "Enable traffic monitoring module (enabled by default)"
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

/// DNS module arguments
#[derive(Debug, Args, Clone)]
pub struct DnsArgs {
    #[clap(long, default_value = "false", help = "Enable DNS monitoring module")]
    pub enable_dns: bool,
}

/// Connection module arguments
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
    /// Get iface from common args
    pub fn iface(&self) -> &str {
        &self.common.iface
    }

    /// Get port from common args
    pub fn port(&self) -> u16 {
        self.common.port
    }

    /// Get data_dir from common args
    pub fn data_dir(&self) -> &str {
        &self.common.data_dir
    }

    /// Get web_log from common args
    pub fn web_log(&self) -> bool {
        self.common.web_log
    }

    /// Get enable_traffic from traffic args
    pub fn enable_traffic(&self) -> bool {
        self.traffic.enable_traffic
    }

    /// Get traffic_retention_seconds from traffic args
    pub fn traffic_retention_seconds(&self) -> u32 {
        self.traffic.traffic_retention_seconds
    }

    /// Get traffic_flush_interval_seconds from traffic args
    pub fn traffic_flush_interval_seconds(&self) -> u32 {
        self.traffic.traffic_flush_interval_seconds
    }

    /// Get traffic_persist_history from traffic args
    pub fn traffic_persist_history(&self) -> bool {
        self.traffic.traffic_persist_history
    }

    /// Get enable_dns from dns args
    pub fn enable_dns(&self) -> bool {
        self.dns.enable_dns
    }

    /// Get enable_connection from connection args
    pub fn enable_connection(&self) -> bool {
        self.connection.enable_connection
    }
}

// Validate arguments
fn validate_arguments(opt: &Options) -> Result<(), anyhow::Error> {
    // Check if network interface exists
    if get_interface_info(opt.iface()).is_none() {
        return Err(anyhow::anyhow!(
            "Network interface '{}' does not exist",
            opt.iface()
        ));
    }

    // Check if port is valid (0-65535)
    if opt.port() == 0 {
        return Err(anyhow::anyhow!("Port number cannot be 0"));
    }

    // Only validate traffic-specific arguments if traffic module is enabled
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

// Load and initialize hostname bindings (shared resource for traffic and connection modules)
fn load_hostname_bindings(
    data_dir: &str,
) -> std::sync::Arc<std::sync::Mutex<std::collections::HashMap<[u8; 6], String>>> {
    let bindings = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    // Load existing hostname bindings from file (priority source)
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

    // Load additional hostname bindings from ubus (fallback source)
    if let Ok(ubus_bindings) = crate::storage::hostname::load_hostname_from_ubus() {
        let mut bindings_map = bindings.lock().unwrap();
        let mut ubus_count = 0;
        for (mac, hostname) in ubus_bindings {
            // Only add if MAC address doesn't already exist (saved bindings take priority)
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

// Initialize eBPF programs for traffic module
async fn init_traffic_ebpf(options: &Options) -> Result<(aya::Ebpf, aya::Ebpf), anyhow::Error> {
    load_traffic(options.iface().to_string()).await
}

// Initialize eBPF programs for DNS module
async fn init_dns_ebpf(options: &Options) -> Result<(aya::Ebpf, aya::Ebpf), anyhow::Error> {
    load_dns(options.iface().to_string()).await
}

// Initialize subnet configuration (IPv4 and IPv6) in eBPF maps (for traffic module)
async fn init_traffic_subnet_info(
    egress_ebpf: &mut aya::Ebpf,
    ingress_ebpf: &mut aya::Ebpf,
    subnet_info: &SubnetInfo,
) -> Result<(), anyhow::Error> {
    // Configure IPv4 subnet information
    let mut ipv4_subnet_info: Array<_, [u8; 4]> =
        Array::try_from(ingress_ebpf.take_map("IPV4_SUBNET_INFO").unwrap())?;

    ipv4_subnet_info.set(0, &subnet_info.interface_ip, 0)?;
    ipv4_subnet_info.set(1, &subnet_info.subnet_mask, 0)?;

    let mut ipv4_subnet_info: Array<_, [u8; 4]> =
        Array::try_from(egress_ebpf.take_map("IPV4_SUBNET_INFO").unwrap())?;
    ipv4_subnet_info.set(0, &subnet_info.interface_ip, 0)?;
    ipv4_subnet_info.set(1, &subnet_info.subnet_mask, 0)?;

    // Configure IPv6 subnet information
    let mut ingress_ipv6_subnet_info: Array<_, [u8; 32]> =
        Array::try_from(ingress_ebpf.take_map("IPV6_SUBNET_INFO").unwrap())?;

    let mut egress_ipv6_subnet_info: Array<_, [u8; 32]> =
        Array::try_from(egress_ebpf.take_map("IPV6_SUBNET_INFO").unwrap())?;

    // Initialize all entries as disabled
    for i in 0..16 {
        ingress_ipv6_subnet_info.set(i, &[0u8; 32], 0)?;
        egress_ipv6_subnet_info.set(i, &[0u8; 32], 0)?;
    }

    // Set up to 16 IPv6 prefixes (matches Linux kernel default max_addresses)
    for (idx, (ipv6_addr, prefix_len)) in subnet_info.ipv6_addresses.iter().enumerate().take(16) {
        let mut subnet_data = [0u8; 32];

        // Copy network prefix (16 bytes)
        subnet_data[0..16].copy_from_slice(ipv6_addr);

        // Set prefix length
        subnet_data[16] = *prefix_len;

        // Set enabled flag
        subnet_data[17] = 1;

        ingress_ipv6_subnet_info.set(idx as u32, &subnet_data, 0)?;
        egress_ipv6_subnet_info.set(idx as u32, &subnet_data, 0)?;

        // Classify IPv6 address type
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

    Ok(())
}

// Subnet information structure (shared across modules)
#[derive(Debug, Clone)]
struct SubnetInfo {
    interface_ip: [u8; 4],
    subnet_mask: [u8; 4],
    ipv6_addresses: Vec<([u8; 16], u8)>,
}

impl SubnetInfo {
    fn from_interface(iface: &str) -> Result<Self, anyhow::Error> {
        // Get IPv4 subnet information
        let interface_info = get_interface_info(iface);
        let (interface_ip, subnet_mask) = interface_info.ok_or_else(|| {
            anyhow::anyhow!("Failed to get interface information for '{}'", iface)
        })?;

        // Get IPv6 addresses
        let ipv6_addresses = crate::utils::network_utils::get_interface_ipv6_info(iface);

        Ok(SubnetInfo {
            interface_ip,
            subnet_mask,
            ipv6_addresses,
        })
    }
}

// Create module contexts: load eBPF programs, configure kernel maps, and create context objects
async fn create_module_contexts(
    options: &Options,
    subnet_info: &SubnetInfo,
    shared_hostname_bindings: &std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<[u8; 6], String>>,
    >,
) -> Result<Vec<ModuleContext>, anyhow::Error> {
    let mut module_contexts = Vec::new();

    // Initialize traffic module
    if options.enable_traffic() {
        log::info!("Initializing traffic module...");

        // Load and configure eBPF programs
        let (mut ingress, mut egress) = init_traffic_ebpf(options).await?;
        init_traffic_subnet_info(&mut ingress, &mut egress, subnet_info).await?;

        // Create traffic module context
        let mut traffic_ctx = TrafficModuleContext::new(options.clone(), ingress, egress);
        traffic_ctx.hostname_bindings = std::sync::Arc::clone(shared_hostname_bindings);

        module_contexts.push(ModuleContext::Traffic(traffic_ctx));
    }

    // Initialize DNS module
    if options.enable_dns() {
        log::info!("Initializing DNS module...");

        // Load eBPF programs
        let (ingress, egress) = init_dns_ebpf(options).await?;

        // Create DNS module context
        let dns_ctx = DnsModuleContext::new(options.clone(), ingress, egress);
        module_contexts.push(ModuleContext::Dns(dns_ctx));
    }

    // Initialize connection module
    if options.enable_connection() {
        log::info!("Initializing connection module...");

        // Create connection module context
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

// Start hostname refresh task: periodically updates hostname bindings from ubus
fn start_hostname_refresh_task(
    shared_hostname_bindings: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<[u8; 6], String>>,
    >,
    options: Options,
    shutdown_notify: Arc<tokio::sync::Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Load hostname bindings from ubus (silently fails if ubus not available)
                    if let Ok(ubus_bindings) = crate::storage::hostname::load_hostname_from_ubus() {
                        let mut bindings_map = shared_hostname_bindings.lock().unwrap();
                        let mut updated_count = 0;

                        // Load saved bindings to check priority
                        let saved_bindings = crate::storage::hostname::load_hostname_bindings(options.data_dir())
                            .unwrap_or_default();
                        let saved_macs: std::collections::HashSet<[u8; 6]> =
                            saved_bindings.iter().map(|(mac, _)| *mac).collect();

                        for (mac, hostname) in ubus_bindings {
                            // Only update if not manually set (not in saved bindings)
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

// Run service, start web server and provide TUI output
async fn run_service(options: &Options) -> Result<(), anyhow::Error> {
    // Use Notify for graceful shutdown
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());
    let shutdown_notify_clone = shutdown_notify.clone();

    tokio::spawn(async move {
        if signal::ctrl_c().await.is_ok() {
            info!("Received shutdown signal, gracefully shutting down...");
            shutdown_notify_clone.notify_waiters();
        }
    });

    // Get subnet information once (shared across modules)
    let subnet_info = SubnetInfo::from_interface(options.iface())?;

    // Load shared hostname bindings once (shared across modules)
    let shared_hostname_bindings = load_hostname_bindings(options.data_dir());

    // Create module contexts: load eBPF programs and configure kernel maps
    let module_contexts =
        create_module_contexts(options, &subnet_info, &shared_hostname_bindings).await?;

    // Create monitor manager (modules are inferred from contexts)
    let mut monitor_manager = MonitorManager::from_contexts(&module_contexts);

    // Initialize all enabled modules
    monitor_manager.init_modules(&module_contexts).await?;

    // Start web server with API router
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

    // Start hostname refresh task (every 5 seconds)
    let hostname_refresh_task = start_hostname_refresh_task(
        std::sync::Arc::clone(&shared_hostname_bindings),
        options.clone(),
        shutdown_notify.clone(),
    );

    // Start internal loops for all modules via MonitorManager
    let mut tasks = monitor_manager
        .start_modules(module_contexts, shutdown_notify.clone())
        .await?;

    // Add web server task to the list
    tasks.push(web_task);

    // Add hostname refresh task to the list
    tasks.push(hostname_refresh_task);

    // Wait for shutdown signal
    shutdown_notify.notified().await;
    info!("Stopping all modules...");

    // Wait for all tasks to complete
    for task in tasks {
        if let Err(e) = task.await {
            log::error!("Module task error: {}", e);
        }
    }

    info!("All modules stopped, program exiting");

    Ok(())
}

pub async fn run(options: Options) -> Result<(), anyhow::Error> {
    // Validate arguments
    validate_arguments(&options)?;

    // Set up logging
    env_logger::Builder::new()
        .filter(None, LevelFilter::Info)
        .target(env_logger::Target::Stdout)
        .init();

    // Startup diagnostics
    log_startup_info(&options);

    // Check if at least one module is enabled
    if !options.enable_traffic() && !options.enable_dns() && !options.enable_connection() {
        return Err(anyhow::anyhow!(
            "No monitoring modules enabled. At least one module must be enabled: --enable-traffic (default), --enable-dns, or --enable-connection"
        ));
    }

    // Run service (initializes all modules and starts web server)
    run_service(&options).await?;

    Ok(())
}
