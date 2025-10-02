pub mod connection;
pub mod dns;
pub mod traffic;

use crate::api::ApiRouter;
use crate::command::Options;
use crate::storage::traffic::{BaselineTotals, MemoryRingManager};
use bandix_common::MacTrafficStats;
use std::collections::HashMap as StdHashMap;
use std::sync::{Arc, Mutex};

// Re-export ConnectionModuleContext from connection module
pub use connection::ConnectionModuleContext;

/// Monitor module configuration
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    pub enable_traffic: bool,
    pub enable_dns: bool,
    pub enable_connection: bool,
}

impl MonitorConfig {
    pub fn from_options(options: &Options) -> Self {
        MonitorConfig {
            enable_traffic: options.enable_traffic,
            enable_dns: options.enable_dns,
            enable_connection: options.enable_connection,
        }
    }
}

/// Traffic module context
pub struct TrafficModuleContext {
    pub options: Options,
    pub mac_stats: Arc<Mutex<StdHashMap<[u8; 6], MacTrafficStats>>>,
    pub baselines: Arc<Mutex<StdHashMap<[u8; 6], BaselineTotals>>>,
    pub rate_limits: Arc<Mutex<StdHashMap<[u8; 6], [u64; 2]>>>,
    pub hostname_bindings: Arc<Mutex<StdHashMap<[u8; 6], String>>>,
    pub memory_ring_manager: Arc<MemoryRingManager>,
    pub ingress_ebpf: Option<aya::Ebpf>,
    pub egress_ebpf: Option<aya::Ebpf>,
}

impl TrafficModuleContext {
    /// Create traffic module context
    pub fn new(options: Options, ingress_ebpf: aya::Ebpf, egress_ebpf: aya::Ebpf) -> Self {
        let memory_ring_manager = Arc::new(MemoryRingManager::new(
            options.data_dir.clone(),
            options.traffic_retention_seconds,
        ));
        
        // Load existing ring files into memory at startup
        if let Err(e) = memory_ring_manager.load_from_files() {
            log::error!("Failed to load ring files into memory at startup: {}", e);
        } else {
            log::info!("Successfully loaded existing ring files into memory");
        }
        
        // Create shared hostname bindings - this will be used by both traffic and connection modules
        let hostname_bindings = Arc::new(Mutex::new(StdHashMap::new()));
        
        Self {
            options,
            mac_stats: Arc::new(Mutex::new(StdHashMap::new())),
            baselines: Arc::new(Mutex::new(StdHashMap::new())),
            rate_limits: Arc::new(Mutex::new(StdHashMap::new())),
            hostname_bindings,
            memory_ring_manager,
            ingress_ebpf: Some(ingress_ebpf),
            egress_ebpf: Some(egress_ebpf),
        }
    }
}

/// DNS module context
#[derive(Clone)]
pub struct DnsModuleContext {
    pub options: Options,
    // DNS module specific context fields
    // e.g.: DNS query logs, DNS statistics, etc.
}

impl DnsModuleContext {
    /// Create DNS module context
    pub fn new(options: Options) -> Self {
        Self { options }
    }
}

/// Generic module context (for module manager)
pub enum ModuleContext {
    Traffic(TrafficModuleContext),
    Dns(DnsModuleContext),
    Connection(ConnectionModuleContext),
}

impl Clone for ModuleContext {
    fn clone(&self) -> Self {
        match self {
            ModuleContext::Traffic(ctx) => ModuleContext::Traffic(TrafficModuleContext {
                options: ctx.options.clone(),
                mac_stats: Arc::clone(&ctx.mac_stats),
                baselines: Arc::clone(&ctx.baselines),
                rate_limits: Arc::clone(&ctx.rate_limits),
                hostname_bindings: Arc::clone(&ctx.hostname_bindings),
                memory_ring_manager: Arc::clone(&ctx.memory_ring_manager),
                ingress_ebpf: None, // eBPF programs cannot be cloned, set to None
                egress_ebpf: None,  // eBPF programs cannot be cloned, set to None
            }),
            ModuleContext::Dns(ctx) => ModuleContext::Dns(ctx.clone()),
            ModuleContext::Connection(ctx) => ModuleContext::Connection(ctx.clone()),
        }
    }
}

/// Module type enumeration
#[derive(Clone)]
pub enum ModuleType {
    Traffic,
    Dns,
    Connection,
}

impl ModuleType {
    async fn init_data(&self, ctx: &ModuleContext) -> Result<(), anyhow::Error> {
        match (self, ctx) {
            (ModuleType::Traffic, ModuleContext::Traffic(traffic_ctx)) => {
                // Traffic module data initialization logic
                crate::storage::traffic::ensure_schema(&traffic_ctx.options.data_dir)?;

                // Load rate limits
                let limits =
                    crate::storage::traffic::load_all_limits(&traffic_ctx.options.data_dir)?;
                {
                    let mut rl = traffic_ctx.rate_limits.lock().unwrap();
                    for (mac, rx, tx) in limits {
                        rl.insert(mac, [rx, tx]);
                    }
                }

                // Note: hostname bindings are now loaded and shared in command.rs,
                // so we don't need to load them here again

                // Rebuild ring files (if needed)
                let rebuilt = crate::storage::traffic::rebuild_all_ring_files_if_mismatch(
                    &traffic_ctx.options.data_dir,
                    traffic_ctx.options.traffic_retention_seconds,
                )?;

                // Load baseline data
                let preloaded_baselines = if rebuilt {
                    Vec::new()
                } else {
                    crate::storage::traffic::load_latest_totals(&traffic_ctx.options.data_dir)?
                };

                // Apply preloaded baseline data
                {
                    let mut b = traffic_ctx.baselines.lock().unwrap();
                    for (mac, base) in preloaded_baselines {
                        b.insert(mac, base);
                    }
                }
                Ok(())
            }
            (ModuleType::Dns, ModuleContext::Dns(_dns_ctx)) => {
                // DNS module data initialization logic
                Ok(())
            }
            (ModuleType::Connection, ModuleContext::Connection(_connection_ctx)) => {
                // Connection module data initialization logic
                Ok(())
            }
            _ => Err(anyhow::anyhow!("Module context type mismatch")),
        }
    }

    async fn mount_apis(
        &self,
        ctx: &ModuleContext,
        api_router: &mut ApiRouter,
    ) -> Result<(), anyhow::Error> {
        match (self, ctx) {
            (ModuleType::Traffic, ModuleContext::Traffic(traffic_ctx)) => {
                use crate::api::{traffic::TrafficApiHandler, ApiHandler};

                // Create traffic API handler
                let handler = ApiHandler::Traffic(TrafficApiHandler::new(
                    Arc::clone(&traffic_ctx.mac_stats),
                    Arc::clone(&traffic_ctx.rate_limits),
                    Arc::clone(&traffic_ctx.hostname_bindings),
                    Arc::clone(&traffic_ctx.memory_ring_manager),
                    traffic_ctx.options.clone(),
                ));

                // Register with API router
                api_router.register_handler(handler);

                Ok(())
            }
            (ModuleType::Dns, ModuleContext::Dns(dns_ctx)) => {
                use crate::api::{dns::DnsApiHandler, ApiHandler};

                // Create DNS API handler
                let handler = ApiHandler::Dns(DnsApiHandler::new(dns_ctx.options.clone()));

                // Register with API router
                api_router.register_handler(handler);
                Ok(())
            }
            (ModuleType::Connection, ModuleContext::Connection(connection_ctx)) => {
                use crate::api::{connection::ConnectionApiHandler, ApiHandler};

                // Create connection API handler
                let handler = ApiHandler::Connection(ConnectionApiHandler::new(
                    Arc::clone(&connection_ctx.device_connection_stats),
                    Arc::clone(&connection_ctx.hostname_bindings),
                ));

                // Register with API router
                api_router.register_handler(handler);
                Ok(())
            }
            _ => Err(anyhow::anyhow!("Module context type mismatch")),
        }
    }

    async fn start_monitoring(
        &self,
        ctx: ModuleContext,
        shutdown_notify: Arc<tokio::sync::Notify>,
    ) -> Result<(), anyhow::Error> {
        match (self, ctx) {
            (ModuleType::Traffic, ModuleContext::Traffic(mut traffic_ctx)) => {
                let traffic_monitor = traffic::TrafficMonitor::new();
                if let Err(e) = traffic_monitor
                    .start(&mut traffic_ctx, shutdown_notify)
                    .await
                {
                    log::error!("Traffic monitoring module error: {}", e);
                }
                Ok(())
            }
            (ModuleType::Dns, ModuleContext::Dns(mut dns_ctx)) => {
                let dns_monitor = dns::DnsMonitor::new();
                if let Err(e) = dns_monitor.start(&mut dns_ctx, shutdown_notify).await {
                    log::error!("DNS monitoring module error: {}", e);
                }
                Ok(())
            }
            (ModuleType::Connection, ModuleContext::Connection(mut connection_ctx)) => {
                let connection_monitor = connection::ConnectionMonitor::new();
                if let Err(e) = connection_monitor
                    .start(&mut connection_ctx, shutdown_notify)
                    .await
                {
                    log::error!("Connection monitoring module error: {}", e);
                }
                Ok(())
            }
            _ => Err(anyhow::anyhow!("Module context type mismatch")),
        }
    }
}

/// Monitor manager
pub struct MonitorManager {
    modules: Vec<ModuleType>,
    api_router: ApiRouter,
}

impl MonitorManager {
    pub fn new(config: MonitorConfig) -> Self {
        let mut modules: Vec<ModuleType> = Vec::new();

        if config.enable_traffic {
            modules.push(ModuleType::Traffic);
        }

        if config.enable_dns {
            modules.push(ModuleType::Dns);
        }

        if config.enable_connection {
            modules.push(ModuleType::Connection);
        }

        MonitorManager {
            modules,
            api_router: ApiRouter::new(),
        }
    }

    /// Initialize all enabled modules
    pub async fn init_modules(&mut self, contexts: &[ModuleContext]) -> Result<(), anyhow::Error> {
        for (module, ctx) in self.modules.iter().zip(contexts.iter()) {
            module.init_data(ctx).await?;
            module.mount_apis(ctx, &mut self.api_router).await?;
        }
        Ok(())
    }

    /// Get the API router
    pub fn get_api_router(&self) -> &ApiRouter {
        &self.api_router
    }

    /// Start all enabled modules
    pub async fn start_modules(
        &self,
        contexts: Vec<ModuleContext>,
        shutdown_notify: Arc<tokio::sync::Notify>,
    ) -> Result<Vec<tokio::task::JoinHandle<()>>, anyhow::Error> {
        let mut tasks = Vec::new();

        // Create a vector of module types to avoid borrowing self in async tasks
        let module_types: Vec<ModuleType> = self.modules.clone();

        for (module, ctx) in module_types.into_iter().zip(contexts.into_iter()) {
            let shutdown_notify = shutdown_notify.clone();
            let task = tokio::spawn(async move {
                if let Err(e) = module.start_monitoring(ctx, shutdown_notify).await {
                    log::error!("Module start error: {}", e);
                }
            });
            tasks.push(task);
        }

        Ok(tasks)
    }
}
