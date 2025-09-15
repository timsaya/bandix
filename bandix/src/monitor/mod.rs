pub mod dns;
pub mod traffic;

use crate::api::ApiRouter;
use crate::command::Options;
use crate::storage::traffic::BaselineTotals;
use bandix_common::MacTrafficStats;
use std::collections::HashMap as StdHashMap;
use std::sync::{Arc, Mutex};

/// Monitor module configuration
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    pub enable_traffic: bool,
    pub enable_dns: bool,
}

impl MonitorConfig {
    pub fn from_options(options: &Options) -> Self {
        MonitorConfig {
            enable_traffic: options.enable_traffic,
            enable_dns: options.enable_dns,
        }
    }

    pub fn is_any_enabled(&self) -> bool {
        self.enable_traffic || self.enable_dns
    }
}

/// Traffic module context
pub struct TrafficModuleContext {
    pub options: Options,
    pub mac_stats: Arc<Mutex<StdHashMap<[u8; 6], MacTrafficStats>>>,
    pub baselines: Arc<Mutex<StdHashMap<[u8; 6], BaselineTotals>>>,
    pub rate_limits: Arc<Mutex<StdHashMap<[u8; 6], [u64; 2]>>>,
    pub ingress_ebpf: Option<aya::Ebpf>,
    pub egress_ebpf: Option<aya::Ebpf>,
}

impl TrafficModuleContext {
    /// Create traffic module context
    pub fn new(options: Options, ingress_ebpf: aya::Ebpf, egress_ebpf: aya::Ebpf) -> Self {
        Self {
            options,
            mac_stats: Arc::new(Mutex::new(StdHashMap::new())),
            baselines: Arc::new(Mutex::new(StdHashMap::new())),
            rate_limits: Arc::new(Mutex::new(StdHashMap::new())),
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
}

impl Clone for ModuleContext {
    fn clone(&self) -> Self {
        match self {
            ModuleContext::Traffic(ctx) => ModuleContext::Traffic(TrafficModuleContext {
                options: ctx.options.clone(),
                mac_stats: Arc::clone(&ctx.mac_stats),
                baselines: Arc::clone(&ctx.baselines),
                rate_limits: Arc::clone(&ctx.rate_limits),
                ingress_ebpf: None, // eBPF programs cannot be cloned, set to None
                egress_ebpf: None,  // eBPF programs cannot be cloned, set to None
            }),
            ModuleContext::Dns(ctx) => ModuleContext::Dns(ctx.clone()),
        }
    }
}

/// Traffic module interface
pub trait TrafficModule: Send + Sync {
    /// Module name
    fn name(&self) -> &'static str;

    /// Initialize module data
    async fn init_data(&self, ctx: &TrafficModuleContext) -> Result<(), anyhow::Error>;

    /// Mount API interfaces
    async fn mount_apis(&self, ctx: &TrafficModuleContext, api_router: &mut ApiRouter) -> Result<(), anyhow::Error>;

    /// Start monitoring task
    async fn start_monitoring(&self, ctx: &mut TrafficModuleContext) -> Result<(), anyhow::Error>;
}

/// DNS module interface
pub trait DnsModule: Send + Sync {
    /// Module name
    fn name(&self) -> &'static str;

    /// Initialize module data
    async fn init_data(&self, ctx: &DnsModuleContext) -> Result<(), anyhow::Error>;

    /// Mount API interfaces
    async fn mount_apis(&self, ctx: &DnsModuleContext, api_router: &mut ApiRouter) -> Result<(), anyhow::Error>;

    /// Start monitoring task
    async fn start_monitoring(&self, ctx: &mut DnsModuleContext) -> Result<(), anyhow::Error>;
}

/// Traffic monitoring module
pub struct TrafficModuleImpl;

impl TrafficModule for TrafficModuleImpl {
    fn name(&self) -> &'static str {
        "traffic"
    }

    async fn init_data(&self, ctx: &TrafficModuleContext) -> Result<(), anyhow::Error> {
        // Traffic module data initialization logic

        // Ensure data directory and schema
        crate::storage::traffic::ensure_schema(&ctx.options.data_dir)?;

        // Load rate limits
        let limits = crate::storage::traffic::load_all_limits(&ctx.options.data_dir)?;
        {
            let mut rl = ctx.rate_limits.lock().unwrap();
            for (mac, rx, tx) in limits {
                rl.insert(mac, [rx, tx]);
            }
        }

        // Rebuild ring files (if needed)
        let rebuilt = crate::storage::traffic::rebuild_all_ring_files_if_mismatch(
            &ctx.options.data_dir,
            ctx.options.traffic_retention_seconds,
        )?;

        // Load baseline data
        let preloaded_baselines = if rebuilt {
            Vec::new()
        } else {
            crate::storage::traffic::load_latest_totals(&ctx.options.data_dir)?
        };

        // Apply preloaded baseline data
        {
            let mut b = ctx.baselines.lock().unwrap();
            for (mac, base) in preloaded_baselines {
                b.insert(mac, base);
            }
        }
        Ok(())
    }

    async fn mount_apis(&self, ctx: &TrafficModuleContext, api_router: &mut ApiRouter) -> Result<(), anyhow::Error> {
        use crate::api::{ApiHandler, traffic::TrafficApiHandler};
        
        // Create traffic API handler
        let handler = ApiHandler::Traffic(TrafficApiHandler::new(
            Arc::clone(&ctx.mac_stats),
            Arc::clone(&ctx.rate_limits),
            ctx.options.clone(),
        ));
        
        // Register with API router
        api_router.register_handler(handler);
        
        Ok(())
    }

    async fn start_monitoring(&self, _ctx: &mut TrafficModuleContext) -> Result<(), anyhow::Error> {
        // This method is no longer used as we directly call traffic::start in command.rs
        log::info!("Traffic monitoring module enabled (started via direct call)");
        Ok(())
    }
}

/// DNS monitoring module
pub struct DnsModuleImpl;

impl DnsModule for DnsModuleImpl {
    fn name(&self) -> &'static str {
        "dns"
    }

    async fn init_data(&self, ctx: &DnsModuleContext) -> Result<(), anyhow::Error> {
        // DNS module data initialization logic

        // TODO: Implement DNS data storage initialization
        // e.g.: Create DNS query log tables, configure DNS monitoring parameters, etc.
        let dns_monitor = dns::DnsMonitor::new();
        dns_monitor.init_data_storage(ctx).await?;

        Ok(())
    }

    async fn mount_apis(&self, ctx: &DnsModuleContext, api_router: &mut ApiRouter) -> Result<(), anyhow::Error> {
        use crate::api::{ApiHandler, dns::DnsApiHandler};
        
        // Create DNS API handler
        let handler = ApiHandler::Dns(DnsApiHandler::new(ctx.options.clone()));
        
        // Register with API router
        api_router.register_handler(handler);
        
        Ok(())
    }

    async fn start_monitoring(&self, _ctx: &mut DnsModuleContext) -> Result<(), anyhow::Error> {
        // This method is no longer used as we directly call dns::DnsMonitor::start in command.rs
        log::info!("DNS monitoring module enabled (started via direct call)");
        Ok(())
    }
}

/// Module type enumeration
pub enum ModuleType {
    Traffic(TrafficModuleImpl),
    Dns(DnsModuleImpl),
}

impl ModuleType {
    fn name(&self) -> &'static str {
        match self {
            ModuleType::Traffic(module) => module.name(),
            ModuleType::Dns(module) => module.name(),
        }
    }

    async fn init_data(&self, ctx: &ModuleContext) -> Result<(), anyhow::Error> {
        match (self, ctx) {
            (ModuleType::Traffic(module), ModuleContext::Traffic(traffic_ctx)) => {
                module.init_data(traffic_ctx).await
            }
            (ModuleType::Dns(module), ModuleContext::Dns(dns_ctx)) => {
                module.init_data(dns_ctx).await
            }
            _ => Err(anyhow::anyhow!("Module context type mismatch")),
        }
    }

    async fn mount_apis(&self, ctx: &ModuleContext, api_router: &mut ApiRouter) -> Result<(), anyhow::Error> {
        match (self, ctx) {
            (ModuleType::Traffic(module), ModuleContext::Traffic(traffic_ctx)) => {
                module.mount_apis(traffic_ctx, api_router).await
            }
            (ModuleType::Dns(module), ModuleContext::Dns(dns_ctx)) => {
                module.mount_apis(dns_ctx, api_router).await
            }
            _ => Err(anyhow::anyhow!("Module context type mismatch")),
        }
    }

    async fn start_monitoring(&self, ctx: &mut ModuleContext) -> Result<(), anyhow::Error> {
        match (self, ctx) {
            (ModuleType::Traffic(module), ModuleContext::Traffic(traffic_ctx)) => {
                module.start_monitoring(traffic_ctx).await
            }
            (ModuleType::Dns(module), ModuleContext::Dns(dns_ctx)) => {
                module.start_monitoring(dns_ctx).await
            }
            _ => Err(anyhow::anyhow!("Module context type mismatch")),
        }
    }
}

/// Monitor manager
pub struct MonitorManager {
    config: MonitorConfig,
    modules: Vec<ModuleType>,
    api_router: ApiRouter,
}

impl MonitorManager {
    pub fn new(config: MonitorConfig) -> Self {
        let mut modules: Vec<ModuleType> = Vec::new();

        if config.enable_traffic {
            modules.push(ModuleType::Traffic(TrafficModuleImpl));
        }

        if config.enable_dns {
            modules.push(ModuleType::Dns(DnsModuleImpl));
        }

        MonitorManager { 
            config, 
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

    /// Start monitoring for all enabled modules
    pub async fn start_all_monitoring(
        &self,
        contexts: &mut [ModuleContext],
    ) -> Result<(), anyhow::Error> {
        for (module, ctx) in self.modules.iter().zip(contexts.iter_mut()) {
            module.start_monitoring(ctx).await?;
        }
        Ok(())
    }

    /// Get count of enabled modules
    pub fn enabled_modules_count(&self) -> usize {
        self.modules.len()
    }

    /// Get the API router
    pub fn get_api_router(&self) -> &ApiRouter {
        &self.api_router
    }
}
