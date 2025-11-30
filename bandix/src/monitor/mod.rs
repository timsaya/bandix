pub mod connection;
pub mod dns;
pub mod traffic;

use crate::api::ApiRouter;
use crate::command::Options;
use crate::storage::traffic::{BaselineTotals, RealtimeRingManager, MultiLevelRingManager, ScheduledRateLimit};
use bandix_common::MacTrafficStats;
use std::collections::HashMap as StdHashMap;
use std::sync::{Arc, Mutex};

// Re-export ConnectionModuleContext from connection module
pub use connection::ConnectionModuleContext;

/// Traffic module context
pub struct TrafficModuleContext {
    pub options: Options,
    pub mac_stats: Arc<Mutex<StdHashMap<[u8; 6], MacTrafficStats>>>,
    pub baselines: Arc<Mutex<StdHashMap<[u8; 6], BaselineTotals>>>,
    pub scheduled_rate_limits: Arc<Mutex<Vec<ScheduledRateLimit>>>,
    pub hostname_bindings: Arc<Mutex<StdHashMap<[u8; 6], String>>>,
    pub realtime_ring_manager: Arc<RealtimeRingManager>, // Real-time 1-second sampling
    pub multi_level_ring_manager: Arc<MultiLevelRingManager>, // Multi-level sampling (day/week/month)
    pub ingress_ebpf: Option<Arc<aya::Ebpf>>,
    pub egress_ebpf: Option<Arc<aya::Ebpf>>,
}

impl TrafficModuleContext {
    /// Create traffic module context
    /// Both ingress_ebpf and egress_ebpf are Arc references to the same eBPF object
    /// This ensures both programs share the same maps (MAC_TRAFFIC, MAC_RATE_LIMITS, etc.)
    pub fn new(options: Options, ingress_ebpf: Arc<aya::Ebpf>, egress_ebpf: Arc<aya::Ebpf>) -> Self {
        // Real-time 1-second sampling ring manager
        let realtime_ring_manager = Arc::new(RealtimeRingManager::new(
            options.data_dir().to_string(),
            options.traffic_retention_seconds(),
        ));

        // Multi-level sampling ring manager (day/week/month)
        let multi_level_ring_manager = Arc::new(MultiLevelRingManager::new(
            options.data_dir().to_string(),
        ));

        // realtime_ring_manager.generate_test_data(options.traffic_retention_seconds()).unwrap();
        
        // Load existing ring files into memory at startup (only if persistence is enabled)
        if options.traffic_persist_history() {
            // Load real-time ring files
            if let Err(e) = realtime_ring_manager.load_from_files() {
                log::error!("Failed to load ring files into memory at startup: {}", e);
            } else {
                log::debug!("Successfully loaded existing ring files into memory");
            }
            
            // Load multi-level ring files
            if let Err(e) = multi_level_ring_manager.load_from_files() {
                log::warn!("Failed to load multi-level ring files: {}", e);
            } else {
                log::debug!("Successfully loaded multi-level ring files");
            }
        } else {
            log::debug!("Traffic history persistence disabled, starting with empty memory ring");
        }
        
        // Create shared hostname bindings - this will be used by both traffic and connection modules
        let hostname_bindings = Arc::new(Mutex::new(StdHashMap::new()));
        
        Self {
            options,
            mac_stats: Arc::new(Mutex::new(StdHashMap::new())),
            baselines: Arc::new(Mutex::new(StdHashMap::new())),
            scheduled_rate_limits: Arc::new(Mutex::new(Vec::new())),
            hostname_bindings,
            realtime_ring_manager,
            multi_level_ring_manager,
            ingress_ebpf: Some(ingress_ebpf),
            egress_ebpf: Some(egress_ebpf),
        }
    }
}

/// DNS query record
#[derive(Debug, Clone)]
pub struct DnsQueryRecord {
    pub timestamp: u64,
    pub domain: String,
    pub query_type: String,
    pub response_code: String,
    pub source_ip: String,
    pub destination_ip: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub transaction_id: u16,
    pub is_query: bool,
    pub response_ips: Vec<String>,
    pub response_records: Vec<String>, // All response records (A, AAAA, CNAME, HTTPS, etc.)
    pub response_time_ms: Option<u64>, // Response time in milliseconds, None if no response matched
    pub device_mac: String,            // Device MAC address (from source IP)
    pub device_name: String,           // Device hostname (from hostname bindings)
}

/// DNS module context
pub struct DnsModuleContext {
    pub options: Options,
    pub ingress_ebpf: Option<std::sync::Arc<aya::Ebpf>>,
    pub egress_ebpf: Option<std::sync::Arc<aya::Ebpf>>,
    pub dns_map: Option<aya::maps::Map>,
    pub dns_queries: Arc<Mutex<Vec<DnsQueryRecord>>>,
    pub hostname_bindings: Arc<Mutex<std::collections::HashMap<[u8; 6], String>>>,
}

impl DnsModuleContext {
    /// Create DNS module context with pre-acquired RingBuf map
    /// This is used when DNS module shares eBPF object with other modules (e.g., traffic)
    pub fn new_with_map(
        options: Options, 
        ingress_ebpf: std::sync::Arc<aya::Ebpf>, 
        egress_ebpf: std::sync::Arc<aya::Ebpf>,
        dns_map: aya::maps::Map,
        hostname_bindings: Arc<Mutex<std::collections::HashMap<[u8; 6], String>>>,
    ) -> Self {
        Self {
            options,
            ingress_ebpf: Some(ingress_ebpf),
            egress_ebpf: Some(egress_ebpf),
            dns_map: Some(dns_map),
            dns_queries: Arc::new(Mutex::new(Vec::new())),
            hostname_bindings,
        }
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
                scheduled_rate_limits: Arc::clone(&ctx.scheduled_rate_limits),
                hostname_bindings: Arc::clone(&ctx.hostname_bindings),
                realtime_ring_manager: Arc::clone(&ctx.realtime_ring_manager),
                multi_level_ring_manager: Arc::clone(&ctx.multi_level_ring_manager),
                ingress_ebpf: ctx.ingress_ebpf.as_ref().map(|e| Arc::clone(e)),
                egress_ebpf: ctx.egress_ebpf.as_ref().map(|e| Arc::clone(e)),
            }),
            ModuleContext::Dns(ctx) => ModuleContext::Dns(DnsModuleContext {
                options: ctx.options.clone(),
                ingress_ebpf: ctx.ingress_ebpf.as_ref().map(|e| std::sync::Arc::clone(e)),
                egress_ebpf: ctx.egress_ebpf.as_ref().map(|e| std::sync::Arc::clone(e)),
                dns_map: None, // Don't clone the map, it should be taken only once
                dns_queries: Arc::clone(&ctx.dns_queries),
                hostname_bindings: Arc::clone(&ctx.hostname_bindings),
            }),
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
                crate::storage::traffic::ensure_schema(traffic_ctx.options.data_dir())?;

                // Load scheduled rate limits (includes legacy limits converted to scheduled format)
                let scheduled_limits =
                    crate::storage::traffic::load_all_scheduled_limits(traffic_ctx.options.data_dir())?;
                {
                    let mut srl = traffic_ctx.scheduled_rate_limits.lock().unwrap();
                    *srl = scheduled_limits;
                }

                // Note: hostname bindings are now loaded and shared in command.rs,
                // so we don't need to load them here again

                // Rebuild ring files and load baseline data (only if persistence is enabled)
                if traffic_ctx.options.traffic_persist_history() {
                    // Rebuild ring files (if needed) for original manager
                    let rebuilt = crate::storage::traffic::rebuild_all_ring_files_if_mismatch(
                        traffic_ctx.options.data_dir(),
                        traffic_ctx.options.traffic_retention_seconds(),
                    )?;

                    // Load baseline data
                    let preloaded_baselines = if rebuilt {
                        Vec::new()
                    } else {
                        crate::storage::traffic::load_latest_totals(traffic_ctx.options.data_dir())?
                    };

                    // Apply preloaded baseline data
                    {
                        let mut b = traffic_ctx.baselines.lock().unwrap();
                        for (mac, base) in preloaded_baselines {
                            b.insert(mac, base);
                        }
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
                    Arc::clone(&traffic_ctx.scheduled_rate_limits),
                    Arc::clone(&traffic_ctx.hostname_bindings),
                    Arc::clone(&traffic_ctx.realtime_ring_manager),
                    Arc::clone(&traffic_ctx.multi_level_ring_manager),
                    traffic_ctx.options.clone(),
                ));

                // Register with API router
                api_router.register_handler(handler);

                Ok(())
            }
            (ModuleType::Dns, ModuleContext::Dns(dns_ctx)) => {
                use crate::api::{dns::DnsApiHandler, ApiHandler};

                // Create DNS API handler
                let handler = ApiHandler::Dns(DnsApiHandler::new(
                    dns_ctx.options.clone(),
                    Arc::clone(&dns_ctx.dns_queries),
                    Arc::clone(&dns_ctx.hostname_bindings),
                ));

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
    /// Create a new MonitorManager from module contexts (modules are inferred from contexts)
    pub fn from_contexts(contexts: &[ModuleContext]) -> Self {
        let modules: Vec<ModuleType> = contexts
            .iter()
            .map(|ctx| match ctx {
                ModuleContext::Traffic(_) => ModuleType::Traffic,
                ModuleContext::Dns(_) => ModuleType::Dns,
                ModuleContext::Connection(_) => ModuleType::Connection,
            })
            .collect();

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
