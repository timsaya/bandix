pub mod connection;
pub mod dns;
pub mod traffic;

use crate::api::ApiRouter;
use crate::command::Options;
use crate::device::DeviceManager;
use crate::storage::traffic::{LongTermRingManager, RealtimeRingManager, ScheduledRateLimit};
use std::collections::HashMap as StdHashMap;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;

// 从连接模块重新导出 ConnectionModuleContext
pub use connection::ConnectionModuleContext;

/// 流量模块上下文
pub struct TrafficModuleContext {
    pub options: Options,
    pub scheduled_rate_limits: Arc<Mutex<Vec<ScheduledRateLimit>>>,
    pub hostname_bindings: Arc<Mutex<StdHashMap<[u8; 6], String>>>,
    pub rate_limit_whitelist: Arc<Mutex<HashSet<[u8; 6]>>>,
    pub rate_limit_whitelist_enabled: Arc<AtomicBool>,
    pub default_wan_rate_limits: Arc<Mutex<[u64; 2]>>,
    pub realtime_manager: Arc<RealtimeRingManager>,  // 实时1秒采样（仅内存）
    pub long_term_manager: Arc<LongTermRingManager>, // 长期采样（1小时间隔，365天保留，已持久化）
    pub device_manager: Arc<DeviceManager>,          // 统一的设备管理器（包含设备信息和流量统计）
    pub ingress_ebpf: Option<Arc<aya::Ebpf>>,
    pub egress_ebpf: Option<Arc<aya::Ebpf>>,
    pub last_ebpf_traffic: Arc<Mutex<StdHashMap<[u8; 6], [u64; 4]>>>, // 上次从 eBPF 读取的累积值
}

impl TrafficModuleContext {
    /// 创建流量模块上下文
    /// ingress_ebpf 和 egress_ebpf 都是对同一个 eBPF 对象的 Arc 引用
    /// 这确保两个程序共享相同的映射（MAC_TRAFFIC、MAC_RATE_LIMITS 等）
    pub fn new(options: Options, ingress_ebpf: Arc<aya::Ebpf>, egress_ebpf: Arc<aya::Ebpf>, device_manager: Arc<DeviceManager>) -> Self {
        let realtime_manager = Arc::new(RealtimeRingManager::new(
            options.data_dir().to_string(),
            options.traffic_retention_seconds(),
        ));

        let long_term_manager = Arc::new(LongTermRingManager::new(
            options.data_dir().to_string(),
            options.traffic_flush_interval_seconds(),
        ));

        let hostname_bindings = Arc::new(Mutex::new(StdHashMap::new()));
        let rate_limit_whitelist = Arc::new(Mutex::new(HashSet::new()));
        let rate_limit_whitelist_enabled = Arc::new(AtomicBool::new(false));
        let default_wan_rate_limits = Arc::new(Mutex::new([0u64; 2]));

        Self {
            options,
            scheduled_rate_limits: Arc::new(Mutex::new(Vec::new())),
            hostname_bindings,
            rate_limit_whitelist,
            rate_limit_whitelist_enabled,
            default_wan_rate_limits,
            realtime_manager,
            long_term_manager,
            device_manager,
            ingress_ebpf: Some(ingress_ebpf),
            egress_ebpf: Some(egress_ebpf),
            last_ebpf_traffic: Arc::new(Mutex::new(StdHashMap::new())),
        }
    }
}

/// DNS 查询记录
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
    pub response_records: Vec<String>, // 所有响应记录（A、AAAA、CNAME、HTTPS 等）
    pub response_time_ms: Option<u64>, // 响应时间（毫秒），如果没有匹配的响应则为 None
    pub device_mac: String,            // 设备 MAC 地址（来自源 IP）
    pub device_name: String,           // 设备主机名（来自主机名绑定）
}

/// DNS 模块上下文
pub struct DnsModuleContext {
    pub options: Options,
    pub ingress_ebpf: Option<std::sync::Arc<aya::Ebpf>>,
    pub egress_ebpf: Option<std::sync::Arc<aya::Ebpf>>,
    pub dns_map: Option<aya::maps::Map>,
    pub dns_queries: Arc<Mutex<Vec<DnsQueryRecord>>>,
    pub hostname_bindings: Arc<Mutex<std::collections::HashMap<[u8; 6], String>>>,
}

impl DnsModuleContext {
    /// 使用预获取的 RingBuf 映射创建 DNS 模块上下文
    /// 当 DNS 模块与其他模块共享 eBPF 对象时使用（例如，流量模块）
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

/// 通用模块上下文（用于模块管理器）
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
                scheduled_rate_limits: Arc::clone(&ctx.scheduled_rate_limits),
                hostname_bindings: Arc::clone(&ctx.hostname_bindings),
                rate_limit_whitelist: Arc::clone(&ctx.rate_limit_whitelist),
                rate_limit_whitelist_enabled: Arc::clone(&ctx.rate_limit_whitelist_enabled),
                default_wan_rate_limits: Arc::clone(&ctx.default_wan_rate_limits),
                realtime_manager: Arc::clone(&ctx.realtime_manager),
                long_term_manager: Arc::clone(&ctx.long_term_manager),
                device_manager: Arc::clone(&ctx.device_manager),
                ingress_ebpf: ctx.ingress_ebpf.as_ref().map(|e| Arc::clone(e)),
                egress_ebpf: ctx.egress_ebpf.as_ref().map(|e| Arc::clone(e)),
                last_ebpf_traffic: Arc::clone(&ctx.last_ebpf_traffic),
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

/// 模块类型枚举
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
                // 流量模块数据初始化逻辑，初始化需要的文件和目录
                crate::storage::traffic::ensure_schema(traffic_ctx.options.data_dir())?;

                // 加载预定的速率限制 包括迁移旧的限速格式
                let scheduled_limits = crate::storage::traffic::load_all_scheduled_limits(traffic_ctx.options.data_dir())?;

                {
                    let mut srl = traffic_ctx.scheduled_rate_limits.lock().unwrap();
                    *srl = scheduled_limits;
                }

                if let Ok(policy) = crate::storage::traffic::load_rate_limit_policy(traffic_ctx.options.data_dir()) {
                    {
                        let mut guard = traffic_ctx.rate_limit_whitelist.lock().unwrap();
                        *guard = policy.whitelist;
                    }
                    traffic_ctx
                        .rate_limit_whitelist_enabled
                        .store(policy.enabled, std::sync::atomic::Ordering::Relaxed);
                    {
                        let mut guard = traffic_ctx.default_wan_rate_limits.lock().unwrap();
                        *guard = policy.default_wan_limits;
                    }
                }

                // 如果开启了持久化，那么从历史数据，加载基线流量
                if traffic_ctx.options.traffic_persist_history() {
                    // 加载 ring 文件中的设备
                    match traffic_ctx.long_term_manager.load_from_files() {
                        Ok(device_info) => {
                            let device_count = device_info.len();
                            // 将 ring 文件中的设备添加到设备管理器
                            for (mac, ipv4) in device_info.into_iter() {
                                traffic_ctx.device_manager.add_offline_device(mac, ipv4);
                            }
                            log::debug!("Successfully loaded long-term ring files");
                            if device_count > 0 {
                                log::info!("Restored {} offline devices from ring files", device_count);
                            }
                        }
                        Err(e) => {
                            log::warn!("Failed to load long-term ring files: {}", e);
                        }
                    }

                    // 加载 accumulator 文件（未完成的小时数据）
                    if let Err(e) = traffic_ctx.long_term_manager.load_accumulators() {
                        log::warn!("Failed to load accumulator file: {}", e);
                    }

                    // 从持久化数据恢复基线到设备管理器
                    let baselines_with_ts = traffic_ctx.long_term_manager.get_all_baselines_with_ts();
                    if !baselines_with_ts.is_empty() {
                        let mut restored_count = 0;

                        for (mac, (ts_ms, wan_rx_bytes, wan_tx_bytes, lan_rx_bytes, lan_tx_bytes, last_online_ts)) in
                            baselines_with_ts.iter()
                        {
                            if let Err(e) = traffic_ctx.device_manager.update_device_traffic_stats(mac, |stats| {
                                // 恢复WAN和LAN流量字节数作为基线
                                stats.wan_rx_bytes = *wan_rx_bytes;
                                stats.wan_tx_bytes = *wan_tx_bytes;
                                stats.lan_rx_bytes = *lan_rx_bytes;
                                stats.lan_tx_bytes = *lan_tx_bytes;

                                stats.lan_last_rx_bytes = *lan_rx_bytes;
                                stats.lan_last_tx_bytes = *lan_tx_bytes;
                                stats.wan_last_rx_bytes = *wan_rx_bytes;
                                stats.wan_last_tx_bytes = *wan_tx_bytes;
                                stats.last_sample_ts = *ts_ms;

                                if *last_online_ts > stats.last_online_ts {
                                    stats.last_online_ts = *last_online_ts;
                                } else if stats.last_online_ts == 0 && *ts_ms > 0 {
                                    stats.last_online_ts = *ts_ms;
                                }
                            }) {
                                log::warn!("Failed to restore baseline for device {:?}: {}", mac, e);
                            } else {
                                restored_count += 1;
                            }
                        }

                        log::info!("Restored baseline for {} devices from persistent storage", restored_count);
                    }
                }

                Ok(())
            }
            (ModuleType::Dns, ModuleContext::Dns(_dns_ctx)) => {
                // DNS 模块数据初始化逻辑
                Ok(())
            }
            (ModuleType::Connection, ModuleContext::Connection(_connection_ctx)) => {
                // 连接模块数据初始化逻辑
                Ok(())
            }
            _ => Err(anyhow::anyhow!("Module context type mismatch")),
        }
    }

    async fn mount_apis(&self, ctx: &ModuleContext, api_router: &mut ApiRouter) -> Result<(), anyhow::Error> {
        match (self, ctx) {
            (ModuleType::Traffic, ModuleContext::Traffic(traffic_ctx)) => {
                use crate::api::{traffic::TrafficApiHandler, ApiHandler};

                // 创建流量 API 处理程序
                let handler = ApiHandler::Traffic(TrafficApiHandler::new_with_rate_limit_whitelist(
                    Arc::clone(&traffic_ctx.scheduled_rate_limits),
                    Arc::clone(&traffic_ctx.hostname_bindings),
                    Arc::clone(&traffic_ctx.rate_limit_whitelist),
                    Arc::clone(&traffic_ctx.rate_limit_whitelist_enabled),
                    Arc::clone(&traffic_ctx.default_wan_rate_limits),
                    Arc::clone(&traffic_ctx.realtime_manager),
                    Arc::clone(&traffic_ctx.long_term_manager),
                    Arc::clone(&traffic_ctx.device_manager),
                    traffic_ctx.options.clone(),
                ));

                // 注册到 API 路由器
                api_router.register_handler(handler);

                Ok(())
            }
            (ModuleType::Dns, ModuleContext::Dns(dns_ctx)) => {
                use crate::api::{dns::DnsApiHandler, ApiHandler};

                // 创建 DNS API 处理程序
                let handler = ApiHandler::Dns(DnsApiHandler::new(
                    dns_ctx.options.clone(),
                    Arc::clone(&dns_ctx.dns_queries),
                    Arc::clone(&dns_ctx.hostname_bindings),
                ));

                // 注册到 API 路由器
                api_router.register_handler(handler);
                Ok(())
            }
            (ModuleType::Connection, ModuleContext::Connection(connection_ctx)) => {
                use crate::api::{connection::ConnectionApiHandler, ApiHandler};

                // 创建连接 API 处理程序
                let handler = ApiHandler::Connection(ConnectionApiHandler::new(
                    Arc::clone(&connection_ctx.device_connection_stats),
                    Arc::clone(&connection_ctx.hostname_bindings),
                ));

                // 注册到 API 路由器
                api_router.register_handler(handler);
                Ok(())
            }
            _ => Err(anyhow::anyhow!("Module context type mismatch")),
        }
    }

    async fn start_monitoring(&self, ctx: ModuleContext, shutdown_notify: Arc<tokio::sync::Notify>) -> Result<(), anyhow::Error> {
        match (self, ctx) {
            (ModuleType::Traffic, ModuleContext::Traffic(mut traffic_ctx)) => {
                let traffic_monitor = traffic::TrafficMonitor::new();
                if let Err(e) = traffic_monitor.start(&mut traffic_ctx, shutdown_notify).await {
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
                if let Err(e) = connection_monitor.start(&mut connection_ctx, shutdown_notify).await {
                    log::error!("Connection monitoring module error: {}", e);
                }
                Ok(())
            }
            _ => Err(anyhow::anyhow!("Module context type mismatch")),
        }
    }
}

/// 监控管理器
pub struct MonitorManager {
    modules: Vec<ModuleType>,
    api_router: ApiRouter,
}

impl MonitorManager {
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

    /// 初始化所有启用的模块
    pub async fn init_modules(&mut self, contexts: &[ModuleContext]) -> Result<(), anyhow::Error> {
        for (module, ctx) in self.modules.iter().zip(contexts.iter()) {
            module.init_data(ctx).await?;
            module.mount_apis(ctx, &mut self.api_router).await?;
        }
        Ok(())
    }

    /// 获取 API 路由器
    pub fn get_api_router(&self) -> &ApiRouter {
        &self.api_router
    }

    /// 启动所有启用的模块
    pub async fn start_modules(
        &self,
        contexts: Vec<ModuleContext>,
        shutdown_notify: Arc<tokio::sync::Notify>,
    ) -> Result<Vec<tokio::task::JoinHandle<()>>, anyhow::Error> {
        let mut tasks = Vec::new();

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
