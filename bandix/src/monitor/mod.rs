pub mod traffic;

use std::collections::HashMap as StdHashMap;
use std::sync::{Arc, Mutex};
use bandix_common::MacTrafficStats;
use crate::storage::BaselineTotals;

/// 监控模块配置
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    pub enable_traffic: bool,
    pub enable_dns: bool,
}

impl MonitorConfig {
    pub fn new() -> Self {
        MonitorConfig {
            enable_traffic: false,
            enable_dns: false,
        }
    }

    pub fn enable_traffic(mut self) -> Self {
        self.enable_traffic = true;
        self
    }

    pub fn enable_dns(mut self) -> Self {
        self.enable_dns = true;
        self
    }

    pub fn is_any_enabled(&self) -> bool {
        self.enable_traffic || self.enable_dns
    }
}

/// 监控管理器
pub struct MonitorManager {
    config: MonitorConfig,
}

impl MonitorManager {
    pub fn new(config: MonitorConfig) -> Self {
        MonitorManager { config }
    }

    /// 启动所有已启用的监控模块
    pub async fn start_monitors(
        &self,
        mac_stats: &Arc<Mutex<StdHashMap<[u8; 6], MacTrafficStats>>>,
        ingress_ebpf: &mut aya::Ebpf,
        egress_ebpf: &mut aya::Ebpf,
        baselines: &Arc<Mutex<StdHashMap<[u8; 6], BaselineTotals>>>,
        rate_limits: &Arc<Mutex<StdHashMap<[u8; 6], [u64; 2]>>>,
    ) -> Result<(), anyhow::Error> {
        if self.config.enable_traffic {
            self.start_traffic_monitor(mac_stats, ingress_ebpf, egress_ebpf, baselines, rate_limits).await?;
        }

        if self.config.enable_dns {
            self.start_dns_monitor().await?;
        }

        Ok(())
    }

    async fn start_traffic_monitor(
        &self,
        mac_stats: &Arc<Mutex<StdHashMap<[u8; 6], MacTrafficStats>>>,
        ingress_ebpf: &mut aya::Ebpf,
        egress_ebpf: &mut aya::Ebpf,
        baselines: &Arc<Mutex<StdHashMap<[u8; 6], BaselineTotals>>>,
        rate_limits: &Arc<Mutex<StdHashMap<[u8; 6], [u64; 2]>>>,
    ) -> Result<(), anyhow::Error> {
        traffic::update(mac_stats, ingress_ebpf, egress_ebpf, baselines, rate_limits).await
    }

    async fn start_dns_monitor(&self) -> Result<(), anyhow::Error> {
        // TODO: DNS 监控功能待实现
        // log::info!("DNS 监控模块已启用（功能待实现）");
        Ok(())
    }
}
