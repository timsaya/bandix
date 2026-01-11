use crate::monitor::TrafficModuleContext;
use anyhow::Result;
use aya::maps::HashMap;
use aya::maps::MapData;
use serde::Serialize;
use std::collections::HashMap as StdHashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex as TokioMutex;

struct RawTrafficData {
    pub lan_tx_bytes: u64, // lan 发送字节数
    pub lan_rx_bytes: u64, // lan 接收字节数
    pub wan_tx_bytes: u64, // wan 发送字节数
    pub wan_rx_bytes: u64, // wan 接收字节数
}

/// 流量监控模块的具体实现
pub struct TrafficMonitor {
    http: reqwest::Client,
    export_in_flight: Arc<AtomicBool>,
    export_latest: Arc<TokioMutex<Option<TrafficExportPayload>>>,
}

impl TrafficMonitor {
    pub fn new() -> Self {
        let http = reqwest::Client::builder().timeout(Duration::from_millis(800)).build().unwrap();
        TrafficMonitor {
            http,
            export_in_flight: Arc::new(AtomicBool::new(false)),
            export_latest: Arc::new(TokioMutex::new(None)),
        }
    }

    pub async fn start(&self, ctx: &mut TrafficModuleContext, shutdown_notify: std::sync::Arc<tokio::sync::Notify>) -> Result<()> {
        self.start_monitoring_loop(ctx, shutdown_notify).await
    }

    fn sync_last_ebpf_traffic(&self, ctx: &mut TrafficModuleContext, ebpf: Arc<aya::Ebpf>) {
        match self.collect_traffic_data(&ebpf) {
            Ok(traffic_data) => {
                let mut last_ebpf = ctx.last_ebpf_traffic.lock().unwrap();
                last_ebpf.clear();
                for (mac, value) in traffic_data {
                    last_ebpf.insert(mac, value);
                }
            }
            Err(e) => {
                log::warn!("Failed to sync last eBPF traffic snapshot: {}", e);
            }
        }
    }

    async fn start_monitoring_loop(
        &self,
        ctx: &mut TrafficModuleContext,
        shutdown_notify: std::sync::Arc<tokio::sync::Notify>,
    ) -> Result<()> {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));

        let persist_enabled = ctx.options.traffic_persist_history();

        let ebpf_snapshot = ctx.ingress_ebpf.clone();
        if let Some(ebpf) = ebpf_snapshot {
            self.sync_last_ebpf_traffic(ctx, ebpf);
        }

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.process_monitoring_cycle(ctx).await;
                }
                _ = shutdown_notify.notified() => {
                    log::debug!("Traffic monitoring module received shutdown signal, stopping...");
                    if persist_enabled {
                        log::debug!("Flushing all dirty rings before shutdown...");
                        if let Err(e) = ctx.long_term_manager.flush_dirty_rings().await {
                            log::error!("Failed to flush long-term rings during shutdown: {}", e);
                        }
                    }
                    break;
                }
            }
        }

        Ok(())
    }

    async fn process_monitoring_cycle(&self, ctx: &mut TrafficModuleContext) {
        let ingress_ebpf = match ctx.ingress_ebpf.as_ref() {
            Some(ebpf) => Arc::clone(ebpf),
            None => {
                log::error!("eBPF programs not initialized, skipping this monitoring cycle");
                return;
            }
        };

        if let Err(e) = self.process_traffic_data(ctx, &ingress_ebpf).await {
            log::error!("Failed to process traffic data: {}", e);
        }

        // 检测是否要应用限速规则
        if let Err(e) = self.apply_rate_limits(ctx, &ingress_ebpf) {
            log::error!("Failed to update rate limits: {}", e);
        }

        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_millis() as u64;

        let traffic_snapshot = ctx.device_manager.get_all_devices_with_mac();

        if let Err(e) = ctx.realtime_manager.insert_metrics_batch(ts_ms, &traffic_snapshot) {
            log::error!("Failed to persist metrics to memory ring: {}", e);
        }

        if let Err(e) = ctx.long_term_manager.insert_metrics_batch(ts_ms, &traffic_snapshot) {
            log::error!("Failed to persist metrics to long-term ring: {}", e);
        }

        let export_url = ctx.options.traffic_export_url().trim();
        if !export_url.is_empty() {
            self.export_devices_snapshot(ctx, export_url.to_string(), ts_ms, &traffic_snapshot)
                .await;
        }
    }
}

#[derive(Serialize, Clone)]
struct TrafficExportDevice {
    mac: String,
    ip: String,
    hostname: String,
    total_rx_bytes: u64,
    total_tx_bytes: u64,
    total_rx_rate: u64,
    total_tx_rate: u64,
    lan_rx_bytes: u64,
    lan_tx_bytes: u64,
    lan_rx_rate: u64,
    lan_tx_rate: u64,
    wan_rx_bytes: u64,
    wan_tx_bytes: u64,
    wan_rx_rate: u64,
    wan_tx_rate: u64,
    last_online_ts: u64,
}

#[derive(Serialize, Clone)]
struct TrafficExportPayload {
    ts_ms: u64,
    devices: Vec<TrafficExportDevice>,
}

impl TrafficMonitor {
    /// 检查 MAC 地址是否为特殊地址（广播、多播等）
    fn is_special_mac_address(&self, mac: &[u8; 6]) -> bool {
        // 广播地址 FF:FF:FF:FF:FF:FF
        if mac == &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] {
            return true;
        }

        // 多播地址（第一个字节的最低位为1）
        if (mac[0] & 0x01) == 0x01 {
            return true;
        }

        // 零地址 00:00:00:00:00:00
        if mac == &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00] {
            return true;
        }

        false
    }

    fn collect_traffic_data(&self, ebpf: &Arc<aya::Ebpf>) -> Result<StdHashMap<[u8; 6], [u64; 4]>, anyhow::Error> {
        let mut traffic_data = StdHashMap::new();

        // 由于入口和出口共享同一个 eBPF 对象和映射，我们只需要读取一次
        let traffic_map = HashMap::<&MapData, [u8; 6], [u64; 4]>::try_from(
            ebpf.map("MAC_TRAFFIC").ok_or(anyhow::anyhow!("Cannot find MAC_TRAFFIC map"))?,
        )?;

        for entry in traffic_map.iter() {
            let (key, value) = entry.unwrap();
            // 排除广播和多播地址
            if self.is_special_mac_address(&key) {
                continue;
            }
            traffic_data.insert(key, value);
        }

        Ok(traffic_data)
    }

    fn build_raw_device_traffic(
        &self,
        traffic_data: &StdHashMap<[u8; 6], [u64; 4]>,
        device_manager: &crate::device::DeviceManager,
    ) -> Result<StdHashMap<[u8; 6], RawTrafficData>, anyhow::Error> {
        let mut traffic = StdHashMap::new();

        // 为每个已知设备构建流量数据
        for (mac, _) in device_manager.get_all_devices_with_mac() {
            if let Some(data) = traffic_data.get(&mac) {
                traffic.insert(
                    mac,
                    RawTrafficData {
                        lan_tx_bytes: data[0], // lan 发送
                        lan_rx_bytes: data[1], // lan 接收
                        wan_tx_bytes: data[2], // wan 发送
                        wan_rx_bytes: data[3], // wan 接收
                    },
                );
            }
        }

        Ok(traffic)
    }

    async fn process_traffic_data(&self, ctx: &mut TrafficModuleContext, ebpf: &Arc<aya::Ebpf>) -> Result<(), anyhow::Error> {
        let traffic_data = self.collect_traffic_data(ebpf)?;

        // 获取所有已知设备
        let all_devices = ctx.device_manager.get_all_devices_with_mac();
        let all_device_macs: std::collections::HashSet<[u8; 6]> = all_devices.iter().map(|(_, device)| device.mac).collect();

        // 检测是否有新设备（使用原始的 traffic_data）
        let mut has_new_device = false;
        for mac in traffic_data.keys() {
            if !all_device_macs.contains(mac) {
                has_new_device = true;
                break;
            }
        }

        // 如果发现新设备，立即刷新设备列表以获取 IP 地址
        if has_new_device {
            log::info!("Detected new device(s) with traffic, refreshing device list...");
            if let Err(e) = ctx.device_manager.refresh_devices().await {
                log::warn!("Failed to refresh devices for new device detection: {}", e);
            }
        }

        // 现在构建流量数据（新设备已经在设备管理器中了）
        let raw_device_traffic = self.build_raw_device_traffic(&traffic_data, &ctx.device_manager)?;

        let scheduled_limits = ctx.scheduled_rate_limits.lock().unwrap().clone();

        // 重新获取所有设备（包括刚刚添加的新设备）
        let all_devices = ctx.device_manager.get_all_devices_with_mac();
        let all_device_macs: std::collections::HashSet<[u8; 6]> = all_devices.iter().map(|(_, device)| device.mac).collect();

        // 处理设备流量数据
        self.process_device_traffic_updates(ctx, &raw_device_traffic, &all_device_macs, &scheduled_limits)?;

        Ok(())
    }

    /// 处理所有设备的流量更新，包括有流量和无流量的设备
    fn process_device_traffic_updates(
        &self,
        ctx: &mut TrafficModuleContext,
        raw_device_traffic: &StdHashMap<[u8; 6], RawTrafficData>,
        all_device_macs: &std::collections::HashSet<[u8; 6]>,
        scheduled_limits: &[crate::storage::traffic::ScheduledRateLimit],
    ) -> Result<(), anyhow::Error> {
        // 先处理有流量的设备
        for (mac, raw_traffic) in raw_device_traffic.iter() {
            self.process_active_device_traffic(ctx, mac, raw_traffic, scheduled_limits)?;
        }

        // 处理没有流量的设备（离线设备，即从 ring 文件恢复的设备）
        for mac in all_device_macs.iter() {
            if !raw_device_traffic.contains_key(mac) {
                self.process_inactive_device_traffic(ctx, mac, scheduled_limits)?;
            }
        }

        Ok(())
    }

    /// 处理有流量设备的统计更新
    fn process_active_device_traffic(
        &self,
        ctx: &mut TrafficModuleContext,
        mac: &[u8; 6],
        raw_traffic: &RawTrafficData,
        scheduled_limits: &[crate::storage::traffic::ScheduledRateLimit],
    ) -> Result<(), anyhow::Error> {
        // 计算增量
        let last_ebpf = ctx.last_ebpf_traffic.lock().unwrap();
        let last_values = last_ebpf.get(mac).copied().unwrap_or([0u64; 4]);
        drop(last_ebpf);

        let lan_tx_delta = raw_traffic.lan_tx_bytes.saturating_sub(last_values[0]);
        let lan_rx_delta = raw_traffic.lan_rx_bytes.saturating_sub(last_values[1]);
        let wan_tx_delta = raw_traffic.wan_tx_bytes.saturating_sub(last_values[2]);
        let wan_rx_delta = raw_traffic.wan_rx_bytes.saturating_sub(last_values[3]);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;

        // 更新设备流量统计
        if let Err(e) = ctx.device_manager.update_device_traffic_stats(mac, |stats| {
            // 从预定规则计算当前有效速率限制
            if let Some(limits) = crate::storage::traffic::calculate_current_rate_limit(scheduled_limits, mac) {
                stats.wan_rx_rate_limit = limits[0];
                stats.wan_tx_rate_limit = limits[1];
            }

            // 累加增量到统计值
            stats.lan_rx_bytes = stats.lan_rx_bytes.saturating_add(lan_rx_delta);
            stats.lan_tx_bytes = stats.lan_tx_bytes.saturating_add(lan_tx_delta);
            stats.wan_rx_bytes = stats.wan_rx_bytes.saturating_add(wan_rx_delta);
            stats.wan_tx_bytes = stats.wan_tx_bytes.saturating_add(wan_tx_delta);

            // 计算速率和活动时间
            self.update_device_rates_and_activity(stats, now);

            // 将当前值保存为下次计算的基础
            stats.lan_last_rx_bytes = stats.lan_rx_bytes;
            stats.lan_last_tx_bytes = stats.lan_tx_bytes;
            stats.wan_last_rx_bytes = stats.wan_rx_bytes;
            stats.wan_last_tx_bytes = stats.wan_tx_bytes;
            stats.last_sample_ts = now;
        }) {
            log::warn!("Failed to update device stats for {:?}: {}", mac, e);
        }

        // 保存当前 eBPF 值用于下次计算
        let mut last_ebpf = ctx.last_ebpf_traffic.lock().unwrap();
        last_ebpf.insert(
            *mac,
            [
                raw_traffic.lan_tx_bytes,
                raw_traffic.lan_rx_bytes,
                raw_traffic.wan_tx_bytes,
                raw_traffic.wan_rx_bytes,
            ],
        );

        Ok(())
    }

    /// 处理无流量设备的统计更新
    fn process_inactive_device_traffic(
        &self,
        ctx: &mut TrafficModuleContext,
        mac: &[u8; 6],
        scheduled_limits: &[crate::storage::traffic::ScheduledRateLimit],
    ) -> Result<(), anyhow::Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;

        if let Err(e) = ctx.device_manager.update_device_traffic_stats(mac, |stats| {
            // 从预定规则计算当前有效速率限制
            if let Some(limits) = crate::storage::traffic::calculate_current_rate_limit(scheduled_limits, mac) {
                stats.wan_rx_rate_limit = limits[0];
                stats.wan_tx_rate_limit = limits[1];
            }

            // 对于没有流量的设备，速率应该为0
            stats.wan_rx_rate = 0;
            stats.wan_tx_rate = 0;
            stats.lan_rx_rate = 0;
            stats.lan_tx_rate = 0;

            stats.lan_last_rx_bytes = stats.lan_rx_bytes;
            stats.lan_last_tx_bytes = stats.lan_tx_bytes;
            stats.wan_last_rx_bytes = stats.wan_rx_bytes;
            stats.wan_last_tx_bytes = stats.wan_tx_bytes;

            // 更新最后采样时间
            stats.last_sample_ts = now;
        }) {
            log::warn!("Failed to update offline device stats for {:?}: {}", mac, e);
        }

        Ok(())
    }

    /// 更新设备的速率和活动时间
    fn update_device_rates_and_activity(&self, stats: &mut crate::device::UnifiedDevice, now: u64) {
        if stats.last_sample_ts != 0 {
            let time_diff = now.saturating_sub(stats.last_sample_ts);
            if time_diff > 0 {
                // 计算各项速率
                let lan_rx_diff = stats.lan_rx_bytes.saturating_sub(stats.lan_last_rx_bytes);
                let lan_tx_diff = stats.lan_tx_bytes.saturating_sub(stats.lan_last_tx_bytes);
                let wan_rx_diff = stats.wan_rx_bytes.saturating_sub(stats.wan_last_rx_bytes);
                let wan_tx_diff = stats.wan_tx_bytes.saturating_sub(stats.wan_last_tx_bytes);

                stats.lan_rx_rate = (lan_rx_diff * 1000) / time_diff;
                stats.lan_tx_rate = (lan_tx_diff * 1000) / time_diff;
                stats.wan_rx_rate = (wan_rx_diff * 1000) / time_diff;
                stats.wan_tx_rate = (wan_tx_diff * 1000) / time_diff;
            }
        } else {
            stats.lan_rx_rate = 0;
            stats.lan_tx_rate = 0;
            stats.wan_rx_rate = 0;
            stats.wan_tx_rate = 0;
        }
    }

    fn apply_rate_limits(&self, ctx: &mut TrafficModuleContext, _ebpf: &Arc<aya::Ebpf>) -> Result<(), anyhow::Error> {
        // 从预定规则计算当前有效速率限制
        let scheduled_limits = ctx.scheduled_rate_limits.lock().unwrap();

        let policy_enabled = ctx.rate_limit_whitelist_enabled.load(std::sync::atomic::Ordering::Relaxed);
        let whitelist = ctx.rate_limit_whitelist.lock().unwrap().clone();
        let default_limits = *ctx.default_wan_rate_limits.lock().unwrap();

        let device_macs: std::collections::HashSet<[u8; 6]> = ctx
            .device_manager
            .get_all_devices_with_mac()
            .into_iter()
            .map(|(mac, _)| mac)
            .collect();

        let mut desired_limits: std::collections::HashMap<[u8; 6], [u64; 2]> = std::collections::HashMap::new();

        for mac in device_macs {
            if let Some(limits) = crate::storage::traffic::calculate_current_rate_limit(&scheduled_limits, &mac) {
                desired_limits.insert(mac, limits);
                continue;
            }

            if !policy_enabled {
                desired_limits.insert(mac, [0, 0]);
                continue;
            }

            if whitelist.contains(&mac) {
                desired_limits.insert(mac, [0, 0]);
            } else {
                desired_limits.insert(mac, default_limits);
            }
        }

        drop(scheduled_limits);

        // 获取入口 eBPF 引用（入口和出口共享同一个 eBPF 对象和映射）
        let ingress_ebpf = ctx
            .ingress_ebpf
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Ingress eBPF program not initialized"))?;

        // 使用 unsafe 获取对 eBPF 对象的可变访问
        // 这是安全的，因为 eBPF 映射是线程安全的
        let ebpf_mut = unsafe {
            let ptr = Arc::as_ptr(ingress_ebpf) as *const aya::Ebpf as *mut aya::Ebpf;
            &mut *ptr
        };

        let mut mac_rate_limits: HashMap<_, [u8; 6], [u64; 2]> = HashMap::try_from(
            ebpf_mut
                .map_mut("MAC_RATE_LIMITS")
                .ok_or(anyhow::anyhow!("Cannot find MAC_RATE_LIMITS"))?,
        )?;

        // 收集当前在 eBPF 映射中的所有 MAC
        let mut existing_macs_in_ebpf: std::collections::HashSet<[u8; 6]> = std::collections::HashSet::new();
        for entry in mac_rate_limits.iter() {
            if let Ok((mac, _)) = entry {
                existing_macs_in_ebpf.insert(mac);
            }
        }

        // 将有效限制应用到 eBPF 映射（更新或添加）
        for (mac, lim) in desired_limits.iter() {
            mac_rate_limits.insert(mac, &[lim[0], lim[1]], 0).unwrap();
            existing_macs_in_ebpf.remove(mac);
        }

        // 清除不再有匹配规则的 MAC 的限制
        // 设置为 [0, 0] 以移除速率限制（无限制）
        for mac in existing_macs_in_ebpf.iter() {
            mac_rate_limits.insert(mac, &[0, 0], 0).unwrap();
        }

        Ok(())
    }

    async fn export_devices_snapshot(
        &self,
        ctx: &TrafficModuleContext,
        url: String,
        ts_ms: u64,
        snapshot: &Vec<([u8; 6], crate::device::UnifiedDevice)>,
    ) {
        let bindings = ctx.hostname_bindings.lock().unwrap().clone();
        let mut devices = Vec::with_capacity(snapshot.len());
        for (mac, dev) in snapshot.iter() {
            let ipv4 = dev.get_current_ipv4();
            let ip = format!("{}.{}.{}.{}", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
            let hostname = if !dev.hostname.is_empty() {
                dev.hostname.clone()
            } else {
                bindings.get(mac).cloned().unwrap_or_default()
            };
            devices.push(TrafficExportDevice {
                mac: crate::utils::format_utils::format_mac(mac),
                ip,
                hostname,
                total_rx_bytes: dev.total_rx_bytes(),
                total_tx_bytes: dev.total_tx_bytes(),
                total_rx_rate: dev.total_rx_rate(),
                total_tx_rate: dev.total_tx_rate(),
                lan_rx_bytes: dev.lan_rx_bytes,
                lan_tx_bytes: dev.lan_tx_bytes,
                lan_rx_rate: dev.lan_rx_rate,
                lan_tx_rate: dev.lan_tx_rate,
                wan_rx_bytes: dev.wan_rx_bytes,
                wan_tx_bytes: dev.wan_tx_bytes,
                wan_rx_rate: dev.wan_rx_rate,
                wan_tx_rate: dev.wan_tx_rate,
                last_online_ts: dev.last_online_ts,
            });
        }

        let payload = TrafficExportPayload { ts_ms, devices };

        {
            let mut guard = self.export_latest.lock().await;
            *guard = Some(payload);
        }

        if self
            .export_in_flight
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let client = self.http.clone();
        let export_latest = Arc::clone(&self.export_latest);
        let export_in_flight = Arc::clone(&self.export_in_flight);
        tokio::spawn(async move {
            let payload = { export_latest.lock().await.clone() };
            if let Some(payload) = payload {
                let _ = client.post(url).json(&payload).send().await;
            }
            export_in_flight.store(false, Ordering::Relaxed);
        });
    }

    // events are emitted by DeviceManager background refresh task (neighbor-table based)
}
