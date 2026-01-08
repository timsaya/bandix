use crate::monitor::TrafficModuleContext;
use anyhow::Result;
use aya::maps::HashMap;
use aya::maps::MapData;
use std::collections::HashMap as StdHashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct RawTrafficData {
    pub lan_tx_bytes: u64,              // lan 发送字节数
    pub lan_rx_bytes: u64,              // lan 接收字节数
    pub wan_tx_bytes: u64,              // wan 发送字节数
    pub wan_rx_bytes: u64,              // wan 接收字节数
}

/// 流量监控模块的具体实现
pub struct TrafficMonitor;

impl TrafficMonitor {
    pub fn new() -> Self {
        TrafficMonitor
    }

    pub async fn start(
        &self,
        ctx: &mut TrafficModuleContext,
        shutdown_notify: std::sync::Arc<tokio::sync::Notify>,
    ) -> Result<()> {
        self.start_monitoring_loop(ctx, shutdown_notify).await
    }

    async fn start_monitoring_loop(
        &self,
        ctx: &mut TrafficModuleContext,
        shutdown_notify: std::sync::Arc<tokio::sync::Notify>,
    ) -> Result<()> {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));

        let persist_enabled = ctx.options.traffic_persist_history();

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

        if let Err(e) = self.process_traffic_data(ctx, &ingress_ebpf) {
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

        let snapshot = ctx.device_manager.get_all_devices_for_snapshot();

        if let Err(e) = ctx.realtime_manager.insert_metrics_batch(ts_ms, &snapshot) {
            log::error!("Failed to persist metrics to memory ring: {}", e);
        }

        if let Err(e) = ctx.long_term_manager.insert_metrics_batch(ts_ms, &snapshot) {
            log::error!("Failed to persist metrics to long-term ring: {}", e);
        }
    }
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

    fn collect_traffic_data(
        &self,
        ebpf: &Arc<aya::Ebpf>,
    ) -> Result<StdHashMap<[u8; 6], [u64; 4]>, anyhow::Error> {
        let mut traffic_data = StdHashMap::new();

        // 由于入口和出口共享同一个 eBPF 对象和映射，我们只需要读取一次
        let traffic_map = HashMap::<&MapData, [u8; 6], [u64; 4]>::try_from(
            ebpf.map("MAC_TRAFFIC")
                .ok_or(anyhow::anyhow!("Cannot find MAC_TRAFFIC map"))?,
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

        // 为每个有流量的 MAC 地址构建流量数据
        for (mac, data) in traffic_data.iter() {
            if device_manager.get_device_by_mac(mac).is_some() {
                traffic.insert(
                    *mac,
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

    fn process_traffic_data(
        &self,
        ctx: &mut TrafficModuleContext,
        ebpf: &Arc<aya::Ebpf>,
    ) -> Result<(), anyhow::Error> {
        let traffic_data = self.collect_traffic_data(ebpf)?;

        let raw_device_traffic =
            self.build_raw_device_traffic(&traffic_data, &ctx.device_manager)?;

        let scheduled_limits = ctx.scheduled_rate_limits.lock().unwrap();

        
        // 获取所有设备（包括离线设备），确保它们都被处理
        let all_devices = ctx.device_manager.get_all_devices();
        let all_device_macs: std::collections::HashSet<[u8; 6]> = 
            all_devices.iter().map(|d| d.mac).collect();

        // 先处理有流量的设备
        for (mac, raw_traffic) in raw_device_traffic.iter() {
            // 确保设备存在，如果不存在则创建
            if ctx.device_manager.get_device_by_mac(mac).is_none() {
                ctx.device_manager.add_offline_device(*mac);
            }
            
            // 更新设备的 IP 地址（从 eBPF 收集的数据到 UnifiedDevice）
            // IP 信息会通过 refresh_devices() 定期更新，这里不需要手动更新
            // 因为 eBPF 收集的 IP 可能不是最新的，应该以 ARP 表为准

            // eBPF map 存储的是累积值，需要计算增量
            let last_ebpf = ctx.last_ebpf_traffic.lock().unwrap();
            let last_values = last_ebpf.get(mac).copied().unwrap_or([0u64; 4]);
            drop(last_ebpf);

            // 计算增量
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
                if let Some(limits) =
                    crate::storage::traffic::calculate_current_rate_limit(&scheduled_limits, mac)
                {
                    stats.wan_rx_rate_limit = limits[0];
                    stats.wan_tx_rate_limit = limits[1];
                }

                // 累加增量到统计值
                stats.lan_rx_bytes = stats.lan_rx_bytes.saturating_add(lan_rx_delta);
                stats.lan_tx_bytes = stats.lan_tx_bytes.saturating_add(lan_tx_delta);
                stats.wan_rx_bytes = stats.wan_rx_bytes.saturating_add(wan_rx_delta);
                stats.wan_tx_bytes = stats.wan_tx_bytes.saturating_add(wan_tx_delta);

                // 如果是第一次采样则设置最后活动时间
                if stats.last_sample_ts == 0 {
                    stats.last_online_ts = now;
                }

                // 后续的采样
                if stats.last_sample_ts > 0 {
                    let time_diff = now.saturating_sub(stats.last_sample_ts);

                    if time_diff > 0 {
                        // 计算lan 接收速率
                        let lan_rx_diff = stats.lan_rx_bytes.saturating_sub(stats.lan_last_rx_bytes);
                        stats.lan_rx_rate = (lan_rx_diff * 1000) / time_diff;

                        // 计算lan 发送速率
                        let lan_tx_diff = stats.lan_tx_bytes.saturating_sub(stats.lan_last_tx_bytes);
                        stats.lan_tx_rate = (lan_tx_diff * 1000) / time_diff;

                        // 计算wan 接收速率
                        let wan_rx_diff = stats.wan_rx_bytes.saturating_sub(stats.wan_last_rx_bytes);
                        stats.wan_rx_rate = (wan_rx_diff * 1000) / time_diff;

                        // 计算wan 发送速率
                        let wan_tx_diff = stats.wan_tx_bytes.saturating_sub(stats.wan_last_tx_bytes);
                        stats.wan_tx_rate = (wan_tx_diff * 1000) / time_diff;

                        // 仅当任何发送流量增加时更新最后活动时间
                        let total_tx_diff = lan_tx_diff + wan_tx_diff;
                        if total_tx_diff > 0 {
                            stats.last_online_ts = now;
                        }
                    }
                }

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
        }

        // 处理没有流量的设备（离线设备或当前没有活动的设备）
        // 确保它们至少更新速率限制、IP地址等信息
        for mac in all_device_macs.iter() {
            // 跳过已经处理过的设备（有流量的设备）
            if raw_device_traffic.contains_key(mac) {
                continue;
            }

            // 更新离线设备的速率限制和速率
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_millis() as u64;
                
            if let Err(e) = ctx.device_manager.update_device_traffic_stats(mac, |stats| {
                // 从预定规则计算当前有效速率限制
                if let Some(limits) =
                    crate::storage::traffic::calculate_current_rate_limit(&scheduled_limits, mac)
                {
                    stats.wan_rx_rate_limit = limits[0];
                    stats.wan_tx_rate_limit = limits[1];
                }

                // 对于没有流量的设备，速率应该为0
                stats.wan_rx_rate = 0;
                stats.wan_tx_rate = 0;
                stats.lan_rx_rate = 0;
                stats.lan_tx_rate = 0;

                // 如果 last_online_ts 为0，设置一个初始值（使用当前时间）
                if stats.last_online_ts == 0 {
                    stats.last_online_ts = now;
                }

                // 更新最后采样时间
                stats.last_sample_ts = now;
            }) {
                log::warn!("Failed to update offline device stats for {:?}: {}", mac, e);
            }
        }

        Ok(())
    }

    fn apply_rate_limits(
        &self,
        ctx: &mut TrafficModuleContext,
        _ebpf: &Arc<aya::Ebpf>,
    ) -> Result<(), anyhow::Error> {
        // 从预定规则计算当前有效速率限制
        let scheduled_limits = ctx.scheduled_rate_limits.lock().unwrap();

        // 从预定限制收集所有唯一的 MAC 地址
        use std::collections::HashSet;
        let macs: HashSet<[u8; 6]> = scheduled_limits.iter().map(|r| r.mac).collect();

        // 为每个 MAC 计算当前有效限制
        let mut effective_limits: std::collections::HashMap<[u8; 6], [u64; 2]> =
            std::collections::HashMap::new();
        for mac in macs {
            if let Some(limits) =
                crate::storage::traffic::calculate_current_rate_limit(&scheduled_limits, &mac)
            {
                effective_limits.insert(mac, limits);
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
        let mut existing_macs_in_ebpf: std::collections::HashSet<[u8; 6]> =
            std::collections::HashSet::new();
        for entry in mac_rate_limits.iter() {
            if let Ok((mac, _)) = entry {
                existing_macs_in_ebpf.insert(mac);
            }
        }

        // 将有效限制应用到 eBPF 映射（更新或添加）
        for (mac, lim) in effective_limits.iter() {
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
}
