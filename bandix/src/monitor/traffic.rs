use crate::monitor::TrafficModuleContext;
use anyhow::Result;
use aya::maps::HashMap;
use aya::maps::MapData;
use bandix_common::DeviceTrafficStats;
use std::collections::HashMap as StdHashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct RawTrafficData {
    pub ip_address: [u8; 4],
    pub ipv6_addresses: [[u8; 16]; 16], // IPv6 地址（最多16个）
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
        let mut flush_interval = persist_enabled.then_some(tokio::time::interval(
            tokio::time::Duration::from_secs(ctx.options.traffic_flush_interval_seconds() as u64),
        ));

        loop {
            let flush_future = async {
                match &mut flush_interval {
                    Some(fi) => fi.tick().await,
                    None => std::future::pending().await,
                }
            };

            tokio::select! {
                _ = interval.tick() => {
                    self.process_monitoring_cycle(ctx).await;
                }
                _ = flush_future => {
                    log::debug!("Starting periodic flush of dirty rings to disk (interval: {} seconds)...",
                               ctx.options.traffic_flush_interval_seconds());
                    if let Err(e) = ctx.long_term_manager.flush_dirty_rings().await {
                        log::error!("Failed to flush long-term rings to disk: {}", e);
                    } else {
                        log::debug!("Successfully flushed dirty rings to disk");
                    }
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

        if let Err(e) = self.apply_rate_limits(ctx, &ingress_ebpf) {
            log::error!("Failed to update rate limits: {}", e);
        }

        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_millis() as u64;

        let snapshot: Vec<([u8; 6], DeviceTrafficStats)> = {
            let stats = ctx.device_traffic_stats.lock().unwrap();
            stats.iter().map(|(k, v)| (*k, *v)).collect()
        };

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

        // 从 DeviceManager 获取所有设备
        let devices = device_manager.get_all_devices();
        let devices_map: StdHashMap<[u8; 6], crate::device::ArpLine> =
            devices.into_iter().map(|d| (d.mac, d)).collect();

        // 为每个有流量的 MAC 地址构建流量数据
        for (mac, data) in traffic_data.iter() {
            if let Some(device_info) = devices_map.get(mac) {
                let mut ipv6_addresses = [[0u8; 16]; 16];

                // 从设备信息复制 IPv6 地址（最多16个）
                for (i, ipv6_addr) in device_info.ipv6_addresses.iter().enumerate().take(16) {
                    if *ipv6_addr != [0u8; 16] {
                        ipv6_addresses[i] = *ipv6_addr;
                    }
                }

                traffic.insert(
                    *mac,
                    RawTrafficData {
                        ip_address: device_info.ip,
                        ipv6_addresses,
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

        let mut device_traffic_stats_map = ctx.device_traffic_stats.lock().unwrap();
        let scheduled_limits = ctx.scheduled_rate_limits.lock().unwrap();

        for (mac, raw_traffic) in raw_device_traffic.iter() {
            let stats = device_traffic_stats_map.entry(*mac).or_insert_with(|| {
                DeviceTrafficStats::from_ip(raw_traffic.ip_address, raw_traffic.ipv6_addresses)
            });

            // 从预定规则计算当前有效速率限制
            if let Some(limits) =
                crate::storage::traffic::calculate_current_rate_limit(&scheduled_limits, mac)
            {
                stats.wan_rx_rate_limit = limits[0];
                stats.wan_tx_rate_limit = limits[1];
            }

            // 用 eBPF 收集的最新 IP 覆盖，以避免停留在 0.0.0.0。
            if raw_traffic.ip_address != [0, 0, 0, 0] {
                stats.ip_address = raw_traffic.ip_address;
            }

            // 从 DeviceManager 更新 IPv6 地址
            // 将 DeviceManager 中的新 IPv6 地址合并到现有地址中
            if let Some(device_info) = ctx.device_manager.get_device_by_mac(mac) {
                let current_count = stats.ipv6_count() as usize;

                // 收集需要添加的新 IPv6 地址（过滤零地址和重复地址）
                let new_ipv6_addresses: Vec<[u8; 16]> = device_info
                    .ipv6_addresses
                    .iter()
                    .filter(|addr| **addr != [0u8; 16]) // 过滤零地址
                    .filter(|addr| !stats.ipv6_addresses[..current_count].contains(addr)) // 过滤重复地址
                    .take(16 - current_count) // 限制数量，避免超出数组容量
                    .cloned()
                    .collect();

                // 将新地址添加到数组中
                for (i, ipv6_addr) in new_ipv6_addresses.into_iter().enumerate() {
                    stats.ipv6_addresses[current_count + i] = ipv6_addr;
                }
            }

            // eBPF map 存储的是累积值，需要计算增量
            let last_ebpf = ctx.last_ebpf_traffic.lock().unwrap();
            let last_values = last_ebpf.get(mac).copied().unwrap_or([0u64; 4]);
            drop(last_ebpf);

            // 计算增量
            let lan_tx_delta = raw_traffic.lan_tx_bytes.saturating_sub(last_values[0]);
            let lan_rx_delta = raw_traffic.lan_rx_bytes.saturating_sub(last_values[1]);
            let wan_tx_delta = raw_traffic.wan_tx_bytes.saturating_sub(last_values[2]);
            let wan_rx_delta = raw_traffic.wan_rx_bytes.saturating_sub(last_values[3]);

            // 累加增量到统计值
            stats.lan_rx_bytes = stats.lan_rx_bytes.saturating_add(lan_rx_delta);
            stats.lan_tx_bytes = stats.lan_tx_bytes.saturating_add(lan_tx_delta);
            stats.wan_rx_bytes = stats.wan_rx_bytes.saturating_add(wan_rx_delta);
            stats.wan_tx_bytes = stats.wan_tx_bytes.saturating_add(wan_tx_delta);

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

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_millis() as u64;

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
        // 这是安全的，因为 eBPF 映射是线程安全的，我们只是在更新映射，
        // 不是修改 eBPF 对象本身
        let ebpf_mut = unsafe {
            // Get a raw pointer to the inner Ebpf object
            let ptr = Arc::as_ptr(ingress_ebpf) as *const aya::Ebpf as *mut aya::Ebpf;
            &mut *ptr
        };

        // Use map_mut to update rate limits
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
