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
    pub ipv6_addresses: [[u8; 16]; 16], // IPv6 addresses (up to 16)
    pub lan_tx_bytes: u64,              // Local network send bytes
    pub lan_rx_bytes: u64,              // Local network receive bytes
    pub wan_tx_bytes: u64,              // Cross-network send bytes
    pub wan_rx_bytes: u64,              // Cross-network receive bytes
}

/// Specific implementation of Traffic monitoring module
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
        let interval = tokio::time::interval(tokio::time::Duration::from_secs(1));

        // Only create flush interval if persistence is enabled
        if ctx.options.traffic_persist_history() {
            self.start_monitoring_loop_with_persist(ctx, interval, shutdown_notify)
                .await
        } else {
            self.start_monitoring_loop_memory_only(ctx, interval, shutdown_notify)
                .await
        }
    }

    /// Traffic monitoring loop with persistence enabled
    async fn start_monitoring_loop_with_persist(
        &self,
        ctx: &mut TrafficModuleContext,
        mut interval: tokio::time::Interval,
        shutdown_notify: std::sync::Arc<tokio::sync::Notify>,
    ) -> Result<()> {
        let mut flush_interval = tokio::time::interval(tokio::time::Duration::from_secs(
            ctx.options.traffic_flush_interval_seconds() as u64,
        ));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.process_monitoring_cycle(ctx).await;
                }
                _ = flush_interval.tick() => {
                    log::debug!("Starting periodic flush of dirty rings to disk (interval: {}s)...",
                               ctx.options.traffic_flush_interval_seconds());
                    if let Err(e) = ctx.long_term_manager.flush_dirty_rings().await {
                        log::error!("Failed to flush multi-level rings to disk: {}", e);
                    } else {
                        log::debug!("Successfully flushed dirty rings to disk");
                    }
                }
                _ = shutdown_notify.notified() => {
                    log::debug!("Traffic monitoring module received shutdown signal, stopping...");
                    log::debug!("Flushing all dirty rings before shutdown...");
                    if let Err(e) = ctx.long_term_manager.flush_dirty_rings().await {
                        log::error!("Failed to flush multi-level rings during shutdown: {}", e);
                    }
                    break;
                }
            }
        }

        Ok(())
    }

    async fn start_monitoring_loop_memory_only(
        &self,
        ctx: &mut TrafficModuleContext,
        mut interval: tokio::time::Interval,
        shutdown_notify: std::sync::Arc<tokio::sync::Notify>,
    ) -> Result<()> {
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.process_monitoring_cycle(ctx).await;
                }
                _ = shutdown_notify.notified() => {
                    log::debug!("Traffic monitoring module received shutdown signal, stopping...");
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

        if let Err(e) = ctx
            .realtime_manager
            .insert_metrics_batch(ts_ms, &snapshot)
        {
            log::error!("metrics persist to memory ring error: {}", e);
        }

        if let Err(e) = ctx
            .long_term_manager
            .insert_metrics_batch(ts_ms, &snapshot)
        {
            log::error!("metrics persist to multi-level ring error: {}", e);
        }
    }
}

impl TrafficMonitor {
    /// Check if MAC address is special address (broadcast, multicast, etc.)
    fn is_special_mac_address(&self, mac: &[u8; 6]) -> bool {
        // Broadcast address FF:FF:FF:FF:FF:FF
        if mac == &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] {
            return true;
        }

        // Multicast address (lowest bit of first byte is 1)
        if (mac[0] & 0x01) == 0x01 {
            return true;
        }

        // Zero address 00:00:00:00:00:00
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

        // Since ingress and egress share the same eBPF object and maps, we only need to read once
        let traffic_map = HashMap::<&MapData, [u8; 6], [u64; 4]>::try_from(
            ebpf.map("MAC_TRAFFIC")
                .ok_or(anyhow::anyhow!("Cannot find MAC_TRAFFIC map"))?,
        )?;

        for entry in traffic_map.iter() {
            let (key, value) = entry.unwrap();
            // Exclude broadcast and multicast addresses
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

        // Get all devices from DeviceManager
        let devices = device_manager.get_all_devices();
        let devices_map: StdHashMap<[u8; 6], crate::device::ArpLine> =
            devices.into_iter().map(|d| (d.mac, d)).collect();

        // Build traffic data for each MAC address that has traffic
        for (mac, data) in traffic_data.iter() {
            if let Some(device_info) = devices_map.get(mac) {
                let mut ipv6_addresses = [[0u8; 16]; 16];

                // Copy IPv6 addresses from device info (up to 16)
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
                        lan_tx_bytes: data[0], // Local network send
                        lan_rx_bytes: data[1], // Local network receive
                        wan_tx_bytes: data[2], // Cross-network send
                        wan_rx_bytes: data[3], // Cross-network receive
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

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;

        let mut device_traffic_stats_map = ctx.device_traffic_stats.lock().unwrap();
        let scheduled_limits = ctx.scheduled_rate_limits.lock().unwrap();

        for (mac, raw_traffic) in raw_device_traffic.iter() {
            let stats = device_traffic_stats_map.entry(*mac).or_insert_with(|| {
                DeviceTrafficStats::from_ip(raw_traffic.ip_address, raw_traffic.ipv6_addresses)
            });

            // Calculate current effective rate limit from scheduled rules
            if let Some(limits) =
                crate::storage::traffic::calculate_current_rate_limit(&scheduled_limits, mac)
            {
                stats.wan_rx_rate_limit = limits[0];
                stats.wan_tx_rate_limit = limits[1];
            }

            // If the entry already exists (e.g., created earlier due to rate limit config and IP is still default),
            // overwrite with the latest IP collected by eBPF to avoid staying at 0.0.0.0.
            if raw_traffic.ip_address != [0, 0, 0, 0] && stats.ip_address != raw_traffic.ip_address
            {
                stats.ip_address = raw_traffic.ip_address;
            }

            // Update IPv6 addresses from DeviceManager
            // Merge new IPv6 addresses from DeviceManager into existing ones
            if let Some(device_info) = ctx.device_manager.get_device_by_mac(mac) {
                for ipv6_addr in device_info.ipv6_addresses.iter() {
                    // Check if this IPv6 address is not all zeros
                    if *ipv6_addr != [0u8; 16] {
                        // Check if this IPv6 address already exists in the array
                        let mut found = false;
                        let current_count = stats.ipv6_count() as usize;
                        for i in 0..current_count {
                            if stats.ipv6_addresses[i] == *ipv6_addr {
                                found = true;
                                break;
                            }
                        }

                        // Add new IPv6 address if not found and we have space (up to 16)
                        if !found && current_count < 16 {
                            stats.ipv6_addresses[current_count] = *ipv6_addr;
                        }
                    }
                }
            }

            // Update traffic bytes (baseline already applied during initialization)
            // eBPF provides incremental values since last reset, so we add them to existing baseline
            stats.lan_rx_bytes += raw_traffic.lan_rx_bytes;
            stats.lan_tx_bytes += raw_traffic.lan_tx_bytes;
            stats.wan_rx_bytes += raw_traffic.wan_rx_bytes;
            stats.wan_tx_bytes += raw_traffic.wan_tx_bytes;

            // Calculate rate (bytes/sec)
            if stats.last_sample_ts > 0 {
                let time_diff = now.saturating_sub(stats.last_sample_ts);
                if time_diff > 0 {
                    // Calculate local network receive rate
                    let lan_rx_diff = stats.lan_rx_bytes.saturating_sub(stats.lan_last_rx_bytes);
                    stats.lan_rx_rate = (lan_rx_diff * 1000) / time_diff;

                    // Calculate local network send rate
                    let lan_tx_diff = stats.lan_tx_bytes.saturating_sub(stats.lan_last_tx_bytes);
                    stats.lan_tx_rate = (lan_tx_diff * 1000) / time_diff;

                    // Calculate cross-network receive rate
                    let wan_rx_diff = stats.wan_rx_bytes.saturating_sub(stats.wan_last_rx_bytes);
                    stats.wan_rx_rate = (wan_rx_diff * 1000) / time_diff;

                    // Calculate cross-network send rate
                    let wan_tx_diff = stats.wan_tx_bytes.saturating_sub(stats.wan_last_tx_bytes);
                    stats.wan_tx_rate = (wan_tx_diff * 1000) / time_diff;

                    // Update last active time only if any transmit traffic increased
                    let total_tx_diff = lan_tx_diff + wan_tx_diff;
                    if total_tx_diff > 0 {
                        stats.last_online_ts = now;
                    }
                }
            }

            // If first sample and there is transmit traffic, set last active time
            if stats.last_sample_ts == 0 {
                if stats.total_tx_bytes() > 0 {
                    stats.last_online_ts = now;
                }
            }

            // Save current values as basis for next calculation
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
        // Calculate current effective rate limits from scheduled rules
        let scheduled_limits = ctx.scheduled_rate_limits.lock().unwrap();

        // Collect all unique MAC addresses from scheduled limits
        use std::collections::HashSet;
        let macs: HashSet<[u8; 6]> = scheduled_limits.iter().map(|r| r.mac).collect();

        // Calculate current effective limits for each MAC
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

        // Get ingress eBPF reference (both ingress and egress share the same eBPF object and maps)
        let ingress_ebpf = ctx
            .ingress_ebpf
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Ingress eBPF program not initialized"))?;

        // Get mutable access to the eBPF object using unsafe
        // This is safe because eBPF maps are thread-safe and we're only updating the map,
        // not modifying the eBPF object itself
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

        // Collect all MACs currently in eBPF map
        let mut existing_macs_in_ebpf: std::collections::HashSet<[u8; 6]> =
            std::collections::HashSet::new();
        for entry in mac_rate_limits.iter() {
            if let Ok((mac, _)) = entry {
                existing_macs_in_ebpf.insert(mac);
            }
        }

        // Apply effective limits to eBPF map (update or add)
        for (mac, lim) in effective_limits.iter() {
            mac_rate_limits.insert(mac, &[lim[0], lim[1]], 0).unwrap();
            existing_macs_in_ebpf.remove(mac);
        }

        // Clear limits for MACs that no longer have matching rules
        // Set to [0, 0] to remove rate limiting (unlimited)
        for mac in existing_macs_in_ebpf.iter() {
            mac_rate_limits.insert(mac, &[0, 0], 0).unwrap();
        }

        Ok(())
    }
}
