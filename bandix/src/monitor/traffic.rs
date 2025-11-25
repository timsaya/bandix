use crate::monitor::TrafficModuleContext;
use crate::storage::traffic::BaselineTotals;
use anyhow::Result;
use aya::maps::HashMap;
use aya::maps::MapData;
use bandix_common::MacTrafficStats;
use std::collections::HashMap as StdHashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct TrafficData {
    pub ip_address: [u8; 4],
    pub local_tx_bytes: u64, // Local network send bytes
    pub local_rx_bytes: u64, // Local network receive bytes
    pub wide_tx_bytes: u64,  // Cross-network send bytes
    pub wide_rx_bytes: u64,  // Cross-network receive bytes
}

/// Specific implementation of Traffic monitoring module
pub struct TrafficMonitor;

impl TrafficMonitor {
    pub fn new() -> Self {
        TrafficMonitor
    }

    /// Start traffic monitoring (includes internal loop)
    pub async fn start(
        &self,
        ctx: &mut TrafficModuleContext,
        shutdown_notify: std::sync::Arc<tokio::sync::Notify>,
    ) -> Result<()> {
        // Start internal loop
        self.start_monitoring_loop(ctx, shutdown_notify).await
    }

    /// Traffic monitoring internal loop
    async fn start_monitoring_loop(
        &self,
        ctx: &mut TrafficModuleContext,
        shutdown_notify: std::sync::Arc<tokio::sync::Notify>,
    ) -> Result<()> {
        let interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
        
        // Only create flush interval if persistence is enabled
        if ctx.options.traffic_persist_history() {
            self.start_monitoring_loop_with_persist(ctx, interval, shutdown_notify).await
        } else {
            self.start_monitoring_loop_memory_only(ctx, interval, shutdown_notify).await
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
            ctx.options.traffic_flush_interval_seconds() as u64
        ));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.process_monitoring_cycle(ctx).await;
                }
                _ = flush_interval.tick() => {
                    // Flush dirty rings to disk at configured interval
                    log::debug!("Starting periodic flush of dirty rings to disk (interval: {}s)...", 
                               ctx.options.traffic_flush_interval_seconds());
                    if let Err(e) = ctx.memory_ring_manager.flush_dirty_rings().await {
                        log::error!("Failed to flush dirty rings to disk: {}", e);
                    } else {
                        log::debug!("Successfully flushed dirty rings to disk");
                    }
                }
                _ = shutdown_notify.notified() => {
                    log::debug!("Traffic monitoring module received shutdown signal, stopping...");
                    // Flush all dirty data before shutdown
                    log::debug!("Flushing all dirty rings before shutdown...");
                    if let Err(e) = ctx.memory_ring_manager.flush_dirty_rings().await {
                        log::error!("Failed to flush dirty rings during shutdown: {}", e);
                    }
                    break;
                }
            }
        }

        Ok(())
    }

    /// Traffic monitoring loop with memory-only (no persistence)
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

    /// Process one monitoring cycle (extract eBPF data and update stats)
    async fn process_monitoring_cycle(&self, ctx: &mut TrafficModuleContext) {
        // Get eBPF program (ingress and egress share the same eBPF object and maps)
        let ingress_ebpf = match ctx.ingress_ebpf.as_ref() {
            Some(ebpf) => Arc::clone(ebpf),
            None => {
                log::error!("eBPF programs not initialized, skipping this monitoring cycle");
                return;
            }
        };

        // Process traffic data (using ingress_ebpf since both share the same maps)
        if let Err(e) = self.process_traffic_data(ctx, &ingress_ebpf) {
            log::error!("Failed to process traffic data: {}", e);
        }

        // Update rate limits (using ingress_ebpf since both share the same maps)
        if let Err(e) = self.apply_rate_limits(ctx, &ingress_ebpf) {
            log::error!("Failed to update rate limits: {}", e);
        }

        // Execute metrics persistence to memory ring
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_millis() as u64;

        let snapshot: Vec<([u8; 6], MacTrafficStats)> = {
            let stats = ctx.mac_stats.lock().unwrap();
            stats.iter().map(|(k, v)| (*k, *v)).collect()
        };

        if let Err(e) = ctx.memory_ring_manager.insert_metrics_batch(ts_ms, &snapshot) {
            log::error!("metrics persist to memory ring error: {}", e);
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

    fn collect_mac_ip_mapping(
        &self,
        ebpf: &Arc<aya::Ebpf>,
    ) -> Result<StdHashMap<[u8; 6], [u8; 4]>, anyhow::Error> {
        let mut mac_ip_mapping = StdHashMap::new();

        // Since ingress and egress share the same eBPF object and maps, we only need to read once
        let mac_ip_mapping_map = HashMap::<&MapData, [u8; 6], [u8; 4]>::try_from(
            ebpf
                .map("MAC_IPV4_MAPPING")
                .ok_or(anyhow::anyhow!("Cannot find MAC_IPV4_MAPPING map"))?,
        )?;

        for entry in mac_ip_mapping_map.iter() {
            let (key, value) = entry.unwrap();
            mac_ip_mapping.insert(key, value);
        }

        Ok(mac_ip_mapping)
    }

    fn collect_mac_ipv6_mapping(
        &self,
        ebpf: &Arc<aya::Ebpf>,
    ) -> Result<StdHashMap<[u8; 6], [u8; 16]>, anyhow::Error> {
        let mut mac_ipv6_mapping = StdHashMap::new();

        // Since ingress and egress share the same eBPF object and maps, we only need to read once
        let mac_ipv6_mapping_map = HashMap::<&MapData, [u8; 6], [u8; 16]>::try_from(
            ebpf
                .map("MAC_IPV6_MAPPING")
                .ok_or(anyhow::anyhow!("Cannot find MAC_IPV6_MAPPING map"))?,
        )?;

        for entry in mac_ipv6_mapping_map.iter() {
            let (key, value) = entry.unwrap();
            mac_ipv6_mapping.insert(key, value);
        }

        Ok(mac_ipv6_mapping)
    }

    fn collect_traffic_data(
        &self,
        ebpf: &Arc<aya::Ebpf>,
    ) -> Result<StdHashMap<[u8; 6], [u64; 4]>, anyhow::Error> {
        let mut traffic_data = StdHashMap::new();

        // Since ingress and egress share the same eBPF object and maps, we only need to read once
        let traffic_map = HashMap::<&MapData, [u8; 6], [u64; 4]>::try_from(
            ebpf
                .map("MAC_TRAFFIC")
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

    fn merge(
        &self,
        traffic_data: &StdHashMap<[u8; 6], [u64; 4]>,
        mac_ip_mapping: &StdHashMap<[u8; 6], [u8; 4]>,
    ) -> Result<StdHashMap<[u8; 6], TrafficData>, anyhow::Error> {
        let mut traffic = StdHashMap::new();

        for (mac, ip) in mac_ip_mapping.iter() {
            if let Some(data) = traffic_data.get(mac) {
                traffic.insert(
                    *mac,
                    TrafficData {
                        ip_address: *ip,
                        local_tx_bytes: data[0], // Local network send
                        local_rx_bytes: data[1], // Local network receive
                        wide_tx_bytes: data[2],  // Cross-network send
                        wide_rx_bytes: data[3],  // Cross-network receive
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
        let mac_ip_mapping = self.collect_mac_ip_mapping(ebpf)?;
        let mac_ipv6_mapping = self.collect_mac_ipv6_mapping(ebpf)?;
        let traffic_data = self.collect_traffic_data(ebpf)?;

        let device_traffic_stats = self.merge(&traffic_data, &mac_ip_mapping)?;

        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;

        let mut stats_map = ctx.mac_stats.lock().unwrap();
        let baseline_map = ctx.baselines.lock().unwrap();
        let scheduled_limits = ctx.scheduled_rate_limits.lock().unwrap();

        for (mac, traffic_data) in device_traffic_stats.iter() {
            let stats = stats_map.entry(*mac).or_insert_with(|| MacTrafficStats {
                ip_address: traffic_data.ip_address,
                ipv6_addresses: [[0; 16]; 16],
                ipv6_count: 0,
                // Total traffic statistics
                total_rx_bytes: 0,
                total_tx_bytes: 0,
                total_rx_packets: 0,
                total_tx_packets: 0,
                total_last_rx_bytes: 0,
                total_last_tx_bytes: 0,
                total_rx_rate: 0,
                total_tx_rate: 0,
                // Cross-network rate limits
                wide_rx_rate_limit: 0,
                wide_tx_rate_limit: 0,
                // Local network traffic statistics
                local_rx_bytes: 0,
                local_tx_bytes: 0,
                local_rx_rate: 0,
                local_tx_rate: 0,
                local_last_rx_bytes: 0,
                local_last_tx_bytes: 0,
                // Cross-network traffic statistics
                wide_rx_bytes: 0,
                wide_tx_bytes: 0,
                wide_rx_rate: 0,
                wide_tx_rate: 0,
                wide_last_rx_bytes: 0,
                wide_last_tx_bytes: 0,
                last_online_ts: 0,
                last_sample_ts: 0,
            });

            // Calculate current effective rate limit from scheduled rules
            if let Some(limits) = crate::storage::traffic::calculate_current_rate_limit(&scheduled_limits, mac) {
                stats.wide_rx_rate_limit = limits[0];
                stats.wide_tx_rate_limit = limits[1];
            }

            // If the entry already exists (e.g., created earlier due to rate limit config and IP is still default),
            // overwrite with the latest IP collected by eBPF to avoid staying at 0.0.0.0.
            if traffic_data.ip_address != [0, 0, 0, 0]
                && stats.ip_address != traffic_data.ip_address
            {
                stats.ip_address = traffic_data.ip_address;
            }

            // Update IPv6 addresses from eBPF map
            if let Some(ipv6_addr) = mac_ipv6_mapping.get(mac) {
                // Check if this IPv6 address is not all zeros
                if *ipv6_addr != [0u8; 16] {
                    // Check if this IPv6 address already exists in the array
                    let mut found = false;
                    for i in 0..(stats.ipv6_count as usize) {
                        if stats.ipv6_addresses[i] == *ipv6_addr {
                            found = true;
                            break;
                        }
                    }
                    
                    // Add new IPv6 address if not found and we have space (up to 16)
                    if !found && (stats.ipv6_count as usize) < 16 {
                        stats.ipv6_addresses[stats.ipv6_count as usize] = *ipv6_addr;
                        stats.ipv6_count += 1;
                    }
                }
            }

            // Calculate total traffic
            let total_rx_bytes = traffic_data.local_rx_bytes + traffic_data.wide_rx_bytes;
            let total_tx_bytes = traffic_data.local_tx_bytes + traffic_data.wide_tx_bytes;

            // Lookup baseline for current MAC (default zeros)
            let b = baseline_map.get(mac).copied().unwrap_or(BaselineTotals {
                total_rx_bytes: 0,
                total_tx_bytes: 0,
                local_rx_bytes: 0,
                local_tx_bytes: 0,
                wide_rx_bytes: 0,
                wide_tx_bytes: 0,
                last_online_ts: 0,
            });

            // Update total bytes with baseline added
            stats.total_rx_bytes = total_rx_bytes + b.total_rx_bytes;
            stats.total_tx_bytes = total_tx_bytes + b.total_tx_bytes;

            // Update local network traffic with baseline added
            stats.local_rx_bytes = traffic_data.local_rx_bytes + b.local_rx_bytes;
            stats.local_tx_bytes = traffic_data.local_tx_bytes + b.local_tx_bytes;

            // Update cross-network traffic with baseline added
            stats.wide_rx_bytes = traffic_data.wide_rx_bytes + b.wide_rx_bytes;
            stats.wide_tx_bytes = traffic_data.wide_tx_bytes + b.wide_tx_bytes;

            // If we have baseline last_online_ts and current value is zero, seed it to avoid startup gap
            if stats.last_online_ts == 0 && b.last_online_ts > 0 {
                stats.last_online_ts = b.last_online_ts;
            }

            // Calculate rate (bytes/sec)
            if stats.last_sample_ts > 0 {
                let time_diff = now.saturating_sub(stats.last_sample_ts);
                if time_diff > 0 {
                    // Calculate total receive rate
                    let rx_diff = stats
                        .total_rx_bytes
                        .saturating_sub(stats.total_last_rx_bytes);
                    stats.total_rx_rate = (rx_diff * 1000) / time_diff; // Convert to bytes/sec

                    // Calculate total send rate
                    let tx_diff = stats
                        .total_tx_bytes
                        .saturating_sub(stats.total_last_tx_bytes);
                    stats.total_tx_rate = (tx_diff * 1000) / time_diff; // Convert to bytes/sec

                    // Calculate local network receive rate
                    let local_rx_diff = stats
                        .local_rx_bytes
                        .saturating_sub(stats.local_last_rx_bytes);
                    stats.local_rx_rate = (local_rx_diff * 1000) / time_diff;

                    // Calculate local network send rate
                    let local_tx_diff = stats
                        .local_tx_bytes
                        .saturating_sub(stats.local_last_tx_bytes);
                    stats.local_tx_rate = (local_tx_diff * 1000) / time_diff;

                    // Calculate cross-network receive rate
                    let wide_rx_diff = stats.wide_rx_bytes.saturating_sub(stats.wide_last_rx_bytes);
                    stats.wide_rx_rate = (wide_rx_diff * 1000) / time_diff;

                    // Calculate cross-network send rate
                    let wide_tx_diff = stats.wide_tx_bytes.saturating_sub(stats.wide_last_tx_bytes);
                    stats.wide_tx_rate = (wide_tx_diff * 1000) / time_diff;

                    // Update last active time only if any transmit traffic increased
                    if tx_diff > 0 || local_tx_diff > 0 || wide_tx_diff > 0 {
                        stats.last_online_ts = now;
                    }
                }
            }

            // If first sample and there is transmit traffic, set last active time
            if stats.last_sample_ts == 0 {
                if stats.total_tx_bytes > 0 || stats.local_tx_bytes > 0 || stats.wide_tx_bytes > 0 {
                    stats.last_online_ts = now;
                }
            }

            // Save current values as basis for next calculation
            stats.total_last_rx_bytes = stats.total_rx_bytes;
            stats.total_last_tx_bytes = stats.total_tx_bytes;
            stats.local_last_rx_bytes = stats.local_rx_bytes;
            stats.local_last_tx_bytes = stats.local_tx_bytes;
            stats.wide_last_rx_bytes = stats.wide_rx_bytes;
            stats.wide_last_tx_bytes = stats.wide_tx_bytes;
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
        let mut effective_limits: std::collections::HashMap<[u8; 6], [u64; 2]> = std::collections::HashMap::new();
        for mac in macs {
            if let Some(limits) = crate::storage::traffic::calculate_current_rate_limit(&scheduled_limits, &mac) {
                effective_limits.insert(mac, limits);
            }
        }
        drop(scheduled_limits);

        // Get ingress eBPF reference (both ingress and egress share the same eBPF object and maps)
        let ingress_ebpf = ctx.ingress_ebpf.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Ingress eBPF program not initialized")
        })?;

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
        let mut existing_macs_in_ebpf: std::collections::HashSet<[u8; 6]> = std::collections::HashSet::new();
        for entry in mac_rate_limits.iter() {
            if let Ok((mac, _)) = entry {
                existing_macs_in_ebpf.insert(mac);
            }
        }

        // Apply effective limits to eBPF map (update or add)
        for (mac, lim) in effective_limits.iter() {
            mac_rate_limits
                .insert(mac, &[lim[0], lim[1]], 0)
                .unwrap();
            existing_macs_in_ebpf.remove(mac);
        }

        // Clear limits for MACs that no longer have matching rules
        // Set to [0, 0] to remove rate limiting (unlimited)
        for mac in existing_macs_in_ebpf.iter() {
            mac_rate_limits
                .insert(mac, &[0, 0], 0)
                .unwrap();
        }

        Ok(())
    }
}
