use crate::monitor::TrafficModuleContext;
use crate::storage::traffic::BaselineTotals;
use anyhow::Result;
use aya::maps::HashMap;
use aya::maps::MapData;
use bandix_common::MacTrafficStats;
use std::collections::HashMap as StdHashMap;
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
        
        // Check if any persistence is enabled
        let any_persist = ctx.options.traffic_persist_main_ring 
            || ctx.options.traffic_persist_day_ring 
            || ctx.options.traffic_persist_week_ring;
        
        if any_persist {
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
            ctx.options.traffic_flush_interval_seconds as u64
        ));

        // Downsample interval for day ring: every 1 minute (main ring -> day ring)
        let mut day_downsample_interval = tokio::time::interval(tokio::time::Duration::from_secs(60)); // 1 minute
        
        // Downsample interval for week ring: every 5 minutes (day ring -> week ring)
        let mut week_downsample_interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // 5 minutes

        // Downsample interval for month ring: every 15 minutes (week ring -> month ring)
        let mut month_downsample_interval = tokio::time::interval(tokio::time::Duration::from_secs(900)); // 15 minutes

        // Downsample interval for year ring: every 1 hour (month ring -> year ring)  
        let mut year_downsample_interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // 1 hour

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.process_monitoring_cycle(ctx).await;
                }
                _ = flush_interval.tick() => {
                    // Flush dirty rings to disk at configured interval
                    log::debug!("Starting periodic flush of dirty rings to disk (interval: {}s)...", 
                               ctx.options.traffic_flush_interval_seconds);
                    
                    // Flush main ring if persistence is enabled
                    if ctx.options.traffic_persist_main_ring {
                        if let Err(e) = ctx.memory_ring_manager.flush_dirty_rings().await {
                            log::error!("Failed to flush main ring to disk: {}", e);
                        } else {
                            log::debug!("Successfully flushed main ring to disk");
                        }
                    }
                    
                    // Flush day ring if persistence is enabled
                    if ctx.options.traffic_persist_day_ring {
                        if let Some(ref day_mgr) = ctx.day_ring_manager {
                            if let Err(e) = day_mgr.flush_dirty_rings() {
                                log::error!("Failed to flush day ring: {}", e);
                            } else {
                                log::debug!("Successfully flushed day ring to disk");
                            }
                        }
                    }
                    
                    // Flush week ring if persistence is enabled
                    if ctx.options.traffic_persist_week_ring {
                        if let Some(ref week_mgr) = ctx.week_ring_manager {
                            if let Err(e) = week_mgr.flush_dirty_rings() {
                                log::error!("Failed to flush week ring: {}", e);
                            } else {
                                log::debug!("Successfully flushed week ring to disk");
                            }
                        }
                    }

                    // Flush month ring if persistence is enabled
                    if ctx.options.traffic_persist_month_ring {
                        if let Some(ref month_mgr) = ctx.month_ring_manager {
                            if let Err(e) = month_mgr.flush_dirty_rings() {
                                log::error!("Failed to flush month ring: {}", e);
                            } else {
                                log::debug!("Successfully flushed month ring to disk");
                            }
                        }
                    }

                    // Flush year ring if persistence is enabled
                    if ctx.options.traffic_persist_year_ring {
                        if let Some(ref year_mgr) = ctx.year_ring_manager {
                            if let Err(e) = year_mgr.flush_dirty_rings() {
                                log::error!("Failed to flush year ring: {}", e);
                            } else {
                                log::debug!("Successfully flushed year ring to disk");
                            }
                        }
                    }
                }
                _ = day_downsample_interval.tick() => {
                    // Downsample from main ring to day ring
                    log::debug!("Downsampling main ring to day ring (1-minute aggregation)...");
                    if let Some(ref day_mgr) = &ctx.day_ring_manager {
                        if let Err(e) = day_mgr.downsample_from_main(&ctx.memory_ring_manager.rings) {
                            log::error!("Failed to downsample to day ring: {}", e);
                        } else {
                            log::debug!("Successfully downsampled to day ring");
                        }
                    }
                }
                _ = week_downsample_interval.tick() => {
                    // Downsample from day ring to week ring
                    log::debug!("Downsampling day ring to week ring (5-minute aggregation)...");
                    if let (Some(ref day_mgr), Some(ref week_mgr)) = 
                        (&ctx.day_ring_manager, &ctx.week_ring_manager) {
                        if let Err(e) = week_mgr.downsample_from_day(&day_mgr.rings) {
                            log::error!("Failed to downsample to week ring: {}", e);
                        } else {
                            log::debug!("Successfully downsampled to week ring");
                        }
                    }
                }
                _ = month_downsample_interval.tick() => {
                    // Downsample from week ring to month ring
                    log::debug!("Downsampling week ring to month ring (15-minute aggregation)...");
                    if let (Some(ref week_mgr), Some(ref month_mgr)) = 
                        (&ctx.week_ring_manager, &ctx.month_ring_manager) {
                        if let Err(e) = month_mgr.downsample_from_week(&week_mgr.rings) {
                            log::error!("Failed to downsample to month ring: {}", e);
                        } else {
                            log::debug!("Successfully downsampled to month ring");
                        }
                    }
                }
                _ = year_downsample_interval.tick() => {
                    // Downsample from month ring to year ring
                    log::debug!("Downsampling month ring to year ring (1-hour aggregation)...");
                    if let (Some(ref month_mgr), Some(ref year_mgr)) = 
                        (&ctx.month_ring_manager, &ctx.year_ring_manager) {
                        if let Err(e) = year_mgr.downsample_from_month(&month_mgr.rings) {
                            log::error!("Failed to downsample to year ring: {}", e);
                        } else {
                            log::debug!("Successfully downsampled to year ring");
                        }
                    }
                }
                _ = shutdown_notify.notified() => {
                    log::info!("Traffic monitoring module received shutdown signal, stopping...");
                    // Flush all dirty data before shutdown
                    log::info!("Flushing all dirty rings before shutdown...");
                    
                    // Flush main ring if persistence is enabled
                    if ctx.options.traffic_persist_main_ring {
                        if let Err(e) = ctx.memory_ring_manager.flush_dirty_rings().await {
                            log::error!("Failed to flush main ring during shutdown: {}", e);
                        }
                    }
                    
                    // Flush day ring if persistence is enabled
                    if ctx.options.traffic_persist_day_ring {
                        if let Some(ref day_mgr) = ctx.day_ring_manager {
                            if let Err(e) = day_mgr.flush_dirty_rings() {
                                log::error!("Failed to flush day ring during shutdown: {}", e);
                            }
                        }
                    }
                    
                    // Flush week ring if persistence is enabled
                    if ctx.options.traffic_persist_week_ring {
                        if let Some(ref week_mgr) = ctx.week_ring_manager {
                            if let Err(e) = week_mgr.flush_dirty_rings() {
                                log::error!("Failed to flush week ring during shutdown: {}", e);
                            }
                        }
                    }
                    
                    // Flush month ring if persistence is enabled
                    if ctx.options.traffic_persist_month_ring {
                        if let Some(ref month_mgr) = ctx.month_ring_manager {
                            if let Err(e) = month_mgr.flush_dirty_rings() {
                                log::error!("Failed to flush month ring during shutdown: {}", e);
                            }
                        }
                    }
                    
                    // Flush year ring if persistence is enabled
                    if ctx.options.traffic_persist_year_ring {
                        if let Some(ref year_mgr) = ctx.year_ring_manager {
                            if let Err(e) = year_mgr.flush_dirty_rings() {
                                log::error!("Failed to flush year ring during shutdown: {}", e);
                            }
                        }
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
        // Downsample interval for day ring: every 1 minute (main ring -> day ring)
        let mut day_downsample_interval = tokio::time::interval(tokio::time::Duration::from_secs(60)); // 1 minute
        
        // Downsample interval for week ring: every 5 minutes (day ring -> week ring)
        let mut week_downsample_interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // 5 minutes

        // Downsample interval for month ring: every 15 minutes (week ring -> month ring)
        let mut month_downsample_interval = tokio::time::interval(tokio::time::Duration::from_secs(900)); // 15 minutes

        // Downsample interval for year ring: every 1 hour (month ring -> year ring)  
        let mut year_downsample_interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // 1 hour

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.process_monitoring_cycle(ctx).await;
                }
                _ = day_downsample_interval.tick() => {
                    // Downsample from main ring to day ring
                    log::debug!("Downsampling main ring to day ring (1-minute aggregation)...");
                    if let Some(ref day_mgr) = &ctx.day_ring_manager {
                        if let Err(e) = day_mgr.downsample_from_main(&ctx.memory_ring_manager.rings) {
                            log::error!("Failed to downsample to day ring: {}", e);
                        } else {
                            log::debug!("Successfully downsampled to day ring");
                        }
                    }
                }
                _ = week_downsample_interval.tick() => {
                    // Downsample from day ring to week ring
                    log::debug!("Downsampling day ring to week ring (5-minute aggregation)...");
                    if let (Some(ref day_mgr), Some(ref week_mgr)) = 
                        (&ctx.day_ring_manager, &ctx.week_ring_manager) {
                        if let Err(e) = week_mgr.downsample_from_day(&day_mgr.rings) {
                            log::error!("Failed to downsample to week ring: {}", e);
                        } else {
                            log::debug!("Successfully downsampled to week ring");
                        }
                    }
                }
                _ = month_downsample_interval.tick() => {
                    // Downsample from week ring to month ring
                    log::debug!("Downsampling week ring to month ring (15-minute aggregation)...");
                    if let (Some(ref week_mgr), Some(ref month_mgr)) = 
                        (&ctx.week_ring_manager, &ctx.month_ring_manager) {
                        if let Err(e) = month_mgr.downsample_from_week(&week_mgr.rings) {
                            log::error!("Failed to downsample to month ring: {}", e);
                        } else {
                            log::debug!("Successfully downsampled to month ring");
                        }
                    }
                }
                _ = year_downsample_interval.tick() => {
                    // Downsample from month ring to year ring
                    log::debug!("Downsampling month ring to year ring (1-hour aggregation)...");
                    if let (Some(ref month_mgr), Some(ref year_mgr)) = 
                        (&ctx.month_ring_manager, &ctx.year_ring_manager) {
                        if let Err(e) = year_mgr.downsample_from_month(&month_mgr.rings) {
                            log::error!("Failed to downsample to year ring: {}", e);
                        } else {
                            log::debug!("Successfully downsampled to year ring");
                        }
                    }
                }
                _ = shutdown_notify.notified() => {
                    log::info!("Traffic monitoring module received shutdown signal, stopping...");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Process one monitoring cycle (extract eBPF data and update stats)
    async fn process_monitoring_cycle(&self, ctx: &mut TrafficModuleContext) {
        // Get eBPF programs
        let (mut ingress_ebpf, mut egress_ebpf) = match (ctx.ingress_ebpf.take(), ctx.egress_ebpf.take()) {
            (Some(ingress), Some(egress)) => (ingress, egress),
            _ => {
                log::error!("eBPF programs not initialized, skipping this monitoring cycle");
                return;
            }
        };

        // Process traffic data
        if let Err(e) = self.process_traffic_data(ctx, &mut ingress_ebpf, &mut egress_ebpf) {
            log::error!("Failed to process traffic data: {}", e);
        }

        // Update rate limits
        if let Err(e) = self.apply_rate_limits(ctx, &mut ingress_ebpf, &mut egress_ebpf) {
            log::error!("Failed to update rate limits: {}", e);
        }

        // Put eBPF programs back into context
        ctx.ingress_ebpf = Some(ingress_ebpf);
        ctx.egress_ebpf = Some(egress_ebpf);

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

        // Note: Day ring data is populated via downsampling from main ring, not direct insertion
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
        ingress_ebpf: &aya::Ebpf,
        egress_ebpf: &aya::Ebpf,
    ) -> Result<StdHashMap<[u8; 6], [u8; 4]>, anyhow::Error> {
        let mut mac_ip_mapping = StdHashMap::new();

        let ingress_mac_ip_mapping = HashMap::<&MapData, [u8; 6], [u8; 4]>::try_from(
            ingress_ebpf
                .map("MAC_IPV4_MAPPING")
                .ok_or(anyhow::anyhow!("Cannot find ingress MAC_IPV4_MAPPING map"))?,
        )?;

        let egress_mac_ip_mapping = HashMap::<&MapData, [u8; 6], [u8; 4]>::try_from(
            egress_ebpf
                .map("MAC_IPV4_MAPPING")
                .ok_or(anyhow::anyhow!("Cannot find MAC_IPV4_MAPPING map"))?,
        )?;

        for entry in ingress_mac_ip_mapping.iter() {
            let (key, value) = entry.unwrap();
            mac_ip_mapping.insert(key, value);
        }

        for entry in egress_mac_ip_mapping.iter() {
            let (key, value) = entry.unwrap();
            mac_ip_mapping.insert(key, value);
        }

        Ok(mac_ip_mapping)
    }

    fn collect_mac_ipv6_mapping(
        &self,
        ingress_ebpf: &aya::Ebpf,
        egress_ebpf: &aya::Ebpf,
    ) -> Result<StdHashMap<[u8; 6], [u8; 16]>, anyhow::Error> {
        let mut mac_ipv6_mapping = StdHashMap::new();

        let ingress_mac_ipv6_mapping = HashMap::<&MapData, [u8; 6], [u8; 16]>::try_from(
            ingress_ebpf
                .map("MAC_IPV6_MAPPING")
                .ok_or(anyhow::anyhow!("Cannot find ingress MAC_IPV6_MAPPING map"))?,
        )?;

        let egress_mac_ipv6_mapping = HashMap::<&MapData, [u8; 6], [u8; 16]>::try_from(
            egress_ebpf
                .map("MAC_IPV6_MAPPING")
                .ok_or(anyhow::anyhow!("Cannot find egress MAC_IPV6_MAPPING map"))?,
        )?;

        for entry in ingress_mac_ipv6_mapping.iter() {
            let (key, value) = entry.unwrap();
            mac_ipv6_mapping.insert(key, value);
        }

        for entry in egress_mac_ipv6_mapping.iter() {
            let (key, value) = entry.unwrap();
            mac_ipv6_mapping.insert(key, value);
        }

        Ok(mac_ipv6_mapping)
    }

    fn collect_traffic_data(
        &self,
        ingress_ebpf: &aya::Ebpf,
        egress_ebpf: &aya::Ebpf,
    ) -> Result<StdHashMap<[u8; 6], [u64; 4]>, anyhow::Error> {
        let mut traffic_data = StdHashMap::new();

        let ingress_traffic = HashMap::<&MapData, [u8; 6], [u64; 4]>::try_from(
            ingress_ebpf
                .map("MAC_TRAFFIC")
                .ok_or(anyhow::anyhow!("Cannot find ingress MAC_TRAFFIC map"))?,
        )?;

        let egress_traffic = HashMap::<&MapData, [u8; 6], [u64; 4]>::try_from(
            egress_ebpf
                .map("MAC_TRAFFIC")
                .ok_or(anyhow::anyhow!("Cannot find egress MAC_TRAFFIC map"))?,
        )?;

        // Process ingress direction traffic data
        for entry in ingress_traffic.iter() {
            let (key, value) = entry.unwrap();
            // Exclude broadcast and multicast addresses
            if self.is_special_mac_address(&key) {
                continue;
            }
            traffic_data.insert(key, value);
        }

        // Merge egress direction traffic data
        for entry in egress_traffic.iter() {
            let (key, value) = entry.unwrap();

            // Exclude broadcast and multicast addresses
            if self.is_special_mac_address(&key) {
                continue;
            }

            if let Some(existing) = traffic_data.get_mut(&key) {
                // Merge local network and cross-network traffic
                existing[0] = existing[0].saturating_add(value[0]); // Local network send
                existing[1] = existing[1].saturating_add(value[1]); // Local network receive
                existing[2] = existing[2].saturating_add(value[2]); // Cross-network send
                existing[3] = existing[3].saturating_add(value[3]); // Cross-network receive
            } else {
                traffic_data.insert(key, value);
            }
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
        ingress_ebpf: &mut aya::Ebpf,
        egress_ebpf: &mut aya::Ebpf,
    ) -> Result<(), anyhow::Error> {
        let mac_ip_mapping = self.collect_mac_ip_mapping(&ingress_ebpf, &egress_ebpf)?;
        let mac_ipv6_mapping = self.collect_mac_ipv6_mapping(&ingress_ebpf, &egress_ebpf)?;
        let traffic_data = self.collect_traffic_data(&ingress_ebpf, &egress_ebpf)?;

        let device_traffic_stats = self.merge(&traffic_data, &mac_ip_mapping)?;

        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;

        let mut stats_map = ctx.mac_stats.lock().unwrap();
        let baseline_map = ctx.baselines.lock().unwrap();
        let rl_map = ctx.rate_limits.lock().unwrap();

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

            // Apply rate limit if exists in rate_limits map
            if let Some(lim) = rl_map.get(mac) {
                stats.wide_rx_rate_limit = lim[0];
                stats.wide_tx_rate_limit = lim[1];
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
        ingress_ebpf: &mut aya::Ebpf,
        egress_ebpf: &mut aya::Ebpf,
    ) -> Result<(), anyhow::Error> {
        let rl_map = ctx.rate_limits.lock().unwrap();

        let mut ingress_mac_rate_limits: HashMap<_, [u8; 6], [u64; 2]> = HashMap::try_from(
            ingress_ebpf
                .map_mut("MAC_RATE_LIMITS")
                .ok_or(anyhow::anyhow!("Cannot find ingress MAC_RATE_LIMITS"))?,
        )?;

        let mut egress_mac_rate_limits: HashMap<_, [u8; 6], [u64; 2]> = HashMap::try_from(
            egress_ebpf
                .map_mut("MAC_RATE_LIMITS")
                .ok_or(anyhow::anyhow!("Cannot find egress MAC_RATE_LIMITS"))?,
        )?;

        for (mac, lim) in rl_map.iter() {
            ingress_mac_rate_limits
                .insert(mac, &[lim[0], lim[1]], 0)
                .unwrap();

            egress_mac_rate_limits
                .insert(mac, &[lim[0], lim[1]], 0)
                .unwrap();
        }

        Ok(())
    }
}
