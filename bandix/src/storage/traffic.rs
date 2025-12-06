use anyhow::Context;
use bandix_common::MacTrafficStats;
use chrono::{DateTime, Datelike, Local, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// Local helpers to parse/format MAC addresses (for file storage interaction)
fn parse_mac_text(mac_str: &str) -> Result<[u8; 6], anyhow::Error> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return Err(anyhow::anyhow!("Invalid MAC address format"));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .with_context(|| format!("Invalid MAC segment '{}': not hex", part))?;
    }
    Ok(mac)
}

// Convert MAC to a filename-safe 12-hex string without colons
fn mac_to_filename(mac: &[u8; 6]) -> String {
    let mut s = String::with_capacity(12);
    for b in mac {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// Directory layout:
// base_dir/
//   rate_limits.txt                 Text: one line per entry - mac rx tx (legacy format, converted to scheduled)
//   rate_limits_schedule.txt        Text: scheduled rate limits - mac schedule start_hour:start_min end_hour:end_min days rx tx
//   metrics/
//     <mac12>.ring                  Fixed-size ring file (capacity determined by config)

/// Time slot for scheduled rate limits
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeSlot {
    pub start_hour: u8,   // 0-23
    pub start_minute: u8, // 0-59
    pub end_hour: u8,     // 0-24 (24 means end of day, i.e., 24:00 = next day 00:00)
    pub end_minute: u8,   // 0-59 (must be 0 if end_hour == 24)
    pub days_of_week: u8, // Bit mask: bit 0=Monday, bit 6=Sunday (0b1111111 = all days)
}

impl TimeSlot {
    /// Create a time slot for all days, all hours (00:00-24:00)
    pub fn all_time() -> Self {
        Self {
            start_hour: 0,
            start_minute: 0,
            end_hour: 24,
            end_minute: 0,
            days_of_week: 0b1111111, // All 7 days
        }
    }

    /// Check if current time matches this time slot
    pub fn matches(&self, now: &DateTime<Local>) -> bool {
        let current_hour = now.hour() as u8;
        let current_minute = now.minute() as u8;
        let current_day = (now.weekday().num_days_from_monday()) as u8;

        // Check if day of week matches
        if (self.days_of_week & (1 << current_day)) == 0 {
            return false;
        }

        // Convert to minutes for comparison
        let current_time = current_hour as u32 * 60 + current_minute as u32;
        let start_time = self.start_hour as u32 * 60 + self.start_minute as u32;
        let end_time = self.end_hour as u32 * 60 + self.end_minute as u32;

        if start_time <= end_time {
            // Same day time slot
            current_time >= start_time && current_time < end_time
        } else {
            // Cross-day time slot (e.g., 22:00-06:00)
            current_time >= start_time || current_time < end_time
        }
    }

    /// Parse time slot from string format "HH:MM"
    /// Supports 24:00 to represent end of day
    pub fn parse_time(time_str: &str) -> Result<(u8, u8), anyhow::Error> {
        let parts: Vec<&str> = time_str.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid time format, expected HH:MM"));
        }
        let hour: u8 = parts[0]
            .parse()
            .with_context(|| format!("Invalid hour: {}", parts[0]))?;
        let minute: u8 = parts[1]
            .parse()
            .with_context(|| format!("Invalid minute: {}", parts[1]))?;
        if hour > 24 {
            return Err(anyhow::anyhow!("Hour must be 0-24"));
        }
        if hour == 24 && minute != 0 {
            return Err(anyhow::anyhow!("When hour is 24, minute must be 0"));
        }
        if minute > 59 {
            return Err(anyhow::anyhow!("Minute must be 0-59"));
        }
        Ok((hour, minute))
    }

    /// Format time slot to string "HH:MM"
    pub fn format_time(hour: u8, minute: u8) -> String {
        format!("{:02}:{:02}", hour, minute)
    }

    /// Parse days of week from string format "1111111" (7 bits) or comma-separated list "1,2,3,4,5"
    pub fn parse_days(days_str: &str) -> Result<u8, anyhow::Error> {
        if days_str.len() == 7 && days_str.chars().all(|c| c == '0' || c == '1') {
            // Binary format: "1111111"
            let mut days = 0u8;
            for (i, ch) in days_str.chars().enumerate() {
                if ch == '1' {
                    days |= 1 << i;
                }
            }
            Ok(days)
        } else {
            // Comma-separated format: "1,2,3,4,5" (1=Monday, 7=Sunday)
            let mut days = 0u8;
            for part in days_str.split(',') {
                let day: u8 = part
                    .trim()
                    .parse()
                    .with_context(|| format!("Invalid day number: {}", part))?;
                if day < 1 || day > 7 {
                    return Err(anyhow::anyhow!("Day must be 1-7 (Monday-Sunday)"));
                }
                days |= 1 << (day - 1);
            }
            Ok(days)
        }
    }

    /// Format days of week to binary string
    pub fn format_days(days: u8) -> String {
        (0..7)
            .map(|i| if (days & (1 << i)) != 0 { '1' } else { '0' })
            .collect()
    }
}

/// Scheduled rate limit rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledRateLimit {
    pub mac: [u8; 6],
    pub time_slot: TimeSlot,
    pub wide_rx_rate_limit: u64,
    pub wide_tx_rate_limit: u64,
}

const RING_MAGIC: [u8; 4] = *b"BXR1"; // bandix ring magic

// ============================================================================
// Real-time Ring File Format (for 1-second sampling)
// ============================================================================
/// Real-time ring file format version
/// Version 2: slot adds last_online_ts field
/// Version 3: slot adds ip_address field (IPv4 address stored as u64, low 32 bits)
const RING_VERSION_REALTIME_V2: u32 = 2;
const RING_VERSION_REALTIME_V3: u32 = 3;
const RING_VERSION_REALTIME: u32 = RING_VERSION_REALTIME_V3; // Current version

// Per-slot structure for real-time data (little-endian):
// Version 2:
//   ts_ms: u64
//   total_rx_rate..wide_tx_bytes: 12 u64 values in total (see MetricsRow)
//   last_online_ts: u64
//   Slot size = 14 * 8 = 112 bytes
// Version 3:
//   ts_ms: u64
//   total_rx_rate..wide_tx_bytes: 12 u64 values in total (see MetricsRow)
//   last_online_ts: u64
//   ip_address: u64 (IPv4 address stored in low 32 bits, high 32 bits are 0)
//   Slot size = 15 * 8 = 120 bytes
const SLOT_U64S_REALTIME_V2: usize = 14;
const SLOT_U64S_REALTIME_V3: usize = 15;
const SLOT_U64S_REALTIME: usize = SLOT_U64S_REALTIME_V3; // Current version
const SLOT_SIZE_REALTIME: usize = SLOT_U64S_REALTIME * 8;

// ============================================================================
// Multi-level Ring File Format (for day/week/month/year sampling with statistics)
// ============================================================================
/// Multi-level ring file format version
/// Version 3: slot contains statistics (avg, max, min, p90, p95, p99) instead of real-time values
/// Note: This will be used when implementing file persistence for multilevel rings
#[allow(dead_code)]
const RING_VERSION_MULTILEVEL: u32 = 3;

// Per-slot structure for multi-level statistics (little-endian):
// ts_ms: u64
// For wide rate metrics (wide_rx_rate, wide_tx_rate):
//   avg: u64, max: u64, min: u64, p90: u64, p95: u64, p99: u64 (6 * 8 = 48 bytes per metric)
// wide_rx_bytes: u64, wide_tx_bytes: u64
// Slot size = 1 + (2 metrics * 6 stats) + 2 bytes = 1 + 12 + 2 = 15 * 8 = 120 bytes (since v3)
const SLOT_U64S_MULTILEVEL: usize = 15; // 1 + (2 metrics * 6 stats) + 2 bytes = 15
/// Slot size for multilevel ring files (120 bytes)
/// Note: This will be used when implementing file persistence for multilevel rings
#[allow(dead_code)]
const SLOT_SIZE_MULTILEVEL: usize = SLOT_U64S_MULTILEVEL * 8;

// Common constants
const DEFAULT_RING_CAPACITY: u32 = 3600; // Default capacity is 3600 (1 hour, 1 sample per second); actual capacity is determined by argument when created
const HEADER_SIZE: usize = 4 /*magic*/ + 4 /*version*/ + 4 /*capacity*/;

/// In-memory Ring structure for real-time data (1-second sampling)
#[derive(Debug, Clone)]
pub struct RealtimeRing {
    pub capacity: u32,
    pub slots: Vec<[u64; SLOT_U64S_REALTIME]>,
    pub current_index: u64,
    pub dirty: bool, // Flag indicating whether there is data not yet persisted to disk
}

impl RealtimeRing {
    pub fn new(capacity: u32) -> Self {
        let cap = if capacity == 0 {
            DEFAULT_RING_CAPACITY
        } else {
            capacity
        };

        Self {
            capacity: cap,
            slots: vec![[0u64; SLOT_U64S_REALTIME]; cap as usize],
            current_index: 0,
            dirty: false,
        }
    }

    pub fn insert(&mut self, ts_ms: u64, data: &[u64; SLOT_U64S_REALTIME]) {
        let idx = calc_slot_index(ts_ms, self.capacity);
        self.slots[idx as usize] = *data;
        self.current_index = idx;
        self.dirty = true;
    }

    pub fn query(&self, start_ms: u64, end_ms: u64) -> Vec<MetricsRow> {
        let mut rows = Vec::new();

        for slot in &self.slots {
            let ts = slot[0];
            if ts == 0 {
                continue;
            }
            if ts < start_ms || ts > end_ms {
                continue;
            }

            rows.push(MetricsRow {
                ts_ms: slot[0],
                total_rx_rate: slot[1],
                total_tx_rate: slot[2],
                local_rx_rate: slot[3],
                local_tx_rate: slot[4],
                wide_rx_rate: slot[5],
                wide_tx_rate: slot[6],
                total_rx_bytes: slot[7],
                total_tx_bytes: slot[8],
                local_rx_bytes: slot[9],
                local_tx_bytes: slot[10],
                wide_rx_bytes: slot[11],
                wide_tx_bytes: slot[12],
            });
        }

        rows.sort_by_key(|r| r.ts_ms);
        rows
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }
}

/// In-memory Ring structure for multilevel statistics (30s/3min/10min/1h sampling)
#[derive(Debug, Clone)]
pub struct MultilevelRing {
    pub capacity: u32,
    pub slots: Vec<[u64; SLOT_U64S_MULTILEVEL]>,
    pub current_index: u64,
    pub dirty: bool,
}

impl MultilevelRing {
    pub fn new(capacity: u32) -> Self {
        let cap = if capacity == 0 {
            DEFAULT_RING_CAPACITY
        } else {
            capacity
        };

        Self {
            capacity: cap,
            slots: vec![[0u64; SLOT_U64S_MULTILEVEL]; cap as usize],
            current_index: 0,
            dirty: false,
        }
    }

    pub fn insert_stats(&mut self, ts_ms: u64, stats: &DeviceStatsAccumulator, interval_seconds: u64) {
        let idx = calc_slot_index_with_interval(ts_ms, self.capacity, interval_seconds);
        let mut slot = [0u64; SLOT_U64S_MULTILEVEL];

        // ts_ms
        slot[0] = ts_ms;

        // wide_rx_rate: avg, max, min, p90, p95, p99 (indices 1-6)
        slot[1] = stats.wide_rx_rate.avg;
        slot[2] = stats.wide_rx_rate.max;
        slot[3] = stats.wide_rx_rate.min;
        slot[4] = stats.wide_rx_rate.p90;
        slot[5] = stats.wide_rx_rate.p95;
        slot[6] = stats.wide_rx_rate.p99;

        // wide_tx_rate: avg, max, min, p90, p95, p99 (indices 7-12)
        slot[7] = stats.wide_tx_rate.avg;
        slot[8] = stats.wide_tx_rate.max;
        slot[9] = stats.wide_tx_rate.min;
        slot[10] = stats.wide_tx_rate.p90;
        slot[11] = stats.wide_tx_rate.p95;
        slot[12] = stats.wide_tx_rate.p99;

        // Total wide traffic bytes (indices 13-14)
        slot[13] = stats.wide_rx_bytes;
        slot[14] = stats.wide_tx_bytes;

        self.slots[idx as usize] = slot;
        self.current_index = idx;
        self.dirty = true;
    }

    pub fn query_stats(&self, start_ms: u64, end_ms: u64) -> Vec<MetricsRowWithStats> {
        let mut rows = Vec::new();

        for slot in &self.slots {
            let ts = slot[0];
            if ts == 0 {
                continue;
            }
            if ts < start_ms || ts > end_ms {
                continue;
            }

            rows.push(MetricsRowWithStats {
                ts_ms: slot[0],
                // wide_rx_rate stats (indices 1-6)
                wide_rx_rate_avg: slot[1],
                wide_rx_rate_max: slot[2],
                wide_rx_rate_min: slot[3],
                wide_rx_rate_p90: slot[4],
                wide_rx_rate_p95: slot[5],
                wide_rx_rate_p99: slot[6],
                // wide_tx_rate stats (indices 7-12)
                wide_tx_rate_avg: slot[7],
                wide_tx_rate_max: slot[8],
                wide_tx_rate_min: slot[9],
                wide_tx_rate_p90: slot[10],
                wide_tx_rate_p95: slot[11],
                wide_tx_rate_p99: slot[12],
                // Total wide traffic bytes (indices 13-14)
                wide_rx_bytes: slot[13],
                wide_tx_bytes: slot[14],
            });
        }

        rows.sort_by_key(|r| r.ts_ms);
        rows
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }
}

/// Memory Ring Manager for real-time data (1-second sampling)
pub struct RealtimeRingManager {
    pub rings: Arc<Mutex<HashMap<[u8; 6], RealtimeRing>>>,
    pub base_dir: String,
    pub capacity: u32,
}

impl RealtimeRingManager {
    pub fn new(base_dir: String, capacity: u32) -> Self {
        Self {
            rings: Arc::new(Mutex::new(HashMap::new())),
            base_dir,
            capacity,
        }
    }

    /// Generate test data for existing devices or create test devices
    /// Generates mock traffic data for the specified number of seconds (1 sample per second)
    /// If no devices exist, creates a few test devices with random MAC addresses
    #[allow(dead_code, unused)]
    pub fn generate_test_data(&self, seconds: u32) -> Result<(), anyhow::Error> {
        if seconds == 0 {
            return Ok(());
        }

        let mut rings = self.rings.lock().unwrap();

        // If no devices exist, create some test devices
        let test_macs: Vec<[u8; 6]>;
        if rings.is_empty() {
            test_macs = vec![
                [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                [0x00, 0x11, 0x22, 0x33, 0x44, 0x66],
                [0x00, 0x11, 0x22, 0x33, 0x44, 0x77],
            ];
            for mac in &test_macs {
                rings.insert(*mac, RealtimeRing::new(self.capacity));
            }
        } else {
            test_macs = rings.keys().copied().collect();
        }

        drop(rings);

        // Generate data for each second
        let now_ms = Utc::now().timestamp_millis() as u64;
        let start_ms = now_ms - (seconds as u64 * 1000);

        // Track cumulative bytes for each device
        let mut device_bytes: HashMap<[u8; 6], (u64, u64, u64, u64)> = HashMap::new();

        for second_offset in 0..seconds {
            let ts_ms = start_ms + (second_offset as u64 * 1000);

            let mut batch = Vec::new();
            for mac in &test_macs {
                // Generate mock data with some variation
                // Use a simple hash-like function based on MAC and timestamp for pseudo-randomness
                let mac_seed = (mac[0] as u64) * 1000000 + (mac[5] as u64) * 1000;

                // Base rates (bytes per second) - vary by device
                let base_rx_rate = 100000 + ((mac_seed % 500000) as u64); // 100KB/s to 600KB/s
                let base_tx_rate = 50000 + ((mac_seed % 200000) as u64); // 50KB/s to 250KB/s

                // Add some time-based variation (simulate traffic patterns)
                let time_variation = (second_offset as f64 * 0.1).sin() * 0.3 + 1.0;
                let rx_rate = (base_rx_rate as f64 * time_variation) as u64;
                let tx_rate = (base_tx_rate as f64 * time_variation) as u64;

                // Get or initialize cumulative bytes for this device
                let (mut total_rx_bytes, mut total_tx_bytes, _, _) =
                    device_bytes.get(mac).copied().unwrap_or((0, 0, 0, 0));

                // Increment cumulative bytes by current rate (since rate is bytes per second)
                total_rx_bytes += rx_rate;
                total_tx_bytes += tx_rate;

                // Split between local and wide (70% wide, 30% local)
                let wide_rx_bytes = (total_rx_bytes * 7) / 10;
                let local_rx_bytes = total_rx_bytes - wide_rx_bytes;
                let wide_tx_bytes = (total_tx_bytes * 7) / 10;
                let local_tx_bytes = total_tx_bytes - wide_tx_bytes;

                // Update cumulative bytes
                device_bytes.insert(
                    *mac,
                    (
                        total_rx_bytes,
                        total_tx_bytes,
                        local_rx_bytes,
                        local_tx_bytes,
                    ),
                );

                // Wide rates (same proportion)
                let wide_rx_rate = (rx_rate * 7) / 10;
                let local_rx_rate = rx_rate - wide_rx_rate;
                let wide_tx_rate = (tx_rate * 7) / 10;
                let local_tx_rate = tx_rate - wide_tx_rate;

                let stats = MacTrafficStats {
                    ip_address: [192, 168, 1, (mac[5] % 100) as u8 + 10],
                    ipv6_addresses: [[0; 16]; 16],
                    ipv6_count: 0,
                    total_rx_bytes,
                    total_tx_bytes,
                    total_rx_packets: total_rx_bytes / 1500, // Approximate packet count
                    total_tx_packets: total_tx_bytes / 1500,
                    total_last_rx_bytes: total_rx_bytes,
                    total_last_tx_bytes: total_tx_bytes,
                    total_rx_rate: rx_rate,
                    total_tx_rate: tx_rate,
                    local_rx_bytes,
                    local_tx_bytes,
                    local_rx_rate,
                    local_tx_rate,
                    local_last_rx_bytes: local_rx_bytes,
                    local_last_tx_bytes: local_tx_bytes,
                    wide_rx_bytes,
                    wide_tx_bytes,
                    wide_rx_rate,
                    wide_tx_rate,
                    wide_last_rx_bytes: wide_rx_bytes,
                    wide_last_tx_bytes: wide_tx_bytes,
                    wide_rx_rate_limit: 0,
                    wide_tx_rate_limit: 0,
                    last_online_ts: ts_ms,
                    last_sample_ts: ts_ms,
                };

                batch.push((*mac, stats));
            }

            // Insert batch for this timestamp
            self.insert_metrics_batch(ts_ms, &batch)?;
        }

        Ok(())
    }

    /// Insert data into memory Ring
    pub fn insert_metrics_batch(
        &self,
        ts_ms: u64,
        rows: &Vec<([u8; 6], MacTrafficStats)>,
    ) -> Result<(), anyhow::Error> {
        if rows.is_empty() {
            return Ok(());
        }

        let mut rings = self.rings.lock().unwrap();

        for (mac, s) in rows.iter() {
            let ring = rings
                .entry(*mac)
                .or_insert_with(|| RealtimeRing::new(self.capacity));

            // Convert IPv4 address [u8; 4] to u64 (stored in low 32 bits)
            let ip_address_u64 = u64::from_le_bytes([
                s.ip_address[0],
                s.ip_address[1],
                s.ip_address[2],
                s.ip_address[3],
                0, 0, 0, 0,
            ]);

            let rec: [u64; SLOT_U64S_REALTIME] = [
                ts_ms,
                s.total_rx_rate,
                s.total_tx_rate,
                s.local_rx_rate,
                s.local_tx_rate,
                s.wide_rx_rate,
                s.wide_tx_rate,
                s.total_rx_bytes,
                s.total_tx_bytes,
                s.local_rx_bytes,
                s.local_tx_bytes,
                s.wide_rx_bytes,
                s.wide_tx_bytes,
                s.last_online_ts,
                ip_address_u64, // IPv4 address (v3)
            ];

            ring.insert(ts_ms, &rec);
        }

        Ok(())
    }

    /// Query data from memory Ring
    pub fn query_metrics(
        &self,
        mac: &[u8; 6],
        start_ms: u64,
        end_ms: u64,
    ) -> Result<Vec<MetricsRow>, anyhow::Error> {
        let rings = self.rings.lock().unwrap();

        if let Some(ring) = rings.get(mac) {
            Ok(ring.query(start_ms, end_ms))
        } else {
            Ok(Vec::new())
        }
    }

    /// Aggregate query data from all devices
    pub fn query_metrics_aggregate_all(
        &self,
        start_ms: u64,
        end_ms: u64,
    ) -> Result<Vec<MetricsRow>, anyhow::Error> {
        use std::collections::BTreeMap;

        let rings = self.rings.lock().unwrap();
        let mut ts_to_agg: BTreeMap<u64, [u64; SLOT_U64S_REALTIME]> = BTreeMap::new();

        for (_mac, ring) in rings.iter() {
            for slot in &ring.slots {
                let ts = slot[0];
                if ts == 0 {
                    continue;
                }
                if ts < start_ms || ts > end_ms {
                    continue;
                }

                let agg = ts_to_agg.entry(ts).or_insert([0u64; SLOT_U64S_REALTIME]);
                agg[0] = ts; // keep timestamp
                             // Aggregate only metric fields (exclude last_online_ts at index 13)
                for j in 1..13 {
                    agg[j] = agg[j].saturating_add(slot[j]);
                }
            }
        }

        let rows_vec: Vec<MetricsRow> = ts_to_agg
            .into_iter()
            .map(|(_ts, rec)| MetricsRow {
                ts_ms: rec[0],
                total_rx_rate: rec[1],
                total_tx_rate: rec[2],
                local_rx_rate: rec[3],
                local_tx_rate: rec[4],
                wide_rx_rate: rec[5],
                wide_tx_rate: rec[6],
                total_rx_bytes: rec[7],
                total_tx_bytes: rec[8],
                local_rx_bytes: rec[9],
                local_tx_bytes: rec[10],
                wide_rx_bytes: rec[11],
                wide_tx_bytes: rec[12],
            })
            .collect();

        Ok(rows_vec)
    }

    /// Flush dirty data to disk
    pub async fn flush_dirty_rings(&self) -> Result<(), anyhow::Error> {
        let mut rings = self.rings.lock().unwrap();

        for (mac, ring) in rings.iter_mut() {
            if ring.is_dirty() {
                self.persist_ring_to_file(mac, ring)?;
                ring.mark_clean();
            }
        }

        Ok(())
    }

    /// Persist a single Ring to file
    fn persist_ring_to_file(
        &self,
        mac: &[u8; 6],
        ring: &RealtimeRing,
    ) -> Result<(), anyhow::Error> {
        let path = ring_file_path(&self.base_dir, mac);
        let f = init_ring_file(&path, ring.capacity)?;

        for (idx, slot) in ring.slots.iter().enumerate() {
            if slot[0] != 0 {
                // Only write non-empty slots
                write_slot(&f, idx as u64, slot)?;
            }
        }

        f.sync_all()?;
        Ok(())
    }

    /// Load data from files to memory at startup
    pub fn load_from_files(&self) -> Result<(), anyhow::Error> {
        let dir = ring_dir(&self.base_dir);
        if !dir.exists() {
            return Ok(());
        }

        let mut rings = self.rings.lock().unwrap();

        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if path.extension().and_then(|s| s.to_str()) != Some("ring") {
                continue;
            }

            // Parse MAC from filename
            let fname = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if fname.len() != 12 {
                continue;
            }
            let mut mac = [0u8; 6];
            let mut ok = true;
            for i in 0..6 {
                if let Ok(v) = u8::from_str_radix(&fname[i * 2..i * 2 + 2], 16) {
                    mac[i] = v;
                } else {
                    ok = false;
                    break;
                }
            }
            if !ok {
                continue;
            }

            // Load from file to memory
            if let Ok(mut f) = OpenOptions::new().read(true).open(&path) {
                if let Ok((ver, cap)) = read_header(&mut f) {
                    if ver == RING_VERSION_REALTIME_V2 || ver == RING_VERSION_REALTIME_V3 {
                        if cap != self.capacity {
                            log::warn!(
                                "Skipping ring file {:?} with capacity {} (expected {}), file should have been deleted",
                                path,
                                cap,
                                self.capacity
                            );
                            continue;
                        }

                        let mut ring = RealtimeRing::new(self.capacity);

                        for i in 0..(self.capacity as u64) {
                            if ver == RING_VERSION_REALTIME_V2 {
                                // Read v2 slot and convert to v3
                                if let Ok(v2_slot) = read_slot_v2(&f, i) {
                                    if v2_slot[0] != 0 {
                                        let mut v3_slot = [0u64; SLOT_U64S_REALTIME];
                                        for j in 0..SLOT_U64S_REALTIME_V2 {
                                            v3_slot[j] = v2_slot[j];
                                        }
                                        // IP address remains 0 for v2 data
                                        ring.slots[i as usize] = v3_slot;
                                    }
                                }
                            } else {
                                // Read v3 slot
                                if let Ok(slot) = read_slot(&f, i) {
                                    if slot[0] != 0 {
                                        ring.slots[i as usize] = slot;
                                    }
                                }
                            }
                        }

                        ring.mark_clean(); // Just loaded from file, mark as clean
                        rings.insert(mac, ring);
                    }
                }
            }
        }

        Ok(())
    }
}

/// Statistics for a metric (average, max, min, p90, p95, p99)
#[derive(Debug, Clone)]
pub struct MetricStats {
    pub samples: Vec<u64>, // Store all samples for percentile calculation
    pub avg: u64,          // Average value (Mean)
    pub max: u64,          // Maximum value
    pub min: u64,          // Minimum value
    pub p90: u64,          // 90th percentile
    pub p95: u64,          // 95th percentile
    pub p99: u64,          // 99th percentile
}

impl MetricStats {
    pub fn new() -> Self {
        Self {
            samples: Vec::new(),
            avg: 0,
            max: 0,
            min: u64::MAX,
            p90: 0,
            p95: 0,
            p99: 0,
        }
    }

    pub fn add_sample(&mut self, value: u64) {
        self.samples.push(value);

        if self.samples.len() == 1 {
            self.min = value;
            self.max = value;
        } else {
            if value < self.min {
                self.min = value;
            }
            if value > self.max {
                self.max = value;
            }
        }
    }

    pub fn finalize(&mut self) {
        if self.samples.is_empty() {
            self.min = 0;
            self.avg = 0;
            self.max = 0;
            self.p90 = 0;
            self.p95 = 0;
            self.p99 = 0;
            return;
        }

        // Calculate average (Mean)
        let sum: u64 = self.samples.iter().sum();
        self.avg = sum / self.samples.len() as u64;

        // Calculate percentiles
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();

        let len = sorted.len();
        if len > 0 {
            // P90: index at 90% of sorted array
            let p90_idx = ((len - 1) as f64 * 0.90) as usize;
            self.p90 = sorted[p90_idx.min(len - 1)];

            // P95: index at 95% of sorted array
            let p95_idx = ((len - 1) as f64 * 0.95) as usize;
            self.p95 = sorted[p95_idx.min(len - 1)];

            // P99: index at 99% of sorted array
            let p99_idx = ((len - 1) as f64 * 0.99) as usize;
            self.p99 = sorted[p99_idx.min(len - 1)];
        }
    }
}

/// Accumulated statistics for a device during a sampling interval
/// Only stores wide network statistics and total wide traffic
#[derive(Debug, Clone)]
pub struct DeviceStatsAccumulator {
    pub ts_end_ms: u64,
    pub wide_rx_rate: MetricStats, // Wide network receive rate statistics
    pub wide_tx_rate: MetricStats, // Wide network transmit rate statistics
    pub wide_rx_bytes: u64,        // Total wide network receive bytes (cumulative)
    pub wide_tx_bytes: u64,        // Total wide network transmit bytes (cumulative)
}

impl DeviceStatsAccumulator {
    pub fn new(ts_ms: u64) -> Self {
        Self {
            ts_end_ms: ts_ms,
            wide_rx_rate: MetricStats::new(),
            wide_tx_rate: MetricStats::new(),
            wide_rx_bytes: 0,
            wide_tx_bytes: 0,
        }
    }

    pub fn add_sample(&mut self, stats: &MacTrafficStats, ts_ms: u64) {
        self.ts_end_ms = ts_ms;
        // Only accumulate wide network statistics
        self.wide_rx_rate.add_sample(stats.wide_rx_rate);
        self.wide_tx_rate.add_sample(stats.wide_tx_rate);

        // Keep latest cumulative wide traffic values
        self.wide_rx_bytes = stats.wide_rx_bytes;
        self.wide_tx_bytes = stats.wide_tx_bytes;
    }

    pub fn finalize(&mut self) {
        self.wide_rx_rate.finalize();
        self.wide_tx_rate.finalize();
    }
}

/// Sampling level configuration
#[derive(Debug, Clone)]
pub struct SamplingLevel {
    /// Sampling interval in seconds
    pub interval_seconds: u64,
    /// Retention period in seconds
    pub retention_seconds: u64,
    /// Capacity (calculated from retention / interval)
    pub capacity: u32,
    /// Subdirectory name for this level
    pub subdir: String,
    /// Whether to use statistics (avg/max/min) instead of real-time values
    pub use_statistics: bool,
}

impl SamplingLevel {
    pub fn new(
        interval_seconds: u64,
        retention_seconds: u64,
        subdir: String,
        use_statistics: bool,
    ) -> Self {
        let capacity = (retention_seconds / interval_seconds) as u32;
        Self {
            interval_seconds,
            retention_seconds,
            capacity,
            subdir,
            use_statistics,
        }
    }

    /// Check if timestamp should be sampled at this level
    /// Returns true if the timestamp aligns with the sampling interval
    pub fn should_sample(&self, ts_ms: u64) -> bool {
        let ts_sec = ts_ms / 1000;
        // Check if timestamp is aligned to the sampling interval
        // For example, for 30s interval: 0, 30, 60, 90, etc.
        ts_sec % self.interval_seconds == 0
    }
}

/// Memory Ring Manager for multilevel statistics (30s/3min/10min/1h sampling)
pub struct MultilevelRingManager {
    pub rings: Arc<Mutex<HashMap<[u8; 6], MultilevelRing>>>,
    pub base_dir: String,
    pub capacity: u32,
}

impl MultilevelRingManager {
    pub fn new(base_dir: String, capacity: u32) -> Self {
        Self {
            rings: Arc::new(Mutex::new(HashMap::new())),
            base_dir,
            capacity,
        }
    }

    pub fn insert_stats(
        &self,
        ts_ms: u64,
        mac: &[u8; 6],
        stats: &DeviceStatsAccumulator,
        interval_seconds: u64,
    ) -> Result<(), anyhow::Error> {
        let mut rings = self.rings.lock().unwrap();
        let ring = rings
            .entry(*mac)
            .or_insert_with(|| MultilevelRing::new(self.capacity));

        ring.insert_stats(ts_ms, stats, interval_seconds);
        Ok(())
    }

    pub fn query_stats(
        &self,
        mac: &[u8; 6],
        start_ms: u64,
        end_ms: u64,
    ) -> Result<Vec<MetricsRowWithStats>, anyhow::Error> {
        let rings = self.rings.lock().unwrap();
        if let Some(ring) = rings.get(mac) {
            Ok(ring.query_stats(start_ms, end_ms))
        } else {
            Ok(Vec::new())
        }
    }

    /// Query statistics for all devices grouped by MAC address
    /// Returns a map of MAC address to aggregated statistics within the time range
    pub fn query_stats_by_device(
        &self,
        start_ms: u64,
        end_ms: u64,
    ) -> Result<HashMap<[u8; 6], MetricsRowWithStats>, anyhow::Error> {
        let rings = self.rings.lock().unwrap();
        let mut device_stats: HashMap<[u8; 6], MetricsRowWithStats> = HashMap::new();

        for (mac, ring) in rings.iter() {
            let rows = ring.query_stats(start_ms, end_ms);
            
            // Aggregate all rows for this device into a single stats entry
            let mut aggregated = MetricsRowWithStats {
                ts_ms: start_ms, // Use start time as reference
                wide_rx_rate_avg: 0,
                wide_rx_rate_max: 0,
                wide_rx_rate_min: u64::MAX,
                wide_rx_rate_p90: 0,
                wide_rx_rate_p95: 0,
                wide_rx_rate_p99: 0,
                wide_tx_rate_avg: 0,
                wide_tx_rate_max: 0,
                wide_tx_rate_min: u64::MAX,
                wide_tx_rate_p90: 0,
                wide_tx_rate_p95: 0,
                wide_tx_rate_p99: 0,
                wide_rx_bytes: 0,
                wide_tx_bytes: 0,
            };

            if rows.is_empty() {
                continue;
            }

            // For bytes: calculate the increment within the time range
            // Since wide_rx_bytes and wide_tx_bytes are cumulative values,
            // if there's only one sample, use its value (total up to that point)
            // if there are multiple samples, use the difference (increment in the time range)
            // For rates: aggregate statistics
            let first_row = &rows[0];
            let last_row = &rows[rows.len() - 1];
            
            if rows.len() == 1 {
                // Only one sample: use the cumulative value directly
                aggregated.wide_rx_bytes = last_row.wide_rx_bytes;
                aggregated.wide_tx_bytes = last_row.wide_tx_bytes;
            } else {
                // Multiple samples: calculate increment (difference between last and first)
                aggregated.wide_rx_bytes = last_row.wide_rx_bytes.saturating_sub(first_row.wide_rx_bytes);
                aggregated.wide_tx_bytes = last_row.wide_tx_bytes.saturating_sub(first_row.wide_tx_bytes);
            }

            // Aggregate rate statistics: sum for avg, max for max/p90/p95/p99, min for min
            for row in &rows {
                aggregated.wide_rx_rate_avg = aggregated.wide_rx_rate_avg.saturating_add(row.wide_rx_rate_avg);
                aggregated.wide_rx_rate_max = aggregated.wide_rx_rate_max.max(row.wide_rx_rate_max);
                aggregated.wide_rx_rate_min = aggregated.wide_rx_rate_min.min(row.wide_rx_rate_min);
                aggregated.wide_rx_rate_p90 = aggregated.wide_rx_rate_p90.max(row.wide_rx_rate_p90);
                aggregated.wide_rx_rate_p95 = aggregated.wide_rx_rate_p95.max(row.wide_rx_rate_p95);
                aggregated.wide_rx_rate_p99 = aggregated.wide_rx_rate_p99.max(row.wide_rx_rate_p99);

                aggregated.wide_tx_rate_avg = aggregated.wide_tx_rate_avg.saturating_add(row.wide_tx_rate_avg);
                aggregated.wide_tx_rate_max = aggregated.wide_tx_rate_max.max(row.wide_tx_rate_max);
                aggregated.wide_tx_rate_min = aggregated.wide_tx_rate_min.min(row.wide_tx_rate_min);
                aggregated.wide_tx_rate_p90 = aggregated.wide_tx_rate_p90.max(row.wide_tx_rate_p90);
                aggregated.wide_tx_rate_p95 = aggregated.wide_tx_rate_p95.max(row.wide_tx_rate_p95);
                aggregated.wide_tx_rate_p99 = aggregated.wide_tx_rate_p99.max(row.wide_tx_rate_p99);
            }

            // Average the rate averages
            let count = rows.len() as u64;
            if count > 0 {
                aggregated.wide_rx_rate_avg /= count;
                aggregated.wide_tx_rate_avg /= count;
            }

            // Fix min values
            if aggregated.wide_rx_rate_min == u64::MAX {
                aggregated.wide_rx_rate_min = 0;
            }
            if aggregated.wide_tx_rate_min == u64::MAX {
                aggregated.wide_tx_rate_min = 0;
            }

            device_stats.insert(*mac, aggregated);
        }

        Ok(device_stats)
    }

    /// Query time series increments for a specific device
    /// Returns a list of increments (current value - previous value) for each time point
    pub fn query_time_series_increments(
        &self,
        mac: &[u8; 6],
        start_ms: u64,
        end_ms: u64,
    ) -> Result<Vec<(u64, u64, u64)>, anyhow::Error> {
        // Returns Vec<(ts_ms, rx_bytes_increment, tx_bytes_increment)>
        let rings = self.rings.lock().unwrap();
        if let Some(ring) = rings.get(mac) {
            let rows = ring.query_stats(start_ms, end_ms);
            
            if rows.is_empty() {
                return Ok(Vec::new());
            }

            let mut increments = Vec::new();
            let mut prev_rx = rows[0].wide_rx_bytes;
            let mut prev_tx = rows[0].wide_tx_bytes;

            // First point: use its value as baseline (increment is 0 or use first value)
            // For the first point, we can't calculate increment, so we skip it or use 0
            // Actually, let's include it with increment = 0, or we can use the first value as increment
            
            // For subsequent points, calculate increment
            for (idx, row) in rows.iter().enumerate() {
                if idx == 0 {
                    // First point: no increment, but we can include it with 0 increment
                    // Or skip it - let's skip the first point since we can't calculate increment
                    prev_rx = row.wide_rx_bytes;
                    prev_tx = row.wide_tx_bytes;
                    continue;
                }

                // Calculate increment (handle wrap-around)
                let rx_inc = if row.wide_rx_bytes >= prev_rx {
                    row.wide_rx_bytes - prev_rx
                } else {
                    // Handle potential wrap-around (unlikely for cumulative bytes, but safe)
                    row.wide_rx_bytes
                };

                let tx_inc = if row.wide_tx_bytes >= prev_tx {
                    row.wide_tx_bytes - prev_tx
                } else {
                    row.wide_tx_bytes
                };

                increments.push((row.ts_ms, rx_inc, tx_inc));

                prev_rx = row.wide_rx_bytes;
                prev_tx = row.wide_tx_bytes;
            }

            Ok(increments)
        } else {
            Ok(Vec::new())
        }
    }

    /// Query time series increments for all devices (aggregated)
    pub fn query_time_series_increments_aggregate(
        &self,
        start_ms: u64,
        end_ms: u64,
    ) -> Result<Vec<(u64, u64, u64)>, anyhow::Error> {
        // Returns Vec<(ts_ms, rx_bytes_increment, tx_bytes_increment)>
        let rings = self.rings.lock().unwrap();
        let mut all_rows_by_ts: std::collections::BTreeMap<u64, (u64, u64)> = std::collections::BTreeMap::new();

        // Collect all rows from all devices, aggregate by timestamp
        for (_mac, ring) in rings.iter() {
            let rows = ring.query_stats(start_ms, end_ms);
            for row in rows {
                let entry = all_rows_by_ts.entry(row.ts_ms).or_insert((0, 0));
                entry.0 = entry.0.saturating_add(row.wide_rx_bytes);
                entry.1 = entry.1.saturating_add(row.wide_tx_bytes);
            }
        }

        if all_rows_by_ts.is_empty() {
            return Ok(Vec::new());
        }

        let mut increments = Vec::new();
        let mut prev_rx = 0u64;
        let mut prev_tx = 0u64;
        let mut is_first = true;

        for (_ts_ms, (rx_bytes, tx_bytes)) in all_rows_by_ts.iter() {
            if is_first {
                prev_rx = *rx_bytes;
                prev_tx = *tx_bytes;
                is_first = false;
                continue;
            }

            let rx_inc = if *rx_bytes >= prev_rx {
                *rx_bytes - prev_rx
            } else {
                *rx_bytes
            };

            let tx_inc = if *tx_bytes >= prev_tx {
                *tx_bytes - prev_tx
            } else {
                *tx_bytes
            };

            increments.push((*_ts_ms, rx_inc, tx_inc));

            prev_rx = *rx_bytes;
            prev_tx = *tx_bytes;
        }

        Ok(increments)
    }

    pub fn query_stats_aggregate_all(
        &self,
        start_ms: u64,
        end_ms: u64,
    ) -> Result<Vec<MetricsRowWithStats>, anyhow::Error> {
        let rings = self.rings.lock().unwrap();
        let mut all_rows = Vec::new();

        for (_mac, ring) in rings.iter() {
            let mut rows = ring.query_stats(start_ms, end_ms);
            all_rows.append(&mut rows);
        }

        // Aggregate by timestamp
        use std::collections::BTreeMap;
        let mut ts_to_stats: BTreeMap<u64, MetricsRowWithStats> = BTreeMap::new();

        for row in all_rows {
            let entry = ts_to_stats.entry(row.ts_ms).or_insert(MetricsRowWithStats {
                ts_ms: row.ts_ms,
                wide_rx_rate_avg: 0,
                wide_rx_rate_max: 0,
                wide_rx_rate_min: u64::MAX,
                wide_rx_rate_p90: 0,
                wide_rx_rate_p95: 0,
                wide_rx_rate_p99: 0,
                wide_tx_rate_avg: 0,
                wide_tx_rate_max: 0,
                wide_tx_rate_min: u64::MAX,
                wide_tx_rate_p90: 0,
                wide_tx_rate_p95: 0,
                wide_tx_rate_p99: 0,
                wide_rx_bytes: 0,
                wide_tx_bytes: 0,
            });

            // Aggregate: sum for avg/bytes, max for max/p90/p95/p99, min for min
            entry.wide_rx_rate_avg = entry.wide_rx_rate_avg.saturating_add(row.wide_rx_rate_avg);
            entry.wide_rx_rate_max = entry.wide_rx_rate_max.max(row.wide_rx_rate_max);
            entry.wide_rx_rate_min = entry.wide_rx_rate_min.min(row.wide_rx_rate_min);
            entry.wide_rx_rate_p90 = entry.wide_rx_rate_p90.max(row.wide_rx_rate_p90);
            entry.wide_rx_rate_p95 = entry.wide_rx_rate_p95.max(row.wide_rx_rate_p95);
            entry.wide_rx_rate_p99 = entry.wide_rx_rate_p99.max(row.wide_rx_rate_p99);

            entry.wide_tx_rate_avg = entry.wide_tx_rate_avg.saturating_add(row.wide_tx_rate_avg);
            entry.wide_tx_rate_max = entry.wide_tx_rate_max.max(row.wide_tx_rate_max);
            entry.wide_tx_rate_min = entry.wide_tx_rate_min.min(row.wide_tx_rate_min);
            entry.wide_tx_rate_p90 = entry.wide_tx_rate_p90.max(row.wide_tx_rate_p90);
            entry.wide_tx_rate_p95 = entry.wide_tx_rate_p95.max(row.wide_tx_rate_p95);
            entry.wide_tx_rate_p99 = entry.wide_tx_rate_p99.max(row.wide_tx_rate_p99);

            entry.wide_rx_bytes = entry.wide_rx_bytes.saturating_add(row.wide_rx_bytes);
            entry.wide_tx_bytes = entry.wide_tx_bytes.saturating_add(row.wide_tx_bytes);
        }

        // Fix min values that are still u64::MAX
        for stats in ts_to_stats.values_mut() {
            if stats.wide_rx_rate_min == u64::MAX {
                stats.wide_rx_rate_min = 0;
            }
            if stats.wide_tx_rate_min == u64::MAX {
                stats.wide_tx_rate_min = 0;
            }
        }

        Ok(ts_to_stats.into_values().collect())
    }

    /// Persist a single RingV3 to file
    fn persist_ring_to_file_multilevel(
        &self,
        mac: &[u8; 6],
        ring: &MultilevelRing,
    ) -> Result<(), anyhow::Error> {
        let path = ring_file_path_v3(&self.base_dir, mac);
        let f = init_ring_file_v3(&path, ring.capacity)?;

        for (idx, slot) in ring.slots.iter().enumerate() {
            if slot[0] != 0 {
                // Only write non-empty slots
                write_slot_v3(&f, idx as u64, slot)?;
            }
        }

        f.sync_all()?;
        Ok(())
    }

    pub async fn flush_dirty_rings(&self) -> Result<(), anyhow::Error> {
        let mut rings = self.rings.lock().unwrap();
        for (mac, ring) in rings.iter_mut() {
            if ring.is_dirty() {
                self.persist_ring_to_file_multilevel(mac, ring)?;
                ring.mark_clean();
            }
        }
        Ok(())
    }

    pub fn load_from_files(&self) -> Result<(), anyhow::Error> {
        let dir = Path::new(&self.base_dir);
        if !dir.exists() {
            return Ok(());
        }

        let mut rings = self.rings.lock().unwrap();

        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if path.extension().and_then(|s| s.to_str()) != Some("ring") {
                continue;
            }

            // Parse MAC from filename
            let fname = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if fname.len() != 12 {
                continue;
            }
            let mut mac = [0u8; 6];
            let mut ok = true;
            for i in 0..6 {
                if let Ok(v) = u8::from_str_radix(&fname[i * 2..i * 2 + 2], 16) {
                    mac[i] = v;
                } else {
                    ok = false;
                    break;
                }
            }
            if !ok {
                continue;
            }

            // Load from file to memory
            if let Ok(mut f) = OpenOptions::new().read(true).open(&path) {
                if let Ok((ver, cap)) = read_header(&mut f) {
                    if ver == RING_VERSION_MULTILEVEL {
                        // For multilevel rings, capacity is fixed and doesn't depend on manager's capacity
                        // Use file's capacity directly
                        let mut ring = MultilevelRing::new(cap);

                        for i in 0..(cap as u64) {
                            if let Ok(slot) = read_slot_v3(&f, i) {
                                if slot[0] != 0 {
                                    ring.slots[i as usize] = slot;
                                }
                            }
                        }

                        ring.mark_clean(); // Just loaded from file, mark as clean
                        rings.insert(mac, ring);
                    }
                }
            }
        }

        Ok(())
    }
}

/// Multi-level Ring Manager for hierarchical sampling
pub struct MultiLevelRingManager {
    pub levels: Vec<SamplingLevel>,
    pub managers: Vec<MultilevelRingManager>,
    // Accumulators for statistics: (level_index, mac) -> DeviceStatsAccumulator
    pub accumulators: Arc<Mutex<HashMap<(usize, [u8; 6]), DeviceStatsAccumulator>>>,
}

impl MultiLevelRingManager {
    /// Create a new multi-level ring manager with default levels:
    /// - Level 1: 30s interval, 1 day retention (use statistics)
    /// - Level 2: 3min interval, 1 week retention (use statistics)
    /// - Level 3: 10min interval, 1 month retention (use statistics)
    /// - Level 4: 1h interval, 365 days retention (use statistics)
    pub fn new(base_dir: String) -> Self {
        let levels = vec![
            SamplingLevel::new(30, 24 * 3600, "day".to_string(), true), // 1 day, 30s interval, use stats
            SamplingLevel::new(180, 7 * 24 * 3600, "week".to_string(), true), // 1 week, 3min interval, use stats
            SamplingLevel::new(600, 30 * 24 * 3600, "month".to_string(), true), // 1 month, 10min interval, use stats
            SamplingLevel::new(3600, 365 * 24 * 3600, "year".to_string(), true), // 365 days, 1h interval, use stats
        ];

        let managers: Vec<MultilevelRingManager> = levels
            .iter()
            .map(|level| {
                MultilevelRingManager::new(
                    Path::new(&base_dir)
                        .join("metrics")
                        .join(&level.subdir)
                        .to_string_lossy()
                        .to_string(),
                    level.capacity,
                )
            })
            .collect();

        Self {
            levels,
            managers,
            accumulators: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Insert metrics batch into appropriate levels based on sampling intervals
    /// For levels using statistics, accumulates data during the interval and writes stats at sampling time
    pub fn insert_metrics_batch(
        &self,
        ts_ms: u64,
        rows: &Vec<([u8; 6], MacTrafficStats)>,
    ) -> Result<(), anyhow::Error> {
        if rows.is_empty() {
            return Ok(());
        }

        let mut accumulators = self.accumulators.lock().unwrap();

        // Process each level
        for (level_idx, (level, manager)) in
            self.levels.iter().zip(self.managers.iter()).enumerate()
        {
            if level.use_statistics {
                // For statistics-based levels, accumulate data during the interval
                for (mac, stats) in rows.iter() {
                    let key = (level_idx, *mac);

                    // Get or create accumulator for this device and level
                    let accumulator = accumulators
                        .entry(key)
                        .or_insert_with(|| DeviceStatsAccumulator::new(ts_ms));

                    // Add sample to accumulator
                    accumulator.add_sample(stats, ts_ms);

                    // Check if we should flush (at sampling interval boundary)
                    if level.should_sample(ts_ms) {
                        // Finalize statistics (calculate avg, p90, p95, p99)
                        accumulator.finalize();

                        // Insert statistics into v3 ring manager with interval_seconds
                        manager.insert_stats(accumulator.ts_end_ms, mac, accumulator, level.interval_seconds)?;

                        // Remove accumulator after flushing
                        accumulators.remove(&key);
                    }
                }
            }
        }

        Ok(())
    }

    /// Flush dirty data to disk for all levels
    pub async fn flush_dirty_rings(&self) -> Result<(), anyhow::Error> {
        for manager in &self.managers {
            manager.flush_dirty_rings().await?;
        }
        Ok(())
    }

    /// Load data from files to memory at startup
    pub fn load_from_files(&self) -> Result<(), anyhow::Error> {
        for manager in &self.managers {
            manager.load_from_files()?;
        }
        Ok(())
    }

    /// Get the manager for a specific level by subdirectory name
    pub fn get_manager_by_level(&self, level_name: &str) -> Option<&MultilevelRingManager> {
        self.levels
            .iter()
            .zip(self.managers.iter())
            .find(|(level, _)| level.subdir == level_name)
            .map(|(_, manager)| manager)
    }

    /// Get the sampling level for a specific level by subdirectory name
    pub fn get_level_by_name(&self, level_name: &str) -> Option<&SamplingLevel> {
        self.levels.iter().find(|level| level.subdir == level_name)
    }
}

fn ring_dir(base: &str) -> PathBuf {
    Path::new(base).join("metrics")
}
fn limits_path(base: &str) -> PathBuf {
    Path::new(base).join("rate_limits.txt")
}
// bindings_path moved to storage::hostname module
fn ring_file_path(base: &str, mac: &[u8; 6]) -> PathBuf {
    ring_dir(base).join(format!("{}.ring", mac_to_filename(mac)))
}

fn ring_file_path_v3(base: &str, mac: &[u8; 6]) -> PathBuf {
    Path::new(base).join(format!("{}.ring", mac_to_filename(mac)))
}

fn ensure_parent_dir(path: &Path) -> Result<(), anyhow::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn write_header(f: &mut File, capacity: u32, version: u32) -> Result<(), anyhow::Error> {
    f.seek(SeekFrom::Start(0))?;
    f.write_all(&RING_MAGIC)?;
    f.write_all(&version.to_le_bytes())?;
    f.write_all(&capacity.to_le_bytes())?;
    Ok(())
}

fn read_header(f: &mut File) -> Result<(u32, u32), anyhow::Error> {
    let mut magic = [0u8; 4];
    f.seek(SeekFrom::Start(0))?;
    f.read_exact(&mut magic)?;
    if magic != RING_MAGIC {
        return Err(anyhow::anyhow!("invalid ring file magic"));
    }
    let mut buf4 = [0u8; 4];
    f.read_exact(&mut buf4)?;
    let ver = u32::from_le_bytes(buf4);
    f.read_exact(&mut buf4)?;
    let cap = u32::from_le_bytes(buf4);
    Ok((ver, cap))
}

fn init_ring_file(path: &Path, capacity: u32) -> Result<File, anyhow::Error> {
    ensure_parent_dir(path)?;
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;

    let metadata = f.metadata()?;
    let cap = if capacity == 0 {
        DEFAULT_RING_CAPACITY
    } else {
        capacity
    };
    let expected_size = HEADER_SIZE as u64 + (cap as u64) * (SLOT_SIZE_REALTIME as u64);

    if metadata.len() != expected_size {
        // Reinitialize
        f.set_len(0)?;
        write_header(&mut f, cap, RING_VERSION_REALTIME)?;
        // Write zeroed slot area
        let zero_chunk = vec![0u8; 4096];
        let mut remaining = expected_size - HEADER_SIZE as u64;
        while remaining > 0 {
            let to_write = std::cmp::min(remaining, zero_chunk.len() as u64) as usize;
            f.write_all(&zero_chunk[..to_write])?;
            remaining -= to_write as u64;
        }
        f.flush()?;
    } else {
        // Validate header
        let (ver, _cap) = read_header(&mut f)?;
        // If file is v2 format, upgrade to v3 by rewriting with new format
        if ver == RING_VERSION_REALTIME_V2 {
            log::info!("Upgrading ring file from v2 to v3 format");
            // Read all v2 slots
            let mut v2_slots = Vec::new();
            for i in 0..(cap as u64) {
                if let Ok(slot) = read_slot_v2(&f, i) {
                    if slot[0] != 0 {
                        v2_slots.push((i, slot));
                    }
                }
            }
            // Rewrite file as v3
            f.set_len(0)?;
            write_header(&mut f, cap, RING_VERSION_REALTIME)?;
            let zero_chunk = vec![0u8; 4096];
            let mut remaining = expected_size - HEADER_SIZE as u64;
            while remaining > 0 {
                let to_write = std::cmp::min(remaining, zero_chunk.len() as u64) as usize;
                f.write_all(&zero_chunk[..to_write])?;
                remaining -= to_write as u64;
            }
            // Write v2 slots as v3 (with IP address = 0)
            for (idx, v2_slot) in v2_slots {
                let mut v3_slot = [0u64; SLOT_U64S_REALTIME];
                for i in 0..SLOT_U64S_REALTIME_V2 {
                    v3_slot[i] = v2_slot[i];
                }
                // IP address remains 0 (unknown for old data)
                write_slot(&f, idx, &v3_slot)?;
            }
            f.flush()?;
        }
    }
    Ok(f)
}

fn calc_slot_index(ts_ms: u64, capacity: u32) -> u64 {
    ((ts_ms / 1000) % capacity as u64) as u64
}

/// Calculate slot index for multilevel rings with sampling interval
/// This ensures that data is stored correctly based on sampling interval, not just timestamp modulo
fn calc_slot_index_with_interval(ts_ms: u64, capacity: u32, interval_seconds: u64) -> u64 {
    let ts_sec = ts_ms / 1000;
    // Calculate slot index based on sampling interval
    // For example, with 30s interval: slot = (ts_sec / 30) % capacity
    // This ensures each sampling point gets a unique slot until capacity is reached
    ((ts_sec / interval_seconds) % capacity as u64) as u64
}

fn write_slot(
    mut f: &File,
    idx: u64,
    data: &[u64; SLOT_U64S_REALTIME],
) -> Result<(), anyhow::Error> {
    let offset = HEADER_SIZE as u64 + idx * (SLOT_SIZE_REALTIME as u64);
    let mut bytes = [0u8; SLOT_SIZE_REALTIME];
    for (i, v) in data.iter().enumerate() {
        let b = v.to_le_bytes();
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&b);
    }
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(&bytes)?;
    Ok(())
}

// Read slot for v2 format (14 u64s)
fn read_slot_v2(mut f: &File, idx: u64) -> Result<[u64; SLOT_U64S_REALTIME_V2], anyhow::Error> {
    let slot_size_v2 = SLOT_U64S_REALTIME_V2 * 8;
    let offset = HEADER_SIZE as u64 + idx * (slot_size_v2 as u64);
    let mut bytes = vec![0u8; slot_size_v2];
    f.seek(SeekFrom::Start(offset))?;
    f.read_exact(&mut bytes)?;
    let mut out = [0u64; SLOT_U64S_REALTIME_V2];
    for i in 0..SLOT_U64S_REALTIME_V2 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        out[i] = u64::from_le_bytes(b);
    }
    Ok(out)
}

// Read slot for v3 format (15 u64s)
fn read_slot(mut f: &File, idx: u64) -> Result<[u64; SLOT_U64S_REALTIME], anyhow::Error> {
    let offset = HEADER_SIZE as u64 + idx * (SLOT_SIZE_REALTIME as u64);
    let mut bytes = vec![0u8; SLOT_SIZE_REALTIME];
    f.seek(SeekFrom::Start(offset))?;
    f.read_exact(&mut bytes)?;
    let mut out = [0u64; SLOT_U64S_REALTIME];
    for i in 0..SLOT_U64S_REALTIME {
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        out[i] = u64::from_le_bytes(b);
    }
    Ok(out)
}

// ============================================================================
// Multi-level Ring File I/O Functions (v3 format)
// ============================================================================

fn write_header_v3(f: &mut File, capacity: u32) -> Result<(), anyhow::Error> {
    f.seek(SeekFrom::Start(0))?;
    f.write_all(&RING_MAGIC)?;
    f.write_all(&RING_VERSION_MULTILEVEL.to_le_bytes())?;
    f.write_all(&capacity.to_le_bytes())?;
    Ok(())
}

fn init_ring_file_v3(path: &Path, capacity: u32) -> Result<File, anyhow::Error> {
    ensure_parent_dir(path)?;
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;

    let metadata = f.metadata()?;
    let cap = if capacity == 0 {
        DEFAULT_RING_CAPACITY
    } else {
        capacity
    };
    let expected_size = HEADER_SIZE as u64 + (cap as u64) * (SLOT_SIZE_MULTILEVEL as u64);

    if metadata.len() != expected_size {
        // Reinitialize
        f.set_len(0)?;
        write_header_v3(&mut f, cap)?;
        // Write zeroed slot area
        let zero_chunk = vec![0u8; 4096];
        let mut remaining = expected_size - HEADER_SIZE as u64;
        while remaining > 0 {
            let to_write = std::cmp::min(remaining, zero_chunk.len() as u64) as usize;
            f.write_all(&zero_chunk[..to_write])?;
            remaining -= to_write as u64;
        }
        f.flush()?;
    } else {
        // Validate header
        let (ver, _) = read_header(&mut f)?;
        if ver != RING_VERSION_MULTILEVEL {
            // File exists but wrong version, reinitialize
            f.set_len(0)?;
            write_header_v3(&mut f, cap)?;
            let zero_chunk = vec![0u8; 4096];
            let mut remaining = expected_size - HEADER_SIZE as u64;
            while remaining > 0 {
                let to_write = std::cmp::min(remaining, zero_chunk.len() as u64) as usize;
                f.write_all(&zero_chunk[..to_write])?;
                remaining -= to_write as u64;
            }
            f.flush()?;
        }
    }
    Ok(f)
}

fn write_slot_v3(
    mut f: &File,
    idx: u64,
    data: &[u64; SLOT_U64S_MULTILEVEL],
) -> Result<(), anyhow::Error> {
    let offset = HEADER_SIZE as u64 + idx * (SLOT_SIZE_MULTILEVEL as u64);
    let mut bytes = vec![0u8; SLOT_SIZE_MULTILEVEL];
    for (i, v) in data.iter().enumerate() {
        let b = v.to_le_bytes();
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&b);
    }
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(&bytes)?;
    Ok(())
}

fn read_slot_v3(mut f: &File, idx: u64) -> Result<[u64; SLOT_U64S_MULTILEVEL], anyhow::Error> {
    let offset = HEADER_SIZE as u64 + idx * (SLOT_SIZE_MULTILEVEL as u64);
    let mut bytes = vec![0u8; SLOT_SIZE_MULTILEVEL];
    f.seek(SeekFrom::Start(offset))?;
    f.read_exact(&mut bytes)?;
    let mut out = [0u64; SLOT_U64S_MULTILEVEL];
    for i in 0..SLOT_U64S_MULTILEVEL {
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        out[i] = u64::from_le_bytes(b);
    }
    Ok(out)
}

pub fn ensure_schema(base_dir: &str) -> Result<(), anyhow::Error> {
    // Create directory and hostname binding files
    // Note: rate_limits.txt is deprecated and no longer created
    // Create metrics directories for multi-level sampling
    fs::create_dir_all(ring_dir(base_dir))
        .with_context(|| format!("Failed to create metrics dir under {}", base_dir))?;
    // Create subdirectories for each sampling level
    fs::create_dir_all(Path::new(base_dir).join("metrics").join("day"))
        .with_context(|| format!("Failed to create day metrics dir under {}", base_dir))?;
    fs::create_dir_all(Path::new(base_dir).join("metrics").join("week"))
        .with_context(|| format!("Failed to create week metrics dir under {}", base_dir))?;
    fs::create_dir_all(Path::new(base_dir).join("metrics").join("month"))
        .with_context(|| format!("Failed to create month metrics dir under {}", base_dir))?;
    let bindings = crate::storage::hostname::bindings_path(base_dir);
    if !bindings.exists() {
        File::create(&bindings)?;
    }
    Ok(())
}

/// At startup, check if all ring file capacities in the `metrics` directory match the given
/// `traffic_retention_seconds`; if any inconsistency is found, delete all ring files in that directory.
/// Note: This operation will clear historical time series data, only keeping rate limit configuration files.
/// Files will be automatically recreated when needed with the correct capacity.
pub fn rebuild_all_ring_files_if_mismatch(
    base_dir: &str,
    traffic_retention_seconds: u32,
) -> Result<bool, anyhow::Error> {
    let dir = ring_dir(base_dir);
    if !dir.exists() {
        return Ok(false);
    }

    // First check if there are any inconsistencies
    let mut mismatch_found = false;
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("ring") {
            continue;
        }
        let mut f = OpenOptions::new().read(true).open(&path)?;
        let (_ver, cap) = read_header(&mut f)?;
        if cap != traffic_retention_seconds {
            mismatch_found = true;
            break;
        }
    }

    if !mismatch_found {
        return Ok(false);
    }

    // If inconsistencies are found, delete all .ring files
    // Files will be automatically recreated with correct capacity when needed
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("ring") {
            continue;
        }
        // Delete the file
        match fs::remove_file(&path) {
            Ok(_) => {
                log::info!(
                    "Deleted ring file {:?} due to capacity mismatch (expected: {}s)",
                    path,
                    traffic_retention_seconds
                );
            }
            Err(e) => {
                log::warn!("Failed to delete ring file {:?}: {}", path, e);
            }
        }
    }

    Ok(true)
}

pub fn load_all_limits(base_dir: &str) -> Result<Vec<([u8; 6], u64, u64)>, anyhow::Error> {
    let path = limits_path(base_dir);
    let mut out = Vec::new();
    if !path.exists() {
        return Ok(out);
    }
    let content = fs::read_to_string(&path)?;
    for (lineno, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Format: mac rx tx (MAC in colon-separated or 12-hex format are both supported)
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 3 {
            continue;
        }
        let mac_str = parts[0];
        let mac = if mac_str.contains(':') {
            parse_mac_text(mac_str)
        } else if mac_str.len() == 12 {
            let mut mac = [0u8; 6];
            for i in 0..6 {
                mac[i] = u8::from_str_radix(&mac_str[i * 2..i * 2 + 2], 16)
                    .with_context(|| format!("invalid mac hex at line {}", lineno + 1))?;
            }
            Ok(mac)
        } else {
            Err(anyhow::anyhow!("invalid mac format at line {}", lineno + 1))
        }?;
        let rx: u64 = parts[1]
            .parse()
            .with_context(|| format!("invalid rx at line {}", lineno + 1))?;
        let tx: u64 = parts[2]
            .parse()
            .with_context(|| format!("invalid tx at line {}", lineno + 1))?;
        out.push((mac, rx, tx));
    }
    Ok(out)
}

pub fn upsert_hostname_binding(
    base_dir: &str,
    mac: &[u8; 6],
    hostname: &str,
) -> Result<(), anyhow::Error> {
    let path = crate::storage::hostname::bindings_path(base_dir);
    ensure_parent_dir(&path)?;
    let mut map: std::collections::BTreeMap<String, String> = Default::default();
    if path.exists() {
        let content = fs::read_to_string(&path)?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            if parts.len() != 2 {
                continue;
            }
            map.insert(parts[0].to_string(), parts[1].to_string());
        }
    }
    let key = mac_to_filename(mac);

    if hostname.is_empty() {
        // Remove binding if hostname is empty
        map.remove(&key);
    } else {
        // Set or update binding
        map.insert(key.clone(), hostname.to_string());
    }

    let mut buf = String::new();
    buf.push_str("# mac hostname\n");
    for (k, hostname) in map {
        buf.push_str(&format!("{} {}\n", k, hostname));
    }
    fs::write(&path, buf)?;
    Ok(())
}

// load_hostname_bindings and load_hostname_from_ubus moved to storage::hostname module

#[derive(Debug, Clone, Copy)]
pub struct MetricsRow {
    pub ts_ms: u64,
    pub total_rx_rate: u64,
    pub total_tx_rate: u64,
    pub local_rx_rate: u64,
    pub local_tx_rate: u64,
    pub wide_rx_rate: u64,
    pub wide_tx_rate: u64,
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
    pub local_rx_bytes: u64,
    pub local_tx_bytes: u64,
    pub wide_rx_bytes: u64,
    pub wide_tx_bytes: u64,
}

/// Metrics row with statistics (for multi-level sampling)
#[derive(Debug, Clone, Copy)]
/// Metrics row with statistics (for multi-level sampling)
/// Only contains wide network statistics and total wide traffic
pub struct MetricsRowWithStats {
    pub ts_ms: u64,
    // Wide network receive rate statistics (avg, max, min, p90, p95, p99)
    pub wide_rx_rate_avg: u64, // Mean: typical bandwidth usage
    pub wide_rx_rate_max: u64, // Max: peak load or burst traffic
    pub wide_rx_rate_min: u64, // Min: idle or low load state
    pub wide_rx_rate_p90: u64, // 90th percentile
    pub wide_rx_rate_p95: u64, // 95th percentile
    pub wide_rx_rate_p99: u64, // 99th percentile
    // Wide network transmit rate statistics (avg, max, min, p90, p95, p99)
    pub wide_tx_rate_avg: u64, // Mean: typical bandwidth usage
    pub wide_tx_rate_max: u64, // Max: peak load or burst traffic
    pub wide_tx_rate_min: u64, // Min: idle or low load state
    pub wide_tx_rate_p90: u64, // 90th percentile
    pub wide_tx_rate_p95: u64, // 95th percentile
    pub wide_tx_rate_p99: u64, // 99th percentile
    // Total wide network traffic (cumulative bytes)
    pub wide_rx_bytes: u64, // Total wide network receive bytes
    pub wide_tx_bytes: u64, // Total wide network transmit bytes
}

#[derive(Debug, Clone, Copy)]
pub struct BaselineTotals {
    pub ip_address: [u8; 4], // IPv4 address from ring file
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
    pub local_rx_bytes: u64,
    pub local_tx_bytes: u64,
    pub wide_rx_bytes: u64,
    pub wide_tx_bytes: u64,
    pub last_online_ts: u64,
}

// Use the latest record from each device's ring as baseline
pub fn load_latest_totals(base_dir: &str) -> Result<Vec<([u8; 6], BaselineTotals)>, anyhow::Error> {
    let dir = ring_dir(base_dir);
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("ring") {
            continue;
        }

        // Parse MAC from filename
        let fname = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if fname.len() != 12 {
            continue;
        }
        let mut mac = [0u8; 6];
        let mut ok = true;
        for i in 0..6 {
            if let Ok(v) = u8::from_str_radix(&fname[i * 2..i * 2 + 2], 16) {
                mac[i] = v;
            } else {
                ok = false;
                break;
            }
        }
        if !ok {
            continue;
        }

        let mut f = OpenOptions::new().read(true).open(&path)?;
        let (ver, cap) = read_header(&mut f)?;
        if ver != RING_VERSION_REALTIME_V2 && ver != RING_VERSION_REALTIME_V3 {
            continue;
        }
        let mut best: Option<([u64; SLOT_U64S_REALTIME], u32)> = None;
        for i in 0..(cap as u64) {
            let rec = if ver == RING_VERSION_REALTIME_V2 {
                // Read v2 and convert to v3
                if let Ok(v2_rec) = read_slot_v2(&f, i) {
                    if v2_rec[0] == 0 {
                        continue;
                    }
                    let mut v3_rec = [0u64; SLOT_U64S_REALTIME];
                    for j in 0..SLOT_U64S_REALTIME_V2 {
                        v3_rec[j] = v2_rec[j];
                    }
                    // IP address remains 0
                    v3_rec
                } else {
                    continue;
                }
            } else {
                // Read v3
                if let Ok(v3_rec) = read_slot(&f, i) {
                    if v3_rec[0] == 0 {
                        continue;
                    }
                    v3_rec
                } else {
                    continue;
                }
            };
            
            if best.as_ref().map(|(b, _)| rec[0] > b[0]).unwrap_or(true) {
                best = Some((rec, ver));
            }
        }
        if let Some((rec, _ver)) = best {
            // Extract IPv4 address from u64 (low 32 bits)
            let ip_bytes = rec[14].to_le_bytes();
            let ip_address = [ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]];
            
            out.push((
                mac,
                BaselineTotals {
                    ip_address,
                    total_rx_bytes: rec[7],
                    total_tx_bytes: rec[8],
                    local_rx_bytes: rec[9],
                    local_tx_bytes: rec[10],
                    wide_rx_bytes: rec[11],
                    wide_tx_bytes: rec[12],
                    last_online_ts: rec[13],
                },
            ));
        }
    }
    Ok(out)
}

fn limits_schedule_path(base: &str) -> PathBuf {
    Path::new(base).join("rate_limits_schedule.txt")
}

/// Load all scheduled rate limits from file
/// Also migrates legacy rate_limits.txt entries to scheduled format (all days, all hours)
/// Legacy file is deprecated and will be migrated on first load
pub fn load_all_scheduled_limits(base_dir: &str) -> Result<Vec<ScheduledRateLimit>, anyhow::Error> {
    let mut out = Vec::new();

    // First, check if legacy rate_limits.txt exists and migrate it
    let legacy_path = limits_path(base_dir);
    if legacy_path.exists() {
        let legacy_limits = load_all_limits(base_dir)?;
        if !legacy_limits.is_empty() {
            let mut migrated_count = 0;

            // Convert legacy limits to scheduled format and save to new file
            // Skip entries where both rx and tx are 0 (unlimited, no need to store)
            for (mac, rx, tx) in legacy_limits.iter() {
                // Skip if both limits are 0 (unlimited)
                if *rx == 0 && *tx == 0 {
                    log::debug!("Skipping migration of unlimited rate limit for MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                    continue;
                }

                let scheduled_limit = ScheduledRateLimit {
                    mac: *mac,
                    time_slot: TimeSlot::all_time(),
                    wide_rx_rate_limit: *rx,
                    wide_tx_rate_limit: *tx,
                };
                // Save to new file (will merge with existing scheduled limits)
                upsert_scheduled_limit(base_dir, &scheduled_limit)?;
                out.push(scheduled_limit);
                migrated_count += 1;
            }

            if migrated_count > 0 {
                log::info!(
                    "Migrated {} legacy rate limit entries from rate_limits.txt to scheduled format",
                    migrated_count
                );
            } else {
                log::info!("All legacy rate limits are unlimited (0), skipping migration");
            }

            // Remove legacy file after migration (even if all were unlimited)
            if let Err(e) = fs::remove_file(&legacy_path) {
                log::warn!(
                    "Failed to remove legacy rate_limits.txt after migration: {}",
                    e
                );
            } else {
                log::info!("Successfully removed legacy rate_limits.txt");
            }
        } else {
            // File exists but is empty, remove it
            if let Err(e) = fs::remove_file(&legacy_path) {
                log::warn!("Failed to remove empty legacy rate_limits.txt: {}", e);
            } else {
                log::debug!("Removed empty legacy rate_limits.txt");
            }
        }
    }

    // Then, load scheduled limits from rate_limits_schedule.txt
    let path = limits_schedule_path(base_dir);
    if !path.exists() {
        return Ok(out);
    }

    let content = fs::read_to_string(&path)?;
    for (lineno, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Format: mac schedule start_hour:start_min end_hour:end_min days rx tx
        // Example: aabbccddeeff schedule 09:00 18:00 1111100 1048576 1048576
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 7 {
            continue;
        }

        if parts[1] != "schedule" {
            continue;
        }

        let mac_str = parts[0];
        let mac = if mac_str.contains(':') {
            parse_mac_text(mac_str)
        } else if mac_str.len() == 12 {
            let mut mac = [0u8; 6];
            for i in 0..6 {
                mac[i] = u8::from_str_radix(&mac_str[i * 2..i * 2 + 2], 16)
                    .with_context(|| format!("invalid mac hex at line {}", lineno + 1))?;
            }
            Ok(mac)
        } else {
            Err(anyhow::anyhow!("invalid mac format at line {}", lineno + 1))
        }?;

        let (start_hour, start_minute) = TimeSlot::parse_time(parts[2])
            .with_context(|| format!("invalid start time at line {}", lineno + 1))?;
        let (end_hour, end_minute) = TimeSlot::parse_time(parts[3])
            .with_context(|| format!("invalid end time at line {}", lineno + 1))?;
        let days_of_week = TimeSlot::parse_days(parts[4])
            .with_context(|| format!("invalid days format at line {}", lineno + 1))?;

        let rx: u64 = parts[5]
            .parse()
            .with_context(|| format!("invalid rx at line {}", lineno + 1))?;
        let tx: u64 = parts[6]
            .parse()
            .with_context(|| format!("invalid tx at line {}", lineno + 1))?;

        out.push(ScheduledRateLimit {
            mac,
            time_slot: TimeSlot {
                start_hour,
                start_minute,
                end_hour,
                end_minute,
                days_of_week,
            },
            wide_rx_rate_limit: rx,
            wide_tx_rate_limit: tx,
        });
    }

    Ok(out)
}

/// Save scheduled rate limit to file
pub fn upsert_scheduled_limit(
    base_dir: &str,
    scheduled_limit: &ScheduledRateLimit,
) -> Result<(), anyhow::Error> {
    let path = limits_schedule_path(base_dir);
    ensure_parent_dir(&path)?;

    let mut rules: Vec<ScheduledRateLimit> = Vec::new();

    // Load existing rules
    if path.exists() {
        let content = fs::read_to_string(&path)?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() != 7 || parts[1] != "schedule" {
                continue;
            }

            let mac_str = parts[0];
            let mac = if mac_str.contains(':') {
                parse_mac_text(mac_str).ok()
            } else if mac_str.len() == 12 {
                let mut mac = [0u8; 6];
                let mut ok = true;
                for i in 0..6 {
                    if let Ok(v) = u8::from_str_radix(&mac_str[i * 2..i * 2 + 2], 16) {
                        mac[i] = v;
                    } else {
                        ok = false;
                        break;
                    }
                }
                if ok {
                    Some(mac)
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(mac) = mac {
                if let Ok((start_hour, start_minute)) = TimeSlot::parse_time(parts[2]) {
                    if let Ok((end_hour, end_minute)) = TimeSlot::parse_time(parts[3]) {
                        if let Ok(days_of_week) = TimeSlot::parse_days(parts[4]) {
                            if let Ok(rx) = parts[5].parse::<u64>() {
                                if let Ok(tx) = parts[6].parse::<u64>() {
                                    rules.push(ScheduledRateLimit {
                                        mac,
                                        time_slot: TimeSlot {
                                            start_hour,
                                            start_minute,
                                            end_hour,
                                            end_minute,
                                            days_of_week,
                                        },
                                        wide_rx_rate_limit: rx,
                                        wide_tx_rate_limit: tx,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Remove existing rules with same MAC and time slot (to update)
    let mac_key = mac_to_filename(&scheduled_limit.mac);
    rules.retain(|r| {
        let r_mac = mac_to_filename(&r.mac);
        !(r_mac == mac_key
            && r.time_slot.start_hour == scheduled_limit.time_slot.start_hour
            && r.time_slot.start_minute == scheduled_limit.time_slot.start_minute
            && r.time_slot.end_hour == scheduled_limit.time_slot.end_hour
            && r.time_slot.end_minute == scheduled_limit.time_slot.end_minute
            && r.time_slot.days_of_week == scheduled_limit.time_slot.days_of_week)
    });

    // Add new/updated rule
    rules.push(scheduled_limit.clone());

    // Sort by MAC and time slot for consistent output
    rules.sort_by(|a, b| {
        let mac_a = mac_to_filename(&a.mac);
        let mac_b = mac_to_filename(&b.mac);
        mac_a.cmp(&mac_b).then_with(|| {
            a.time_slot
                .start_hour
                .cmp(&b.time_slot.start_hour)
                .then_with(|| a.time_slot.start_minute.cmp(&b.time_slot.start_minute))
        })
    });

    // Write back to file
    let mut buf = String::new();
    buf.push_str("# mac schedule start_hour:start_min end_hour:end_min days rx tx\n");
    buf.push_str("# days: 7-bit binary (Monday-Sunday) or comma-separated (1-7)\n");
    for rule in rules {
        let mac_str = mac_to_filename(&rule.mac);
        let start_str =
            TimeSlot::format_time(rule.time_slot.start_hour, rule.time_slot.start_minute);
        let end_str = TimeSlot::format_time(rule.time_slot.end_hour, rule.time_slot.end_minute);
        let days_str = TimeSlot::format_days(rule.time_slot.days_of_week);
        buf.push_str(&format!(
            "{} schedule {} {} {} {} {}\n",
            mac_str, start_str, end_str, days_str, rule.wide_rx_rate_limit, rule.wide_tx_rate_limit
        ));
    }

    fs::write(&path, buf)?;
    Ok(())
}

/// Delete a scheduled rate limit rule
pub fn delete_scheduled_limit(
    base_dir: &str,
    mac: &[u8; 6],
    time_slot: &TimeSlot,
) -> Result<(), anyhow::Error> {
    let path = limits_schedule_path(base_dir);
    if !path.exists() {
        return Ok(());
    }

    let mut rules: Vec<ScheduledRateLimit> = Vec::new();
    let content = fs::read_to_string(&path)?;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 7 || parts[1] != "schedule" {
            continue;
        }

        let mac_str = parts[0];
        let parsed_mac = if mac_str.contains(':') {
            parse_mac_text(mac_str).ok()
        } else if mac_str.len() == 12 {
            let mut parsed = [0u8; 6];
            let mut ok = true;
            for i in 0..6 {
                if let Ok(v) = u8::from_str_radix(&mac_str[i * 2..i * 2 + 2], 16) {
                    parsed[i] = v;
                } else {
                    ok = false;
                    break;
                }
            }
            if ok {
                Some(parsed)
            } else {
                None
            }
        } else {
            None
        };

        if let Some(parsed_mac) = parsed_mac {
            if parsed_mac == *mac {
                if let Ok((start_hour, start_minute)) = TimeSlot::parse_time(parts[2]) {
                    if let Ok((end_hour, end_minute)) = TimeSlot::parse_time(parts[3]) {
                        if let Ok(days_of_week) = TimeSlot::parse_days(parts[4]) {
                            // Check if this matches the time slot to delete
                            if start_hour == time_slot.start_hour
                                && start_minute == time_slot.start_minute
                                && end_hour == time_slot.end_hour
                                && end_minute == time_slot.end_minute
                                && days_of_week == time_slot.days_of_week
                            {
                                // Skip this rule (delete it)
                                continue;
                            }
                        }
                    }
                }
            }
        }

        // Keep this rule
        if let Ok((start_hour, start_minute)) = TimeSlot::parse_time(parts[2]) {
            if let Ok((end_hour, end_minute)) = TimeSlot::parse_time(parts[3]) {
                if let Ok(days_of_week) = TimeSlot::parse_days(parts[4]) {
                    if let Ok(rx) = parts[5].parse::<u64>() {
                        if let Ok(tx) = parts[6].parse::<u64>() {
                            if let Some(parsed_mac) = parsed_mac {
                                rules.push(ScheduledRateLimit {
                                    mac: parsed_mac,
                                    time_slot: TimeSlot {
                                        start_hour,
                                        start_minute,
                                        end_hour,
                                        end_minute,
                                        days_of_week,
                                    },
                                    wide_rx_rate_limit: rx,
                                    wide_tx_rate_limit: tx,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // Write back to file
    let mut buf = String::new();
    buf.push_str("# mac schedule start_hour:start_min end_hour:end_min days rx tx\n");
    buf.push_str("# days: 7-bit binary (Monday-Sunday) or comma-separated (1-7)\n");
    for rule in rules {
        let mac_str = mac_to_filename(&rule.mac);
        let start_str =
            TimeSlot::format_time(rule.time_slot.start_hour, rule.time_slot.start_minute);
        let end_str = TimeSlot::format_time(rule.time_slot.end_hour, rule.time_slot.end_minute);
        let days_str = TimeSlot::format_days(rule.time_slot.days_of_week);
        buf.push_str(&format!(
            "{} schedule {} {} {} {} {}\n",
            mac_str, start_str, end_str, days_str, rule.wide_rx_rate_limit, rule.wide_tx_rate_limit
        ));
    }

    fs::write(&path, buf)?;
    Ok(())
}

/// Calculate current effective rate limit for a MAC address based on scheduled rules
pub fn calculate_current_rate_limit(
    scheduled_limits: &[ScheduledRateLimit],
    mac: &[u8; 6],
) -> Option<[u64; 2]> {
    let now = Local::now();

    // Find all matching rules for this MAC
    let matching_rules: Vec<&ScheduledRateLimit> = scheduled_limits
        .iter()
        .filter(|rule| rule.mac == *mac && rule.time_slot.matches(&now))
        .collect();

    if matching_rules.is_empty() {
        return None;
    }

    // If multiple rules match, use the most restrictive (lowest non-zero limit)
    // If a rule has 0, it means unlimited, so we take the minimum of non-zero values
    let mut rx_limit: Option<u64> = None;
    let mut tx_limit: Option<u64> = None;

    for rule in matching_rules {
        if rule.wide_rx_rate_limit > 0 {
            rx_limit = Some(rx_limit.map_or(rule.wide_rx_rate_limit, |current: u64| {
                current.min(rule.wide_rx_rate_limit)
            }));
        }
        if rule.wide_tx_rate_limit > 0 {
            tx_limit = Some(tx_limit.map_or(rule.wide_tx_rate_limit, |current: u64| {
                current.min(rule.wide_tx_rate_limit)
            }));
        }
    }

    // Return [0, 0] if unlimited, or the calculated limits
    Some([rx_limit.unwrap_or(0), tx_limit.unwrap_or(0)])
}
