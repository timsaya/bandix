use anyhow::Context;
use bandix_common::MacTrafficStats;
use chrono::{DateTime, Datelike, Local, Timelike};
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
const RING_VERSION: u32 = 2; // bump to v2: slot adds last_online_ts
                             // Default capacity is 3600 (1 hour, 1 sample per second); actual capacity is determined by argument when created
const DEFAULT_RING_CAPACITY: u32 = 3600;

// Per-slot structure (little-endian):
// ts_ms: u64
// total_rx_rate..wide_tx_bytes: 12 u64 values in total (see MetricsRow)
// last_online_ts: u64
// Slot size = 14 * 8 = 112 bytes (since v2)
const SLOT_U64S: usize = 14;
const SLOT_SIZE: usize = SLOT_U64S * 8;
const HEADER_SIZE: usize = 4 /*magic*/ + 4 /*version*/ + 4 /*capacity*/;

/// In-memory Ring structure
#[derive(Debug, Clone)]
pub struct MemoryRing {
    pub capacity: u32,
    pub slots: Vec<[u64; SLOT_U64S]>,
    pub current_index: u64,
    pub dirty: bool, // Flag indicating whether there is data not yet persisted to disk
}

impl MemoryRing {
    pub fn new(capacity: u32) -> Self {
        let cap = if capacity == 0 {
            DEFAULT_RING_CAPACITY
        } else {
            capacity
        };

        Self {
            capacity: cap,
            slots: vec![[0u64; SLOT_U64S]; cap as usize],
            current_index: 0,
            dirty: false,
        }
    }

    pub fn insert(&mut self, ts_ms: u64, data: &[u64; SLOT_U64S]) {
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

/// Memory Ring Manager
pub struct MemoryRingManager {
    pub rings: Arc<Mutex<HashMap<[u8; 6], MemoryRing>>>,
    pub base_dir: String,
    pub capacity: u32,
}

impl MemoryRingManager {
    pub fn new(base_dir: String, capacity: u32) -> Self {
        Self {
            rings: Arc::new(Mutex::new(HashMap::new())),
            base_dir,
            capacity,
        }
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
                .or_insert_with(|| MemoryRing::new(self.capacity));

            let rec: [u64; SLOT_U64S] = [
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
        let mut ts_to_agg: BTreeMap<u64, [u64; SLOT_U64S]> = BTreeMap::new();

        for (_mac, ring) in rings.iter() {
            for slot in &ring.slots {
                let ts = slot[0];
                if ts == 0 {
                    continue;
                }
                if ts < start_ms || ts > end_ms {
                    continue;
                }

                let agg = ts_to_agg.entry(ts).or_insert([0u64; SLOT_U64S]);
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
    fn persist_ring_to_file(&self, mac: &[u8; 6], ring: &MemoryRing) -> Result<(), anyhow::Error> {
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
                    if ver == RING_VERSION {
                        let mut ring = MemoryRing::new(cap);

                        for i in 0..(cap as u64) {
                            if let Ok(slot) = read_slot(&f, i) {
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

fn ensure_parent_dir(path: &Path) -> Result<(), anyhow::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn write_header(f: &mut File, capacity: u32) -> Result<(), anyhow::Error> {
    f.seek(SeekFrom::Start(0))?;
    f.write_all(&RING_MAGIC)?;
    f.write_all(&RING_VERSION.to_le_bytes())?;
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
    let expected_size = HEADER_SIZE as u64 + (cap as u64) * (SLOT_SIZE as u64);

    if metadata.len() != expected_size {
        // Reinitialize
        f.set_len(0)?;
        write_header(&mut f, cap)?;
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
        let _ = read_header(&mut f)?;
    }
    Ok(f)
}

fn reinit_ring_file(path: &Path, capacity: u32) -> Result<File, anyhow::Error> {
    ensure_parent_dir(path)?;
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;

    let cap = if capacity == 0 {
        DEFAULT_RING_CAPACITY
    } else {
        capacity
    };
    let expected_size = HEADER_SIZE as u64 + (cap as u64) * (SLOT_SIZE as u64);

    // Force reinitialize regardless of current size/header
    f.set_len(0)?;
    write_header(&mut f, cap)?;
    let zero_chunk = vec![0u8; 4096];
    let mut remaining = expected_size - HEADER_SIZE as u64;
    while remaining > 0 {
        let to_write = std::cmp::min(remaining, zero_chunk.len() as u64) as usize;
        f.write_all(&zero_chunk[..to_write])?;
        remaining -= to_write as u64;
    }
    f.flush()?;
    Ok(f)
}

fn calc_slot_index(ts_ms: u64, capacity: u32) -> u64 {
    ((ts_ms / 1000) % capacity as u64) as u64
}

fn write_slot(mut f: &File, idx: u64, data: &[u64; SLOT_U64S]) -> Result<(), anyhow::Error> {
    let offset = HEADER_SIZE as u64 + idx * (SLOT_SIZE as u64);
    let mut bytes = [0u8; SLOT_SIZE];
    for (i, v) in data.iter().enumerate() {
        let b = v.to_le_bytes();
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&b);
    }
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(&bytes)?;
    Ok(())
}

fn read_slot(mut f: &File, idx: u64) -> Result<[u64; SLOT_U64S], anyhow::Error> {
    let offset = HEADER_SIZE as u64 + idx * (SLOT_SIZE as u64);
    let mut bytes = [0u8; SLOT_SIZE];
    f.seek(SeekFrom::Start(offset))?;
    f.read_exact(&mut bytes)?;
    let mut out = [0u64; SLOT_U64S];
    for i in 0..SLOT_U64S {
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        out[i] = u64::from_le_bytes(b);
    }
    Ok(out)
}

pub fn ensure_schema(base_dir: &str) -> Result<(), anyhow::Error> {
    // Create directory and hostname binding files
    // Note: rate_limits.txt is deprecated and no longer created
    fs::create_dir_all(ring_dir(base_dir))
        .with_context(|| format!("Failed to create metrics dir under {}", base_dir))?;
    let bindings = crate::storage::hostname::bindings_path(base_dir);
    if !bindings.exists() {
        File::create(&bindings)?;
    }
    Ok(())
}

/// At startup, check if all ring file capacities in the `metrics` directory match the given
/// `traffic_retention_seconds`; if any inconsistency is found, rebuild all ring files in that directory.
/// Note: This operation will clear historical time series data, only keeping rate limit configuration files.
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

    // If inconsistencies are found, rebuild all .ring files
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("ring") {
            continue;
        }
        // Force rebuild
        let _ = reinit_ring_file(&path, traffic_retention_seconds)?;
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

#[derive(Debug, Clone, Copy)]
pub struct BaselineTotals {
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
        if ver != RING_VERSION {
            continue;
        }
        let mut best: Option<[u64; SLOT_U64S]> = None;
        for i in 0..(cap as u64) {
            let rec = read_slot(&f, i)?;
            if rec[0] == 0 {
                continue;
            }
            if best.as_ref().map(|b| rec[0] > b[0]).unwrap_or(true) {
                best = Some(rec);
            }
        }
        if let Some(rec) = best {
            out.push((
                mac,
                BaselineTotals {
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
