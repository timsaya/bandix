use anyhow::Context;
use bandix_common::MacTrafficStats;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

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
//   rate_limits.txt                 Text: one line per entry - mac rx tx
//   metrics/
//     <mac12>.ring                  Fixed-size ring file (capacity determined by config)

const RING_MAGIC: [u8; 4] = *b"BXR1"; // bandix ring v1
const RING_VERSION: u32 = 1;
// Default capacity is 3600 (1 hour, 1 sample per second); actual capacity is determined by argument when created
const DEFAULT_RING_CAPACITY: u32 = 3600;

// Per-slot structure (little-endian):
// ts_ms: u64
// total_rx_rate..wide_tx_bytes: 12 u64 values in total (see MetricsRow)
// Slot size = 13 * 8 = 104 bytes
const SLOT_U64S: usize = 13;
const SLOT_SIZE: usize = SLOT_U64S * 8;
const HEADER_SIZE: usize = 4 /*magic*/ + 4 /*version*/ + 4 /*capacity*/;

fn ring_dir(base: &str) -> PathBuf {
    Path::new(base).join("metrics")
}
fn limits_path(base: &str) -> PathBuf {
    Path::new(base).join("rate_limits.txt")
}
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
    let cap = if capacity == 0 { DEFAULT_RING_CAPACITY } else { capacity };
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

    let cap = if capacity == 0 { DEFAULT_RING_CAPACITY } else { capacity };
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
    // Create directory and empty rate limit file
    fs::create_dir_all(ring_dir(base_dir))
        .with_context(|| format!("Failed to create metrics dir under {}", base_dir))?;
    let limits = limits_path(base_dir);
    if !limits.exists() {
        File::create(&limits)?;
    }
    Ok(())
}

/// 在启动时检查 `metrics` 目录下的所有 ring 文件容量是否与给定的
/// `retention_seconds` 一致；若发现任意不一致，则重建该目录下所有 ring 文件。
/// 注意：该操作会清空历史时间序列，仅保留限速配置文件。
pub fn rebuild_all_ring_files_if_mismatch(
    base_dir: &str,
    retention_seconds: u32,
) -> Result<(), anyhow::Error> {
    let dir = ring_dir(base_dir);
    if !dir.exists() {
        return Ok(());
    }

    // 先检测是否存在不一致
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
        if cap != retention_seconds {
            mismatch_found = true;
            break;
        }
    }

    if !mismatch_found {
        return Ok(());
    }

    // 若发现不一致，重建所有 .ring 文件
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("ring") {
            continue;
        }
        // 强制重建
        let _ = reinit_ring_file(&path, retention_seconds)?;
    }

    Ok(())
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

pub fn upsert_limit(
    base_dir: &str,
    mac: &[u8; 6],
    wide_rx_rate_limit: u64,
    wide_tx_rate_limit: u64,
) -> Result<(), anyhow::Error> {
    let path = limits_path(base_dir);
    ensure_parent_dir(&path)?;
    let mut map: std::collections::BTreeMap<String, (u64, u64)> = Default::default();
    if path.exists() {
        let content = fs::read_to_string(&path)?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() != 3 {
                continue;
            }
            map.insert(
                parts[0].to_string(),
                (parts[1].parse().unwrap_or(0), parts[2].parse().unwrap_or(0)),
            );
        }
    }
    let key = mac_to_filename(mac);
    map.insert(key.clone(), (wide_rx_rate_limit, wide_tx_rate_limit));

    let mut buf = String::new();
    buf.push_str("# mac rx tx (rate limits in bytes/sec)\n");
    for (k, (rx, tx)) in map {
        buf.push_str(&format!("{} {} {}\n", k, rx, tx));
    }
    fs::write(&path, buf)?;
    Ok(())
}

pub fn insert_metrics_batch(
    base_dir: &str,
    ts_ms: u64,
    rows: &Vec<([u8; 6], MacTrafficStats)>,
    retention_seconds: u32,
) -> Result<(), anyhow::Error> {
    if rows.is_empty() {
        return Ok(());
    }
    for (mac, s) in rows.iter() {
        let path = ring_file_path(base_dir, mac);
        let mut f = init_ring_file(&path, retention_seconds)?;
        let (_ver, cap) = read_header(&mut f)?;
        let idx = calc_slot_index(ts_ms, cap);

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
        ];
        write_slot(&f, idx, &rec)?;
        f.sync_all()?;
    }
    Ok(())
}

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

pub fn query_metrics(
    base_dir: &str,
    mac: &[u8; 6],
    start_ms: u64,
    end_ms: u64,
    limit: Option<usize>,
) -> Result<Vec<MetricsRow>, anyhow::Error> {
    let path = ring_file_path(base_dir, mac);
    let mut rows_vec = Vec::new();
    if !path.exists() {
        return Ok(rows_vec);
    }
    let mut f = OpenOptions::new().read(true).open(&path)?;
    let (_ver, cap) = read_header(&mut f)?;
    // Iterate over all slots and filter by range
    for i in 0..(cap as u64) {
        let rec = read_slot(&f, i)?;
        let ts = rec[0];
        if ts == 0 {
            continue;
        }
        if ts < start_ms || ts > end_ms {
            continue;
        }
        rows_vec.push(MetricsRow {
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
        });
    }
    // Ascending order
    rows_vec.sort_by_key(|r| r.ts_ms);
    if let Some(max_rows) = limit {
        rows_vec.truncate(max_rows);
    }
    Ok(rows_vec)
}

/// Aggregate metrics across all devices for the entire retention window.
/// Returned rows are sorted by timestamp ascending. When `limit` is provided,
/// it truncates the number of rows to the first `limit` entries after sorting.
pub fn query_metrics_aggregate_all(
    base_dir: &str,
    limit: Option<usize>,
    
) -> Result<Vec<MetricsRow>, anyhow::Error> {
    use std::collections::BTreeMap;

    let dir = ring_dir(base_dir);
    let mut ts_to_agg: BTreeMap<u64, [u64; SLOT_U64S]> = BTreeMap::new();
    if !dir.exists() {
        return Ok(Vec::new());
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

        let mut f = OpenOptions::new().read(true).open(&path)?;
        let (_ver, cap) = read_header(&mut f)?;
        for i in 0..(cap as u64) {
            let rec = read_slot(&f, i)?;
            let ts = rec[0];
            if ts == 0 {
                continue;
            }
            let agg = ts_to_agg.entry(ts).or_insert([0u64; SLOT_U64S]);
            agg[0] = ts; // keep timestamp
            // Sum all counters/rates
            for j in 1..SLOT_U64S {
                agg[j] = agg[j].saturating_add(rec[j]);
            }
        }
    }

    let mut rows_vec: Vec<MetricsRow> = ts_to_agg
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

    if let Some(max_rows) = limit {
        rows_vec.truncate(max_rows);
    }
    Ok(rows_vec)
}

#[derive(Debug, Clone, Copy)]
pub struct BaselineTotals {
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
    pub local_rx_bytes: u64,
    pub local_tx_bytes: u64,
    pub wide_rx_bytes: u64,
    pub wide_tx_bytes: u64,
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
        let (_ver, cap) = read_header(&mut f)?;
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
                },
            ));
        }
    }
    Ok(out)
}
