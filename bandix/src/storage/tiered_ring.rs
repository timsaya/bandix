use anyhow::Context;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// 分层存储架构：
// 1. 日环（Day Ring）：1天数据，1分钟采样，仅存储WAN数据
// 2. 周环（Week Ring）：1周数据，5分钟采样，仅存储WAN数据

// 文件扩展名
const DAY_RING_EXT: &str = "day.ring";
const WEEK_RING_EXT: &str = "week.ring";

// Ring 文件魔数和版本
const TIERED_RING_MAGIC: [u8; 4] = *b"BXT1"; // Bandix Tiered ring
const TIERED_RING_VERSION: u32 = 1;

// 分层槽位结构（仅WAN数据，7个u64）
// 索引 0: ts_ms (时间戳)
// 索引 1: wide_rx_rate_avg (WAN接收平均速率)
// 索引 2: wide_tx_rate_avg (WAN发送平均速率)
// 索引 3: wide_rx_rate_peak (WAN接收峰值速率)
// 索引 4: wide_tx_rate_peak (WAN发送峰值速率)
// 索引 5: wide_rx_bytes (WAN接收累计字节)
// 索引 6: wide_tx_bytes (WAN发送累计字节)
const TIERED_SLOT_U64S: usize = 7;
const TIERED_SLOT_SIZE: usize = TIERED_SLOT_U64S * 8; // 56 bytes
const TIERED_HEADER_SIZE: usize = 4 /*magic*/ + 4 /*version*/ + 4 /*capacity*/;

// 默认容量
const DAY_RING_CAPACITY: u32 = 24 * 60; // 1440 slots (1天，1分钟一个样本)
const WEEK_RING_CAPACITY: u32 = 7 * 24 * 12; // 2016 slots (1周，5分钟一个样本)

/// 分层槽位数据
#[derive(Debug, Clone, Copy)]
pub struct TieredSlot {
    pub ts_ms: u64,
    pub wide_rx_rate_avg: u64,
    pub wide_tx_rate_avg: u64,
    pub wide_rx_rate_peak: u64,
    pub wide_tx_rate_peak: u64,
    pub wide_rx_bytes: u64,
    pub wide_tx_bytes: u64,
}

impl TieredSlot {
    pub fn from_array(data: &[u64; TIERED_SLOT_U64S]) -> Self {
        Self {
            ts_ms: data[0],
            wide_rx_rate_avg: data[1],
            wide_tx_rate_avg: data[2],
            wide_rx_rate_peak: data[3],
            wide_tx_rate_peak: data[4],
            wide_rx_bytes: data[5],
            wide_tx_bytes: data[6],
        }
    }

    pub fn to_array(&self) -> [u64; TIERED_SLOT_U64S] {
        [
            self.ts_ms,
            self.wide_rx_rate_avg,
            self.wide_tx_rate_avg,
            self.wide_rx_rate_peak,
            self.wide_tx_rate_peak,
            self.wide_rx_bytes,
            self.wide_tx_bytes,
        ]
    }
}

/// 内存中的分层环形缓冲区
#[derive(Debug, Clone)]
pub struct TieredMemoryRing {
    pub capacity: u32,
    pub slots: Vec<[u64; TIERED_SLOT_U64S]>,
    pub dirty: bool,
}

impl TieredMemoryRing {
    pub fn new(capacity: u32) -> Self {
        Self {
            capacity,
            slots: vec![[0u64; TIERED_SLOT_U64S]; capacity as usize],
            dirty: false,
        }
    }

    pub fn insert(&mut self, ts_ms: u64, data: &[u64; TIERED_SLOT_U64S]) {
        let idx = self.calc_slot_index(ts_ms);
        self.slots[idx as usize] = *data;
        self.dirty = true;
    }

    pub fn query(&self, start_ms: u64, end_ms: u64) -> Vec<TieredSlot> {
        let mut rows = Vec::new();

        for slot in &self.slots {
            let ts = slot[0];
            if ts == 0 {
                continue;
            }
            if ts < start_ms || ts > end_ms {
                continue;
            }

            rows.push(TieredSlot::from_array(slot));
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

    fn calc_slot_index(&self, ts_ms: u64) -> u64 {
        ((ts_ms / 1000) % self.capacity as u64) as u64
    }
}

/// 日环管理器（1天，1分钟采样）
pub struct DayRingManager {
    pub rings: Arc<Mutex<HashMap<[u8; 6], TieredMemoryRing>>>,
    pub base_dir: String,
}

impl DayRingManager {
    pub fn new(base_dir: String) -> Self {
        Self {
            rings: Arc::new(Mutex::new(HashMap::new())),
            base_dir,
        }
    }

    /// 插入数据（从1秒采样的数据中每60秒取一个样本）
    pub fn insert(&self, ts_ms: u64, mac: &[u8; 6], slot: TieredSlot) -> Result<(), anyhow::Error> {
        // 只在分钟边界插入
        if (ts_ms / 1000) % 60 != 0 {
            return Ok(());
        }

        let mut rings = self.rings.lock().unwrap();
        let ring = rings
            .entry(*mac)
            .or_insert_with(|| TieredMemoryRing::new(DAY_RING_CAPACITY));

        ring.insert(ts_ms, &slot.to_array());
        Ok(())
    }

    /// 查询数据
    pub fn query(
        &self,
        mac: &[u8; 6],
        start_ms: u64,
        end_ms: u64,
    ) -> Result<Vec<TieredSlot>, anyhow::Error> {
        let rings = self.rings.lock().unwrap();
        if let Some(ring) = rings.get(mac) {
            Ok(ring.query(start_ms, end_ms))
        } else {
            Ok(Vec::new())
        }
    }

    /// 聚合查询所有设备
    pub fn query_aggregate_all(
        &self,
        start_ms: u64,
        end_ms: u64,
    ) -> Result<Vec<TieredSlot>, anyhow::Error> {
        use std::collections::BTreeMap;

        let rings = self.rings.lock().unwrap();
        let mut ts_to_agg: BTreeMap<u64, [u64; TIERED_SLOT_U64S]> = BTreeMap::new();

        for (_mac, ring) in rings.iter() {
            for slot in &ring.slots {
                let ts = slot[0];
                if ts == 0 {
                    continue;
                }
                if ts < start_ms || ts > end_ms {
                    continue;
                }

                let agg = ts_to_agg.entry(ts).or_insert([0u64; TIERED_SLOT_U64S]);
                agg[0] = ts;
                // 聚合速率和字节数
                for j in 1..TIERED_SLOT_U64S {
                    agg[j] = agg[j].saturating_add(slot[j]);
                }
            }
        }

        let rows: Vec<TieredSlot> = ts_to_agg
            .into_iter()
            .map(|(_ts, rec)| TieredSlot::from_array(&rec))
            .collect();

        Ok(rows)
    }

    /// 从主环降采样到日环（每1分钟聚合一次）
    pub fn downsample_from_main(
        &self,
        main_rings: &Arc<Mutex<HashMap<[u8; 6], crate::storage::traffic::MemoryRing>>>,
    ) -> Result<(), anyhow::Error> {
        use crate::storage::traffic::MetricsRow;
        
        let main_rings_lock = main_rings.lock().unwrap();
        let mut day_rings = self.rings.lock().unwrap();

        for (mac, main_ring) in main_rings_lock.iter() {
            let day_ring = day_rings
                .entry(*mac)
                .or_insert_with(|| TieredMemoryRing::new(DAY_RING_CAPACITY));

            // 遍历主环，每1分钟聚合一次
            let mut aggregates: HashMap<u64, Vec<MetricsRow>> = HashMap::new();

            // 获取主环所有非空数据
            for slot in &main_ring.slots {
                if slot[0] == 0 {
                    continue;
                }

                let ts = slot[0];
                // 计算1分钟边界
                let bucket_ts = (ts / (60 * 1000)) * (60 * 1000);
                
                let row = MetricsRow {
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
                };
                
                aggregates.entry(bucket_ts).or_insert_with(Vec::new).push(row);
            }

            // 将聚合结果写入日环
            for (bucket_ts, rows) in aggregates {
                if rows.is_empty() {
                    continue;
                }

                let mut agg = [0u64; TIERED_SLOT_U64S];
                agg[0] = bucket_ts;

                // 计算平均速率、峰值速率和最大字节数（只保留WAN数据）
                let count = rows.len() as u64;
                let mut sum_rx_rate = 0u64;
                let mut sum_tx_rate = 0u64;
                let mut peak_rx_rate = 0u64;
                let mut peak_tx_rate = 0u64;
                let mut max_rx_bytes = 0u64;
                let mut max_tx_bytes = 0u64;

                for row in &rows {
                    sum_rx_rate = sum_rx_rate.saturating_add(row.wide_rx_rate);
                    sum_tx_rate = sum_tx_rate.saturating_add(row.wide_tx_rate);
                    peak_rx_rate = peak_rx_rate.max(row.wide_rx_rate); // 取峰值
                    peak_tx_rate = peak_tx_rate.max(row.wide_tx_rate); // 取峰值
                    max_rx_bytes = max_rx_bytes.max(row.wide_rx_bytes);
                    max_tx_bytes = max_tx_bytes.max(row.wide_tx_bytes);
                }

                agg[1] = sum_rx_rate / count; // 平均接收速率
                agg[2] = sum_tx_rate / count; // 平均发送速率
                agg[3] = peak_rx_rate; // 峰值接收速率
                agg[4] = peak_tx_rate; // 峰值发送速率
                agg[5] = max_rx_bytes; // 最大接收字节数
                agg[6] = max_tx_bytes; // 最大发送字节数

                day_ring.insert(bucket_ts, &agg);
            }
        }

        Ok(())
    }

    /// 持久化脏数据到磁盘
    pub fn flush_dirty_rings(&self) -> Result<(), anyhow::Error> {
        let mut rings = self.rings.lock().unwrap();

        for (mac, ring) in rings.iter_mut() {
            if ring.is_dirty() {
                let path = day_ring_file_path(&self.base_dir, mac);
                persist_tiered_ring(&path, ring)?;
                ring.mark_clean();
            }
        }

        Ok(())
    }

    /// 从磁盘加载数据
    pub fn load_from_files(&self) -> Result<(), anyhow::Error> {
        let dir = tiered_ring_dir(&self.base_dir);
        if !dir.exists() {
            return Ok(());
        }

        let mut rings = self.rings.lock().unwrap();

        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if !is_day_ring_file(&path) {
                continue;
            }

            if let Some(mac) = parse_mac_from_filename(&path, DAY_RING_EXT) {
                if let Ok(ring) = load_tiered_ring(&path, DAY_RING_CAPACITY) {
                    rings.insert(mac, ring);
                }
            }
        }

        Ok(())
    }
}

/// 周环管理器（1周，5分钟采样）
pub struct WeekRingManager {
    pub rings: Arc<Mutex<HashMap<[u8; 6], TieredMemoryRing>>>,
    pub base_dir: String,
}

impl WeekRingManager {
    pub fn new(base_dir: String) -> Self {
        Self {
            rings: Arc::new(Mutex::new(HashMap::new())),
            base_dir,
        }
    }

    /// 从日环降采样到周环（每5分钟聚合一次）
    pub fn downsample_from_day(
        &self,
        day_rings: &Arc<Mutex<HashMap<[u8; 6], TieredMemoryRing>>>,
    ) -> Result<(), anyhow::Error> {
        let day_rings_lock = day_rings.lock().unwrap();
        let mut week_rings = self.rings.lock().unwrap();

        for (mac, day_ring) in day_rings_lock.iter() {
            let week_ring = week_rings
                .entry(*mac)
                .or_insert_with(|| TieredMemoryRing::new(WEEK_RING_CAPACITY));

            // 遍历日环，每5分钟聚合一次
            let mut aggregates: HashMap<u64, Vec<[u64; TIERED_SLOT_U64S]>> = HashMap::new();

            for slot in &day_ring.slots {
                if slot[0] == 0 {
                    continue;
                }

                let ts = slot[0];
                // 计算5分钟边界
                let bucket_ts = (ts / (5 * 60 * 1000)) * (5 * 60 * 1000);
                aggregates.entry(bucket_ts).or_insert_with(Vec::new).push(*slot);
            }

            // 将聚合结果写入周环
            for (bucket_ts, slots) in aggregates {
                if slots.is_empty() {
                    continue;
                }

                let mut agg = [0u64; TIERED_SLOT_U64S];
                agg[0] = bucket_ts;

                // 计算平均速率、峰值速率和最大字节数
                let count = slots.len() as u64;
                let mut sum_rx_rate = 0u64;
                let mut sum_tx_rate = 0u64;
                let mut peak_rx_rate = 0u64;
                let mut peak_tx_rate = 0u64;
                let mut max_rx_bytes = 0u64;
                let mut max_tx_bytes = 0u64;

                for slot in &slots {
                    sum_rx_rate = sum_rx_rate.saturating_add(slot[1]);
                    sum_tx_rate = sum_tx_rate.saturating_add(slot[2]);
                    peak_rx_rate = peak_rx_rate.max(slot[3]); // 取峰值
                    peak_tx_rate = peak_tx_rate.max(slot[4]); // 取峰值
                    max_rx_bytes = max_rx_bytes.max(slot[5]);
                    max_tx_bytes = max_tx_bytes.max(slot[6]);
                }

                agg[1] = sum_rx_rate / count; // 平均接收速率
                agg[2] = sum_tx_rate / count; // 平均发送速率
                agg[3] = peak_rx_rate; // 峰值接收速率
                agg[4] = peak_tx_rate; // 峰值发送速率
                agg[5] = max_rx_bytes; // 最大接收字节数
                agg[6] = max_tx_bytes; // 最大发送字节数

                week_ring.insert(bucket_ts, &agg);
            }
        }

        Ok(())
    }

    /// 查询数据
    pub fn query(
        &self,
        mac: &[u8; 6],
        start_ms: u64,
        end_ms: u64,
    ) -> Result<Vec<TieredSlot>, anyhow::Error> {
        let rings = self.rings.lock().unwrap();
        if let Some(ring) = rings.get(mac) {
            Ok(ring.query(start_ms, end_ms))
        } else {
            Ok(Vec::new())
        }
    }

    /// 聚合查询所有设备
    pub fn query_aggregate_all(
        &self,
        start_ms: u64,
        end_ms: u64,
    ) -> Result<Vec<TieredSlot>, anyhow::Error> {
        use std::collections::BTreeMap;

        let rings = self.rings.lock().unwrap();
        let mut ts_to_agg: BTreeMap<u64, [u64; TIERED_SLOT_U64S]> = BTreeMap::new();

        for (_mac, ring) in rings.iter() {
            for slot in &ring.slots {
                let ts = slot[0];
                if ts == 0 {
                    continue;
                }
                if ts < start_ms || ts > end_ms {
                    continue;
                }

                let agg = ts_to_agg.entry(ts).or_insert([0u64; TIERED_SLOT_U64S]);
                agg[0] = ts;
                for j in 1..TIERED_SLOT_U64S {
                    agg[j] = agg[j].saturating_add(slot[j]);
                }
            }
        }

        let rows: Vec<TieredSlot> = ts_to_agg
            .into_iter()
            .map(|(_ts, rec)| TieredSlot::from_array(&rec))
            .collect();

        Ok(rows)
    }

    /// 持久化脏数据到磁盘
    pub fn flush_dirty_rings(&self) -> Result<(), anyhow::Error> {
        let mut rings = self.rings.lock().unwrap();

        for (mac, ring) in rings.iter_mut() {
            if ring.is_dirty() {
                let path = week_ring_file_path(&self.base_dir, mac);
                persist_tiered_ring(&path, ring)?;
                ring.mark_clean();
            }
        }

        Ok(())
    }

    /// 从磁盘加载数据
    pub fn load_from_files(&self) -> Result<(), anyhow::Error> {
        let dir = tiered_ring_dir(&self.base_dir);
        if !dir.exists() {
            return Ok(());
        }

        let mut rings = self.rings.lock().unwrap();

        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if !is_week_ring_file(&path) {
                continue;
            }

            if let Some(mac) = parse_mac_from_filename(&path, WEEK_RING_EXT) {
                if let Ok(ring) = load_tiered_ring(&path, WEEK_RING_CAPACITY) {
                    rings.insert(mac, ring);
                }
            }
        }

        Ok(())
    }
}

// ============ 文件操作辅助函数 ============

fn tiered_ring_dir(base: &str) -> PathBuf {
    Path::new(base).join("metrics")
}

fn day_ring_file_path(base: &str, mac: &[u8; 6]) -> PathBuf {
    tiered_ring_dir(base).join(format!("{}.{}", mac_to_filename(mac), DAY_RING_EXT))
}

fn week_ring_file_path(base: &str, mac: &[u8; 6]) -> PathBuf {
    tiered_ring_dir(base).join(format!("{}.{}", mac_to_filename(mac), WEEK_RING_EXT))
}

fn mac_to_filename(mac: &[u8; 6]) -> String {
    let mut s = String::with_capacity(12);
    for b in mac {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn is_day_ring_file(path: &Path) -> bool {
    path.is_file()
        && path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.ends_with(DAY_RING_EXT))
            .unwrap_or(false)
}

fn is_week_ring_file(path: &Path) -> bool {
    path.is_file()
        && path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.ends_with(WEEK_RING_EXT))
            .unwrap_or(false)
}

fn parse_mac_from_filename(path: &Path, ext: &str) -> Option<[u8; 6]> {
    let fname = path.file_name()?.to_str()?;
    if !fname.ends_with(ext) {
        return None;
    }

    let mac_str = fname.strip_suffix(&format!(".{}", ext))?;
    if mac_str.len() != 12 {
        return None;
    }

    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = u8::from_str_radix(&mac_str[i * 2..i * 2 + 2], 16).ok()?;
    }

    Some(mac)
}

fn ensure_parent_dir(path: &Path) -> Result<(), anyhow::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn write_tiered_header(f: &mut File, capacity: u32) -> Result<(), anyhow::Error> {
    f.seek(SeekFrom::Start(0))?;
    f.write_all(&TIERED_RING_MAGIC)?;
    f.write_all(&TIERED_RING_VERSION.to_le_bytes())?;
    f.write_all(&capacity.to_le_bytes())?;
    Ok(())
}

fn read_tiered_header(f: &mut File) -> Result<(u32, u32), anyhow::Error> {
    let mut magic = [0u8; 4];
    f.seek(SeekFrom::Start(0))?;
    f.read_exact(&mut magic)?;
    if magic != TIERED_RING_MAGIC {
        return Err(anyhow::anyhow!("invalid tiered ring file magic"));
    }
    let mut buf4 = [0u8; 4];
    f.read_exact(&mut buf4)?;
    let ver = u32::from_le_bytes(buf4);
    f.read_exact(&mut buf4)?;
    let cap = u32::from_le_bytes(buf4);
    Ok((ver, cap))
}

fn write_tiered_slot(
    f: &File,
    idx: u64,
    data: &[u64; TIERED_SLOT_U64S],
) -> Result<(), anyhow::Error> {
    let offset = TIERED_HEADER_SIZE as u64 + idx * (TIERED_SLOT_SIZE as u64);
    let mut bytes = [0u8; TIERED_SLOT_SIZE];
    for (i, v) in data.iter().enumerate() {
        let b = v.to_le_bytes();
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&b);
    }
    let mut f = f;
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(&bytes)?;
    Ok(())
}

fn read_tiered_slot(f: &File, idx: u64) -> Result<[u64; TIERED_SLOT_U64S], anyhow::Error> {
    let offset = TIERED_HEADER_SIZE as u64 + idx * (TIERED_SLOT_SIZE as u64);
    let mut bytes = [0u8; TIERED_SLOT_SIZE];
    let mut f = f;
    f.seek(SeekFrom::Start(offset))?;
    f.read_exact(&mut bytes)?;
    let mut out = [0u64; TIERED_SLOT_U64S];
    for i in 0..TIERED_SLOT_U64S {
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        out[i] = u64::from_le_bytes(b);
    }
    Ok(out)
}

fn persist_tiered_ring(path: &Path, ring: &TieredMemoryRing) -> Result<(), anyhow::Error> {
    ensure_parent_dir(path)?;
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;

    let metadata = f.metadata()?;
    let expected_size =
        TIERED_HEADER_SIZE as u64 + (ring.capacity as u64) * (TIERED_SLOT_SIZE as u64);

    if metadata.len() != expected_size {
        // 重新初始化文件
        f.set_len(0)?;
        write_tiered_header(&mut f, ring.capacity)?;
        let zero_chunk = vec![0u8; 4096];
        let mut remaining = expected_size - TIERED_HEADER_SIZE as u64;
        while remaining > 0 {
            let to_write = std::cmp::min(remaining, zero_chunk.len() as u64) as usize;
            f.write_all(&zero_chunk[..to_write])?;
            remaining -= to_write as u64;
        }
        f.flush()?;
    }

    // 写入所有非空槽位
    for (idx, slot) in ring.slots.iter().enumerate() {
        if slot[0] != 0 {
            write_tiered_slot(&f, idx as u64, slot)?;
        }
    }

    f.sync_all()?;
    Ok(())
}

fn load_tiered_ring(path: &Path, expected_capacity: u32) -> Result<TieredMemoryRing, anyhow::Error> {
    let mut f = OpenOptions::new().read(true).open(path)?;
    let (ver, cap) = read_tiered_header(&mut f)?;

    if ver != TIERED_RING_VERSION {
        return Err(anyhow::anyhow!("unsupported tiered ring version"));
    }

    if cap != expected_capacity {
        return Err(anyhow::anyhow!("capacity mismatch"));
    }

    let mut ring = TieredMemoryRing::new(cap);

    for i in 0..(cap as u64) {
        if let Ok(slot) = read_tiered_slot(&f, i) {
            if slot[0] != 0 {
                ring.slots[i as usize] = slot;
            }
        }
    }

    ring.mark_clean();
    Ok(ring)
}

pub fn ensure_tiered_schema(base_dir: &str) -> Result<(), anyhow::Error> {
    fs::create_dir_all(tiered_ring_dir(base_dir))
        .with_context(|| format!("Failed to create metrics dir under {}", base_dir))?;
    Ok(())
}

