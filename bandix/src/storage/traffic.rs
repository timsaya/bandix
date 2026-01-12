use anyhow::Context;
use chrono::{DateTime, Datelike, Local, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// 常量定义
// ============================================================================

// ------------------------------
// 共享常量（实时和长期存储都使用）
// ------------------------------
const RING_MAGIC: [u8; 4] = *b"BXR1"; // bandix 环形文件魔数
const DEFAULT_RING_CAPACITY: u32 = 3600; // 默认环形缓冲区容量（3600个槽位）
const HEADER_SIZE: usize = 4 /*magic*/ + 4 /*version*/ + 4 /*capacity*/; // 环形文件头部大小（12字节）

// ------------------------------
// 实时数据常量（1秒采样）
// ------------------------------
const SLOT_U64S_REALTIME: usize = 15; // 实时数据环形槽位大小（15个u64字段）

// 实时数据环形文件槽位结构（小端字节序，15个u64字段，总共120字节）：
// 索引 | 字段名              | 类型 | 说明
// -----|---------------------|------|-------------------------------
//   0   | ts_ms               | u64  | 时间戳（毫秒）
//   1   | total_rx_rate       | u64  | 总接收速率（LAN + WAN）
//   2   | total_tx_rate       | u64  | 总发送速率（LAN + WAN）
//   3   | lan_rx_rate         | u64  | 局域网接收速率
//   4   | lan_tx_rate         | u64  | 局域网发送速率
//   5   | wan_rx_rate         | u64  | 广域网接收速率
//   6   | wan_tx_rate         | u64  | 广域网发送速率
//   7   | total_rx_bytes      | u64  | 总接收字节数（LAN + WAN）
//   8   | total_tx_bytes      | u64  | 总发送字节数（LAN + WAN）
//   9   | lan_rx_bytes        | u64  | 局域网接收字节数
//  10   | lan_tx_bytes        | u64  | 局域网发送字节数
//  11   | wan_rx_bytes        | u64  | 广域网接收字节数
//  12   | wan_tx_bytes        | u64  | 广域网发送字节数
//  13   | last_online_ts      | u64  | 设备最后在线时间戳
//  14   | ip_address          | u64  | IPv4地址（存储在低32位）

// ------------------------------
// 长期统计常量（1小时采样，365天保留）
// ------------------------------
const RING_VERSION_LONG_TERM: u32 = 4;
const SLOT_U64S_LONG_TERM: usize = 32;
const SLOT_SIZE_LONG_TERM: usize = SLOT_U64S_LONG_TERM * 8;

// 长期统计环形文件槽位结构（小端字节序，32个u64字段，总共256字节）：
// 索引 | 字段名              | 类型 | 说明
// -----|---------------------|------|-------------------------------
//   0   | start_ts_ms         | u64  | 时间段开始时间戳（毫秒）
//   1   | end_ts_ms           | u64  | 时间段结束时间戳（毫秒）
//   2   | wan_rx_rate.avg     | u64  | 广域网接收速率平均值
//   3   | wan_rx_rate.max     | u64  | 广域网接收速率最大值
//   4   | wan_rx_rate.min     | u64  | 广域网接收速率最小值
//   5   | wan_rx_rate.p90     | u64  | 广域网接收速率90th百分位数
//   6   | wan_rx_rate.p95     | u64  | 广域网接收速率95th百分位数
//   7   | wan_rx_rate.p99     | u64  | 广域网接收速率99th百分位数
//   8   | wan_tx_rate.avg     | u64  | 广域网发送速率平均值
//   9   | wan_tx_rate.max     | u64  | 广域网发送速率最大值
//  10   | wan_tx_rate.min     | u64  | 广域网发送速率最小值
//  11   | wan_tx_rate.p90     | u64  | 广域网发送速率90th百分位数
//  12   | wan_tx_rate.p95     | u64  | 广域网发送速率95th百分位数
//  13   | wan_tx_rate.p99     | u64  | 广域网发送速率99th百分位数
//  14   | wan_rx_bytes_inc    | u64  | 广域网接收字节数增量（本时段内）
//  15   | wan_tx_bytes_inc    | u64  | 广域网发送字节数增量（本时段内）
//  16   | lan_rx_rate.avg     | u64  | 局域网接收速率平均值
//  17   | lan_rx_rate.max     | u64  | 局域网接收速率最大值
//  18   | lan_rx_rate.min     | u64  | 局域网接收速率最小值
//  19   | lan_rx_rate.p90     | u64  | 局域网接收速率90th百分位数
//  20   | lan_rx_rate.p95     | u64  | 局域网接收速率95th百分位数
//  21   | lan_rx_rate.p99     | u64  | 局域网接收速率99th百分位数
//  22   | lan_tx_rate.avg     | u64  | 局域网发送速率平均值
//  23   | lan_tx_rate.max     | u64  | 局域网发送速率最大值
//  24   | lan_tx_rate.min     | u64  | 局域网发送速率最小值
//  25   | lan_tx_rate.p90     | u64  | 局域网发送速率90th百分位数
//  26   | lan_tx_rate.p95     | u64  | 局域网发送速率95th百分位数
//  27   | lan_tx_rate.p99     | u64  | 局域网发送速率99th百分位数
//  28   | lan_rx_bytes_inc    | u64  | 局域网接收字节数增量（本时段内）
//  29   | lan_tx_bytes_inc    | u64  | 局域网发送字节数增量（本时段内）
//  30   | last_online_ts      | u64  | 设备最后在线时间戳（毫秒）
//  31   | ipv4_address        | u64  | IPv4地址（存储在低32位）

// 本地助手函数，用于解析/格式化 MAC 地址（用于文件存储交互）
fn parse_mac_text(mac_str: &str) -> Result<[u8; 6], anyhow::Error> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return Err(anyhow::anyhow!("Invalid MAC address format"));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).with_context(|| format!("Invalid MAC segment '{}': not hex", part))?;
    }
    Ok(mac)
}

// 将 MAC 转换为文件名安全的12位十六进制字符串（不含冒号）
fn mac_to_filename(mac: &[u8; 6]) -> String {
    let mut s = String::with_capacity(12);
    for b in mac {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// 预定速率限制的时间段
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeSlot {
    pub start_hour: u8,   // 0-23
    pub start_minute: u8, // 0-59
    pub end_hour: u8,     // 0-24（24 表示一天结束，即 24:00 = 次日 00:00）
    pub end_minute: u8,   // 0-59（如果 end_hour == 24 则必须为 0）
    pub days_of_week: u8, // 位掩码：位 0=星期一，位 6=星期日（0b1111111 = 所有天）
}

impl TimeSlot {
    /// 创建一个适用于所有天、所有小时的时间段（00:00-24:00）
    pub fn all_time() -> Self {
        Self {
            start_hour: 0,
            start_minute: 0,
            end_hour: 24,
            end_minute: 0,
            days_of_week: 0b1111111, // 所有7天
        }
    }

    /// 检查当前时间是否匹配此时间段
    pub fn matches(&self, now: &DateTime<Local>) -> bool {
        let current_hour = now.hour() as u8;
        let current_minute = now.minute() as u8;
        let current_day = (now.weekday().num_days_from_monday()) as u8;

        // 检查星期几是否匹配
        if (self.days_of_week & (1 << current_day)) == 0 {
            return false;
        }

        // 转换为分钟用于比较
        let current_time = current_hour as u32 * 60 + current_minute as u32;
        let start_time = self.start_hour as u32 * 60 + self.start_minute as u32;
        let end_time = self.end_hour as u32 * 60 + self.end_minute as u32;

        if start_time <= end_time {
            // 同一天时间段
            current_time >= start_time && current_time < end_time
        } else {
            // 跨天时间段（例如：22:00-06:00）
            current_time >= start_time || current_time < end_time
        }
    }

    /// 从字符串格式 "HH:MM" 解析时间段
    /// 支持使用 24:00 表示一天结束
    pub fn parse_time(time_str: &str) -> Result<(u8, u8), anyhow::Error> {
        let parts: Vec<&str> = time_str.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("无效时间格式，期望 HH:MM"));
        }
        let hour: u8 = parts[0].parse().with_context(|| format!("Invalid hour: {}", parts[0]))?;
        let minute: u8 = parts[1].parse().with_context(|| format!("Invalid minute: {}", parts[1]))?;
        if hour > 24 {
            return Err(anyhow::anyhow!("小时必须是 0-24"));
        }
        if hour == 24 && minute != 0 {
            return Err(anyhow::anyhow!("当小时为 24 时，分钟必须为 0"));
        }
        if minute > 59 {
            return Err(anyhow::anyhow!("分钟必须是 0-59"));
        }
        Ok((hour, minute))
    }

    /// 将时间段格式化为 "HH:MM" 字符串
    pub fn format_time(hour: u8, minute: u8) -> String {
        format!("{:02}:{:02}", hour, minute)
    }

    /// 从字符串格式 "1111111" (7 位) 或逗号分隔列表 "1,2,3,4,5" 解析星期几
    pub fn parse_days(days_str: &str) -> Result<u8, anyhow::Error> {
        if days_str.len() == 7 && days_str.chars().all(|c| c == '0' || c == '1') {
            // 二进制格式："1111111"
            let mut days = 0u8;
            for (i, ch) in days_str.chars().enumerate() {
                if ch == '1' {
                    days |= 1 << i;
                }
            }
            Ok(days)
        } else {
            // 逗号分隔格式："1,2,3,4,5" (1=周一, 7=周日)
            let mut days = 0u8;
            for part in days_str.split(',') {
                let day: u8 = part.trim().parse().with_context(|| format!("无效的天数：{}", part))?;
                if day < 1 || day > 7 {
                    return Err(anyhow::anyhow!("天数必须是 1-7（周一到周日）"));
                }
                days |= 1 << (day - 1);
            }
            Ok(days)
        }
    }

    /// 将星期几格式化为二进制字符串
    pub fn format_days(days: u8) -> String {
        (0..7).map(|i| if (days & (1 << i)) != 0 { '1' } else { '0' }).collect()
    }
}

/// 预定速率限制规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledRateLimit {
    pub mac: [u8; 6],
    pub time_slot: TimeSlot,
    pub wan_rx_rate_limit: u64,
    pub wan_tx_rate_limit: u64,
}

/// 内存中实时数据环形结构（1秒采样）
#[derive(Debug, Clone)]
pub struct RealtimeRing {
    pub capacity: u32,
    pub slots: Vec<[u64; SLOT_U64S_REALTIME]>,
    pub current_index: u64,
}

impl RealtimeRing {
    pub fn new(capacity: u32) -> Self {
        let cap = if capacity == 0 { DEFAULT_RING_CAPACITY } else { capacity };

        Self {
            capacity: cap,
            slots: vec![[0u64; SLOT_U64S_REALTIME]; cap as usize],
            current_index: 0,
        }
    }

    pub fn insert(&mut self, ts_ms: u64, data: &[u64; SLOT_U64S_REALTIME]) {
        let idx = calc_slot_index(ts_ms, self.capacity);
        self.slots[idx as usize] = *data;
        self.current_index = idx;
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
                lan_rx_rate: slot[3],
                lan_tx_rate: slot[4],
                wan_rx_rate: slot[5],
                wan_tx_rate: slot[6],
                total_rx_bytes: slot[7],
                total_tx_bytes: slot[8],
                lan_rx_bytes_inc: slot[9],
                lan_tx_bytes_inc: slot[10],
                wan_rx_bytes_inc: slot[11],
                wan_tx_bytes_inc: slot[12],
            });
        }

        rows.sort_by_key(|r| r.ts_ms);
        rows
    }
}

/// 内存中长期统计数据环形结构（1小时采样）
#[derive(Debug, Clone)]
pub struct LongTermRing {
    pub capacity: u32,
    pub slots: Vec<[u64; SLOT_U64S_LONG_TERM]>,
    pub current_index: u64,
    pub dirty: bool,
}

impl LongTermRing {
    pub fn new(capacity: u32) -> Self {
        let cap = if capacity == 0 { DEFAULT_RING_CAPACITY } else { capacity };

        Self {
            capacity: cap,
            slots: vec![[0u64; SLOT_U64S_LONG_TERM]; cap as usize],
            current_index: 0,
            dirty: false,
        }
    }

    pub fn insert_stats(&mut self, ts_ms: u64, stats: &DeviceStatsAccumulator, interval_seconds: u64) {
        let idx = calc_slot_index_with_interval(ts_ms, self.capacity, interval_seconds);
        let mut slot = [0u64; SLOT_U64S_LONG_TERM];

        // 时间段：start_ts_ms 和 end_ts_ms
        slot[0] = stats.ts_start_ms;
        slot[1] = stats.ts_end_ms;

        // wan_rx_rate: avg, max, min, p90, p95, p99 (indices 2-7)
        slot[2] = stats.wan_rx_rate.avg;
        slot[3] = stats.wan_rx_rate.max;
        slot[4] = stats.wan_rx_rate.min;
        slot[5] = stats.wan_rx_rate.p90;
        slot[6] = stats.wan_rx_rate.p95;
        slot[7] = stats.wan_rx_rate.p99;

        // wan_tx_rate: avg, max, min, p90, p95, p99 (indices 8-13)
        slot[8] = stats.wan_tx_rate.avg;
        slot[9] = stats.wan_tx_rate.max;
        slot[10] = stats.wan_tx_rate.min;
        slot[11] = stats.wan_tx_rate.p90;
        slot[12] = stats.wan_tx_rate.p95;
        slot[13] = stats.wan_tx_rate.p99;

        // 广域网络流量字节数增量（索引14-15）
        slot[14] = stats.get_wan_rx_bytes_increment();
        slot[15] = stats.get_wan_tx_bytes_increment();

        // lan_rx_rate: avg, max, min, p90, p95, p99 (indices 16-21)
        slot[16] = stats.lan_rx_rate.avg;
        slot[17] = stats.lan_rx_rate.max;
        slot[18] = stats.lan_rx_rate.min;
        slot[19] = stats.lan_rx_rate.p90;
        slot[20] = stats.lan_rx_rate.p95;
        slot[21] = stats.lan_rx_rate.p99;

        // lan_tx_rate: avg, max, min, p90, p95, p99 (indices 22-27)
        slot[22] = stats.lan_tx_rate.avg;
        slot[23] = stats.lan_tx_rate.max;
        slot[24] = stats.lan_tx_rate.min;
        slot[25] = stats.lan_tx_rate.p90;
        slot[26] = stats.lan_tx_rate.p95;
        slot[27] = stats.lan_tx_rate.p99;

        // 局域网流量字节数增量（索引28-29）
        slot[28] = stats.get_lan_rx_bytes_increment();
        slot[29] = stats.get_lan_tx_bytes_increment();

        // 设备最后在线时间戳（索引30）
        slot[30] = stats.last_online_ts;

        // IPv4地址（索引31，存储在低32位）
        slot[31] = if let Some(ipv4) = stats.ipv4 { u32::from_be_bytes(ipv4) as u64 } else { 0 };

        self.slots[idx as usize] = slot;
        self.current_index = idx;
        self.dirty = true;
    }

    pub fn query_stats(&self, start_ms: u64, end_ms: u64) -> Vec<MetricsRowWithStats> {
        let mut rows = Vec::new();

        for slot in &self.slots {
            let start_ts = slot[0];
            let end_ts = slot[1];
            if end_ts == 0 {
                continue;
            }
            if end_ts < start_ms || start_ts > end_ms {
                continue;
            }

            rows.push(MetricsRowWithStats {
                start_ts_ms: slot[0],
                end_ts_ms: slot[1],
                // wan_rx_rate stats (indices 2-7)
                wan_rx_rate_avg: slot[2],
                wan_rx_rate_max: slot[3],
                wan_rx_rate_min: slot[4],
                wan_rx_rate_p90: slot[5],
                wan_rx_rate_p95: slot[6],
                wan_rx_rate_p99: slot[7],
                // wan_tx_rate stats (indices 8-13)
                wan_tx_rate_avg: slot[8],
                wan_tx_rate_max: slot[9],
                wan_tx_rate_min: slot[10],
                wan_tx_rate_p90: slot[11],
                wan_tx_rate_p95: slot[12],
                wan_tx_rate_p99: slot[13],
                // 广域网络流量字节数增量（索引14-15）
                wan_rx_bytes_inc: slot[14],
                wan_tx_bytes_inc: slot[15],
                // lan_rx_rate stats (indices 16-21)
                lan_rx_rate_avg: slot[16],
                lan_rx_rate_max: slot[17],
                lan_rx_rate_min: slot[18],
                lan_rx_rate_p90: slot[19],
                lan_rx_rate_p95: slot[20],
                lan_rx_rate_p99: slot[21],
                // lan_tx_rate stats (indices 22-27)
                lan_tx_rate_avg: slot[22],
                lan_tx_rate_max: slot[23],
                lan_tx_rate_min: slot[24],
                lan_tx_rate_p90: slot[25],
                lan_tx_rate_p95: slot[26],
                lan_tx_rate_p99: slot[27],
                // 局域网流量字节数增量（索引28-29）
                lan_rx_bytes_inc: slot[28],
                lan_tx_bytes_inc: slot[29],
                // 设备最后在线时间戳（索引30）
                last_online_ts: slot[30],
            });
        }

        rows.sort_by_key(|r| r.end_ts_ms);
        rows
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    /// 获取所有增量累加后的总流量作为基线
    /// 返回 (end_ts_ms, wan_rx_bytes_total, wan_tx_bytes_total, lan_rx_bytes_total, lan_tx_bytes_total, last_online_ts)
    pub fn get_latest_baseline_with_ts(&self) -> Option<(u64, u64, u64, u64, u64, u64)> {
        let mut latest_end_ts = 0u64;
        let mut total_wan_rx_bytes = 0u64;
        let mut total_wan_tx_bytes = 0u64;
        let mut total_lan_rx_bytes = 0u64;
        let mut total_lan_tx_bytes = 0u64;
        let mut latest_last_online_ts = 0u64;

        for slot in &self.slots {
            let start_ts = slot[0];
            if start_ts == 0 {
                continue;
            }

            let end_ts = slot[1];
            total_wan_rx_bytes = total_wan_rx_bytes.saturating_add(slot[14]);
            total_wan_tx_bytes = total_wan_tx_bytes.saturating_add(slot[15]);
            total_lan_rx_bytes = total_lan_rx_bytes.saturating_add(slot[28]);
            total_lan_tx_bytes = total_lan_tx_bytes.saturating_add(slot[29]);

            if end_ts > latest_end_ts {
                latest_end_ts = end_ts;
                latest_last_online_ts = slot[30];
            }
        }

        if latest_end_ts > 0 {
            Some((
                latest_end_ts,
                total_wan_rx_bytes,
                total_wan_tx_bytes,
                total_lan_rx_bytes,
                total_lan_tx_bytes,
                latest_last_online_ts,
            ))
        } else {
            None
        }
    }
}

/// 实时数据内存环形管理器（1秒采样）
pub struct RealtimeRingManager {
    pub rings: Arc<Mutex<HashMap<[u8; 6], RealtimeRing>>>,
    pub capacity: u32,
}

impl RealtimeRingManager {
    pub fn new(_base_dir: String, capacity: u32) -> Self {
        Self {
            rings: Arc::new(Mutex::new(HashMap::new())),
            capacity,
        }
    }

    /// 将数据插入内存环形缓冲区
    pub fn insert_metrics_batch(
        &self,
        current_ts_ms: u64,
        rows: &Vec<([u8; 6], crate::device::UnifiedDevice)>,
    ) -> Result<(), anyhow::Error> {
        if rows.is_empty() {
            return Ok(());
        }

        let mut rings = self.rings.lock().unwrap();

        for (mac, device) in rows.iter() {
            let ring = rings.entry(*mac).or_insert_with(|| RealtimeRing::new(self.capacity));

            // 将 IPv4 地址 [u8; 4] 转换为 u64（存储在低 32 位）
            let ipv4 = device.current_ipv4.unwrap_or([0, 0, 0, 0]);
            let ip_address_u64 = u64::from_le_bytes([ipv4[0], ipv4[1], ipv4[2], ipv4[3], 0, 0, 0, 0]);

            let rec: [u64; SLOT_U64S_REALTIME] = [
                current_ts_ms,
                device.total_rx_rate(),
                device.total_tx_rate(),
                device.lan_rx_rate,
                device.lan_tx_rate,
                device.wan_rx_rate,
                device.wan_tx_rate,
                device.total_rx_bytes(),
                device.total_tx_bytes(),
                device.lan_rx_bytes,
                device.lan_tx_bytes,
                device.wan_rx_bytes,
                device.wan_tx_bytes,
                device.last_online_ts,
                ip_address_u64,
            ];

            ring.insert(current_ts_ms, &rec);
        }

        Ok(())
    }

    /// 从内存环形缓冲区查询数据
    pub fn query_metrics_by_mac(&self, mac: &[u8; 6], start_ms: u64, end_ms: u64) -> Result<Vec<MetricsRow>, anyhow::Error> {
        let rings = self.rings.lock().unwrap();

        if let Some(ring) = rings.get(mac) {
            Ok(ring.query(start_ms, end_ms))
        } else {
            Ok(Vec::new())
        }
    }

    /// 从所有设备聚合查询数据
    pub fn query_metrics_aggregate_all(&self, start_ms: u64, end_ms: u64) -> Result<Vec<MetricsRow>, anyhow::Error> {
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
                agg[0] = ts; // 保留时间戳
                             // 仅聚合指标字段（排除索引 13 处的 last_online_ts）
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
                lan_rx_rate: rec[3],
                lan_tx_rate: rec[4],
                wan_rx_rate: rec[5],
                wan_tx_rate: rec[6],
                total_rx_bytes: rec[7],
                total_tx_bytes: rec[8],
                lan_rx_bytes_inc: rec[9],
                lan_tx_bytes_inc: rec[10],
                wan_rx_bytes_inc: rec[11],
                wan_tx_bytes_inc: rec[12],
            })
            .collect();

        Ok(rows_vec)
    }
}

/// 指标统计信息（平均值、最大值、最小值、p90、p95、p99）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricStats {
    pub samples: Vec<u64>, // 存储所有样本用于百分位数计算
    pub avg: u64,          // 平均值（均值）
    pub max: u64,          // 最大值
    pub min: u64,          // 最小值
    pub p90: u64,          // 第90百分位数
    pub p95: u64,          // 第95百分位数
    pub p99: u64,          // 第99百分位数
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

        // 计算平均值（均值）
        let sum: u64 = self.samples.iter().sum();
        self.avg = sum / self.samples.len() as u64;

        // 计算百分位数
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();

        let len = sorted.len();
        if len > 0 {
            // P90：在排序数组的 90% 位置的索引
            let p90_idx = ((len - 1) as f64 * 0.90) as usize;
            self.p90 = sorted[p90_idx.min(len - 1)];

            // P95：在排序数组的 95% 位置的索引
            let p95_idx = ((len - 1) as f64 * 0.95) as usize;
            self.p95 = sorted[p95_idx.min(len - 1)];

            // P99：在排序数组的 99% 位置的索引
            let p99_idx = ((len - 1) as f64 * 0.99) as usize;
            self.p99 = sorted[p99_idx.min(len - 1)];
        }
    }
}

/// Accumulator 持久化存储结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccumulatorSnapshot {
    pub saved_at_ms: u64,
    pub accumulators: Vec<(String, DeviceStatsAccumulator)>,
}

/// 采样间隔期间设备累积统计信息
/// 存储广域网络和局域网统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceStatsAccumulator {
    pub ts_start_ms: u64,         // 采样开始时间戳
    pub ts_end_ms: u64,           // 采样结束时间戳
    pub wan_rx_rate: MetricStats, // 广域网络接收速率统计信息
    pub wan_tx_rate: MetricStats, // 广域网络发送速率统计信息
    pub wan_rx_bytes_start: u64,  // 广域网络接收字节数基线（时段开始时）
    pub wan_tx_bytes_start: u64,  // 广域网络发送字节数基线（时段开始时）
    pub wan_rx_bytes: u64,        // 广域网络接收字节数（时段结束时）
    pub wan_tx_bytes: u64,        // 广域网络发送字节数（时段结束时）
    pub lan_rx_rate: MetricStats, // 局域网接收速率统计信息
    pub lan_tx_rate: MetricStats, // 局域网发送速率统计信息
    pub lan_rx_bytes_start: u64,  // 局域网接收字节数基线（时段开始时）
    pub lan_tx_bytes_start: u64,  // 局域网发送字节数基线（时段开始时）
    pub lan_rx_bytes: u64,        // 局域网接收字节数（时段结束时）
    pub lan_tx_bytes: u64,        // 局域网发送字节数（时段结束时）
    pub last_online_ts: u64,      // 设备最后在线时间戳（毫秒）
    pub ipv4: Option<[u8; 4]>,    // IPv4地址
    pub is_first_sample: bool,    // 是否是第一次采样
}

impl DeviceStatsAccumulator {
    pub fn new(ts_ms: u64) -> Self {
        Self {
            ts_start_ms: ts_ms,
            ts_end_ms: ts_ms,
            wan_rx_rate: MetricStats::new(),
            wan_tx_rate: MetricStats::new(),
            wan_rx_bytes_start: 0,
            wan_tx_bytes_start: 0,
            wan_rx_bytes: 0,
            wan_tx_bytes: 0,
            lan_rx_rate: MetricStats::new(),
            lan_tx_rate: MetricStats::new(),
            lan_rx_bytes_start: 0,
            lan_tx_bytes_start: 0,
            lan_rx_bytes: 0,
            lan_tx_bytes: 0,
            last_online_ts: 0,
            ipv4: None,
            is_first_sample: true,
        }
    }

    pub fn add_sample(&mut self, device: &crate::device::UnifiedDevice, ts_ms: u64) {
        self.ts_end_ms = ts_ms;

        if self.is_first_sample {
            self.wan_rx_bytes_start = device.wan_rx_bytes;
            self.wan_tx_bytes_start = device.wan_tx_bytes;
            self.lan_rx_bytes_start = device.lan_rx_bytes;
            self.lan_tx_bytes_start = device.lan_tx_bytes;
            self.is_first_sample = false;
        }

        self.wan_rx_rate.add_sample(device.wan_rx_rate);
        self.wan_tx_rate.add_sample(device.wan_tx_rate);
        self.lan_rx_rate.add_sample(device.lan_rx_rate);
        self.lan_tx_rate.add_sample(device.lan_tx_rate);

        self.wan_rx_bytes = device.wan_rx_bytes;
        self.wan_tx_bytes = device.wan_tx_bytes;
        self.lan_rx_bytes = device.lan_rx_bytes;
        self.lan_tx_bytes = device.lan_tx_bytes;

        if device.last_online_ts > 0 {
            self.last_online_ts = device.last_online_ts;
        }

        if self.ipv4.is_none() {
            self.ipv4 = device.current_ipv4;
        }
    }

    pub fn finalize(&mut self) {
        self.wan_rx_rate.finalize();
        self.wan_tx_rate.finalize();
        self.lan_rx_rate.finalize();
        self.lan_tx_rate.finalize();
    }

    pub fn get_wan_rx_bytes_increment(&self) -> u64 {
        self.wan_rx_bytes.saturating_sub(self.wan_rx_bytes_start)
    }

    pub fn get_wan_tx_bytes_increment(&self) -> u64 {
        self.wan_tx_bytes.saturating_sub(self.wan_tx_bytes_start)
    }

    pub fn get_lan_rx_bytes_increment(&self) -> u64 {
        self.lan_rx_bytes.saturating_sub(self.lan_rx_bytes_start)
    }

    pub fn get_lan_tx_bytes_increment(&self) -> u64 {
        self.lan_tx_bytes.saturating_sub(self.lan_tx_bytes_start)
    }
}

const LONG_TERM_INTERVAL_SECONDS: u64 = 3600;
const LONG_TERM_RETENTION_SECONDS: u64 = 365 * 24 * 3600;

/// 持久统计数据长期环形管理器（1小时采样，365天保留）
pub struct LongTermRingManager {
    pub rings: Arc<Mutex<HashMap<[u8; 6], LongTermRing>>>,
    pub base_dir: String,
    pub capacity: u32,
    pub accumulators: Arc<Mutex<HashMap<[u8; 6], DeviceStatsAccumulator>>>,
    pub persist_interval_seconds: u32,
}

impl LongTermRingManager {
    pub fn new(base_dir: String, persist_interval_seconds: u32) -> Self {
        let capacity = (LONG_TERM_RETENTION_SECONDS / LONG_TERM_INTERVAL_SECONDS) as u32;

        Self {
            rings: Arc::new(Mutex::new(HashMap::new())),
            base_dir: Path::new(&base_dir)
                .join("metrics")
                .join("longterm")
                .to_string_lossy()
                .to_string(),
            capacity,
            accumulators: Arc::new(Mutex::new(HashMap::new())),
            persist_interval_seconds,
        }
    }

    fn accumulator_file_path(&self) -> PathBuf {
        Path::new(&self.base_dir).join("accumulator.json")
    }

    pub fn save_accumulators(&self) -> Result<(), anyhow::Error> {
        let accumulators = self.accumulators.lock().unwrap();

        if accumulators.is_empty() {
            let path = self.accumulator_file_path();
            if path.exists() {
                fs::remove_file(&path)?;
            }
            return Ok(());
        }

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;

        let accumulators_vec: Vec<(String, DeviceStatsAccumulator)> = accumulators
            .iter()
            .map(|(mac, acc)| (mac_to_filename(mac), acc.clone()))
            .collect();

        let snapshot = AccumulatorSnapshot {
            saved_at_ms: now_ms,
            accumulators: accumulators_vec,
        };

        let json = serde_json::to_string_pretty(&snapshot)?;
        let path = self.accumulator_file_path();
        ensure_parent_dir(&path)?;
        fs::write(&path, json)?;

        log::debug!("Saved {} accumulator(s) to {}", accumulators.len(), path.display());
        Ok(())
    }

    pub fn load_accumulators(&self) -> Result<(), anyhow::Error> {
        let path = self.accumulator_file_path();
        if !path.exists() {
            log::debug!("No accumulator file found, starting fresh");
            return Ok(());
        }

        let json = fs::read_to_string(&path)?;
        let snapshot: AccumulatorSnapshot = serde_json::from_str(&json)?;

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64;
        let age_seconds = (now_ms.saturating_sub(snapshot.saved_at_ms)) / 1000;

        if age_seconds > LONG_TERM_INTERVAL_SECONDS {
            log::warn!(
                "Accumulator file is {} seconds old (>{} seconds), discarding",
                age_seconds,
                LONG_TERM_INTERVAL_SECONDS
            );
            fs::remove_file(&path)?;
            return Ok(());
        }

        let mut accumulators = self.accumulators.lock().unwrap();
        accumulators.clear();

        for (mac_str, acc) in snapshot.accumulators {
            if mac_str.len() != 12 {
                log::warn!("Invalid MAC address in accumulator file: {}", mac_str);
                continue;
            }

            let mut mac = [0u8; 6];
            let mut valid = true;
            for i in 0..6 {
                if let Ok(v) = u8::from_str_radix(&mac_str[i * 2..i * 2 + 2], 16) {
                    mac[i] = v;
                } else {
                    log::warn!("Invalid MAC address in accumulator file: {}", mac_str);
                    valid = false;
                    break;
                }
            }

            if valid {
                accumulators.insert(mac, acc);
            }
        }

        log::info!(
            "Restored {} accumulator(s) from previous session ({} seconds ago)",
            accumulators.len(),
            age_seconds
        );

        Ok(())
    }

    pub fn insert_metrics_batch(&self, ts_ms: u64, rows: &Vec<([u8; 6], crate::device::UnifiedDevice)>) -> Result<(), anyhow::Error> {
        if rows.is_empty() {
            return Ok(());
        }

        let mut accumulators = self.accumulators.lock().unwrap();
        let ts_sec = ts_ms / 1000;
        let should_sample = ts_sec % LONG_TERM_INTERVAL_SECONDS == 0;

        for (mac, device) in rows.iter() {
            let accumulator = accumulators.entry(*mac).or_insert_with(|| DeviceStatsAccumulator::new(ts_ms));

            accumulator.add_sample(device, ts_ms);

            if should_sample {
                accumulator.finalize();

                let mut rings = self.rings.lock().unwrap();
                let ring = rings.entry(*mac).or_insert_with(|| LongTermRing::new(self.capacity));

                let slot_idx = calc_slot_index_with_interval(accumulator.ts_end_ms, self.capacity, LONG_TERM_INTERVAL_SECONDS);

                ring.insert_stats(accumulator.ts_end_ms, accumulator, LONG_TERM_INTERVAL_SECONDS);

                let slot = ring.slots[slot_idx as usize];
                drop(rings);

                if let Err(e) = self.persist_single_slot(mac, accumulator.ts_end_ms, &slot) {
                    log::error!("Failed to immediately persist slot for MAC {}: {}", mac_to_filename(mac), e);
                } else {
                    log::debug!(
                        "Immediately persisted slot for MAC {} at {}",
                        mac_to_filename(mac),
                        accumulator.ts_end_ms
                    );
                }

                accumulators.remove(mac);
            }
        }

        drop(accumulators);

        if should_sample {
            if let Err(e) = self.save_accumulators() {
                log::error!("Failed to save accumulators after hourly sample: {}", e);
            }
        } else {
            let save_interval_sec = ts_sec % self.persist_interval_seconds as u64;
            if save_interval_sec == 0 {
                if let Err(e) = self.save_accumulators() {
                    log::error!("Failed to save accumulators: {}", e);
                }
            }
        }

        Ok(())
    }

    pub async fn flush_dirty_rings(&self) -> Result<(), anyhow::Error> {
        if let Err(e) = self.save_accumulators() {
            log::error!("Failed to save accumulators during shutdown: {}", e);
        }

        let dirty_macs: Vec<[u8; 6]> = {
            let rings = self.rings.lock().unwrap();
            rings.iter().filter(|(_, ring)| ring.is_dirty()).map(|(mac, _)| *mac).collect()
        };

        for mac in dirty_macs {
            let mut rings = self.rings.lock().unwrap();
            if let Some(ring) = rings.get_mut(&mac) {
                if ring.is_dirty() {
                    let ring_clone = ring.clone();
                    drop(rings);
                    self.persist_ring_to_file(&mac, &ring_clone)?;
                    let mut rings = self.rings.lock().unwrap();
                    if let Some(ring) = rings.get_mut(&mac) {
                        ring.mark_clean();
                    }
                }
            }
        }
        Ok(())
    }

    pub fn load_from_files(&self) -> Result<Vec<([u8; 6], Option<[u8; 4]>)>, anyhow::Error> {
        let dir = Path::new(&self.base_dir);
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut rings = self.rings.lock().unwrap();
        let mut device_info = Vec::new();

        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if path.extension().and_then(|s| s.to_str()) != Some("ring") {
                continue;
            }

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

            if let Ok(mut f) = OpenOptions::new().read(true).open(&path) {
                if let Ok((ver, cap)) = read_header(&mut f) {
                    if ver == RING_VERSION_LONG_TERM {
                        let mut ring = LongTermRing::new(cap);
                        let mut latest_ipv4: Option<[u8; 4]> = None;
                        let mut latest_ts: u64 = 0;

                        for i in 0..(cap as u64) {
                            if let Ok(slot) = read_slot_v3(&f, i) {
                                if slot[0] != 0 {
                                    ring.slots[i as usize] = slot;

                                    if slot[0] > latest_ts {
                                        latest_ts = slot[0];
                                        if slot[31] != 0 {
                                            let ip_u32 = slot[31] as u32;
                                            latest_ipv4 = Some(ip_u32.to_be_bytes());
                                        }
                                    }
                                }
                            }
                        }

                        ring.mark_clean();
                        rings.insert(mac, ring);
                        device_info.push((mac, latest_ipv4));
                    }
                }
            }
        }

        Ok(device_info)
    }

    fn persist_single_slot(&self, mac: &[u8; 6], ts_ms: u64, slot: &[u64; SLOT_U64S_LONG_TERM]) -> Result<(), anyhow::Error> {
        let path = ring_file_path_v3(&self.base_dir, mac);
        let f = init_ring_file_v3(&path, self.capacity)?;

        let idx = calc_slot_index_with_interval(ts_ms, self.capacity, LONG_TERM_INTERVAL_SECONDS);
        write_slot_v3(&f, idx, slot)?;
        f.sync_all()?;

        Ok(())
    }

    fn persist_ring_to_file(&self, mac: &[u8; 6], ring: &LongTermRing) -> Result<(), anyhow::Error> {
        let path = ring_file_path_v3(&self.base_dir, mac);
        let f = init_ring_file_v3(&path, ring.capacity)?;

        for (idx, slot) in ring.slots.iter().enumerate() {
            if slot[0] != 0 {
                write_slot_v3(&f, idx as u64, slot)?;
            }
        }

        f.sync_all()?;
        Ok(())
    }

    pub fn query_stats_by_mac(&self, mac: &[u8; 6], start_ms: u64, end_ms: u64) -> Result<Vec<MetricsRowWithStats>, anyhow::Error> {
        let rings = self.rings.lock().unwrap();
        if let Some(ring) = rings.get(mac) {
            Ok(ring.query_stats(start_ms, end_ms))
        } else {
            Ok(Vec::new())
        }
    }

    /// 获取所有设备的最新基线（WAN和LAN流量字节数）
    /// 获取所有设备的最新基线和时间戳
    /// 返回 HashMap<MAC地址, (ts_ms, wan_rx_bytes, wan_tx_bytes, lan_rx_bytes, lan_tx_bytes, last_online_ts)>
    /// 包含从 ring 文件和内存中的活跃累积器数据
    pub fn get_all_baselines_with_ts(&self) -> HashMap<[u8; 6], (u64, u64, u64, u64, u64, u64)> {
        let rings = self.rings.lock().unwrap();
        let mut baselines = HashMap::new();

        for (mac, ring) in rings.iter() {
            if let Some((ts, wan_rx, wan_tx, lan_rx, lan_tx, last_online_ts)) = ring.get_latest_baseline_with_ts() {
                baselines.insert(*mac, (ts, wan_rx, wan_tx, lan_rx, lan_tx, last_online_ts));
            }
        }

        drop(rings);

        let accumulators = self.accumulators.lock().unwrap();
        for (mac, accumulator) in accumulators.iter() {
            let ring_baseline = baselines
                .get(mac)
                .map(|(_, wan_rx, wan_tx, lan_rx, lan_tx, _)| (*wan_rx, *wan_tx, *lan_rx, *lan_tx))
                .unwrap_or((0, 0, 0, 0));

            let accumulator_baseline = (
                accumulator.ts_end_ms.max(accumulator.ts_start_ms),
                ring_baseline.0.saturating_add(accumulator.get_wan_rx_bytes_increment()),
                ring_baseline.1.saturating_add(accumulator.get_wan_tx_bytes_increment()),
                ring_baseline.2.saturating_add(accumulator.get_lan_rx_bytes_increment()),
                ring_baseline.3.saturating_add(accumulator.get_lan_tx_bytes_increment()),
                accumulator.last_online_ts,
            );

            baselines.insert(*mac, accumulator_baseline);
        }

        baselines
    }

    /// 获取当前活跃的 accumulator 的增量数据（用于查询当前小时的增量）
    /// 返回 HashMap<MAC地址, (wan_rx_bytes_inc, wan_tx_bytes_inc, lan_rx_bytes_inc, lan_tx_bytes_inc)>
    pub fn get_active_increments(&self) -> HashMap<[u8; 6], (u64, u64, u64, u64)> {
        let accumulators = self.accumulators.lock().unwrap();
        let mut result = HashMap::new();

        for (mac, accumulator) in accumulators.iter() {
            result.insert(
                *mac,
                (
                    accumulator.get_wan_rx_bytes_increment(),
                    accumulator.get_wan_tx_bytes_increment(),
                    accumulator.get_lan_rx_bytes_increment(),
                    accumulator.get_lan_tx_bytes_increment(),
                ),
            );
        }

        result
    }

    /// 获取当前活跃的 accumulator 的完整统计信息（包括速率统计）
    /// 返回 HashMap<MAC地址, DeviceStatsAccumulator>（已经 finalized）
    pub fn get_active_accumulators_with_stats(&self) -> HashMap<[u8; 6], DeviceStatsAccumulator> {
        let accumulators = self.accumulators.lock().unwrap();
        let mut result = HashMap::new();

        for (mac, accumulator) in accumulators.iter() {
            let mut cloned = accumulator.clone();
            cloned.finalize();
            result.insert(*mac, cloned);
        }

        result
    }

    pub fn query_stats_by_device(&self, start_ms: u64, end_ms: u64) -> Result<HashMap<[u8; 6], MetricsRowWithStats>, anyhow::Error> {
        let rings = self.rings.lock().unwrap();
        let mut device_stats: HashMap<[u8; 6], MetricsRowWithStats> = HashMap::new();

        for (mac, ring) in rings.iter() {
            let rows = ring.query_stats(start_ms, end_ms);

            let mut aggregated = MetricsRowWithStats {
                start_ts_ms: start_ms,
                end_ts_ms: end_ms,
                wan_rx_rate_avg: 0,
                wan_rx_rate_max: 0,
                wan_rx_rate_min: u64::MAX,
                wan_rx_rate_p90: 0,
                wan_rx_rate_p95: 0,
                wan_rx_rate_p99: 0,
                wan_tx_rate_avg: 0,
                wan_tx_rate_max: 0,
                wan_tx_rate_min: u64::MAX,
                wan_tx_rate_p90: 0,
                wan_tx_rate_p95: 0,
                wan_tx_rate_p99: 0,
                wan_rx_bytes_inc: 0,
                wan_tx_bytes_inc: 0,
                lan_rx_rate_avg: 0,
                lan_rx_rate_max: 0,
                lan_rx_rate_min: u64::MAX,
                lan_rx_rate_p90: 0,
                lan_rx_rate_p95: 0,
                lan_rx_rate_p99: 0,
                lan_tx_rate_avg: 0,
                lan_tx_rate_max: 0,
                lan_tx_rate_min: u64::MAX,
                lan_tx_rate_p90: 0,
                lan_tx_rate_p95: 0,
                lan_tx_rate_p99: 0,
                lan_rx_bytes_inc: 0,
                lan_tx_bytes_inc: 0,
                last_online_ts: 0,
            };

            if rows.is_empty() {
                continue;
            }

            for row in &rows {
                aggregated.wan_rx_bytes_inc = aggregated.wan_rx_bytes_inc.saturating_add(row.wan_rx_bytes_inc);
                aggregated.wan_tx_bytes_inc = aggregated.wan_tx_bytes_inc.saturating_add(row.wan_tx_bytes_inc);
                aggregated.lan_rx_bytes_inc = aggregated.lan_rx_bytes_inc.saturating_add(row.lan_rx_bytes_inc);
                aggregated.lan_tx_bytes_inc = aggregated.lan_tx_bytes_inc.saturating_add(row.lan_tx_bytes_inc);
                aggregated.last_online_ts = aggregated.last_online_ts.max(row.last_online_ts);
                aggregated.wan_rx_rate_avg = aggregated.wan_rx_rate_avg.saturating_add(row.wan_rx_rate_avg);
                aggregated.wan_rx_rate_max = aggregated.wan_rx_rate_max.max(row.wan_rx_rate_max);
                aggregated.wan_rx_rate_min = aggregated.wan_rx_rate_min.min(row.wan_rx_rate_min);
                aggregated.wan_rx_rate_p90 = aggregated.wan_rx_rate_p90.max(row.wan_rx_rate_p90);
                aggregated.wan_rx_rate_p95 = aggregated.wan_rx_rate_p95.max(row.wan_rx_rate_p95);
                aggregated.wan_rx_rate_p99 = aggregated.wan_rx_rate_p99.max(row.wan_rx_rate_p99);

                aggregated.wan_tx_rate_avg = aggregated.wan_tx_rate_avg.saturating_add(row.wan_tx_rate_avg);
                aggregated.wan_tx_rate_max = aggregated.wan_tx_rate_max.max(row.wan_tx_rate_max);
                aggregated.wan_tx_rate_min = aggregated.wan_tx_rate_min.min(row.wan_tx_rate_min);
                aggregated.wan_tx_rate_p90 = aggregated.wan_tx_rate_p90.max(row.wan_tx_rate_p90);
                aggregated.wan_tx_rate_p95 = aggregated.wan_tx_rate_p95.max(row.wan_tx_rate_p95);
                aggregated.wan_tx_rate_p99 = aggregated.wan_tx_rate_p99.max(row.wan_tx_rate_p99);

                aggregated.lan_rx_rate_avg = aggregated.lan_rx_rate_avg.saturating_add(row.lan_rx_rate_avg);
                aggregated.lan_rx_rate_max = aggregated.lan_rx_rate_max.max(row.lan_rx_rate_max);
                aggregated.lan_rx_rate_min = aggregated.lan_rx_rate_min.min(row.lan_rx_rate_min);
                aggregated.lan_rx_rate_p90 = aggregated.lan_rx_rate_p90.max(row.lan_rx_rate_p90);
                aggregated.lan_rx_rate_p95 = aggregated.lan_rx_rate_p95.max(row.lan_rx_rate_p95);
                aggregated.lan_rx_rate_p99 = aggregated.lan_rx_rate_p99.max(row.lan_rx_rate_p99);

                aggregated.lan_tx_rate_avg = aggregated.lan_tx_rate_avg.saturating_add(row.lan_tx_rate_avg);
                aggregated.lan_tx_rate_max = aggregated.lan_tx_rate_max.max(row.lan_tx_rate_max);
                aggregated.lan_tx_rate_min = aggregated.lan_tx_rate_min.min(row.lan_tx_rate_min);
                aggregated.lan_tx_rate_p90 = aggregated.lan_tx_rate_p90.max(row.lan_tx_rate_p90);
                aggregated.lan_tx_rate_p95 = aggregated.lan_tx_rate_p95.max(row.lan_tx_rate_p95);
                aggregated.lan_tx_rate_p99 = aggregated.lan_tx_rate_p99.max(row.lan_tx_rate_p99);
            }

            let count = rows.len() as u64;
            if count > 0 {
                aggregated.wan_rx_rate_avg /= count;
                aggregated.wan_tx_rate_avg /= count;
                aggregated.lan_rx_rate_avg /= count;
                aggregated.lan_tx_rate_avg /= count;
            }

            if aggregated.wan_rx_rate_min == u64::MAX {
                aggregated.wan_rx_rate_min = 0;
            }
            if aggregated.wan_tx_rate_min == u64::MAX {
                aggregated.wan_tx_rate_min = 0;
            }
            if aggregated.lan_rx_rate_min == u64::MAX {
                aggregated.lan_rx_rate_min = 0;
            }
            if aggregated.lan_tx_rate_min == u64::MAX {
                aggregated.lan_tx_rate_min = 0;
            }

            device_stats.insert(*mac, aggregated);
        }

        Ok(device_stats)
    }

    pub fn query_stats_aggregate_all(&self, start_ms: u64, end_ms: u64) -> Result<Vec<MetricsRowWithStats>, anyhow::Error> {
        let rings = self.rings.lock().unwrap();
        let mut all_rows = Vec::new();

        for (_mac, ring) in rings.iter() {
            let mut rows = ring.query_stats(start_ms, end_ms);
            all_rows.append(&mut rows);
        }

        let mut ts_to_stats: BTreeMap<u64, MetricsRowWithStats> = BTreeMap::new();

        for row in all_rows {
            let entry: &mut MetricsRowWithStats = ts_to_stats.entry(row.end_ts_ms).or_insert(MetricsRowWithStats {
                start_ts_ms: row.start_ts_ms,
                end_ts_ms: row.end_ts_ms,
                wan_rx_rate_avg: 0,
                wan_rx_rate_max: 0,
                wan_rx_rate_min: u64::MAX,
                wan_rx_rate_p90: 0,
                wan_rx_rate_p95: 0,
                wan_rx_rate_p99: 0,
                wan_tx_rate_avg: 0,
                wan_tx_rate_max: 0,
                wan_tx_rate_min: u64::MAX,
                wan_tx_rate_p90: 0,
                wan_tx_rate_p95: 0,
                wan_tx_rate_p99: 0,
                wan_rx_bytes_inc: 0,
                wan_tx_bytes_inc: 0,
                lan_rx_rate_avg: 0,
                lan_rx_rate_max: 0,
                lan_rx_rate_min: u64::MAX,
                lan_rx_rate_p90: 0,
                lan_rx_rate_p95: 0,
                lan_rx_rate_p99: 0,
                lan_tx_rate_avg: 0,
                lan_tx_rate_max: 0,
                lan_tx_rate_min: u64::MAX,
                lan_tx_rate_p90: 0,
                lan_tx_rate_p95: 0,
                lan_tx_rate_p99: 0,
                lan_rx_bytes_inc: 0,
                lan_tx_bytes_inc: 0,
                last_online_ts: 0,
            });

            entry.last_online_ts = entry.last_online_ts.max(row.last_online_ts);
            entry.wan_rx_rate_avg = entry.wan_rx_rate_avg.saturating_add(row.wan_rx_rate_avg);
            entry.wan_rx_rate_max = entry.wan_rx_rate_max.max(row.wan_rx_rate_max);
            entry.wan_rx_rate_min = entry.wan_rx_rate_min.min(row.wan_rx_rate_min);
            entry.wan_rx_rate_p90 = entry.wan_rx_rate_p90.max(row.wan_rx_rate_p90);
            entry.wan_rx_rate_p95 = entry.wan_rx_rate_p95.max(row.wan_rx_rate_p95);
            entry.wan_rx_rate_p99 = entry.wan_rx_rate_p99.max(row.wan_rx_rate_p99);

            entry.wan_tx_rate_avg = entry.wan_tx_rate_avg.saturating_add(row.wan_tx_rate_avg);
            entry.wan_tx_rate_max = entry.wan_tx_rate_max.max(row.wan_tx_rate_max);
            entry.wan_tx_rate_min = entry.wan_tx_rate_min.min(row.wan_tx_rate_min);
            entry.wan_tx_rate_p90 = entry.wan_tx_rate_p90.max(row.wan_tx_rate_p90);
            entry.wan_tx_rate_p95 = entry.wan_tx_rate_p95.max(row.wan_tx_rate_p95);
            entry.wan_tx_rate_p99 = entry.wan_tx_rate_p99.max(row.wan_tx_rate_p99);

            entry.wan_rx_bytes_inc = entry.wan_rx_bytes_inc.saturating_add(row.wan_rx_bytes_inc);
            entry.wan_tx_bytes_inc = entry.wan_tx_bytes_inc.saturating_add(row.wan_tx_bytes_inc);

            entry.lan_rx_rate_avg = entry.lan_rx_rate_avg.saturating_add(row.lan_rx_rate_avg);
            entry.lan_rx_rate_max = entry.lan_rx_rate_max.max(row.lan_rx_rate_max);
            entry.lan_rx_rate_min = entry.lan_rx_rate_min.min(row.lan_rx_rate_min);
            entry.lan_rx_rate_p90 = entry.lan_rx_rate_p90.max(row.lan_rx_rate_p90);
            entry.lan_rx_rate_p95 = entry.lan_rx_rate_p95.max(row.lan_rx_rate_p95);
            entry.lan_rx_rate_p99 = entry.lan_rx_rate_p99.max(row.lan_rx_rate_p99);

            entry.lan_tx_rate_avg = entry.lan_tx_rate_avg.saturating_add(row.lan_tx_rate_avg);
            entry.lan_tx_rate_max = entry.lan_tx_rate_max.max(row.lan_tx_rate_max);
            entry.lan_tx_rate_min = entry.lan_tx_rate_min.min(row.lan_tx_rate_min);
            entry.lan_tx_rate_p90 = entry.lan_tx_rate_p90.max(row.lan_tx_rate_p90);
            entry.lan_tx_rate_p95 = entry.lan_tx_rate_p95.max(row.lan_tx_rate_p95);
            entry.lan_tx_rate_p99 = entry.lan_tx_rate_p99.max(row.lan_tx_rate_p99);

            entry.lan_rx_bytes_inc = entry.lan_rx_bytes_inc.saturating_add(row.lan_rx_bytes_inc);
            entry.lan_tx_bytes_inc = entry.lan_tx_bytes_inc.saturating_add(row.lan_tx_bytes_inc);
        }

        for stats in ts_to_stats.values_mut() {
            if stats.wan_rx_rate_min == u64::MAX {
                stats.wan_rx_rate_min = 0;
            }
            if stats.wan_tx_rate_min == u64::MAX {
                stats.wan_tx_rate_min = 0;
            }
            if stats.lan_rx_rate_min == u64::MAX {
                stats.lan_rx_rate_min = 0;
            }
            if stats.lan_tx_rate_min == u64::MAX {
                stats.lan_tx_rate_min = 0;
            }
        }

        Ok(ts_to_stats.into_values().collect())
    }
}

fn ring_dir(base: &str) -> PathBuf {
    Path::new(base).join("metrics")
}
fn legacy_limits_path(base: &str) -> PathBuf {
    Path::new(base).join("rate_limits.txt")
}
fn rate_limit_whitelist_path(base: &str) -> PathBuf {
    Path::new(base).join("rate_limit_whitelist.txt")
}
fn rate_limit_whitelist_enabled_path(base: &str) -> PathBuf {
    Path::new(base).join("rate_limit_whitelist_enabled.txt")
}
#[allow(dead_code)]
fn default_wan_rate_limit_path(base: &str) -> PathBuf {
    Path::new(base).join("default_wan_rate_limit.txt")
}
fn rate_limit_policy_path(base: &str) -> PathBuf {
    Path::new(base).join("rate_limit_policy.txt")
}

#[derive(Debug, Clone)]
pub struct RateLimitPolicy {
    pub enabled: bool,
    pub default_wan_limits: [u64; 2],
    pub whitelist: HashSet<[u8; 6]>,
}

fn parse_bool_line(line: &str) -> Option<bool> {
    let s = line.trim().to_ascii_lowercase();
    if s.is_empty() {
        return None;
    }
    Some(matches!(s.as_str(), "1" | "true" | "yes" | "on"))
}

fn parse_two_u64_line(line: &str) -> Option<[u64; 2]> {
    let s = line.trim();
    if s.is_empty() {
        return None;
    }
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let rx = parts[0].parse::<u64>().ok()?;
    let tx = parts[1].parse::<u64>().ok()?;
    Some([rx, tx])
}
// bindings_path 已移动到 storage::hostname 模块
fn ring_file_path_v3(base: &str, mac: &[u8; 6]) -> PathBuf {
    Path::new(base).join(format!("{}.ring", mac_to_filename(mac)))
}

fn ensure_parent_dir(path: &Path) -> Result<(), anyhow::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
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

fn calc_slot_index(ts_ms: u64, capacity: u32) -> u64 {
    ((ts_ms / 1000) % capacity as u64) as u64
}

/// 为带采样间隔的多级别环形计算槽位索引
/// 这确保数据根据采样间隔正确存储，而不仅仅是时间戳模运算
fn calc_slot_index_with_interval(ts_ms: u64, capacity: u32, interval_seconds: u64) -> u64 {
    let ts_sec = ts_ms / 1000;
    // 基于采样间隔计算槽位索引
    // 例如，使用 30 秒间隔：slot = (ts_sec / 30) % capacity
    // 这确保每个采样点在达到容量之前获得唯一的槽位
    ((ts_sec / interval_seconds) % capacity as u64) as u64
}

// ============================================================================
// 多级别环形文件 I/O 函数（v3 格式）
// ============================================================================

fn write_header_v3(f: &mut File, capacity: u32) -> Result<(), anyhow::Error> {
    f.seek(SeekFrom::Start(0))?;
    f.write_all(&RING_MAGIC)?;
    f.write_all(&RING_VERSION_LONG_TERM.to_le_bytes())?;
    f.write_all(&capacity.to_le_bytes())?;
    Ok(())
}

fn init_ring_file_v3(path: &Path, capacity: u32) -> Result<File, anyhow::Error> {
    ensure_parent_dir(path)?;
    let mut f = OpenOptions::new().read(true).write(true).create(true).open(path)?;

    let metadata = f.metadata()?;
    let cap = if capacity == 0 { DEFAULT_RING_CAPACITY } else { capacity };
    let expected_size = HEADER_SIZE as u64 + (cap as u64) * (SLOT_SIZE_LONG_TERM as u64);

    if metadata.len() != expected_size {
        // 重新初始化
        f.set_len(0)?;
        write_header_v3(&mut f, cap)?;
        // 写入零填充的槽位区域
        let zero_chunk = vec![0u8; 4096];
        let mut remaining = expected_size - HEADER_SIZE as u64;
        while remaining > 0 {
            let to_write = std::cmp::min(remaining, zero_chunk.len() as u64) as usize;
            f.write_all(&zero_chunk[..to_write])?;
            remaining -= to_write as u64;
        }
        f.flush()?;
    } else {
        let (ver, _) = read_header(&mut f)?;
        if ver != RING_VERSION_LONG_TERM {
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

fn write_slot_v3(mut f: &File, idx: u64, data: &[u64; SLOT_U64S_LONG_TERM]) -> Result<(), anyhow::Error> {
    let offset = HEADER_SIZE as u64 + idx * (SLOT_SIZE_LONG_TERM as u64);
    let mut bytes = vec![0u8; SLOT_SIZE_LONG_TERM];
    for (i, v) in data.iter().enumerate() {
        let b = v.to_le_bytes();
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&b);
    }
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(&bytes)?;
    Ok(())
}

fn read_slot_v3(mut f: &File, idx: u64) -> Result<[u64; SLOT_U64S_LONG_TERM], anyhow::Error> {
    let offset = HEADER_SIZE as u64 + idx * (SLOT_SIZE_LONG_TERM as u64);
    let mut bytes = vec![0u8; SLOT_SIZE_LONG_TERM];
    f.seek(SeekFrom::Start(offset))?;
    f.read_exact(&mut bytes)?;
    let mut out = [0u64; SLOT_U64S_LONG_TERM];
    for i in 0..SLOT_U64S_LONG_TERM {
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        out[i] = u64::from_le_bytes(b);
    }
    Ok(out)
}

pub fn ensure_schema(base_dir: &str) -> Result<(), anyhow::Error> {
    fs::create_dir_all(ring_dir(base_dir)).with_context(|| format!("Failed to create metrics dir under {}", base_dir))?;
    let longterm_dir = Path::new(base_dir).join("metrics").join("longterm");
    fs::create_dir_all(&longterm_dir).with_context(|| format!("Failed to create longterm metrics dir under {}", base_dir))?;
    let bindings = crate::storage::hostname::bindings_path(base_dir);
    if !bindings.exists() {
        File::create(&bindings)?;
    }

    let policy_path = rate_limit_policy_path(base_dir);
    if !policy_path.exists() {
        let policy = RateLimitPolicy {
            enabled: false,
            default_wan_limits: [0, 0],
            whitelist: HashSet::new(),
        };
        save_rate_limit_policy(base_dir, &policy)?;
    }

    Ok(())
}

pub fn load_all_limits(base_dir: &str) -> Result<Vec<([u8; 6], u64, u64)>, anyhow::Error> {
    let path = legacy_limits_path(base_dir);
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
        // 格式：mac rx tx（支持冒号分隔或12位十六进制格式的MAC地址）
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
        let rx: u64 = parts[1].parse().with_context(|| format!("invalid rx at line {}", lineno + 1))?;
        let tx: u64 = parts[2].parse().with_context(|| format!("invalid tx at line {}", lineno + 1))?;
        out.push((mac, rx, tx));
    }
    Ok(out)
}

pub fn upsert_hostname_binding(base_dir: &str, mac: &[u8; 6], hostname: &str) -> Result<(), anyhow::Error> {
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
        // 如果主机名为空则删除绑定
        map.remove(&key);
    } else {
        // 设置或更新绑定
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

// load_hostname_bindings 和 load_hostname_from_ubus 已移动到 storage::hostname 模块

#[derive(Debug, Clone, Copy)]
pub struct MetricsRow {
    pub ts_ms: u64,
    pub total_rx_rate: u64,
    pub total_tx_rate: u64,
    pub lan_rx_rate: u64,
    pub lan_tx_rate: u64,
    pub wan_rx_rate: u64,
    pub wan_tx_rate: u64,
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
    pub lan_rx_bytes_inc: u64,
    pub lan_tx_bytes_inc: u64,
    pub wan_rx_bytes_inc: u64,
    pub wan_tx_bytes_inc: u64,
}

#[derive(Debug, Clone, Copy)]
/// 包含广域网络和局域网统计信息的指标行
pub struct MetricsRowWithStats {
    pub start_ts_ms: u64, // 时间段开始时间戳（毫秒）
    pub end_ts_ms: u64,   // 时间段结束时间戳（毫秒）
    // 广域网络接收速率统计信息（平均值、最大值、最小值、p90、p95、p99）
    pub wan_rx_rate_avg: u64, // 平均值：典型带宽使用量
    pub wan_rx_rate_max: u64, // 最大值：峰值负载或突发流量
    pub wan_rx_rate_min: u64, // 最小值：空闲或低负载状态
    pub wan_rx_rate_p90: u64, // 90th 百分位数
    pub wan_rx_rate_p95: u64, // 95th 百分位数
    pub wan_rx_rate_p99: u64, // 99th 百分位数
    // 广域网络发送速率统计信息（平均值、最大值、最小值、p90、p95、p99）
    pub wan_tx_rate_avg: u64, // 平均值：典型带宽使用量
    pub wan_tx_rate_max: u64, // 最大值：峰值负载或突发流量
    pub wan_tx_rate_min: u64, // 最小值：空闲或低负载状态
    pub wan_tx_rate_p90: u64, // 90th 百分位数
    pub wan_tx_rate_p95: u64, // 95th 百分位数
    pub wan_tx_rate_p99: u64, // 99th 百分位数
    // 广域网络流量增量（本时段内）
    pub wan_rx_bytes_inc: u64, // 广域网络接收字节数增量
    pub wan_tx_bytes_inc: u64, // 广域网络发送字节数增量
    // 局域网接收速率统计信息（平均值、最大值、最小值、p90、p95、p99）
    pub lan_rx_rate_avg: u64, // 平均值：典型带宽使用量
    pub lan_rx_rate_max: u64, // 最大值：峰值负载或突发流量
    pub lan_rx_rate_min: u64, // 最小值：空闲或低负载状态
    pub lan_rx_rate_p90: u64, // 90th 百分位数
    pub lan_rx_rate_p95: u64, // 95th 百分位数
    pub lan_rx_rate_p99: u64, // 99th 百分位数
    // 局域网发送速率统计信息（平均值、最大值、最小值、p90、p95、p99）
    pub lan_tx_rate_avg: u64, // 平均值：典型带宽使用量
    pub lan_tx_rate_max: u64, // 最大值：峰值负载或突发流量
    pub lan_tx_rate_min: u64, // 最小值：空闲或低负载状态
    pub lan_tx_rate_p90: u64, // 90th 百分位数
    pub lan_tx_rate_p95: u64, // 95th 百分位数
    pub lan_tx_rate_p99: u64, // 99th 百分位数
    // 局域网流量增量（本时段内）
    pub lan_rx_bytes_inc: u64, // 局域网接收字节数增量
    pub lan_tx_bytes_inc: u64, // 局域网发送字节数增量
    // 设备最后在线时间戳
    pub last_online_ts: u64, // 设备最后在线时间戳（毫秒）
}

fn limits_schedule_path(base: &str) -> PathBuf {
    Path::new(base).join("rate_limits_schedule.txt")
}

/// 从文件加载所有预定速率限制
/// 同时将旧版 rate_limits.txt 条目迁移到预定格式（全天候）
pub fn load_all_scheduled_limits(base_dir: &str) -> Result<Vec<ScheduledRateLimit>, anyhow::Error> {
    let mut out = Vec::new();

    let legacy_path = legacy_limits_path(base_dir);

    if legacy_path.exists() {
        let legacy_limits = load_all_limits(base_dir)?;

        let mut migrated_count = 0;

        // 将旧版限制转换为预定格式并保存到新文件
        // 跳过 rx 和 tx 都为 0 的条目（无限制，无需存储）
        for (mac, rx, tx) in legacy_limits.iter() {
            if *rx == 0 && *tx == 0 {
                log::debug!(
                    "Skipping migration of unlimited rate limit for MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    mac[0],
                    mac[1],
                    mac[2],
                    mac[3],
                    mac[4],
                    mac[5]
                );
                continue;
            }

            let scheduled_limit = ScheduledRateLimit {
                mac: *mac,
                time_slot: TimeSlot::all_time(),
                wan_rx_rate_limit: *rx,
                wan_tx_rate_limit: *tx,
            };
            // 保存到新文件（将与现有的预定限制合并）
            upsert_scheduled_limit(base_dir, &scheduled_limit)?;
            out.push(scheduled_limit);
            migrated_count += 1;
        }

        if migrated_count > 0 {
            log::info!(
                "Migrated {} legacy rate limit entries from rate_limits.txt to scheduled format",
                migrated_count
            );
        }

        // 迁移后删除旧版文件（即使所有条目都是无限制的）
        if let Err(e) = fs::remove_file(&legacy_path) {
            log::warn!("Failed to remove legacy rate_limits.txt after migration: {}", e);
        }
    }

    // 然后，从 rate_limits_schedule.txt 加载预定限制
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

        // 格式：mac schedule start_hour:start_min end_hour:end_min days rx tx
        // 示例：aabbccddeeff schedule 09:00 18:00 1111100 1048576 1048576
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

        let (start_hour, start_minute) =
            TimeSlot::parse_time(parts[2]).with_context(|| format!("invalid start time at line {}", lineno + 1))?;
        let (end_hour, end_minute) = TimeSlot::parse_time(parts[3]).with_context(|| format!("invalid end time at line {}", lineno + 1))?;
        let days_of_week = TimeSlot::parse_days(parts[4]).with_context(|| format!("invalid days format at line {}", lineno + 1))?;

        let rx: u64 = parts[5].parse().with_context(|| format!("invalid rx at line {}", lineno + 1))?;
        let tx: u64 = parts[6].parse().with_context(|| format!("invalid tx at line {}", lineno + 1))?;

        out.push(ScheduledRateLimit {
            mac,
            time_slot: TimeSlot {
                start_hour,
                start_minute,
                end_hour,
                end_minute,
                days_of_week,
            },
            wan_rx_rate_limit: rx,
            wan_tx_rate_limit: tx,
        });
    }

    Ok(out)
}

pub fn parse_rate_limit_whitelist(input: &str) -> HashSet<[u8; 6]> {
    let mut out = HashSet::new();
    for part in input.split(',') {
        let s = part.trim();
        if s.is_empty() {
            continue;
        }
        let mac = if s.contains(':') {
            parse_mac_text(s).ok()
        } else if s.len() == 12 {
            let mut mac = [0u8; 6];
            let mut ok = true;
            for i in 0..6 {
                if let Ok(v) = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16) {
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
            out.insert(mac);
        }
    }
    out
}

#[allow(dead_code)]
pub fn load_rate_limit_whitelist(base_dir: &str) -> Result<HashSet<[u8; 6]>, anyhow::Error> {
    let path = rate_limit_whitelist_path(base_dir);
    let mut out = HashSet::new();
    if !path.exists() {
        return Ok(out);
    }
    let content = fs::read_to_string(&path)?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        out.extend(parse_rate_limit_whitelist(line));
    }
    Ok(out)
}

#[allow(dead_code)]
pub fn save_rate_limit_whitelist(base_dir: &str, whitelist: &HashSet<[u8; 6]>) -> Result<(), anyhow::Error> {
    let path = rate_limit_whitelist_path(base_dir);
    ensure_parent_dir(&path)?;
    let mut macs: Vec<String> = whitelist.iter().map(|m| mac_to_filename(m)).collect();
    macs.sort();
    let mut buf = String::new();
    buf.push_str("# comma-separated macs (12 hex or aa:bb:cc:dd:ee:ff)\n");
    buf.push_str(&macs.join(","));
    buf.push('\n');
    fs::write(&path, buf)?;
    Ok(())
}

#[allow(dead_code)]
pub fn load_rate_limit_whitelist_enabled(base_dir: &str) -> Result<Option<bool>, anyhow::Error> {
    let path = rate_limit_whitelist_enabled_path(base_dir);
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path)?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let v = matches!(line.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on");
        return Ok(Some(v));
    }
    Ok(None)
}

#[allow(dead_code)]
pub fn save_rate_limit_whitelist_enabled(base_dir: &str, enabled: bool) -> Result<(), anyhow::Error> {
    let path = rate_limit_whitelist_enabled_path(base_dir);
    ensure_parent_dir(&path)?;
    let mut buf = String::new();
    buf.push_str("# enable whitelist policy: true/false\n");
    buf.push_str(if enabled { "true\n" } else { "false\n" });
    fs::write(&path, buf)?;
    Ok(())
}

#[allow(dead_code)]
pub fn load_default_wan_rate_limit(base_dir: &str) -> Result<[u64; 2], anyhow::Error> {
    let path = default_wan_rate_limit_path(base_dir);
    if !path.exists() {
        return Ok([0, 0]);
    }
    let content = fs::read_to_string(&path)?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let rx: u64 = parts[0].parse().unwrap_or(0);
        let tx: u64 = parts[1].parse().unwrap_or(0);
        return Ok([rx, tx]);
    }
    Ok([0, 0])
}

pub fn load_rate_limit_policy(base_dir: &str) -> Result<RateLimitPolicy, anyhow::Error> {
    let path = rate_limit_policy_path(base_dir);
    if path.exists() {
        let content = fs::read_to_string(&path)?;
        let mut lines = content.lines();
        let enabled = lines.next().and_then(parse_bool_line).unwrap_or(false);
        let default_wan_limits = lines.next().and_then(parse_two_u64_line).unwrap_or([0, 0]);
        let whitelist_line = lines.next().unwrap_or("");
        let whitelist = parse_rate_limit_whitelist(whitelist_line);
        return Ok(RateLimitPolicy {
            enabled,
            default_wan_limits,
            whitelist,
        });
    }

    let policy = RateLimitPolicy {
        enabled: false,
        default_wan_limits: [0, 0],
        whitelist: HashSet::new(),
    };
    save_rate_limit_policy(base_dir, &policy)?;
    Ok(policy)
}

pub fn save_rate_limit_policy(base_dir: &str, policy: &RateLimitPolicy) -> Result<(), anyhow::Error> {
    let path = rate_limit_policy_path(base_dir);
    ensure_parent_dir(&path)?;
    let mut macs: Vec<String> = policy.whitelist.iter().map(|m| mac_to_filename(m)).collect();
    macs.sort();
    let mut buf = String::new();
    buf.push_str(if policy.enabled { "true\n" } else { "false\n" });
    buf.push_str(&format!("{} {}\n", policy.default_wan_limits[0], policy.default_wan_limits[1]));
    buf.push_str(&macs.join(","));
    buf.push('\n');
    fs::write(&path, buf)?;
    Ok(())
}

/// 将预定速率限制保存到文件
pub fn upsert_scheduled_limit(base_dir: &str, scheduled_limit: &ScheduledRateLimit) -> Result<(), anyhow::Error> {
    let path = limits_schedule_path(base_dir);
    ensure_parent_dir(&path)?;

    let mut rules: Vec<ScheduledRateLimit> = Vec::new();

    // 加载现有规则
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
                                        wan_rx_rate_limit: rx,
                                        wan_tx_rate_limit: tx,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 删除具有相同 MAC 和时间段的现有规则（用于更新）
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

    // 添加新的/更新的规则
    rules.push(scheduled_limit.clone());

    // 按 MAC 和时间段排序以确保输出一致性
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

    // 写回文件
    let mut buf = String::new();
    buf.push_str("# mac schedule start_hour:start_min end_hour:end_min days rx tx\n");
    buf.push_str("# days: 7位二进制（周一-周日）或逗号分隔（1-7）\n");
    for rule in rules {
        let mac_str = mac_to_filename(&rule.mac);
        let start_str = TimeSlot::format_time(rule.time_slot.start_hour, rule.time_slot.start_minute);
        let end_str = TimeSlot::format_time(rule.time_slot.end_hour, rule.time_slot.end_minute);
        let days_str = TimeSlot::format_days(rule.time_slot.days_of_week);
        buf.push_str(&format!(
            "{} schedule {} {} {} {} {}\n",
            mac_str, start_str, end_str, days_str, rule.wan_rx_rate_limit, rule.wan_tx_rate_limit
        ));
    }

    fs::write(&path, buf)?;
    Ok(())
}

/// 删除预定速率限制规则
pub fn delete_scheduled_limit(base_dir: &str, mac: &[u8; 6], time_slot: &TimeSlot) -> Result<(), anyhow::Error> {
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
                            // 检查是否匹配要删除的时间段
                            if start_hour == time_slot.start_hour
                                && start_minute == time_slot.start_minute
                                && end_hour == time_slot.end_hour
                                && end_minute == time_slot.end_minute
                                && days_of_week == time_slot.days_of_week
                            {
                                // 跳过此规则（删除它）
                                continue;
                            }
                        }
                    }
                }
            }
        }

        // 保留此规则
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
                                    wan_rx_rate_limit: rx,
                                    wan_tx_rate_limit: tx,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // 写回文件
    let mut buf = String::new();
    buf.push_str("# mac schedule start_hour:start_min end_hour:end_min days rx tx\n");
    buf.push_str("# days: 7位二进制（周一-周日）或逗号分隔（1-7）\n");
    for rule in rules {
        let mac_str = mac_to_filename(&rule.mac);
        let start_str = TimeSlot::format_time(rule.time_slot.start_hour, rule.time_slot.start_minute);
        let end_str = TimeSlot::format_time(rule.time_slot.end_hour, rule.time_slot.end_minute);
        let days_str = TimeSlot::format_days(rule.time_slot.days_of_week);
        buf.push_str(&format!(
            "{} schedule {} {} {} {} {}\n",
            mac_str, start_str, end_str, days_str, rule.wan_rx_rate_limit, rule.wan_tx_rate_limit
        ));
    }

    fs::write(&path, buf)?;
    Ok(())
}

/// 根据预定规则计算 MAC 地址的当前有效速率限制
pub fn calculate_current_rate_limit(scheduled_limits: &[ScheduledRateLimit], mac: &[u8; 6]) -> Option<[u64; 2]> {
    let now = Local::now();

    // 查找此 MAC 的所有匹配规则
    let matching_rules: Vec<&ScheduledRateLimit> = scheduled_limits
        .iter()
        .filter(|rule| rule.mac == *mac && rule.time_slot.matches(&now))
        .collect();

    if matching_rules.is_empty() {
        return None;
    }

    // 如果多个规则匹配，使用最严格的（最低的非零限制）
    // 如果规则为 0，表示无限制，因此取非零值的最小值
    let mut rx_limit: Option<u64> = None;
    let mut tx_limit: Option<u64> = None;

    for rule in matching_rules {
        if rule.wan_rx_rate_limit > 0 {
            rx_limit = Some(rx_limit.map_or(rule.wan_rx_rate_limit, |current: u64| current.min(rule.wan_rx_rate_limit)));
        }
        if rule.wan_tx_rate_limit > 0 {
            tx_limit = Some(tx_limit.map_or(rule.wan_tx_rate_limit, |current: u64| current.min(rule.wan_tx_rate_limit)));
        }
    }

    // 如果无限制则返回 [0, 0]，否则返回计算出的限制
    Some([rx_limit.unwrap_or(0), tx_limit.unwrap_or(0)])
}
