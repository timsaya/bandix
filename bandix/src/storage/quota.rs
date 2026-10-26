use anyhow::Context;
use bandix_common::quota::{QuotaThresholds, QUOTA_DOWNLOAD, QUOTA_UPLOAD};
use chrono::{DateTime, Datelike, Local, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

const QUOTA_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaMode {
    #[default]
    Combined,
    Directional,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrafficQuotaLimits {
    pub minute_bytes: u64,
    pub hourly_bytes: u64,
    pub daily_bytes: u64,
    pub weekly_bytes: u64,
    pub monthly_bytes: u64,
    pub total_bytes: u64,
}

impl TrafficQuotaLimits {
    fn values(self) -> [u64; 6] {
        [
            self.minute_bytes,
            self.hourly_bytes,
            self.daily_bytes,
            self.weekly_bytes,
            self.monthly_bytes,
            self.total_bytes,
        ]
    }

    fn add(&mut self, bytes: u64) {
        self.minute_bytes = self.minute_bytes.saturating_add(bytes);
        self.hourly_bytes = self.hourly_bytes.saturating_add(bytes);
        self.daily_bytes = self.daily_bytes.saturating_add(bytes);
        self.weekly_bytes = self.weekly_bytes.saturating_add(bytes);
        self.monthly_bytes = self.monthly_bytes.saturating_add(bytes);
        self.total_bytes = self.total_bytes.saturating_add(bytes);
    }

    fn remaining(self, used: Self) -> [u64; 6] {
        let limits = self.values();
        let usage = used.values();
        std::array::from_fn(|i| remaining_bytes(limits[i], usage[i]))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficQuota {
    #[serde(default)]
    pub mode: QuotaMode,
    /// 0 means unlimited for that period.
    #[serde(default)]
    pub minute_bytes: u64,
    pub hourly_bytes: u64,
    pub daily_bytes: u64,
    pub weekly_bytes: u64,
    pub monthly_bytes: u64,
    pub total_bytes: u64,
    #[serde(default)]
    pub upload: TrafficQuotaLimits,
    #[serde(default)]
    pub download: TrafficQuotaLimits,
}

impl TrafficQuota {
    /// Keep inactive limits zero so legacy readers cannot apply a second policy.
    fn normalize(mut self) -> Self {
        match self.mode {
            QuotaMode::Combined => {
                self.upload = TrafficQuotaLimits::default();
                self.download = TrafficQuotaLimits::default();
            }
            QuotaMode::Directional => {
                self.minute_bytes = 0;
                self.hourly_bytes = 0;
                self.daily_bytes = 0;
                self.weekly_bytes = 0;
                self.monthly_bytes = 0;
                self.total_bytes = 0;
            }
        }
        self
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TrafficQuotaUsage {
    #[serde(default)]
    minute_key: String,
    #[serde(default)]
    minute_bytes: u64,
    hour_key: String,
    hourly_bytes: u64,
    day_key: String,
    daily_bytes: u64,
    week_key: String,
    weekly_bytes: u64,
    month_key: String,
    monthly_bytes: u64,
    total_bytes: u64,
    #[serde(default)]
    upload: TrafficQuotaLimits,
    #[serde(default)]
    download: TrafficQuotaLimits,
}

#[derive(Debug, Clone, Serialize)]
pub struct DirectionQuotaStatus {
    #[serde(flatten)]
    pub limits: TrafficQuotaLimits,
    pub minute_used_bytes: u64,
    pub hourly_used_bytes: u64,
    pub daily_used_bytes: u64,
    pub weekly_used_bytes: u64,
    pub monthly_used_bytes: u64,
    pub total_used_bytes: u64,
    pub blocked: bool,
    pub exceeded_periods: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrafficQuotaStatus {
    pub mac: String,
    pub mode: QuotaMode,
    pub upload: DirectionQuotaStatus,
    pub download: DirectionQuotaStatus,
    pub minute_bytes: u64,
    pub hourly_bytes: u64,
    pub daily_bytes: u64,
    pub weekly_bytes: u64,
    pub monthly_bytes: u64,
    pub total_bytes: u64,
    pub minute_used_bytes: u64,
    pub hourly_used_bytes: u64,
    pub daily_used_bytes: u64,
    pub weekly_used_bytes: u64,
    pub monthly_used_bytes: u64,
    pub total_used_bytes: u64,
    pub minute_key: String,
    pub hour_key: String,
    pub day_key: String,
    pub week_key: String,
    pub month_key: String,
    pub blocked: bool,
    pub exceeded_periods: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedQuotaState {
    schema_version: u32,
    #[serde(default)]
    entries: Vec<PersistedQuotaEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedQuotaEntry {
    mac: String,
    quota: TrafficQuota,
    #[serde(default)]
    usage: TrafficQuotaUsage,
}

/// Per-device WAN traffic quota state.
///
/// Combined (the default) and directional limits are mutually exclusive.
/// Minute and calendar periods
/// use the router's local timezone; an ISO week starts on Monday. A zero limit
/// means unlimited. The lifetime counter starts when a device quota is first added.
pub struct TrafficQuotaManager {
    path: PathBuf,
    quotas: HashMap<[u8; 6], TrafficQuota>,
    usage: HashMap<[u8; 6], TrafficQuotaUsage>,
    dirty: bool,
    last_persist_ms: u64,
}

impl TrafficQuotaManager {
    pub fn new(base_dir: &str) -> Self {
        Self {
            path: Path::new(base_dir).join("traffic_quotas.json"),
            quotas: HashMap::new(),
            usage: HashMap::new(),
            dirty: false,
            last_persist_ms: now_millis(),
        }
    }

    pub fn load(&mut self) -> anyhow::Result<()> {
        if !self.path.exists() {
            return Ok(());
        }
        let payload = fs::read(&self.path).with_context(|| format!("failed to read {}", self.path.display()))?;
        let state: PersistedQuotaState =
            serde_json::from_slice(&payload).with_context(|| format!("failed to parse {}", self.path.display()))?;
        if state.schema_version != 1 && state.schema_version != QUOTA_SCHEMA_VERSION {
            anyhow::bail!(
                "unsupported traffic quota schema version {} in {}",
                state.schema_version,
                self.path.display()
            );
        }

        self.quotas.clear();
        self.usage.clear();
        for entry in state.entries {
            let mac = parse_mac(&entry.mac).with_context(|| format!("invalid quota MAC {}", entry.mac))?;
            self.quotas.insert(mac, entry.quota.normalize());
            self.usage.insert(mac, entry.usage);
        }
        self.dirty = false;
        self.last_persist_ms = now_millis();
        Ok(())
    }

    pub fn set_quota(&mut self, mac: [u8; 6], quota: TrafficQuota, now: &DateTime<Local>) {
        self.quotas.insert(mac, quota.normalize());
        let usage = self.usage.entry(mac).or_default();
        roll_periods(usage, now);
        self.dirty = true;
    }

    pub fn quota(&self, mac: &[u8; 6]) -> Option<TrafficQuota> {
        self.quotas.get(mac).copied()
    }

    pub fn remove_quota(&mut self, mac: &[u8; 6]) -> bool {
        let removed = self.quotas.remove(mac).is_some();
        self.usage.remove(mac);
        if removed {
            self.dirty = true;
        }
        removed
    }

    /// Records usage and returns true when this update newly exhausts a quota.
    pub fn record_usage(&mut self, mac: &[u8; 6], download_bytes: u64, upload_bytes: u64, now: &DateTime<Local>) -> bool {
        let bytes = download_bytes.saturating_add(upload_bytes);
        if bytes == 0 || !self.quotas.contains_key(mac) {
            return false;
        }
        let quota = *self.quotas.get(mac).unwrap();
        let usage = self.usage.entry(*mac).or_default();
        roll_periods(usage, now);
        let was_blocked = blocked_directions(&quota, usage);
        usage.download.add(download_bytes);
        usage.upload.add(upload_bytes);
        usage.minute_bytes = usage.minute_bytes.saturating_add(bytes);
        usage.hourly_bytes = usage.hourly_bytes.saturating_add(bytes);
        usage.daily_bytes = usage.daily_bytes.saturating_add(bytes);
        usage.weekly_bytes = usage.weekly_bytes.saturating_add(bytes);
        usage.monthly_bytes = usage.monthly_bytes.saturating_add(bytes);
        usage.total_bytes = usage.total_bytes.saturating_add(bytes);
        self.dirty = true;
        blocked_directions(&quota, usage) & !was_blocked != 0
    }

    pub fn blocked_directions(&mut self, now: &DateTime<Local>) -> HashMap<[u8; 6], u8> {
        let macs: Vec<[u8; 6]> = self.quotas.keys().copied().collect();
        let mut blocked = HashMap::new();
        for mac in macs {
            let usage = self.usage.entry(mac).or_default();
            if roll_periods(usage, now) {
                self.dirty = true;
            }
            let mask = blocked_directions(self.quotas.get(&mac).unwrap(), usage);
            if mask != 0 {
                blocked.insert(mac, mask);
            }
        }
        blocked
    }

    /// Remaining bytes for minute/hour/day/week/month/lifetime enforcement.
    /// `u64::MAX` denotes an unlimited period; `0` denotes an exhausted one.
    pub fn enforcement_remaining(&mut self, now: &DateTime<Local>) -> HashMap<[u8; 6], QuotaThresholds> {
        let macs: Vec<[u8; 6]> = self.quotas.keys().copied().collect();
        let mut remaining = HashMap::new();
        for mac in macs {
            let quota = *self.quotas.get(&mac).unwrap();
            let usage = self.usage.entry(mac).or_default();
            if roll_periods(usage, now) {
                self.dirty = true;
            }
            remaining.insert(
                mac,
                QuotaThresholds {
                    combined: [
                        remaining_bytes(quota.minute_bytes, usage.minute_bytes),
                        remaining_bytes(quota.hourly_bytes, usage.hourly_bytes),
                        remaining_bytes(quota.daily_bytes, usage.daily_bytes),
                        remaining_bytes(quota.weekly_bytes, usage.weekly_bytes),
                        remaining_bytes(quota.monthly_bytes, usage.monthly_bytes),
                        remaining_bytes(quota.total_bytes, usage.total_bytes),
                    ],
                    download: quota.download.remaining(usage.download),
                    upload: quota.upload.remaining(usage.upload),
                },
            );
        }
        remaining
    }

    pub fn statuses(&mut self, now: &DateTime<Local>) -> Vec<TrafficQuotaStatus> {
        let mut macs: Vec<[u8; 6]> = self.quotas.keys().copied().collect();
        macs.sort();
        macs.into_iter()
            .map(|mac| {
                let quota = *self.quotas.get(&mac).unwrap();
                let usage = self.usage.entry(mac).or_default();
                if roll_periods(usage, now) {
                    self.dirty = true;
                }
                make_status(&mac, quota, usage)
            })
            .collect()
    }

    pub fn status(&mut self, mac: &[u8; 6], now: &DateTime<Local>) -> Option<TrafficQuotaStatus> {
        let quota = *self.quotas.get(mac)?;
        let usage = self.usage.entry(*mac).or_default();
        if roll_periods(usage, now) {
            self.dirty = true;
        }
        Some(make_status(mac, quota, usage))
    }

    pub fn save(&mut self) -> anyhow::Result<()> {
        let mut macs: Vec<[u8; 6]> = self.quotas.keys().copied().collect();
        macs.sort();
        let entries = macs
            .into_iter()
            .map(|mac| PersistedQuotaEntry {
                mac: format_mac(&mac),
                quota: *self.quotas.get(&mac).unwrap(),
                usage: self.usage.get(&mac).cloned().unwrap_or_default(),
            })
            .collect();
        let state = PersistedQuotaState {
            schema_version: QUOTA_SCHEMA_VERSION,
            entries,
        };
        write_json_atomic(&self.path, &state)?;
        self.dirty = false;
        self.last_persist_ms = now_millis();
        Ok(())
    }

    pub fn persist_if_due(&mut self, now_ms: u64, interval_seconds: u32) -> anyhow::Result<()> {
        let interval_ms = (interval_seconds.max(1) as u64).saturating_mul(1000);
        if self.dirty && now_ms.saturating_sub(self.last_persist_ms) >= interval_ms {
            self.save()?;
        }
        Ok(())
    }
}

fn make_status(mac: &[u8; 6], quota: TrafficQuota, usage: &TrafficQuotaUsage) -> TrafficQuotaStatus {
    let mut exceeded_periods = Vec::new();
    if reached(quota.minute_bytes, usage.minute_bytes) {
        exceeded_periods.push("minute".to_string());
    }
    if reached(quota.hourly_bytes, usage.hourly_bytes) {
        exceeded_periods.push("hourly".to_string());
    }
    if reached(quota.daily_bytes, usage.daily_bytes) {
        exceeded_periods.push("daily".to_string());
    }
    if reached(quota.weekly_bytes, usage.weekly_bytes) {
        exceeded_periods.push("weekly".to_string());
    }
    if reached(quota.monthly_bytes, usage.monthly_bytes) {
        exceeded_periods.push("monthly".to_string());
    }
    if reached(quota.total_bytes, usage.total_bytes) {
        exceeded_periods.push("total".to_string());
    }
    TrafficQuotaStatus {
        mac: format_mac(mac),
        mode: quota.mode,
        upload: direction_status(quota.upload, usage.upload, !exceeded_periods.is_empty()),
        download: direction_status(quota.download, usage.download, !exceeded_periods.is_empty()),
        minute_bytes: quota.minute_bytes,
        hourly_bytes: quota.hourly_bytes,
        daily_bytes: quota.daily_bytes,
        weekly_bytes: quota.weekly_bytes,
        monthly_bytes: quota.monthly_bytes,
        total_bytes: quota.total_bytes,
        minute_used_bytes: usage.minute_bytes,
        hourly_used_bytes: usage.hourly_bytes,
        daily_used_bytes: usage.daily_bytes,
        weekly_used_bytes: usage.weekly_bytes,
        monthly_used_bytes: usage.monthly_bytes,
        total_used_bytes: usage.total_bytes,
        minute_key: usage.minute_key.clone(),
        hour_key: usage.hour_key.clone(),
        day_key: usage.day_key.clone(),
        week_key: usage.week_key.clone(),
        month_key: usage.month_key.clone(),
        blocked: blocked_directions(&quota, usage) != 0,
        exceeded_periods,
    }
}

fn direction_status(limits: TrafficQuotaLimits, usage: TrafficQuotaLimits, combined_blocked: bool) -> DirectionQuotaStatus {
    let limit_values = limits.values();
    let used = usage.values();
    let periods = ["minute", "hourly", "daily", "weekly", "monthly", "total"];
    let exceeded_periods: Vec<String> = (0..6)
        .filter(|&i| reached(limit_values[i], used[i]))
        .map(|i| periods[i].to_string())
        .collect();
    DirectionQuotaStatus {
        limits,
        minute_used_bytes: usage.minute_bytes,
        hourly_used_bytes: usage.hourly_bytes,
        daily_used_bytes: usage.daily_bytes,
        weekly_used_bytes: usage.weekly_bytes,
        monthly_used_bytes: usage.monthly_bytes,
        total_used_bytes: usage.total_bytes,
        blocked: combined_blocked || !exceeded_periods.is_empty(),
        exceeded_periods,
    }
}

fn blocked_directions(quota: &TrafficQuota, usage: &TrafficQuotaUsage) -> u8 {
    let combined = reached(quota.minute_bytes, usage.minute_bytes)
        || reached(quota.hourly_bytes, usage.hourly_bytes)
        || reached(quota.daily_bytes, usage.daily_bytes)
        || reached(quota.weekly_bytes, usage.weekly_bytes)
        || reached(quota.monthly_bytes, usage.monthly_bytes)
        || reached(quota.total_bytes, usage.total_bytes);
    if combined {
        return QUOTA_DOWNLOAD | QUOTA_UPLOAD;
    }
    let download = quota.download.remaining(usage.download).contains(&0);
    let upload = quota.upload.remaining(usage.upload).contains(&0);
    (if download { QUOTA_DOWNLOAD } else { 0 }) | (if upload { QUOTA_UPLOAD } else { 0 })
}

fn reached(limit: u64, used: u64) -> bool {
    limit > 0 && used >= limit
}

fn remaining_bytes(limit: u64, used: u64) -> u64 {
    if limit == 0 {
        u64::MAX
    } else {
        limit.saturating_sub(used)
    }
}

fn roll_periods(usage: &mut TrafficQuotaUsage, now: &DateTime<Local>) -> bool {
    let new_minute = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}",
        now.year(),
        now.month(),
        now.day(),
        now.hour(),
        now.minute()
    );
    let new_hour = format!("{:04}-{:02}-{:02}T{:02}", now.year(), now.month(), now.day(), now.hour());
    let new_day = format!("{:04}-{:02}-{:02}", now.year(), now.month(), now.day());
    let iso = now.iso_week();
    let new_week = format!("{:04}-W{:02}", iso.year(), iso.week());
    let new_month = format!("{:04}-{:02}", now.year(), now.month());
    let mut changed = false;
    if usage.minute_key != new_minute {
        usage.minute_key = new_minute;
        usage.minute_bytes = 0;
        usage.upload.minute_bytes = 0;
        usage.download.minute_bytes = 0;
        changed = true;
    }
    if usage.hour_key != new_hour {
        usage.hour_key = new_hour;
        usage.hourly_bytes = 0;
        usage.upload.hourly_bytes = 0;
        usage.download.hourly_bytes = 0;
        changed = true;
    }
    if usage.day_key != new_day {
        usage.day_key = new_day;
        usage.daily_bytes = 0;
        usage.upload.daily_bytes = 0;
        usage.download.daily_bytes = 0;
        changed = true;
    }
    if usage.week_key != new_week {
        usage.week_key = new_week;
        usage.weekly_bytes = 0;
        usage.upload.weekly_bytes = 0;
        usage.download.weekly_bytes = 0;
        changed = true;
    }
    if usage.month_key != new_month {
        usage.month_key = new_month;
        usage.monthly_bytes = 0;
        usage.upload.monthly_bytes = 0;
        usage.download.monthly_bytes = 0;
        changed = true;
    }
    changed
}

fn write_json_atomic<T: Serialize>(path: &Path, data: &T) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("tmp.{}", now_millis()));
    let payload = serde_json::to_vec_pretty(data)?;
    {
        let mut file = File::create(&tmp)?;
        file.write_all(&payload)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn parse_mac(value: &str) -> anyhow::Result<[u8; 6]> {
    crate::utils::network_utils::parse_mac_address(value)
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{LocalResult, TimeZone};

    fn local_time(year: i32, month: u32, day: u32, hour: u32) -> DateTime<Local> {
        match Local.with_ymd_and_hms(year, month, day, hour, 0, 0) {
            LocalResult::Single(value) => value,
            LocalResult::Ambiguous(value, _) => value,
            LocalResult::None => panic!("invalid local test time"),
        }
    }

    fn local_time_at(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> DateTime<Local> {
        match Local.with_ymd_and_hms(year, month, day, hour, minute, 0) {
            LocalResult::Single(value) => value,
            LocalResult::Ambiguous(value, _) => value,
            LocalResult::None => panic!("invalid local test time"),
        }
    }

    #[test]
    fn blocks_when_any_quota_is_reached() {
        let mut manager = TrafficQuotaManager::new("unused");
        let mac = [0, 1, 2, 3, 4, 5];
        let now = local_time(2026, 9, 4, 10);
        manager.set_quota(
            mac,
            TrafficQuota {
                minute_bytes: 0,
                hourly_bytes: 100,
                daily_bytes: 1_000,
                weekly_bytes: 0,
                monthly_bytes: 0,
                total_bytes: 0,
                ..Default::default()
            },
            &now,
        );
        manager.record_usage(&mac, 99, 0, &now);
        assert!(!manager.status(&mac, &now).unwrap().blocked);
        manager.record_usage(&mac, 1, 0, &now);
        let status = manager.status(&mac, &now).unwrap();
        assert!(status.blocked);
        assert_eq!(status.exceeded_periods, vec!["hourly"]);
    }

    #[test]
    fn calendar_periods_reset_but_total_does_not() {
        let mut manager = TrafficQuotaManager::new("unused");
        let mac = [0, 1, 2, 3, 4, 5];
        let before = local_time(2026, 8, 31, 23);
        let after = local_time(2026, 9, 1, 0);
        manager.set_quota(
            mac,
            TrafficQuota {
                minute_bytes: 0,
                hourly_bytes: 10,
                daily_bytes: 10,
                weekly_bytes: 0,
                monthly_bytes: 10,
                total_bytes: 20,
                ..Default::default()
            },
            &before,
        );
        manager.record_usage(&mac, 10, 0, &before);
        assert!(manager.status(&mac, &before).unwrap().blocked);

        let status = manager.status(&mac, &after).unwrap();
        assert!(!status.blocked);
        assert_eq!(status.hourly_used_bytes, 0);
        assert_eq!(status.daily_used_bytes, 0);
        // These dates are in the same ISO week, so only the week counter remains.
        assert_eq!(status.weekly_used_bytes, 10);
        assert_eq!(status.monthly_used_bytes, 0);
        assert_eq!(status.total_used_bytes, 10);

        manager.record_usage(&mac, 10, 0, &after);
        let status = manager.status(&mac, &after).unwrap();
        assert!(status.exceeded_periods.contains(&"total".to_string()));
    }

    #[test]
    fn weekly_quota_resets_on_monday() {
        let mut manager = TrafficQuotaManager::new("unused");
        let mac = [0, 1, 2, 3, 4, 5];
        let sunday = local_time(2026, 9, 6, 23);
        let monday = local_time(2026, 9, 7, 0);
        manager.set_quota(
            mac,
            TrafficQuota {
                weekly_bytes: 10,
                ..TrafficQuota::default()
            },
            &sunday,
        );
        manager.record_usage(&mac, 10, 0, &sunday);
        assert!(manager.status(&mac, &sunday).unwrap().blocked);
        let status = manager.status(&mac, &monday).unwrap();
        assert_eq!(status.weekly_used_bytes, 0);
        assert!(!status.blocked);
    }

    #[test]
    fn minute_quota_resets_on_next_minute() {
        let mut manager = TrafficQuotaManager::new("unused");
        let mac = [0, 1, 2, 3, 4, 5];
        let before = local_time_at(2026, 9, 6, 10, 4);
        let after = local_time_at(2026, 9, 6, 10, 5);
        manager.set_quota(
            mac,
            TrafficQuota {
                minute_bytes: 10,
                ..TrafficQuota::default()
            },
            &before,
        );
        manager.record_usage(&mac, 10, 0, &before);
        assert!(manager.status(&mac, &before).unwrap().blocked);

        let status = manager.status(&mac, &after).unwrap();
        assert_eq!(status.minute_used_bytes, 0);
        assert_eq!(status.hourly_used_bytes, 10);
        assert!(!status.blocked);
    }

    #[test]
    fn enforcement_remaining_uses_unlimited_sentinel() {
        let mut manager = TrafficQuotaManager::new("unused");
        let mac = [0, 1, 2, 3, 4, 5];
        let now = local_time_at(2026, 9, 6, 10, 4);
        manager.set_quota(
            mac,
            TrafficQuota {
                minute_bytes: 10,
                hourly_bytes: 100,
                ..TrafficQuota::default()
            },
            &now,
        );
        manager.record_usage(&mac, 4, 0, &now);
        assert_eq!(
            manager.enforcement_remaining(&now)[&mac].combined,
            [6, 96, u64::MAX, u64::MAX, u64::MAX, u64::MAX]
        );
    }

    #[test]
    fn old_persisted_fields_default_minute_usage_to_zero() {
        let quota: TrafficQuota =
            serde_json::from_str(r#"{"hourly_bytes":1,"daily_bytes":2,"weekly_bytes":3,"monthly_bytes":4,"total_bytes":5}"#).unwrap();
        let usage: TrafficQuotaUsage = serde_json::from_str(
            r#"{"hour_key":"h","hourly_bytes":1,"day_key":"d","daily_bytes":2,"week_key":"w","weekly_bytes":3,"month_key":"m","monthly_bytes":4,"total_bytes":5}"#,
        )
        .unwrap();
        assert_eq!(quota.mode, QuotaMode::Combined);
        assert_eq!(quota.minute_bytes, 0);
        assert_eq!(usage.minute_bytes, 0);
        assert!(usage.minute_key.is_empty());
    }

    #[test]
    fn saves_and_restores_quota_usage() {
        let dir = std::env::temp_dir().join(format!("bandix-quota-test-{}", now_millis()));
        let base = dir.to_str().unwrap();
        let mac = [0, 1, 2, 3, 4, 5];
        let now = local_time(2026, 9, 4, 10);
        let mut manager = TrafficQuotaManager::new(base);
        manager.set_quota(
            mac,
            TrafficQuota {
                total_bytes: 100,
                ..TrafficQuota::default()
            },
            &now,
        );
        manager.record_usage(&mac, 42, 0, &now);
        manager.save().unwrap();

        let mut restored = TrafficQuotaManager::new(base);
        restored.load().unwrap();
        let status = restored.status(&mac, &now).unwrap();
        assert_eq!(status.total_used_bytes, 42);
        assert_eq!(status.total_bytes, 100);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn directional_quotas_exhaust_independently_for_every_period() {
        let mac = [0, 1, 2, 3, 4, 5];
        let now = local_time(2026, 9, 4, 10);
        for field in [
            "minute_bytes",
            "hourly_bytes",
            "daily_bytes",
            "weekly_bytes",
            "monthly_bytes",
            "total_bytes",
        ] {
            let limits: TrafficQuotaLimits = serde_json::from_value(serde_json::json!({field: 10})).unwrap();
            let mut manager = TrafficQuotaManager::new("unused");
            manager.set_quota(
                mac,
                TrafficQuota {
                    mode: QuotaMode::Directional,
                    upload: limits,
                    download: limits,
                    ..Default::default()
                },
                &now,
            );
            assert!(manager.record_usage(&mac, 9, 10, &now));
            let status = manager.status(&mac, &now).unwrap();
            assert!(status.upload.blocked, "{field}");
            assert!(!status.download.blocked, "{field}");
            assert!(status.blocked);
            assert!(status.exceeded_periods.is_empty());
            assert_eq!(manager.blocked_directions(&now)[&mac], QUOTA_UPLOAD);
            assert_eq!(status.total_used_bytes, 19);
            assert_eq!(status.upload.total_used_bytes, 10);
            assert_eq!(status.download.total_used_bytes, 9);
            // The second direction exhausting must also trigger immediate persistence.
            assert!(manager.record_usage(&mac, 1, 0, &now));
            assert_eq!(manager.blocked_directions(&now)[&mac], QUOTA_UPLOAD | QUOTA_DOWNLOAD);
            let remaining = manager.enforcement_remaining(&now)[&mac];
            assert!(remaining.upload.contains(&0));
            assert!(remaining.download.contains(&0));
            assert_eq!(remaining.combined, [u64::MAX; 6]);
        }
    }

    #[test]
    fn directional_periods_reset_together_without_resetting_lifetime() {
        let mac = [0, 1, 2, 3, 4, 5];
        let cases = [
            (
                "minute_bytes",
                local_time_at(2026, 9, 6, 10, 4),
                local_time_at(2026, 9, 6, 10, 5),
            ),
            ("hourly_bytes", local_time_at(2026, 9, 6, 10, 59), local_time(2026, 9, 6, 11)),
            ("daily_bytes", local_time(2026, 9, 6, 23), local_time(2026, 9, 7, 0)),
            ("weekly_bytes", local_time(2026, 9, 6, 23), local_time(2026, 9, 7, 0)),
            ("monthly_bytes", local_time(2026, 8, 31, 23), local_time(2026, 9, 1, 0)),
        ];
        for (field, before, after) in cases {
            let limits: TrafficQuotaLimits = serde_json::from_value(serde_json::json!({field: 10})).unwrap();
            let mut manager = TrafficQuotaManager::new("unused");
            manager.set_quota(
                mac,
                TrafficQuota {
                    mode: QuotaMode::Directional,
                    upload: limits,
                    download: limits,
                    ..Default::default()
                },
                &before,
            );
            manager.record_usage(&mac, 10, 20, &before);
            assert!(manager.status(&mac, &before).unwrap().blocked);
            assert!(manager.blocked_directions(&after).is_empty(), "{field}");
            let status = manager.status(&mac, &after).unwrap();
            assert!(!status.upload.blocked);
            assert!(!status.download.blocked);
            assert_eq!(status.upload.total_used_bytes, 20);
            assert_eq!(status.download.total_used_bytes, 10);
            assert_eq!(
                manager.enforcement_remaining(&after)[&mac].upload,
                limits.remaining(TrafficQuotaLimits::default())
            );
        }
    }

    #[test]
    fn directional_usage_survives_updates_restart_and_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let mac = [0, 1, 2, 3, 4, 5];
        let now = local_time(2026, 9, 4, 10);
        let mut manager = TrafficQuotaManager::new(dir.path().to_str().unwrap());
        let mut quota = TrafficQuota {
            mode: QuotaMode::Directional,
            upload: TrafficQuotaLimits {
                total_bytes: 20,
                ..Default::default()
            },
            download: TrafficQuotaLimits {
                total_bytes: 50,
                ..Default::default()
            },
            ..Default::default()
        };
        manager.set_quota(mac, quota, &now);
        manager.record_usage(&mac, 40, 20, &now);
        manager.save().unwrap();
        let mut restored = TrafficQuotaManager::new(dir.path().to_str().unwrap());
        restored.load().unwrap();
        let status = restored.status(&mac, &now).unwrap();
        assert!(status.upload.blocked);
        assert!(!status.download.blocked);
        assert_eq!(status.download.total_used_bytes, 40);
        quota.upload.total_bytes = 30;
        restored.set_quota(mac, quota, &now);
        assert!(!restored.status(&mac, &now).unwrap().blocked);
        assert_eq!(restored.enforcement_remaining(&now)[&mac].upload[5], 10);
        assert!(restored.remove_quota(&mac));
        assert!(restored.enforcement_remaining(&now).is_empty());
        restored.set_quota(mac, quota, &now);
        assert_eq!(restored.status(&mac, &now).unwrap().upload.total_used_bytes, 0);
    }

    #[test]
    fn modes_are_exclusive_and_switches_preserve_usage() {
        let dir = tempfile::tempdir().unwrap();
        let mut manager = TrafficQuotaManager::new(dir.path().to_str().unwrap());
        let mac = [0, 1, 2, 3, 4, 5];
        let now = local_time(2026, 9, 4, 10);
        let mut quota = TrafficQuota {
            total_bytes: 100,
            upload: TrafficQuotaLimits {
                total_bytes: 20,
                ..Default::default()
            },
            download: TrafficQuotaLimits {
                total_bytes: 30,
                ..Default::default()
            },
            ..Default::default()
        };
        manager.set_quota(mac, quota, &now);
        manager.record_usage(&mac, 30, 20, &now);
        let status = manager.status(&mac, &now).unwrap();
        assert_eq!(status.mode, QuotaMode::Combined);
        assert!(!status.blocked);
        assert_eq!(status.upload.limits.total_bytes, 0);
        assert_eq!(manager.enforcement_remaining(&now)[&mac].upload, [u64::MAX; 6]);
        quota.mode = QuotaMode::Directional;
        manager.set_quota(mac, quota, &now);
        let status = manager.status(&mac, &now).unwrap();
        assert_eq!(status.total_bytes, 0);
        assert_eq!(status.total_used_bytes, 50);
        assert!(status.upload.blocked && status.download.blocked);
        assert_eq!(manager.enforcement_remaining(&now)[&mac].combined, [u64::MAX; 6]);
        manager.save().unwrap();
        let mut restored = TrafficQuotaManager::new(dir.path().to_str().unwrap());
        restored.load().unwrap();
        assert_eq!(restored.status(&mac, &now).unwrap().mode, QuotaMode::Directional);
        quota.mode = QuotaMode::Combined;
        restored.set_quota(mac, quota, &now);
        assert!(!restored.status(&mac, &now).unwrap().blocked);
        assert_eq!(restored.status(&mac, &now).unwrap().total_used_bytes, 50);
    }

    #[test]
    fn version_one_migrates_without_guessing_historical_directions() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().to_str().unwrap();
        let mac = [0, 1, 2, 3, 4, 5];
        let now = local_time(2026, 9, 4, 10);
        let mut manager = TrafficQuotaManager::new(base);
        manager.set_quota(
            mac,
            TrafficQuota {
                total_bytes: 100,
                ..Default::default()
            },
            &now,
        );
        manager.record_usage(&mac, 40, 60, &now);
        manager.save().unwrap();
        let mut old: serde_json::Value = serde_json::from_slice(&fs::read(&manager.path).unwrap()).unwrap();
        old["schema_version"] = 1.into();
        for key in ["quota", "usage"] {
            let fields = old["entries"][0][key].as_object_mut().unwrap();
            fields.remove("upload");
            fields.remove("download");
        }
        fs::write(&manager.path, serde_json::to_vec(&old).unwrap()).unwrap();
        let mut restored = TrafficQuotaManager::new(base);
        restored.load().unwrap();
        let status = restored.status(&mac, &now).unwrap();
        assert_eq!(status.total_used_bytes, 100);
        assert_eq!(status.upload.total_used_bytes, 0);
        assert_eq!(status.download.total_used_bytes, 0);
        assert!(status.upload.blocked && status.download.blocked);
        restored.save().unwrap();
        let saved: serde_json::Value = serde_json::from_slice(&fs::read(&restored.path).unwrap()).unwrap();
        assert_eq!(saved["schema_version"], 2);
    }
}
