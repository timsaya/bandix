use anyhow::Context;
use rusqlite::{params, Connection};

use crate::utils::format_utils::format_mac;
use bandix_common::MacTrafficStats;

// Local helpers to parse/format MAC when interacting with DB
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

fn format_mac_text(mac: &[u8; 6]) -> String {
    format_mac(mac)
}

pub fn ensure_schema(db_path: &str) -> Result<(), anyhow::Error> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open SQLite DB at {}", db_path))?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS rate_limits (
            mac TEXT PRIMARY KEY,
            wide_rx_rate_limit INTEGER NOT NULL,
            wide_tx_rate_limit INTEGER NOT NULL
        )",
        [],
    )
    .context("Failed to create table rate_limits")?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS metrics (
            ts_ms INTEGER NOT NULL,
            mac TEXT NOT NULL,
            total_rx_rate INTEGER NOT NULL,
            total_tx_rate INTEGER NOT NULL,
            local_rx_rate INTEGER NOT NULL,
            local_tx_rate INTEGER NOT NULL,
            wide_rx_rate INTEGER NOT NULL,
            wide_tx_rate INTEGER NOT NULL,
            total_rx_bytes INTEGER NOT NULL,
            total_tx_bytes INTEGER NOT NULL,
            local_rx_bytes INTEGER NOT NULL,
            local_tx_bytes INTEGER NOT NULL,
            wide_rx_bytes INTEGER NOT NULL,
            wide_tx_bytes INTEGER NOT NULL,
            PRIMARY KEY (ts_ms, mac)
        )",
        [],
    )
    .context("Failed to create table metrics")?;

    Ok(())
}

pub fn load_all_limits(
    db_path: &str,
) -> Result<Vec<([u8; 6], u64, u64)>, anyhow::Error> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open SQLite DB at {}", db_path))?;

    let mut stmt = conn
        .prepare(
            "SELECT mac, wide_rx_rate_limit, wide_tx_rate_limit FROM rate_limits",
        )
        .context("Failed to prepare load_all_limits query")?;

    let rows = stmt
        .query_map([], |row| {
            let mac_str: String = row.get(0)?;
            let rx: i64 = row.get(1)?;
            let tx: i64 = row.get(2)?;
            Ok((mac_str, rx as u64, tx as u64))
        })
        .context("Failed to execute load_all_limits query")?;

    let mut out = Vec::new();
    for r in rows {
        let (mac_text, rx, tx) = r?;
        let mac = parse_mac_text(&mac_text)
            .with_context(|| format!("Invalid MAC stored in DB: {}", mac_text))?;
        out.push((mac, rx, tx));
    }
    Ok(out)
}

pub fn upsert_limit(
    db_path: &str,
    mac: &[u8; 6],
    wide_rx_rate_limit: u64,
    wide_tx_rate_limit: u64,
) -> Result<(), anyhow::Error> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open SQLite DB at {}", db_path))?;

    let mac_text = format_mac_text(mac);
    conn.execute(
        "INSERT INTO rate_limits (mac, wide_rx_rate_limit, wide_tx_rate_limit)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(mac) DO UPDATE SET
            wide_rx_rate_limit = excluded.wide_rx_rate_limit,
            wide_tx_rate_limit = excluded.wide_tx_rate_limit",
        params![mac_text, wide_rx_rate_limit as i64, wide_tx_rate_limit as i64],
    )
    .context("Failed to upsert rate limit")?;

    Ok(())
}

pub fn insert_metrics_batch(
    db_path: &str,
    ts_ms: u64,
    rows: &Vec<([u8; 6], MacTrafficStats)>,
) -> Result<(), anyhow::Error> {
    if rows.is_empty() {
        return Ok(());
    }

    let mut conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open SQLite DB at {}", db_path))?;
    let tx = conn.transaction().context("Failed to begin transaction")?;

    {
        let mut stmt = tx
            .prepare(
                "INSERT INTO metrics (
                    ts_ms, mac,
                    total_rx_rate, total_tx_rate,
                    local_rx_rate, local_tx_rate,
                    wide_rx_rate, wide_tx_rate,
                    total_rx_bytes, total_tx_bytes,
                    local_rx_bytes, local_tx_bytes,
                    wide_rx_bytes, wide_tx_bytes
                ) VALUES (
                    ?1, ?2,
                    ?3, ?4,
                    ?5, ?6,
                    ?7, ?8,
                    ?9, ?10,
                    ?11, ?12,
                    ?13, ?14
                ) ON CONFLICT(ts_ms, mac) DO UPDATE SET
                    total_rx_rate=excluded.total_rx_rate,
                    total_tx_rate=excluded.total_tx_rate,
                    local_rx_rate=excluded.local_rx_rate,
                    local_tx_rate=excluded.local_tx_rate,
                    wide_rx_rate=excluded.wide_rx_rate,
                    wide_tx_rate=excluded.wide_tx_rate,
                    total_rx_bytes=excluded.total_rx_bytes,
                    total_tx_bytes=excluded.total_tx_bytes,
                    local_rx_bytes=excluded.local_rx_bytes,
                    local_tx_bytes=excluded.local_tx_bytes,
                    wide_rx_bytes=excluded.wide_rx_bytes,
                    wide_tx_bytes=excluded.wide_tx_bytes",
            )
            .context("Failed to prepare insert_metrics_batch statement")?;

        for (mac, s) in rows.iter() {
            let mac_text = format_mac_text(mac);
            stmt.execute(params![
                ts_ms as i64,
                mac_text,
                s.total_rx_rate as i64,
                s.total_tx_rate as i64,
                s.local_rx_rate as i64,
                s.local_tx_rate as i64,
                s.wide_rx_rate as i64,
                s.wide_tx_rate as i64,
                s.total_rx_bytes as i64,
                s.total_tx_bytes as i64,
                s.local_rx_bytes as i64,
                s.local_tx_bytes as i64,
                s.wide_rx_bytes as i64,
                s.wide_tx_bytes as i64,
            ])
            .context("Failed to insert metrics row")?;
        }
    }

    tx.commit().context("Failed to commit metrics batch")?;
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
    db_path: &str,
    mac: &[u8; 6],
    start_ms: u64,
    end_ms: u64,
    limit: Option<usize>,
) -> Result<Vec<MetricsRow>, anyhow::Error> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open SQLite DB at {}", db_path))?;
    let mac_text = format_mac_text(mac);

    let sql_base = "SELECT ts_ms,
        total_rx_rate, total_tx_rate,
        local_rx_rate, local_tx_rate,
        wide_rx_rate, wide_tx_rate,
        total_rx_bytes, total_tx_bytes,
        local_rx_bytes, local_tx_bytes,
        wide_rx_bytes, wide_tx_bytes
        FROM metrics
        WHERE mac = ?1 AND ts_ms BETWEEN ?2 AND ?3
        ORDER BY ts_ms ASC";

    let mut rows_vec = Vec::new();

    if let Some(max_rows) = limit {
        let mut stmt = conn
            .prepare(&format!("{} LIMIT {}", sql_base, max_rows))
            .context("Failed to prepare limited query")?;
        let rows = stmt.query_map(params![mac_text, start_ms as i64, end_ms as i64], |row| {
            Ok(MetricsRow {
                ts_ms: row.get::<_, i64>(0)? as u64,
                total_rx_rate: row.get::<_, i64>(1)? as u64,
                total_tx_rate: row.get::<_, i64>(2)? as u64,
                local_rx_rate: row.get::<_, i64>(3)? as u64,
                local_tx_rate: row.get::<_, i64>(4)? as u64,
                wide_rx_rate: row.get::<_, i64>(5)? as u64,
                wide_tx_rate: row.get::<_, i64>(6)? as u64,
                total_rx_bytes: row.get::<_, i64>(7)? as u64,
                total_tx_bytes: row.get::<_, i64>(8)? as u64,
                local_rx_bytes: row.get::<_, i64>(9)? as u64,
                local_tx_bytes: row.get::<_, i64>(10)? as u64,
                wide_rx_bytes: row.get::<_, i64>(11)? as u64,
                wide_tx_bytes: row.get::<_, i64>(12)? as u64,
            })
        })?;

        for r in rows { rows_vec.push(r?); }
    } else {
        let mut stmt = conn
            .prepare(sql_base)
            .context("Failed to prepare query")?;
        let rows = stmt.query_map(params![mac_text, start_ms as i64, end_ms as i64], |row| {
            Ok(MetricsRow {
                ts_ms: row.get::<_, i64>(0)? as u64,
                total_rx_rate: row.get::<_, i64>(1)? as u64,
                total_tx_rate: row.get::<_, i64>(2)? as u64,
                local_rx_rate: row.get::<_, i64>(3)? as u64,
                local_tx_rate: row.get::<_, i64>(4)? as u64,
                wide_rx_rate: row.get::<_, i64>(5)? as u64,
                wide_tx_rate: row.get::<_, i64>(6)? as u64,
                total_rx_bytes: row.get::<_, i64>(7)? as u64,
                total_tx_bytes: row.get::<_, i64>(8)? as u64,
                local_rx_bytes: row.get::<_, i64>(9)? as u64,
                local_tx_bytes: row.get::<_, i64>(10)? as u64,
                wide_rx_bytes: row.get::<_, i64>(11)? as u64,
                wide_tx_bytes: row.get::<_, i64>(12)? as u64,
            })
        })?;

        for r in rows { rows_vec.push(r?); }
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

// Load latest totals per MAC as baseline from SQLite
pub fn load_latest_totals(
    db_path: &str,
) -> Result<Vec<([u8; 6], BaselineTotals)>, anyhow::Error> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open SQLite DB at {}", db_path))?;

    let sql = r#"
        SELECT m.mac,
               m.total_rx_bytes, m.total_tx_bytes,
               m.local_rx_bytes, m.local_tx_bytes,
               m.wide_rx_bytes,  m.wide_tx_bytes
        FROM metrics m
        INNER JOIN (
            SELECT mac AS mac_key, MAX(ts_ms) AS max_ts
            FROM metrics
            GROUP BY mac
        ) t ON m.mac = t.mac_key AND m.ts_ms = t.max_ts
    "#;

    let mut stmt = conn
        .prepare(sql)
        .context("Failed to prepare load_latest_totals query")?;

    let rows = stmt.query_map([], |row| {
        let mac_text: String = row.get(0)?;
        let total_rx_bytes: i64 = row.get(1)?;
        let total_tx_bytes: i64 = row.get(2)?;
        let local_rx_bytes: i64 = row.get(3)?;
        let local_tx_bytes: i64 = row.get(4)?;
        let wide_rx_bytes: i64 = row.get(5)?;
        let wide_tx_bytes: i64 = row.get(6)?;

        Ok((
            mac_text,
            BaselineTotals {
                total_rx_bytes: total_rx_bytes as u64,
                total_tx_bytes: total_tx_bytes as u64,
                local_rx_bytes: local_rx_bytes as u64,
                local_tx_bytes: local_tx_bytes as u64,
                wide_rx_bytes: wide_rx_bytes as u64,
                wide_tx_bytes: wide_tx_bytes as u64,
            },
        ))
    })?;

    let mut out = Vec::new();
    for r in rows {
        let (mac_text, baseline) = r?;
        let mac = parse_mac_text(&mac_text)
            .with_context(|| format!("Invalid MAC stored in DB: {}", mac_text))?;
        out.push((mac, baseline));
    }

    Ok(out)
}


