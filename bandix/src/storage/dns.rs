use crate::monitor::DnsQueryRecord;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

const DNS_STORAGE_DIR: &str = "dns";
const DNS_QUERIES_FILE: &str = "queries.jsonl";

fn format_timestamp_ns(unix_ns: u64) -> String {
    use chrono::Local;
    
    let secs = (unix_ns / 1_000_000_000) as i64;
    let nanos = (unix_ns % 1_000_000_000) as u32;
    
    if let Some(datetime) = chrono::DateTime::from_timestamp(secs, nanos) {
        let local_time: chrono::DateTime<Local> = datetime.into();
        local_time.format("%Y-%m-%d %H:%M:%S%.3f").to_string()
    } else {
        "Invalid timestamp".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DnsQueryRecordStorage {
    pub timestamp: u64,
    pub timestamp_formatted: String,
    pub domain: String,
    pub query_type: String,
    pub response_code: String,
    pub source_ip: String,
    pub destination_ip: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub transaction_id: u16,
    pub is_query: bool,
    pub response_ips: Vec<String>,
    pub response_records: Vec<String>,
    pub response_time_ms: Option<u64>,
    pub device_mac: String,
    pub device_name: String,
}

impl From<&DnsQueryRecord> for DnsQueryRecordStorage {
    fn from(record: &DnsQueryRecord) -> Self {
        let unix_ns = crate::utils::time_utils::monotonic_to_unix_ns(record.timestamp);
        let timestamp_formatted = format_timestamp_ns(unix_ns);
        
        Self {
            timestamp: unix_ns,
            timestamp_formatted,
            domain: record.domain.clone(),
            query_type: record.query_type.clone(),
            response_code: record.response_code.clone(),
            source_ip: record.source_ip.clone(),
            destination_ip: record.destination_ip.clone(),
            source_port: record.source_port,
            destination_port: record.destination_port,
            transaction_id: record.transaction_id,
            is_query: record.is_query,
            response_ips: record.response_ips.clone(),
            response_records: record.response_records.clone(),
            response_time_ms: record.response_time_ms,
            device_mac: record.device_mac.clone(),
            device_name: record.device_name.clone(),
        }
    }
}

impl From<DnsQueryRecordStorage> for DnsQueryRecord {
    fn from(storage: DnsQueryRecordStorage) -> Self {
        Self {
            timestamp: crate::utils::time_utils::unix_to_monotonic_ns(storage.timestamp),
            domain: storage.domain,
            query_type: storage.query_type,
            response_code: storage.response_code,
            source_ip: storage.source_ip,
            destination_ip: storage.destination_ip,
            source_port: storage.source_port,
            destination_port: storage.destination_port,
            transaction_id: storage.transaction_id,
            is_query: storage.is_query,
            response_ips: storage.response_ips,
            response_records: storage.response_records,
            response_time_ms: storage.response_time_ms,
            device_mac: storage.device_mac,
            device_name: storage.device_name,
        }
    }
}

fn get_dns_storage_dir(base_dir: &str) -> PathBuf {
    Path::new(base_dir).join(DNS_STORAGE_DIR)
}

fn get_dns_queries_file(base_dir: &str) -> PathBuf {
    get_dns_storage_dir(base_dir).join(DNS_QUERIES_FILE)
}

fn ensure_dns_storage_dir(base_dir: &str) -> Result<()> {
    let dir = get_dns_storage_dir(base_dir);
    if !dir.exists() {
        fs::create_dir_all(&dir).with_context(|| format!("Failed to create DNS storage directory: {}", dir.display()))?;
    }
    Ok(())
}

pub fn ensure_dns_schema(base_dir: &str) -> Result<()> {
    ensure_dns_storage_dir(base_dir)?;
    log::debug!("DNS storage schema initialized at {}/dns/", base_dir);
    Ok(())
}

pub fn load_dns_queries(base_dir: &str, max_records: usize) -> Result<Vec<DnsQueryRecord>> {
    let file_path = get_dns_queries_file(base_dir);

    if !file_path.exists() {
        log::debug!("DNS queries file does not exist: {}", file_path.display());
        return Ok(Vec::new());
    }

    let file = File::open(&file_path).with_context(|| format!("Failed to open DNS queries file: {}", file_path.display()))?;

    let reader = BufReader::new(file);
    let mut records = Vec::new();

    for (line_no, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                log::warn!("Failed to read line {} from DNS queries file: {}", line_no + 1, e);
                continue;
            }
        };

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match serde_json::from_str::<DnsQueryRecordStorage>(&line) {
            Ok(storage_record) => {
                records.push(storage_record.into());
            }
            Err(e) => {
                log::warn!("Failed to parse DNS record at line {}: {}", line_no + 1, e);
                continue;
            }
        }
    }

    if records.len() > max_records {
        let skip = records.len() - max_records;
        records = records.into_iter().skip(skip).collect();
        log::info!("Loaded {} DNS records (skipped {} old records)", records.len(), skip);
    } else {
        log::info!("Loaded {} DNS records from storage", records.len());
    }

    Ok(records)
}

pub fn save_dns_queries(base_dir: &str, records: &[DnsQueryRecord], max_records: usize) -> Result<()> {
    ensure_dns_storage_dir(base_dir)?;

    let file_path = get_dns_queries_file(base_dir);
    let temp_file_path = file_path.with_extension("jsonl.tmp");

    let records_to_save = if records.len() > max_records {
        let skip = records.len() - max_records;
        &records[skip..]
    } else {
        records
    };

    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_file_path)
            .with_context(|| format!("Failed to create temp DNS queries file: {}", temp_file_path.display()))?;

        for record in records_to_save {
            let storage_record: DnsQueryRecordStorage = record.into();
            let json = serde_json::to_string(&storage_record).with_context(|| "Failed to serialize DNS record")?;

            writeln!(file, "{}", json).with_context(|| "Failed to write DNS record to file")?;
        }

        file.flush().with_context(|| "Failed to flush DNS queries file")?;
    }

    fs::rename(&temp_file_path, &file_path).with_context(|| format!("Failed to rename temp file to {}", file_path.display()))?;

    log::debug!("Saved {} DNS records to storage", records_to_save.len());

    Ok(())
}
