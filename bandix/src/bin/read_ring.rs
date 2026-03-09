use std::env;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const RING_MAGIC: [u8; 4] = *b"BXR1";
const RING_VERSION: u32 = 5;
const RING_VERSION_V4: u32 = 4;
const HEADER_SIZE: usize = 4 + 4 + 4;
const HEADER_SIZE_V5: usize = 4 + 4 + 4 + 4;
const SLOT_U64S_LONG_TERM: usize = 32;
const SLOT_SIZE_LONG_TERM: usize = SLOT_U64S_LONG_TERM * 8;

fn read_header(f: &mut File) -> Result<(u32, u32), Box<dyn std::error::Error>> {
    let mut magic = [0u8; 4];
    f.seek(SeekFrom::Start(0))?;
    f.read_exact(&mut magic)?;
    if magic != RING_MAGIC {
        return Err("invalid ring file magic".into());
    }
    let mut buf4 = [0u8; 4];
    f.read_exact(&mut buf4)?;
    let ver = u32::from_le_bytes(buf4);
    f.read_exact(&mut buf4)?;
    let cap = u32::from_le_bytes(buf4);
    Ok((ver, cap))
}

fn read_header_v5(f: &mut File) -> Result<(u32, u32, u32), Box<dyn std::error::Error>> {
    let mut magic = [0u8; 4];
    f.seek(SeekFrom::Start(0))?;
    f.read_exact(&mut magic)?;
    if magic != RING_MAGIC {
        return Err("invalid ring file magic".into());
    }
    let mut buf4 = [0u8; 4];
    f.read_exact(&mut buf4)?;
    let ver = u32::from_le_bytes(buf4);
    f.read_exact(&mut buf4)?;
    let cap = u32::from_le_bytes(buf4);
    f.read_exact(&mut buf4)?;
    let entry_count = u32::from_le_bytes(buf4);
    Ok((ver, cap, entry_count))
}

fn read_slot_bytes(f: &mut File, bytes: &mut [u8]) -> Result<[u64; SLOT_U64S_LONG_TERM], Box<dyn std::error::Error>> {
    f.read_exact(bytes)?;
    let mut out = [0u64; SLOT_U64S_LONG_TERM];
    for i in 0..SLOT_U64S_LONG_TERM {
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        out[i] = u64::from_le_bytes(b);
    }
    Ok(out)
}

fn format_ts(ms: u64) -> String {
    if ms == 0 {
        return "-".to_string();
    }
    let secs = (ms / 1000) as i64;
    let datetime = chrono::DateTime::from_timestamp(secs, ((ms % 1000) * 1_000_000) as u32);
    datetime
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| ms.to_string())
}

fn format_ip(ip_u64: u64) -> String {
    if ip_u64 == 0 {
        return "-".to_string();
    }
    let ip_u32 = ip_u64 as u32;
    format!(
        "{}.{}.{}.{}",
        (ip_u32 >> 24) & 0xff,
        (ip_u32 >> 16) & 0xff,
        (ip_u32 >> 8) & 0xff,
        ip_u32 & 0xff
    )
}

fn parse_v5(path: &Path, limit: usize) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::open(path)?;
    let (ver, cap, entry_count) = read_header_v5(&mut f)?;
    println!("Ring file: {} (version={}, capacity={}, entries={})", path.display(), ver, cap, entry_count);

    let to_read = (entry_count as usize).min(limit);
    let mut slot_buf = vec![0u8; SLOT_SIZE_LONG_TERM];

    f.seek(SeekFrom::Start(HEADER_SIZE_V5 as u64))?;
    for i in 0..to_read {
        let mut idx_buf = [0u8; 8];
        f.read_exact(&mut idx_buf)?;
        let idx = u64::from_le_bytes(idx_buf);
        let slot = read_slot_bytes(&mut f, &mut slot_buf)?;

        if slot[0] == 0 {
            continue;
        }

        let start_ts = slot[0];
        let end_ts = slot[1];
        let wan_rx_inc = slot[14];
        let wan_tx_inc = slot[15];
        let lan_rx_inc = slot[28];
        let lan_tx_inc = slot[29];
        let last_online = slot[30];
        let ip = slot[31];

        println!(
            "  [{}] idx={} start={} end={} wan_rx_inc={} wan_tx_inc={} lan_rx_inc={} lan_tx_inc={} last_online={} ip={}",
            i + 1,
            idx,
            format_ts(start_ts),
            format_ts(end_ts),
            wan_rx_inc,
            wan_tx_inc,
            lan_rx_inc,
            lan_tx_inc,
            format_ts(last_online),
            format_ip(ip)
        );
    }
    if entry_count as usize > limit {
        println!("  ... ({} more entries omitted)", entry_count as usize - limit);
    }
    Ok(())
}

fn parse_v4(path: &Path, capacity: u32, limit: usize) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::open(path)?;
    let metadata = f.metadata()?;
    let file_size = metadata.len();

    println!("Ring file: {} (version=4, capacity={})", path.display(), capacity);

    let mut slot_buf = vec![0u8; SLOT_SIZE_LONG_TERM];
    let mut count = 0;

    for idx in 0..capacity as u64 {
        if count >= limit {
            break;
        }
        let offset = HEADER_SIZE as u64 + idx * SLOT_SIZE_LONG_TERM as u64;
        if offset + SLOT_SIZE_LONG_TERM as u64 > file_size {
            break;
        }

        f.seek(SeekFrom::Start(offset))?;
        let slot = read_slot_bytes(&mut f, &mut slot_buf)?;

        if slot[0] == 0 {
            continue;
        }

        count += 1;
        let start_ts = slot[0];
        let end_ts = slot[1];
        let wan_rx_inc = slot[14];
        let wan_tx_inc = slot[15];
        let lan_rx_inc = slot[28];
        let lan_tx_inc = slot[29];
        let last_online = slot[30];
        let ip = slot[31];

        println!(
            "  [{}] idx={} start={} end={} wan_rx_inc={} wan_tx_inc={} lan_rx_inc={} lan_tx_inc={} last_online={} ip={}",
            count,
            idx,
            format_ts(start_ts),
            format_ts(end_ts),
            wan_rx_inc,
            wan_tx_inc,
            lan_rx_inc,
            lan_tx_inc,
            format_ts(last_online),
            format_ip(ip)
        );
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let limit = 3600;

    if args.len() < 2 {
        eprintln!("Usage: read_ring <path_to.ring>");
        eprintln!("Parse bandix ring file and print first {} entries", limit);
        std::process::exit(1);
    }

    let path = Path::new(&args[1]);
    if !path.exists() {
        return Err(format!("file not found: {}", path.display()).into());
    }

    let mut f = File::open(path)?;
    let (ver, cap) = read_header(&mut f)?;

    if ver == RING_VERSION {
        parse_v5(path, limit)?;
    } else if ver == RING_VERSION_V4 {
        parse_v4(path, cap, limit)?;
    } else {
        return Err(format!("unsupported ring version: {}", ver).into());
    }

    Ok(())
}
