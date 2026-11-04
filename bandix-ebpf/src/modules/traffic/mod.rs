// 流量监控 module
// Integrates throttle and traffic monitoring functionality

pub mod maps;

use aya_ebpf::{
    bindings::{TC_ACT_SHOT, TC_ACT_UNSPEC},
    programs::TcContext,
};
use bandix_common::attribution::{accounting_mac, address_key, arp_target_on_subnet, decode_mac, encode_mac, mac_key, ndp_target_is_unicast, MODE_KEY, UNKNOWN};
use bandix_common::quota::{QUOTA_DOWNLOAD, QUOTA_UPLOAD};
use core::intrinsics::{atomic_xadd, AtomicOrdering};
use network_types::eth::EthHdr;
use network_types::ip::{Ipv4Hdr, Ipv6Hdr};

use crate::utils::{get_current_time, is_subnet_ip, is_subnet_ipv6, min, ptr_at, subnet::IPV4_SUBNET_INFO};
use maps::{MAC_QUOTA_BLOCKED, MAC_QUOTA_THRESHOLDS, MAC_RATE_LIMITS, MAC_TRAFFIC, RATE_BUCKETS};

// ============================================================================
// Public Entry Points
// ============================================================================

#[inline(always)]
pub fn handle_traffic_ingress(ctx: &TcContext) -> Result<i32, ()> {
    let ethhdr: *const EthHdr = ptr_at(ctx, 0)?;
    let ethhdr_type = unsafe { (*ethhdr).ether_type };

    match ethhdr_type {
        network_types::eth::EtherType::Ipv4 => handle_ipv4(ctx, true),
        network_types::eth::EtherType::Ipv6 => handle_ipv6(ctx, true),
        _ => Ok(TC_ACT_UNSPEC),
    }
}

#[inline(always)]
pub fn handle_traffic_egress(ctx: &TcContext) -> Result<i32, ()> {
    let ethhdr: *const EthHdr = ptr_at(ctx, 0)?;
    let ethhdr_type = unsafe { (*ethhdr).ether_type };

    match ethhdr_type {
        network_types::eth::EtherType::Ipv4 => handle_ipv4(ctx, false),
        network_types::eth::EtherType::Ipv6 => handle_ipv6(ctx, false),
        _ => Ok(TC_ACT_UNSPEC),
    }
}

// ============================================================================
// IPv4 Handler
// ============================================================================

#[inline(always)]
fn handle_ipv4(ctx: &TcContext, is_ingress: bool) -> Result<i32, ()> {
    let ethhdr: *const EthHdr = ptr_at(ctx, 0)?;
    let src_mac = unsafe { (*ethhdr).src_addr };
    let dst_mac = unsafe { (*ethhdr).dst_addr };

    // get ipv4 header
    let ipv4hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let data_len = unsafe { u16::from_be_bytes((*ipv4hdr).tot_len) } as u64;

    // IP 地址
    let src_ip = unsafe { (*ipv4hdr).src_addr };
    let dst_ip = unsafe { (*ipv4hdr).dst_addr };

    // Check subnet configuration
    if !is_subnet_configured() {
        return Ok(TC_ACT_UNSPEC);
    }

    // 检查是否addresses are in local subnet
    let src_is_local = is_subnet_ip(&src_ip);
    let dst_is_local = is_subnet_ip(&dst_ip);

    if is_ingress {
        queue_ipv4_resolution(&src_ip);
    }

    // Rate limiting logic
    if is_ingress {
        // Ingress: throttle upload traffic (local -> external)
        if src_is_local && !dst_is_local {
            if should_block_quota(&src_mac, false) {
                return Ok(TC_ACT_SHOT);
            }
            let limits = get_rate_limits(&src_mac);
            if limits.1 > 0 {
                // Check upload limit
                if should_throttle(&src_mac, data_len, limits, false) {
                    return Ok(TC_ACT_SHOT);
                }
            }
        }
    } else {
        // Egress: throttle download traffic (external -> local)
        if dst_is_local && !src_is_local {
            if should_block_quota(&dst_mac, true) {
                return Ok(TC_ACT_SHOT);
            }
            let limits = get_rate_limits(&dst_mac);
            if limits.0 > 0 {
                // Check download limit
                if should_throttle(&dst_mac, data_len, limits, true) {
                    return Ok(TC_ACT_SHOT);
                }
            }
        }
    }

    // Monitor traffic stats
    if src_is_local {
        count_endpoint(&src_mac, &src_ip, data_len, false, dst_is_local);
    }
    if dst_is_local {
        count_endpoint(&dst_mac, &dst_ip, data_len, true, src_is_local);
    }

    Ok(TC_ACT_UNSPEC)
}

#[inline(always)]
fn is_subnet_configured() -> bool {
    // Check if at least one subnet is configured
    for i in 0..16 {
        if let Some(subnet_data) = IPV4_SUBNET_INFO.get(i as u32) {
            let enabled = subnet_data[8];
            if enabled != 0 {
                return true;
            }
        }
    }
    false
}

// ============================================================================
// IPv6 Handler
// ============================================================================

#[inline(always)]
fn handle_ipv6(ctx: &TcContext, is_ingress: bool) -> Result<i32, ()> {
    let ethhdr: *const EthHdr = ptr_at(ctx, 0)?;
    let src_mac = unsafe { (*ethhdr).src_addr };
    let dst_mac = unsafe { (*ethhdr).dst_addr };

    // get ipv6 header
    let ipv6hdr: *const Ipv6Hdr = ptr_at(ctx, EthHdr::LEN)?;
    // IPv6 payload_len + IPv6 header size (40 bytes)
    let payload_len = unsafe { u16::from_be_bytes((*ipv6hdr).payload_len) } as u64;
    let data_len = payload_len + 40;

    // 获取IPv6 addresses (src_addr and dst_addr are already [u8; 16])
    let src_ip = unsafe { (*ipv6hdr).src_addr };
    let dst_ip = unsafe { (*ipv6hdr).dst_addr };

    // 检查是否addresses are in local subnet
    let src_is_local = is_subnet_ipv6(&src_ip);
    let dst_is_local = is_subnet_ipv6(&dst_ip);

    if is_ingress && src_is_local && ndp_target_is_unicast(&src_ip) {
        queue_neighbor_resolution(&src_ip);
    }

    // Rate limiting logic
    if is_ingress {
        // Ingress: throttle upload traffic (local -> external)
        if src_is_local && !dst_is_local {
            if should_block_quota(&src_mac, false) {
                return Ok(TC_ACT_SHOT);
            }
            let limits = get_rate_limits(&src_mac);
            if limits.1 > 0 {
                // Check upload limit
                if should_throttle(&src_mac, data_len, limits, false) {
                    return Ok(TC_ACT_SHOT);
                }
            }
        }
    } else {
        // Egress: throttle download traffic (external -> local)
        if dst_is_local && !src_is_local {
            if should_block_quota(&dst_mac, true) {
                return Ok(TC_ACT_SHOT);
            }
            let limits = get_rate_limits(&dst_mac);
            if limits.0 > 0 {
                // Check download limit
                if should_throttle(&dst_mac, data_len, limits, true) {
                    return Ok(TC_ACT_SHOT);
                }
            }
        }
    }

    // Monitor traffic stats
    if src_is_local {
        count_endpoint(&src_mac, &src_ip, data_len, false, dst_is_local);
    }
    if dst_is_local {
        count_endpoint(&dst_mac, &dst_ip, data_len, true, src_is_local);
    }

    Ok(TC_ACT_UNSPEC)
}

// ============================================================================
// Traffic Monitoring
// ============================================================================

#[inline]
fn update_traffic_stats(mac: &[u8; 6], data_len: u64, is_rx: bool, is_local: bool) {
    let traffic = MAC_TRAFFIC.get_ptr_mut(mac);

    match traffic {
        Some(t) => unsafe {
            if is_local {
                if is_rx {
                    // lan  receive bytes
                    atomic_add_u64(&mut (*t)[1], data_len);
                } else {
                    // lan  send bytes
                    atomic_add_u64(&mut (*t)[0], data_len);
                }
            } else {
                if is_rx {
                    // wan  receive bytes
                    atomic_add_u64(&mut (*t)[3], data_len);
                } else {
                    // wan  send bytes
                    atomic_add_u64(&mut (*t)[2], data_len);
                }
            }
        },
        None => {
            let mut stats = [0u64; 4];
            if is_local {
                if is_rx {
                    stats[1] = data_len; // lan  receive bytes
                } else {
                    stats[0] = data_len; // lan  send bytes
                }
            } else {
                if is_rx {
                    stats[3] = data_len; // wan  receive bytes
                } else {
                    stats[2] = data_len; // wan  send bytes
                }
            }
            let _ = MAC_TRAFFIC.insert(mac, &stats, 0);
        }
    }
}

#[inline(always)]
unsafe fn atomic_add_u64(value: *mut u64, amount: u64) {
    atomic_xadd::<u64, u64, { AtomicOrdering::Relaxed }>(value, amount);
}

#[inline(always)]
unsafe fn atomic_load_u64(value: *const u64) -> u64 {
    core::ptr::read_volatile(value)
}

#[inline(always)]
fn count_endpoint<const N: usize>(mac: &[u8; 6], ip: &[u8; N], bytes: u64, rx: bool, local: bool) {
    let lookup = |key: &[u8; 17]| unsafe { maps::TRAFFIC_OWNERS.get(key).copied().unwrap_or(UNKNOWN) };
    let mode = lookup(&MODE_KEY);
    if mode == UNKNOWN {
        update_traffic_stats(mac, bytes, rx, local);
        return;
    }
    let owner = accounting_mac(encode_mac(mac), lookup(&address_key(ip)), lookup(&mac_key(mac)), mode != 0);
    if owner != 0 {
        update_traffic_stats(&decode_mac(owner), bytes, rx, local);
    }
}

#[inline(always)]
fn queue_ipv4_resolution(ip: &[u8; 4]) {
    let Some(config) = maps::NEIGHBOR_RESOLVE_CONFIG.get(0) else { return };
    if config[8] == 0 {
        return;
    }
    let local = [config[0], config[1], config[2], config[3]];
    let mask = [config[4], config[5], config[6], config[7]];
    if !arp_target_on_subnet(ip, &local, &mask) {
        return;
    }
    queue_neighbor_resolution(ip);
}

#[inline(always)]
fn queue_neighbor_resolution<const N: usize>(ip: &[u8; N]) {
    let Some(config) = maps::NEIGHBOR_RESOLVE_CONFIG.get(0) else { return };
    if config[8] == 0 {
        return;
    }
    let key = address_key(ip);
    if unsafe { maps::TRAFFIC_OWNERS.get(&key) }.is_some()
        || unsafe { maps::NEIGHBOR_RESOLVE_PENDING.get(&key) }.is_some()
    {
        return;
    }
    // BPF_NOEXIST deduplicates concurrent observations of the same source.
    let _ = maps::NEIGHBOR_RESOLVE_PENDING.insert(&key, &1, 1);
}

// ============================================================================
// Rate Limiting (Throttle)
// ============================================================================

#[inline]
fn should_throttle(mac: &[u8; 6], data_len: u64, limits: (u64, u64), is_rx: bool) -> bool {
    let (limit_rx, limit_tx) = limits;
    let limit = if is_rx { limit_rx } else { limit_tx };

    if limit == 0 {
        return false; // No limit
    }

    let bucket = RATE_BUCKETS.get_ptr_mut(mac);
    match bucket {
        Some(b) => unsafe {
            let now = get_current_time();
            let elapsed = now.saturating_sub((*b)[2]); // Prevent time wrap-around

            // 计算tokens to add for RX
            if limit_rx > 0 {
                let rx_tokens_to_add = (elapsed * limit_rx) / 1_000_000_000;
                (*b)[0] = min((*b)[0].saturating_add(rx_tokens_to_add), limit_rx);
            }

            // 计算tokens to add for TX
            if limit_tx > 0 {
                let tx_tokens_to_add = (elapsed * limit_tx) / 1_000_000_000;
                (*b)[1] = min((*b)[1].saturating_add(tx_tokens_to_add), limit_tx);
            }

            // 检查是否enough tokens available for current direction
            let idx = if is_rx { 0 } else { 1 };
            if (*b)[idx] < data_len {
                // Not enough tokens, need to throttle
                (*b)[2] = now; // 更新timestamp
                return true;
            }

            // Enough tokens, consume tokens and allow
            (*b)[idx] = (*b)[idx].saturating_sub(data_len);
            (*b)[2] = now; // 更新timestamp
            false
        },
        None => {
            // First time seeing this MAC, initialize token bucket
            let now = get_current_time();
            // 开始with full buckets for both directions
            let mut bucket_state = [limit_rx, limit_tx, now];

            // Consume tokens for current direction
            let idx = if is_rx { 0 } else { 1 };
            if bucket_state[idx] < data_len {
                // Initial tokens insufficient, need to throttle
                let _ = RATE_BUCKETS.insert(mac, &bucket_state, 0);
                return true;
            }

            bucket_state[idx] = bucket_state[idx].saturating_sub(data_len);
            let _ = RATE_BUCKETS.insert(mac, &bucket_state, 0);
            false
        }
    }
}

#[inline]
fn get_rate_limits(mac: &[u8; 6]) -> (u64, u64) {
    unsafe {
        let limits = MAC_RATE_LIMITS.get(mac);
        match limits {
            Some(limit) => (limit[0], limit[1]), // [rx_limit, tx_limit]
            None => (0, 0),
        }
    }
}

#[inline]
fn is_quota_blocked(mac: &[u8; 6], is_download: bool) -> bool {
    let direction = if is_download { QUOTA_DOWNLOAD } else { QUOTA_UPLOAD };
    unsafe {
        match MAC_QUOTA_BLOCKED.get(mac) {
            Some(value) => *value & direction != 0,
            None => false,
        }
    }
}

#[inline(always)]
fn should_block_quota(mac: &[u8; 6], is_download: bool) -> bool {
    if is_quota_blocked(mac, is_download) {
        return true;
    }

    let thresholds = unsafe {
        match MAC_QUOTA_THRESHOLDS.get(mac) {
            Some(value) => value,
            None => return false,
        }
    };
    let (upload, download) = match MAC_TRAFFIC.get_ptr(mac) {
        Some(stats) => unsafe { (atomic_load_u64(&(*stats)[2]), atomic_load_u64(&(*stats)[3])) },
        None => (0, 0),
    };
    // Thresholds are checked on every packet. Avoid latching a whole-device
    // block here: exhausting one direction must not disable the other.
    thresholds.blocks(download, upload, is_download)
}
