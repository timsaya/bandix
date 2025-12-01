// Traffic monitoring module
// Integrates throttle and traffic monitoring functionality

pub mod maps;

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    programs::TcContext,
};
use network_types::eth::EthHdr;
use network_types::ip::{Ipv4Hdr, Ipv6Hdr};

use crate::utils::{is_subnet_ip, is_subnet_ipv6, ptr_at, min, get_current_time, subnet::IPV4_SUBNET_INFO};
use maps::{MAC_IPV4_MAPPING, MAC_IPV6_MAPPING, MAC_TRAFFIC, MAC_RATE_LIMITS, RATE_BUCKETS};

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
        _ => Ok(TC_ACT_PIPE),
    }
}

#[inline(always)]
pub fn handle_traffic_egress(ctx: &TcContext) -> Result<i32, ()> {
    let ethhdr: *const EthHdr = ptr_at(ctx, 0)?;
    let ethhdr_type = unsafe { (*ethhdr).ether_type };

    match ethhdr_type {
        network_types::eth::EtherType::Ipv4 => handle_ipv4(ctx, false),
        network_types::eth::EtherType::Ipv6 => handle_ipv6(ctx, false),
        _ => Ok(TC_ACT_PIPE),
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

    // IP address
    let src_ip = unsafe { (*ipv4hdr).src_addr };
    let dst_ip = unsafe { (*ipv4hdr).dst_addr };

    // Check subnet configuration
    if !is_subnet_configured() {
        return Ok(TC_ACT_PIPE);
    }

    // Check if addresses are in local subnet
    let src_is_local = is_subnet_ip(&src_ip);
    let dst_is_local = is_subnet_ip(&dst_ip);

    // Rate limiting logic
    if is_ingress {
        // Ingress: throttle upload traffic (local -> external)
        if src_is_local && !dst_is_local {
            let limits = get_rate_limits(&src_mac);
            if limits.1 > 0 { // Check upload limit
                if should_throttle(&src_mac, data_len, limits, false) {
                    return Ok(TC_ACT_SHOT);
                }
            }
        }
    } else {
        // Egress: throttle download traffic (external -> local)
        if dst_is_local && !src_is_local {
            let limits = get_rate_limits(&dst_mac);
            if limits.0 > 0 { // Check download limit
                if should_throttle(&dst_mac, data_len, limits, true) {
                    return Ok(TC_ACT_SHOT);
                }
            }
        }
    }

    // Monitor traffic stats
    monitor_traffic(&src_mac, &dst_mac, data_len, &src_ip, &dst_ip);

    Ok(TC_ACT_PIPE)
}

#[inline(always)]
fn is_subnet_configured() -> bool {
    let network_addr = match IPV4_SUBNET_INFO.get(0) {
        Some(addr) => addr,
        None => return false,
    };

    let subnet_mask = match IPV4_SUBNET_INFO.get(1) {
        Some(mask) => mask,
        None => return false,
    };

    // Check if subnet info is configured
    !(*network_addr == [0, 0, 0, 0] && *subnet_mask == [0, 0, 0, 0])
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

    // Get IPv6 addresses (src_addr and dst_addr are already [u8; 16])
    let src_ip = unsafe { (*ipv6hdr).src_addr };
    let dst_ip = unsafe { (*ipv6hdr).dst_addr };

    // Check if addresses are in local subnet
    let src_is_local = is_subnet_ipv6(&src_ip);
    let dst_is_local = is_subnet_ipv6(&dst_ip);

    // Rate limiting logic
    if is_ingress {
        // Ingress: throttle upload traffic (local -> external)
        if src_is_local && !dst_is_local {
            let limits = get_rate_limits(&src_mac);
            if limits.1 > 0 { // Check upload limit
                if should_throttle(&src_mac, data_len, limits, false) {
                    return Ok(TC_ACT_SHOT);
                }
            }
        }
    } else {
        // Egress: throttle download traffic (external -> local)
        if dst_is_local && !src_is_local {
            let limits = get_rate_limits(&dst_mac);
            if limits.0 > 0 { // Check download limit
                if should_throttle(&dst_mac, data_len, limits, true) {
                    return Ok(TC_ACT_SHOT);
                }
            }
        }
    }

    // Monitor traffic stats
    monitor_traffic_v6(&src_mac, &dst_mac, data_len, &src_ip, &dst_ip);

    Ok(TC_ACT_PIPE)
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
                    // Local network receive bytes
                    (*t)[1] = (*t)[1] + data_len;
                } else {
                    // Local network send bytes
                    (*t)[0] = (*t)[0] + data_len;
                }
            } else {
                if is_rx {
                    // Cross-network receive bytes
                    (*t)[3] = (*t)[3] + data_len;
                } else {
                    // Cross-network send bytes
                    (*t)[2] = (*t)[2] + data_len;
                }
            }
        },
        None => {
            let mut stats = [0u64; 4];
            if is_local {
                if is_rx {
                    stats[1] = data_len; // Local network receive bytes
                } else {
                    stats[0] = data_len; // Local network send bytes
                }
            } else {
                if is_rx {
                    stats[3] = data_len; // Cross-network receive bytes
                } else {
                    stats[2] = data_len; // Cross-network send bytes
                }
            }
            let _ = MAC_TRAFFIC.insert(mac, &stats, 0);
        }
    }
}

#[inline]
fn monitor_traffic(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    data_len: u64,
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
) {
    // check if source ip and destination ip are in local network
    let src_is_local = is_subnet_ip(&src_ip);
    let dst_is_local = is_subnet_ip(&dst_ip);

    if src_is_local {
        // source ip is in local network, this is local network traffic
        let is_local_traffic = dst_is_local;
        update_traffic_stats(&src_mac, data_len, false, is_local_traffic);
        let _ = MAC_IPV4_MAPPING.insert(&src_mac, &src_ip, 0);
    }

    if dst_is_local {
        // destination ip is in local network, this is local network traffic
        let is_local_traffic = src_is_local;
        update_traffic_stats(&dst_mac, data_len, true, is_local_traffic);
        let _ = MAC_IPV4_MAPPING.insert(&dst_mac, &dst_ip, 0);
    }
}

#[inline]
fn monitor_traffic_v6(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    data_len: u64,
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
) {
    // check if source ip and destination ip are in local network
    let src_is_local = is_subnet_ipv6(&src_ip);
    let dst_is_local = is_subnet_ipv6(&dst_ip);

    if src_is_local {
        // source ip is in local network
        let is_local_traffic = dst_is_local;
        update_traffic_stats(&src_mac, data_len, false, is_local_traffic);
        let _ = MAC_IPV6_MAPPING.insert(&src_mac, &src_ip, 0);
    }

    if dst_is_local {
        // destination ip is in local network
        let is_local_traffic = src_is_local;
        update_traffic_stats(&dst_mac, data_len, true, is_local_traffic);
        let _ = MAC_IPV6_MAPPING.insert(&dst_mac, &dst_ip, 0);
    }
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

            // Calculate tokens to add for RX
            if limit_rx > 0 {
                let rx_tokens_to_add = (elapsed * limit_rx) / 1_000_000_000;
                (*b)[0] = min((*b)[0].saturating_add(rx_tokens_to_add), limit_rx);
            }

            // Calculate tokens to add for TX
            if limit_tx > 0 {
                let tx_tokens_to_add = (elapsed * limit_tx) / 1_000_000_000;
                (*b)[1] = min((*b)[1].saturating_add(tx_tokens_to_add), limit_tx);
            }

            // Check if enough tokens available for current direction
            let idx = if is_rx { 0 } else { 1 };
            if (*b)[idx] < data_len {
                // Not enough tokens, need to throttle
                (*b)[2] = now; // Update timestamp
                return true;
            }

            // Enough tokens, consume tokens and allow
            (*b)[idx] = (*b)[idx].saturating_sub(data_len);
            (*b)[2] = now; // Update timestamp
            false
        },
        None => {
            // First time seeing this MAC, initialize token bucket
            let now = get_current_time();
            // Start with full buckets for both directions
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
