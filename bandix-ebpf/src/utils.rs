// ============================================================================
// Subnet Configuration and Network Utils
// ============================================================================

pub mod subnet {
    use aya_ebpf::macros::map;
    use aya_ebpf::maps::Array;

    // IPv4 subnet info: store multiple subnets
    // Each entry: [network address (4 bytes), subnet mask (4 bytes), enabled (1 byte), padding (7 bytes)]
    // Support up to 16 subnets
    #[map]
    pub static IPV4_SUBNET_INFO: Array<[u8; 16]> = Array::with_max_entries(16, 0);

    // IPv6 subnet info: store multiple prefixes
    // Each entry: [network prefix (16 bytes), prefix_len (1 byte), enabled (1 byte), padding (14 bytes)]
    // Support up to 16 subnets (matches Linux kernel default: net.ipv6.conf.*.max_addresses = 16)
    #[map]
    pub static IPV6_SUBNET_INFO: Array<[u8; 32]> = Array::with_max_entries(16, 0);
}

pub mod config {
    use aya_ebpf::macros::map;
    use aya_ebpf::maps::Array;

    // Module enable flags: [traffic_enabled, dns_enabled]
    // Index 0: traffic module (0=disabled, 1=enabled)
    // Index 1: DNS module (0=disabled, 1=enabled)
    #[map]
    pub static MODULE_ENABLE_FLAGS: Array<u8> = Array::with_max_entries(2, 0);
}

use config::MODULE_ENABLE_FLAGS;
use subnet::{IPV4_SUBNET_INFO, IPV6_SUBNET_INFO};

#[inline]
pub fn is_subnet_ip(ip: &[u8; 4]) -> bool {
    // Check against all configured IPv4 subnets (support up to 16 subnets)
    for i in 0..16 {
        if let Some(subnet_data) = IPV4_SUBNET_INFO.get(i as u32) {
            // subnet_data format: [network_addr (4 bytes), subnet_mask (4 bytes), enabled (1 byte), padding (7 bytes)]
            let enabled = subnet_data[8];
            if enabled == 0 {
                continue;
            }

            // Extract network address and subnet mask
            let network_addr = [subnet_data[0], subnet_data[1], subnet_data[2], subnet_data[3]];
            let subnet_mask = [subnet_data[4], subnet_data[5], subnet_data[6], subnet_data[7]];

            // Check if IP is in this subnet
            let mut matches = true;
            for j in 0..4 {
                if (ip[j] & subnet_mask[j]) != (network_addr[j] & subnet_mask[j]) {
                    matches = false;
                    break;
                }
            }

            if matches {
                return true;
            }
        }
    }
    false
}

#[inline(always)]
pub fn is_subnet_ipv6(ip: &[u8; 16]) -> bool {
    // Check against all configured IPv6 subnets (support up to 16 subnets)
    for i in 0..16 {
        if let Some(subnet_data) = IPV6_SUBNET_INFO.get(i as u32) {
            // subnet_data format: [prefix (16 bytes), prefix_len (1 byte), enabled (1 byte), padding (14 bytes)]
            let enabled = subnet_data[17];
            if enabled == 0 {
                continue;
            }

            let prefix_len = subnet_data[16] as usize;
            if prefix_len == 0 || prefix_len > 128 {
                continue;
            }

            // 检查是否IP matches this subnet
            if ip_matches_prefix(ip, subnet_data, prefix_len) {
                return true;
            }
        }
    }
    false
}

#[inline(always)]
fn ip_matches_prefix(ip: &[u8; 16], subnet_data: &[u8; 32], prefix_len: usize) -> bool {
    let bytes_to_check = prefix_len / 8;
    let bits_remainder = prefix_len % 8;

    // Manually unroll loop to avoid eBPF verifier complexity
    // Check complete bytes, up to 16 bytes
    if bytes_to_check > 0 && ip[0] != subnet_data[0] {
        return false;
    }
    if bytes_to_check > 1 && ip[1] != subnet_data[1] {
        return false;
    }
    if bytes_to_check > 2 && ip[2] != subnet_data[2] {
        return false;
    }
    if bytes_to_check > 3 && ip[3] != subnet_data[3] {
        return false;
    }
    if bytes_to_check > 4 && ip[4] != subnet_data[4] {
        return false;
    }
    if bytes_to_check > 5 && ip[5] != subnet_data[5] {
        return false;
    }
    if bytes_to_check > 6 && ip[6] != subnet_data[6] {
        return false;
    }
    if bytes_to_check > 7 && ip[7] != subnet_data[7] {
        return false;
    }
    if bytes_to_check > 8 && ip[8] != subnet_data[8] {
        return false;
    }
    if bytes_to_check > 9 && ip[9] != subnet_data[9] {
        return false;
    }
    if bytes_to_check > 10 && ip[10] != subnet_data[10] {
        return false;
    }
    if bytes_to_check > 11 && ip[11] != subnet_data[11] {
        return false;
    }
    if bytes_to_check > 12 && ip[12] != subnet_data[12] {
        return false;
    }
    if bytes_to_check > 13 && ip[13] != subnet_data[13] {
        return false;
    }
    if bytes_to_check > 14 && ip[14] != subnet_data[14] {
        return false;
    }
    if bytes_to_check > 15 && ip[15] != subnet_data[15] {
        return false;
    }

    // Check remaining bits
    if bits_remainder > 0 && bytes_to_check < 16 {
        let mask = !((1u8 << (8 - bits_remainder)) - 1);
        if (ip[bytes_to_check] & mask) != (subnet_data[bytes_to_check] & mask) {
            return false;
        }
    }

    true
}

// ============================================================================
// Packet Utils
// ============================================================================

use aya_ebpf::programs::TcContext;
use core::mem;

#[inline]
pub fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

// ============================================================================
// Math Utils
// ============================================================================

#[inline]
pub fn min(a: u64, b: u64) -> u64 {
    if a < b {
        a
    } else {
        b
    }
}

// ============================================================================
// Time Utils
// ============================================================================

use aya_ebpf::helpers;

#[inline]
pub fn get_current_time() -> u64 {
    unsafe { core::ptr::read_volatile(&helpers::bpf_ktime_get_ns()) }
}

// ============================================================================
// Module Configuration Utils
// ============================================================================

/// 模块 indices in MODULE_ENABLE_FLAGS array
pub mod module_index {
    pub const TRAFFIC: u32 = 0;
    pub const DNS: u32 = 1;
}

/// 检查是否a module is enabled by index
/// Uses volatile read to ensure the value is always read from memory
#[inline(always)]
pub fn is_module_enabled(index: u32) -> bool {
    match MODULE_ENABLE_FLAGS.get(index) {
        Some(flag_ptr) => unsafe { core::ptr::read_volatile(flag_ptr as *const u8) != 0 },
        None => false,
    }
}

/// 检查是否traffic module is enabled
#[inline(always)]
pub fn is_traffic_enabled() -> bool {
    is_module_enabled(module_index::TRAFFIC)
}

/// 检查是否DNS module is enabled
#[inline(always)]
pub fn is_dns_enabled() -> bool {
    is_module_enabled(module_index::DNS)
}
