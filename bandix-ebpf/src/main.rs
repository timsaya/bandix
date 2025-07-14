#![no_std]
#![no_main]

mod throttle;
mod traffic;
mod utils;

use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap};
use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::classifier,
    programs::TcContext,
};
use network_types::eth::EthHdr;
use network_types::ip::Ipv4Hdr;

use throttle::{get_rate_limit, should_throttle};
use traffic::monitor_traffic;
use utils::{network_utils::is_subnet_ip, packet_utils::ptr_at};

use crate::utils::traffic_utils::{is_egress, is_ingress};

// traffic direction: -1 for ingress, 1 for egress
#[no_mangle]
static TRAFFIC_DIRECTION: i32 = 0;

// record traffic stats of a mac address, [local send bytes, local receive bytes, wide send bytes, wide receive bytes]
#[map]
static MAC_TRAFFIC: HashMap<[u8; 6], [u64; 4]> = HashMap::with_max_entries(1024, 0);

// map mac to ip address
#[map]
static MAC_IP_MAPPING: HashMap<[u8; 6], [u8; 4]> = HashMap::with_max_entries(1024, 0);

// rate limit: [download limit(bytes/s), upload limit(bytes/s)]
#[map]
static MAC_RATE_LIMITS: HashMap<[u8; 6], [u64; 2]> = HashMap::with_max_entries(1024, 0);

// rate bucket status: [download token number, upload token number, last update time(ns)]
#[map]
static RATE_BUCKETS: HashMap<[u8; 6], [u64; 3]> = HashMap::with_max_entries(1024, 0);

// subnet info, [network address, subnet mask]
#[map]
static SUBNET_INFO: Array<[u8; 4]> = Array::with_max_entries(2, 0);

#[classifier]
pub fn bandix(ctx: TcContext) -> i32 {
    match try_bandix(ctx) {
        Ok(ret) => ret,
        _ => TC_ACT_PIPE,
    }
}

#[inline(always)]
fn try_bandix(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    let ethhdr_type = unsafe { (*ethhdr).ether_type };

    // only handle ipv4
    match ethhdr_type {
        network_types::eth::EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    // get source mac address
    let src_mac = unsafe { (*ethhdr).src_addr };
    let dst_mac = unsafe { (*ethhdr).dst_addr };

    // get ipv4 header
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let data_len = unsafe { u16::from_be_bytes((*ipv4hdr).tot_len) } as u64;

    // IP address
    let src_ip = unsafe { (*ipv4hdr).src_addr };
    let dst_ip = unsafe { (*ipv4hdr).dst_addr };

    // 更安全的访问方式 
    let network_addr = match SUBNET_INFO.get(0) {
        Some(addr) => addr,
        None => return Ok(TC_ACT_PIPE),
    };

    let subnet_mask = match SUBNET_INFO.get(1) {
        Some(mask) => mask,
        None => return Ok(TC_ACT_PIPE),
    };

    // 提前检查是否初始化
    if *network_addr == [0, 0, 0, 0] && *subnet_mask == [0, 0, 0, 0] {
        return Ok(TC_ACT_PIPE);
    }

    // if subnet info is not set, skip
    if *network_addr == [0, 0, 0, 0] && *subnet_mask == [0, 0, 0, 0] {
        return Ok(TC_ACT_PIPE);
    }

    // rate limit
    let src_is_local = is_subnet_ip(&src_ip);
    let dst_is_local = is_subnet_ip(&dst_ip);

    if is_ingress() {
        if src_is_local {
            // source ip is in local network
            if !dst_is_local {
                // destination ip is not in local network, this is wide network traffic, need to throttle
                let upload_limit = get_rate_limit(&src_mac, false);
                if should_throttle(&src_mac, data_len, upload_limit, false) {
                    return Ok(TC_ACT_SHOT);
                }
            }
            // destination ip is in local network, this is local network traffic, no need to throttle
        }
    }

    if is_egress() {
        if dst_is_local {
            // destination ip is in local network
            if !src_is_local {
                // source ip is not in local network, this is wide network traffic, need to throttle
                let download_limit = get_rate_limit(&dst_mac, true);
                if should_throttle(&dst_mac, data_len, download_limit, true) {
                    return Ok(TC_ACT_SHOT);
                }
            }
            // source ip is in local network, this is local network traffic, no need to throttle
        }
    }

    // monitor traffic stats
    monitor_traffic(&src_mac, &dst_mac, data_len, &src_ip, &dst_ip);

    Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
