#![no_std]
#![no_main]

use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use aya_ebpf::{bindings::TC_ACT_PIPE, macros::classifier, programs::TcContext};
use core::mem;
use network_types::eth::EthHdr;
use network_types::ip::Ipv4Hdr;

// 流量方向: -1表示入站(ingress), 1表示出站(egress)
#[no_mangle]
static TRAFFIC_DIRECTION: i32 = 0;

// 记录某个MAC地址，即终端设备的流量情况。使用2个值的数组：[发送字节数, 接收字节数]
#[map]
static MAC_TRAFFIC: HashMap<[u8; 6], [u64; 2]> = HashMap::with_max_entries(1024, 0);

// 用于存储 MAC 和 IP 地址的关系
#[map]
static MAC_IP_MAPPING: HashMap<[u8; 6], [u8; 4]> = HashMap::with_max_entries(1024, 0);

#[inline]
fn is_ingress() -> bool {
    let traffic_direction = unsafe { core::ptr::read_volatile(&TRAFFIC_DIRECTION) };
    traffic_direction == -1
}

#[inline]
fn is_egress() -> bool {
    let traffic_direction = unsafe { core::ptr::read_volatile(&TRAFFIC_DIRECTION) };
    traffic_direction == 1
}

#[inline]
fn is_lan_ip(ip: &[u8; 4]) -> bool {
    // 检查是否为局域网IP地址
    // 10.0.0.0/8，排除10.255.255.255
    if ip[0] == 10 {
        return true;
    }

    // 172.16.0.0/12，排除172.16-31.255.255.255的广播地址
    if ip[0] == 172 && (ip[1] >= 16 && ip[1] <= 31) {
        return true;
    }

    // 192.168.0.0/16，排除192.168.255.255
    if ip[0] == 192 && ip[1] == 168 {
        return true;
    }

    false
}

#[classifier]
pub fn bandix(ctx: TcContext) -> i32 {
    match try_bandix(ctx) {
        Ok(ret) => ret,
        _ => TC_ACT_PIPE,
    }
}

#[inline]
fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn try_bandix(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    let ethhdr_type = unsafe { (*ethhdr).ether_type };

    // 只处理 IPv4
    match ethhdr_type {
        network_types::eth::EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    // 获取以太网头部的源MAC地址
    let src_mac = unsafe { (*ethhdr).src_addr };
    let dst_mac = unsafe { (*ethhdr).dst_addr };

    // 获取IPv4头部
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let data_len = unsafe { u16::from_be_bytes((*ipv4hdr).tot_len) } as u64;

    // IP 地址
    let src_ip = unsafe { (*ipv4hdr).src_addr };
    let dst_ip = unsafe { (*ipv4hdr).dst_addr };

    // 监听 lan 口流量
    if is_ingress() {
        if is_lan_ip(&src_ip) {
            // 对局域网 src_ip 设备来说，是发送数据
            update_traffic_stats(&src_mac, data_len, false);
            let _ = MAC_IP_MAPPING.insert(&src_mac, &src_ip, 0);
        }
    }

    if is_egress() {
        if is_lan_ip(&dst_ip) {
            // 对局域网 dst_ip 设备来说，是接收数据
            update_traffic_stats(&dst_mac, data_len, true);
            let _ = MAC_IP_MAPPING.insert(&dst_mac, &dst_ip, 0);
        }
    }

    Ok(TC_ACT_PIPE)
}

#[inline]
fn update_traffic_stats(mac: &[u8; 6], data_len: u64, is_rx: bool) {
    let traffic = MAC_TRAFFIC.get_ptr_mut(mac);

    match traffic {
        Some(t) => unsafe {
            if is_rx {
                // 接收字节数
                (*t)[1] = (*t)[1] + data_len;
            } else {
                // 发送字节数
                (*t)[0] = (*t)[0] + data_len;
            }
        },
        None => {
            let mut stats = [0u64; 2];
            if is_rx {
                stats[1] = data_len; // 接收字节数
            } else {
                stats[0] = data_len; // 发送字节数
            }
            let _ = MAC_TRAFFIC.insert(mac, &stats, 0);
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
