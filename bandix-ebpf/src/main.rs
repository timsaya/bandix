#![no_std]
#![no_main]

use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use aya_ebpf::{bindings::TC_ACT_PIPE, bindings::TC_ACT_SHOT, macros::classifier, programs::TcContext};
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

// 速率限制：[下载限制(bytes/s), 上传限制(bytes/s)]
#[map]
static MAC_RATE_LIMITS: HashMap<[u8; 6], [u64; 2]> = HashMap::with_max_entries(1024, 0);

// 令牌桶状态：[下载令牌数, 上传令牌数, 上次更新时间(ns)]
#[map]
static RATE_BUCKETS: HashMap<[u8; 6], [u64; 3]> = HashMap::with_max_entries(1024, 0);

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

// 获取当前时间（纳秒）
#[inline]
fn get_current_time() -> u64 {
    unsafe { core::ptr::read_volatile(&aya_ebpf::helpers::bpf_ktime_get_ns()) }
}

// 最小值函数
#[inline]
fn min(a: u64, b: u64) -> u64 {
    if a < b { a } else { b }
}

// 检查是否需要限速
#[inline]
fn should_throttle(mac: &[u8; 6], data_len: u64, limit: u64, is_rx: bool) -> bool {
    if limit == 0 {
        return false; // 无限制
    }

    let bucket = RATE_BUCKETS.get_ptr_mut(mac);
    match bucket {
        Some(b) => unsafe {
            let now = get_current_time();
            let elapsed = now.saturating_sub((*b)[2]); // 防止时间回绕
            
            // 计算应该添加的令牌数
            let tokens_to_add = (elapsed * limit) / 1_000_000_000;
            
            // 更新令牌桶中的令牌数（限制最大值为1秒的限制量）
            let idx = if is_rx { 0 } else { 1 };
            (*b)[idx] = min((*b)[idx].saturating_add(tokens_to_add), limit);
            
            // 检查是否有足够的令牌
            if (*b)[idx] < data_len {
                // 没有足够的令牌，需要限速
                (*b)[2] = now; // 更新时间戳
                return true;
            }
            
            // 有足够的令牌，消耗令牌并放行
            (*b)[idx] = (*b)[idx].saturating_sub(data_len);
            (*b)[2] = now; // 更新时间戳
            false
        },
        None => {
            // 首次见到这个 MAC，初始化令牌桶
            let now = get_current_time();
            let mut bucket_state = [limit, limit, now];
            
            // 消耗令牌
            let idx = if is_rx { 0 } else { 1 };
            if bucket_state[idx] < data_len {
                // 初始令牌不足，需要限速
                let _ = RATE_BUCKETS.insert(mac, &bucket_state, 0);
                return true;
            }
            
            bucket_state[idx] = bucket_state[idx].saturating_sub(data_len);
            let _ = RATE_BUCKETS.insert(mac, &bucket_state, 0);
            false
        }
    }
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

    // 检查是否需要限速
    if is_ingress() {
        if is_lan_ip(&dst_ip) {
            // 下载流量 - 对局域网内设备的接收流量进行限速
            unsafe {
                if let Some(limits) = MAC_RATE_LIMITS.get(&dst_mac) {
                    if limits[0] > 0 && should_throttle(&dst_mac, data_len, limits[0], true) {
                        return Ok(TC_ACT_SHOT); // 丢弃数据包
                    }
                }
            }
        }
    }

    if is_egress() {
        if is_lan_ip(&src_ip) {
            // 上传流量 - 对局域网内设备的发送流量进行限速
            unsafe {
                if let Some(limits) = MAC_RATE_LIMITS.get(&src_mac) {
                    if limits[1] > 0 && should_throttle(&src_mac, data_len, limits[1], false) {
                        return Ok(TC_ACT_SHOT); // 丢弃数据包
                    }
                }
            }
        }
    }

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
