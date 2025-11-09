// DNS monitoring module
// This module handles DNS query monitoring and analysis

pub mod maps;

use aya_ebpf::{bindings::TC_ACT_PIPE, helpers::bpf_ktime_get_ns, programs::TcContext};
use bandix_common::PacketHeader;
use core::cmp;

use maps::DNS_DATA;

// Define fixed maximum record structure for reserve<T>
const MAX_PAYLOAD: usize = 1500;

#[repr(C)]
pub struct Record {
    pub header: PacketHeader,
    pub data: [u8; MAX_PAYLOAD],
}

#[inline(always)]
pub fn handle_dns_ingress(ctx: &TcContext) -> Result<i32, ()> {
    match try_handle_dns(ctx, 0) {
        Ok(ret) => Ok(ret),
        Err(ret) => Err(ret),
    }
}

#[inline(always)]
pub fn handle_dns_egress(ctx: &TcContext) -> Result<i32, ()> {
    match try_handle_dns(ctx, 1) {
        Ok(ret) => Ok(ret),
        Err(ret) => Err(ret),
    }
}

fn try_handle_dns(ctx: &TcContext, direction: u32) -> Result<i32, ()> {
    // Get packet length
    let len = ctx.len();
    if len == 0 {
        return Ok(TC_ACT_PIPE);
    }

    // Filter DNS packets in kernel space, only process DNS traffic
    if !is_dns_packet(&ctx, len as usize) {
        // Not a DNS packet, pass through without processing
        return Ok(TC_ACT_PIPE);
    }

    // Calculate data length to copy (not exceeding MAX_PAYLOAD)
    let copy_len = cmp::min(len as usize, MAX_PAYLOAD);

    // Reserve space in ringbuf
    let mut entry = match DNS_DATA.reserve::<Record>(0) {
        Some(entry) => entry,
        None => {
            // Ringbuf is full, skip this packet
            return Ok(TC_ACT_PIPE);
        }
    };

    // Get write pointer for entry
    let entry_ptr = entry.as_mut_ptr() as *mut u8;

    // Write PacketHeader
    let header = PacketHeader {
        timestamp: unsafe { bpf_ktime_get_ns() },
        packet_len: len,
        captured_len: copy_len as u32,
        ifindex: 0, // In TC scenario, ifindex may be 0, can be obtained through other means
        direction,  // 0=Ingress, 1=Egress
    };
    unsafe {
        core::ptr::write_unaligned(entry_ptr as *mut PacketHeader, header);
    }

    // Read data from packet and write directly to ringbuf entry
    let data_offset = core::mem::size_of::<PacketHeader>();
    for i in 0..copy_len {
        match ctx.load(i) {
            Ok(byte) => unsafe {
                *entry_ptr.add(data_offset + i) = byte;
            },
            Err(_) => {
                // If read fails, update actual copied length
                unsafe {
                    let header_ptr = entry_ptr as *mut PacketHeader;
                    (*header_ptr).captured_len = i as u32;
                }
                break;
            }
        }
    }

    // Submit data to userspace
    entry.submit(0);

    Ok(TC_ACT_PIPE)
}

/// Check if packet is DNS packet in kernel space
/// Check Ethernet type, IP protocol and UDP port
/// Supports IPv4 and IPv6
fn is_dns_packet(ctx: &TcContext, len: usize) -> bool {
    // At least need Ethernet header (14 bytes)
    if len < 14 {
        return false;
    }

    // Read Ethernet type (offset 12-13 bytes)
    let eth_type_bytes = match (ctx.load(12), ctx.load(13)) {
        (Ok(b1), Ok(b2)) => [b1, b2],
        _ => return false,
    };
    let eth_type = u16::from_be_bytes(eth_type_bytes);

    // Handle IPv4 (0x0800) or IPv6 (0x86DD)
    match eth_type {
        0x0800 => is_dns_ipv4(ctx, len),
        0x86DD => is_dns_ipv6(ctx, len),
        _ => false,
    }
}

/// Check IPv4 DNS packet
fn is_dns_ipv4(ctx: &TcContext, len: usize) -> bool {
    // IPv4 header start position (after Ethernet header)
    let ip_header_start = 14;

    // At least need IPv4 header minimum length (20 bytes)
    if len < ip_header_start + 20 {
        return false;
    }

    // Read IPv4 header length (IHL, Internet Header Length)
    // IHL is in the lower 4 bits of the first byte, unit is 4 bytes
    let ihl_byte: u8 = match ctx.load(ip_header_start) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let ihl = (ihl_byte & 0x0F) as usize;
    let ip_header_len = ihl * 4;

    // Validate IPv4 header length (minimum 20 bytes, maximum 60 bytes)
    if ip_header_len < 20 || ip_header_len > 60 {
        return false;
    }

    // Check if packet length is sufficient
    if len < ip_header_start + ip_header_len {
        return false;
    }

    // Check protocol type, DNS uses UDP (17)
    let protocol: u8 = match ctx.load(ip_header_start + 9) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if protocol != 17 {
        // Not UDP, skip
        return false;
    }

    // UDP header start position (after IPv4 header)
    let udp_header_start = ip_header_start + ip_header_len;

    // Check UDP header length (at least 8 bytes)
    if len < udp_header_start + 8 {
        return false;
    }

    // Parse UDP ports (source and destination ports)
    let src_port_bytes = match (ctx.load(udp_header_start), ctx.load(udp_header_start + 1)) {
        (Ok(b1), Ok(b2)) => [b1, b2],
        _ => return false,
    };
    let src_port = u16::from_be_bytes(src_port_bytes);

    let dst_port_bytes = match (
        ctx.load(udp_header_start + 2),
        ctx.load(udp_header_start + 3),
    ) {
        (Ok(b1), Ok(b2)) => [b1, b2],
        _ => return false,
    };
    let dst_port = u16::from_be_bytes(dst_port_bytes);

    // Check if DNS packet (port 53)
    src_port == 53 || dst_port == 53
}

/// Check IPv6 DNS packet
/// Supports processing IPv6 extension headers (unroll loop to avoid verifier issues)
fn is_dns_ipv6(ctx: &TcContext, len: usize) -> bool {
    // IPv6 header start position (after Ethernet header)
    const IPV6_HEADER_START: usize = 14;
    const IPV6_HEADER_LEN: usize = 40;

    // At least need IPv6 header
    if len < IPV6_HEADER_START + IPV6_HEADER_LEN {
        return false;
    }

    // IPv6 Next Header field is at offset 6 (relative to IPv6 header)
    let mut next_header: u8 = match ctx.load(IPV6_HEADER_START + 6) {
        Ok(b) => b,
        Err(_) => return false,
    };

    // Current header position (starting after IPv6 header)
    let mut offset = IPV6_HEADER_START + IPV6_HEADER_LEN;

    // Process extension headers (unroll loop, handle up to 3 extension headers)
    // Most DNS packets have 0-1 extension headers, 3 is sufficient to cover most cases

    // First extension header (if any)
    if next_header != 17 {
        if next_header >= 60 {
            return false;
        }
        if len < offset + 8 {
            return false;
        }
        let ext_len: u8 = match ctx.load(offset + 1) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let ext_total = 8 + (ext_len as usize * 8);
        if len < offset + ext_total {
            return false;
        }
        next_header = match ctx.load(offset) {
            Ok(b) => b,
            Err(_) => return false,
        };
        offset += ext_total;
        if offset >= len {
            return false;
        }
    }

    // Second extension header (if any)
    if next_header != 17 {
        if next_header >= 60 {
            return false;
        }
        if len < offset + 8 {
            return false;
        }
        let ext_len: u8 = match ctx.load(offset + 1) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let ext_total = 8 + (ext_len as usize * 8);
        if len < offset + ext_total {
            return false;
        }
        next_header = match ctx.load(offset) {
            Ok(b) => b,
            Err(_) => return false,
        };
        offset += ext_total;
        if offset >= len {
            return false;
        }
    }

    // Third extension header (if any)
    if next_header != 17 {
        if next_header >= 60 {
            return false;
        }
        if len < offset + 8 {
            return false;
        }
        let ext_len: u8 = match ctx.load(offset + 1) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let ext_total = 8 + (ext_len as usize * 8);
        if len < offset + ext_total {
            return false;
        }
        next_header = match ctx.load(offset) {
            Ok(b) => b,
            Err(_) => return false,
        };
        offset += ext_total;
        if offset >= len {
            return false;
        }
    }

    // If not UDP in the end, return false
    if next_header != 17 {
        return false;
    }

    // UDP header start position
    // Check UDP header length (at least 8 bytes)
    if len < offset + 8 {
        return false;
    }

    // Parse UDP ports (source and destination ports)
    let src_port_bytes = match (ctx.load(offset), ctx.load(offset + 1)) {
        (Ok(b1), Ok(b2)) => [b1, b2],
        _ => return false,
    };
    let src_port = u16::from_be_bytes(src_port_bytes);

    let dst_port_bytes = match (ctx.load(offset + 2), ctx.load(offset + 3)) {
        (Ok(b1), Ok(b2)) => [b1, b2],
        _ => return false,
    };
    let dst_port = u16::from_be_bytes(dst_port_bytes);

    // Check if DNS packet (port 53)
    src_port == 53 || dst_port == 53
}
