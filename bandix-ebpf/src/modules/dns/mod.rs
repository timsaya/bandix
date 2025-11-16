// DNS monitoring module
// This module handles DNS query monitoring and analysis

pub mod maps;

use aya_ebpf::{bindings::TC_ACT_PIPE, helpers::bpf_ktime_get_ns, programs::TcContext};
use bandix_common::PacketHeader;
use core::cmp;

use maps::DNS_DATA;

// Protocol constants
const DNS_PORT: u16 = 53;
const PROTO_UDP: u8 = 17;
const PROTO_TCP: u8 = 6;
const ETH_TYPE_IPV4: u16 = 0x0800;
const ETH_TYPE_IPV6: u16 = 0x86DD;

// IPv6 extension header protocol numbers
const IPV6_EXT_HOP_BY_HOP: u8 = 0;
const IPV6_EXT_ROUTING: u8 = 43;
const IPV6_EXT_FRAGMENT: u8 = 44;
const IPV6_EXT_ESP: u8 = 50;
const IPV6_EXT_AH: u8 = 51;
const IPV6_EXT_DEST_OPTIONS: u8 = 60;
const IPV6_EXT_MOBILITY: u8 = 135;

// Header size constants
const ETH_HEADER_LEN: usize = 14;
const IPV4_HEADER_MIN_LEN: usize = 20;
const IPV4_HEADER_MAX_LEN: usize = 60;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const TCP_HEADER_MIN_LEN: usize = 20;
const IPV6_EXT_HEADER_MIN_LEN: usize = 8;
const DNS_HEADER_MIN_LEN: usize = 12;

// Ethernet frame offsets
const ETH_TYPE_OFFSET: usize = 12;

// IPv4 header offsets (relative to IP header start)
const IPV4_IHL_OFFSET: usize = 0;
const IPV4_PROTOCOL_OFFSET: usize = 9;

// IPv6 header offsets (relative to IPv6 header start)
const IPV6_NEXT_HEADER_OFFSET: usize = 6;

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

/// Validate DNS header format
/// Check if the payload at given offset looks like a valid DNS packet
#[inline(always)]
fn validate_dns_header(ctx: &TcContext, dns_offset: usize, len: usize, is_tcp: bool) -> bool {
    // For TCP DNS, there's a 2-byte length prefix before DNS data
    let dns_data_offset = if is_tcp {
        if len < dns_offset + 2 + DNS_HEADER_MIN_LEN {
            return false;
        }
        dns_offset + 2
    } else {
        if len < dns_offset + DNS_HEADER_MIN_LEN {
            return false;
        }
        dns_offset
    };

    // Read DNS header flags (bytes 2-3 of DNS header)
    let flags_bytes = match (
        ctx.load(dns_data_offset + 2),
        ctx.load(dns_data_offset + 3),
    ) {
        (Ok(b1), Ok(b2)) => [b1, b2],
        _ => return false,
    };
    let flags = u16::from_be_bytes(flags_bytes);

    // Check DNS header flags for basic validity
    // Bits: QR(1) | Opcode(4) | AA(1) | TC(1) | RD(1) | RA(1) | Z(3) | RCODE(4)
    
    // Extract Opcode (bits 1-4): should be 0 (standard query) or 1 (inverse query) or 2 (status)
    // Most DNS packets use opcode 0
    let opcode = (flags >> 11) & 0x0F;
    if opcode > 5 {
        // Opcode > 5 is reserved/invalid
        return false;
    }

    // Extract RCODE (bits 12-15): Response code
    let rcode = flags & 0x0F;
    if rcode > 5 && rcode != 9 && rcode != 10 {
        // Invalid RCODE (valid: 0-5, 9, 10; others are reserved or extended)
        return false;
    }

    // Read question count (bytes 4-5)
    let qdcount_bytes = match (
        ctx.load(dns_data_offset + 4),
        ctx.load(dns_data_offset + 5),
    ) {
        (Ok(b1), Ok(b2)) => [b1, b2],
        _ => return false,
    };
    let qdcount = u16::from_be_bytes(qdcount_bytes);

    // Read answer count (bytes 6-7)
    let ancount_bytes = match (
        ctx.load(dns_data_offset + 6),
        ctx.load(dns_data_offset + 7),
    ) {
        (Ok(b1), Ok(b2)) => [b1, b2],
        _ => return false,
    };
    let ancount = u16::from_be_bytes(ancount_bytes);

    // A valid DNS packet should have at least one question (query) or answer (response)
    // Also check for reasonable limits to avoid false positives
    if qdcount == 0 && ancount == 0 {
        return false;
    }

    // Sanity check: question count and answer count shouldn't be too large
    // Most DNS packets have <= 10 questions and <= 100 answers
    if qdcount > 100 || ancount > 500 {
        return false;
    }

    true
}

/// Check if packet is DNS packet in kernel space
/// Check Ethernet type, IP protocol and UDP port
/// Supports IPv4 and IPv6
fn is_dns_packet(ctx: &TcContext, len: usize) -> bool {
    // At least need Ethernet header
    if len < ETH_HEADER_LEN {
        return false;
    }

    // Read Ethernet type
    let eth_type_bytes = match (ctx.load(ETH_TYPE_OFFSET), ctx.load(ETH_TYPE_OFFSET + 1)) {
        (Ok(b1), Ok(b2)) => [b1, b2],
        _ => return false,
    };
    let eth_type = u16::from_be_bytes(eth_type_bytes);

    // Handle IPv4 or IPv6
    match eth_type {
        ETH_TYPE_IPV4 => is_dns_ipv4(ctx, len),
        ETH_TYPE_IPV6 => is_dns_ipv6(ctx, len),
        _ => false,
    }
}

/// Check IPv4 DNS packet (optimized: port check first)
fn is_dns_ipv4(ctx: &TcContext, len: usize) -> bool {
    // IPv4 header start position (after Ethernet header)
    let ip_header_start = ETH_HEADER_LEN;

    // At least need IPv4 header minimum length
    if len < ip_header_start + IPV4_HEADER_MIN_LEN {
        return false;
    }

    // Read IPv4 header length (IHL, Internet Header Length)
    // IHL is in the lower 4 bits of the first byte, unit is 4 bytes
    let ihl_byte: u8 = match ctx.load(ip_header_start + IPV4_IHL_OFFSET) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let ihl = (ihl_byte & 0x0F) as usize;
    let ip_header_len = ihl * 4;

    // Validate IPv4 header length
    if ip_header_len < IPV4_HEADER_MIN_LEN || ip_header_len > IPV4_HEADER_MAX_LEN {
        return false;
    }

    // Check if packet length is sufficient
    if len < ip_header_start + ip_header_len {
        return false;
    }

    // Check protocol type, DNS uses UDP or TCP
    let protocol: u8 = match ctx.load(ip_header_start + IPV4_PROTOCOL_OFFSET) {
        Ok(b) => b,
        Err(_) => return false,
    };
    
    // Support both UDP and TCP
    match protocol {
        PROTO_UDP => {
            // UDP DNS
            let udp_header_start = ip_header_start + ip_header_len;
            
            // Check UDP header length
            if len < udp_header_start + UDP_HEADER_LEN {
                return false;
            }
            
            // Parse UDP ports - check port first for early return
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
            
            // Check if either port is DNS port
            if src_port != DNS_PORT && dst_port != DNS_PORT {
                return false;
            }
            
            // Port matches, now validate DNS header format
            let dns_offset = udp_header_start + UDP_HEADER_LEN;
            validate_dns_header(ctx, dns_offset, len, false)
        }
        PROTO_TCP => {
            // TCP DNS
            let tcp_header_start = ip_header_start + ip_header_len;
            
            // Check TCP header minimum length
            if len < tcp_header_start + TCP_HEADER_MIN_LEN {
                return false;
            }
            
            // Parse TCP ports - check port first for early return
            let src_port_bytes = match (ctx.load(tcp_header_start), ctx.load(tcp_header_start + 1)) {
                (Ok(b1), Ok(b2)) => [b1, b2],
                _ => return false,
            };
            let src_port = u16::from_be_bytes(src_port_bytes);
            
            let dst_port_bytes = match (
                ctx.load(tcp_header_start + 2),
                ctx.load(tcp_header_start + 3),
            ) {
                (Ok(b1), Ok(b2)) => [b1, b2],
                _ => return false,
            };
            let dst_port = u16::from_be_bytes(dst_port_bytes);
            
            // Check if either port is DNS port
            if src_port != DNS_PORT && dst_port != DNS_PORT {
                return false;
            }
            
            // Port matches, now validate DNS header format
            // TCP header data offset is in bits 12-15 of byte 12, unit is 4 bytes
            let data_offset_byte: u8 = match ctx.load(tcp_header_start + 12) {
                Ok(b) => b,
                Err(_) => return false,
            };
            let tcp_header_len = ((data_offset_byte >> 4) as usize) * 4;
            if tcp_header_len < TCP_HEADER_MIN_LEN {
                return false;
            }
            
            let dns_offset = tcp_header_start + tcp_header_len;
            validate_dns_header(ctx, dns_offset, len, true)
        }
        _ => {
            // Not UDP or TCP, skip
            false
        }
    }
}

/// Check if protocol is a known IPv6 extension header
#[inline(always)]
fn is_ipv6_extension_header(next_header: u8) -> bool {
    match next_header {
        IPV6_EXT_HOP_BY_HOP | IPV6_EXT_ROUTING | IPV6_EXT_FRAGMENT | 
        IPV6_EXT_ESP | IPV6_EXT_AH | IPV6_EXT_DEST_OPTIONS | IPV6_EXT_MOBILITY => true,
        _ => false,
    }
}

/// Check IPv6 DNS packet (optimized: port check first)
/// Supports processing IPv6 extension headers (unroll loop to avoid verifier issues)
fn is_dns_ipv6(ctx: &TcContext, len: usize) -> bool {
    // IPv6 header start position (after Ethernet header)
    let ipv6_header_start = ETH_HEADER_LEN;

    // At least need IPv6 header
    if len < ipv6_header_start + IPV6_HEADER_LEN {
        return false;
    }

    // IPv6 Next Header field is at offset 6 (relative to IPv6 header)
    let mut next_header: u8 = match ctx.load(ipv6_header_start + IPV6_NEXT_HEADER_OFFSET) {
        Ok(b) => b,
        Err(_) => return false,
    };

    // Current header position (starting after IPv6 header)
    let mut offset = ipv6_header_start + IPV6_HEADER_LEN;

    // Process extension headers (unroll loop, handle up to 3 extension headers)
    // Most DNS packets have 0-1 extension headers, 3 is sufficient to cover most cases

    // First extension header (if any)
    // Check if it's UDP or TCP - if so, stop processing extension headers
    if next_header != PROTO_UDP && next_header != PROTO_TCP {
        // If it's not an extension header, it's not a valid DNS packet
        if !is_ipv6_extension_header(next_header) {
            return false;
        }
        if len < offset + IPV6_EXT_HEADER_MIN_LEN {
            return false;
        }
        let ext_len: u8 = match ctx.load(offset + 1) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let ext_total = IPV6_EXT_HEADER_MIN_LEN + (ext_len as usize * 8);
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
    if next_header != PROTO_UDP && next_header != PROTO_TCP {
        if !is_ipv6_extension_header(next_header) {
            return false;
        }
        if len < offset + IPV6_EXT_HEADER_MIN_LEN {
            return false;
        }
        let ext_len: u8 = match ctx.load(offset + 1) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let ext_total = IPV6_EXT_HEADER_MIN_LEN + (ext_len as usize * 8);
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
    if next_header != PROTO_UDP && next_header != PROTO_TCP {
        if !is_ipv6_extension_header(next_header) {
            return false;
        }
        if len < offset + IPV6_EXT_HEADER_MIN_LEN {
            return false;
        }
        let ext_len: u8 = match ctx.load(offset + 1) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let ext_total = IPV6_EXT_HEADER_MIN_LEN + (ext_len as usize * 8);
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

    // Support both UDP and TCP - check port early for optimization
    match next_header {
        PROTO_UDP => {
            // UDP DNS
            // Check UDP header length
            if len < offset + UDP_HEADER_LEN {
                return false;
            }
            
            // Parse UDP ports - check port first for early return
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
            
            // Check if either port is DNS port
            if src_port != DNS_PORT && dst_port != DNS_PORT {
                return false;
            }
            
            // Port matches, now validate DNS header format
            let dns_offset = offset + UDP_HEADER_LEN;
            validate_dns_header(ctx, dns_offset, len, false)
        }
        PROTO_TCP => {
            // TCP DNS
            // Check TCP header minimum length
            if len < offset + TCP_HEADER_MIN_LEN {
                return false;
            }
            
            // Parse TCP ports - check port first for early return
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
            
            // Check if either port is DNS port
            if src_port != DNS_PORT && dst_port != DNS_PORT {
                return false;
            }
            
            // Port matches, now validate DNS header format
            // TCP header data offset is in bits 12-15 of byte 12, unit is 4 bytes
            let data_offset_byte: u8 = match ctx.load(offset + 12) {
                Ok(b) => b,
                Err(_) => return false,
            };
            let tcp_header_len = ((data_offset_byte >> 4) as usize) * 4;
            if tcp_header_len < TCP_HEADER_MIN_LEN {
                return false;
            }
            
            let dns_offset = offset + tcp_header_len;
            validate_dns_header(ctx, dns_offset, len, true)
        }
        _ => {
            // Not UDP or TCP
            false
        }
    }
}
