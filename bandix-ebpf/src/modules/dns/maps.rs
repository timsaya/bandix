// DNS 监控 module maps
// 这module contains DNS-related eBPF maps

use aya_ebpf::macros::map;
use aya_ebpf::maps::RingBuf;

// RingBuf for sending DNS packet data to userspace
// Size: 256KB
#[map]
pub static DNS_DATA: RingBuf = RingBuf::with_byte_size(1024 * 256, 0);
