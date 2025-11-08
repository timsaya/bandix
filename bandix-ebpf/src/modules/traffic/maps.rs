use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;

// ============================================================================
// Traffic Monitoring Maps
// ============================================================================

// record traffic stats of a mac address, [local send bytes, local receive bytes, wide send bytes, wide receive bytes]
#[map]
pub static MAC_TRAFFIC: HashMap<[u8; 6], [u64; 4]> = HashMap::with_max_entries(1024, 0);

// map mac to IPv4 address
#[map]
pub static MAC_IPV4_MAPPING: HashMap<[u8; 6], [u8; 4]> = HashMap::with_max_entries(1024, 0);

// map mac to IPv6 address
#[map]
pub static MAC_IPV6_MAPPING: HashMap<[u8; 6], [u8; 16]> = HashMap::with_max_entries(1024, 0);

// ============================================================================
// Rate Limiting Maps
// ============================================================================

// rate limit: [download limit(bytes/s), upload limit(bytes/s)]
#[map]
pub static MAC_RATE_LIMITS: HashMap<[u8; 6], [u64; 2]> = HashMap::with_max_entries(1024, 0);

// rate bucket status: [download token number, upload token number, last update time(ns)]
#[map]
pub static RATE_BUCKETS: HashMap<[u8; 6], [u64; 3]> = HashMap::with_max_entries(1024, 0);

