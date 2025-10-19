pub mod network_utils {

    use crate::{IPV4_SUBNET_INFO, IPV6_SUBNET_INFO};

    #[inline]
    pub fn is_subnet_ip(ip: &[u8; 4]) -> bool {
        let network_addr = match IPV4_SUBNET_INFO.get(0) {
            Some(addr) => addr,
            None => return false,
        };
        let subnet_mask = match IPV4_SUBNET_INFO.get(1) {
            Some(mask) => mask,
            None => return false,
        };

        // If subnet info not set, return false
        if *network_addr == [0, 0, 0, 0] && *subnet_mask == [0, 0, 0, 0] {
            return false;
        }

        // Check if IP is in subnet
        for i in 0..4 {
            if (ip[i] & subnet_mask[i]) != (network_addr[i] & subnet_mask[i]) {
                return false;
            }
        }
        true
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

                // Check if IP matches this subnet
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

        // 手动展开循环以避免 eBPF verifier 复杂性
        // 检查完整字节，最多 16 字节
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

        // 检查剩余的位
        if bits_remainder > 0 && bytes_to_check < 16 {
            let mask = !((1u8 << (8 - bits_remainder)) - 1);
            if (ip[bytes_to_check] & mask) != (subnet_data[bytes_to_check] & mask) {
                return false;
            }
        }

        true
    }
}

pub mod packet_utils {

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
}

pub mod traffic_utils {

    use crate::TRAFFIC_DIRECTION;

    #[inline]
    pub fn is_ingress() -> bool {
        let traffic_direction = unsafe { core::ptr::read_volatile(&TRAFFIC_DIRECTION) };
        traffic_direction == -1
    }

    #[inline]
    pub fn is_egress() -> bool {
        let traffic_direction = unsafe { core::ptr::read_volatile(&TRAFFIC_DIRECTION) };
        traffic_direction == 1
    }
}

pub mod math_utils {

    #[inline]
    pub fn min(a: u64, b: u64) -> u64 {
        if a < b {
            a
        } else {
            b
        }
    }
}

pub mod time_utils {

    use aya_ebpf::helpers;

    #[inline]
    pub fn get_current_time() -> u64 {
        unsafe { core::ptr::read_volatile(&helpers::bpf_ktime_get_ns()) }
    }
}
