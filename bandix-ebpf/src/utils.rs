pub mod network_utils {

    use crate::SUBNET_INFO;

    #[inline]
    pub fn is_subnet_ip(ip: &[u8; 4]) -> bool {
        let network_addr = SUBNET_INFO.get(0).unwrap_or(&[0, 0, 0, 0]);
        let subnet_mask = SUBNET_INFO.get(1).unwrap_or(&[0, 0, 0, 0]);

        // 如果子网信息未设置，返回 false
        if *network_addr == [0, 0, 0, 0] && *subnet_mask == [0, 0, 0, 0] {
            return false;
        }

        // 检查IP是否在子网内
        for i in 0..4 {
            if (ip[i] & subnet_mask[i]) != (network_addr[i] & subnet_mask[i]) {
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
