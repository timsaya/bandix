use crate::utils::math_utils::min;
use crate::utils::time_utils::get_current_time;
use crate::{MAC_RATE_LIMITS, RATE_BUCKETS};

// 检查是否需要限速
#[inline]
pub fn should_throttle(mac: &[u8; 6], data_len: u64, limit: u64, is_rx: bool) -> bool {
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

// 获取指定 MAC 地址的速率限制
#[inline]
pub fn get_rate_limit(mac: &[u8; 6], is_rx: bool) -> u64 {
    unsafe {
        let limits = MAC_RATE_LIMITS.get(mac);
        match limits {
            Some(limit) => {
                if is_rx {
                    limit[1] // 上传限制
                } else {
                    limit[0] // 下载限制
                }
            }
            None => 0, // 无限制
        }
    }
}
