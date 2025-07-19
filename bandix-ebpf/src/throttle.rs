use crate::utils::math_utils::min;
use crate::utils::time_utils::get_current_time;
use crate::{MAC_RATE_LIMITS, RATE_BUCKETS};

// Check if throttling is needed
#[inline]
pub fn should_throttle(mac: &[u8; 6], data_len: u64, limit: u64, is_rx: bool) -> bool {
    if limit == 0 {
        return false; // No limit
    }

    let bucket = RATE_BUCKETS.get_ptr_mut(mac);
    match bucket {
        Some(b) => unsafe {
            let now = get_current_time();
            let elapsed = now.saturating_sub((*b)[2]); // Prevent time wrap-around

            // Calculate tokens to add
            let tokens_to_add = (elapsed * limit) / 1_000_000_000;

            // Update tokens in bucket (limit max to 1 second limit)
            let idx = if is_rx { 0 } else { 1 };
            (*b)[idx] = min((*b)[idx].saturating_add(tokens_to_add), limit);

            // Check if enough tokens available
            if (*b)[idx] < data_len {
                // Not enough tokens, need to throttle
                (*b)[2] = now; // Update timestamp
                return true;
            }

            // Enough tokens, consume tokens and allow
            (*b)[idx] = (*b)[idx].saturating_sub(data_len);
            (*b)[2] = now; // Update timestamp
            false
        },
        None => {
            // First time seeing this MAC, initialize token bucket
            let now = get_current_time();
            let mut bucket_state = [limit, limit, now];

            // Consume tokens
            let idx = if is_rx { 0 } else { 1 };
            if bucket_state[idx] < data_len {
                // Initial tokens insufficient, need to throttle
                let _ = RATE_BUCKETS.insert(mac, &bucket_state, 0);
                return true;
            }

            bucket_state[idx] = bucket_state[idx].saturating_sub(data_len);
            let _ = RATE_BUCKETS.insert(mac, &bucket_state, 0);
            false
        }
    }
}

// Get rate limit for specified MAC address
#[inline]
pub fn get_rate_limit(mac: &[u8; 6], is_rx: bool) -> u64 {
    unsafe {
        let limits = MAC_RATE_LIMITS.get(mac);
        match limits {
            Some(limit) => {
                if is_rx {
                    limit[1] // Upload limit
                } else {
                    limit[0] // Download limit
                }
            }
            None => 0, // No limit
        }
    }
}
