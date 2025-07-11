use crate::MAC_TRAFFIC;

#[inline]
pub fn update_traffic_stats(mac: &[u8; 6], data_len: u64, is_rx: bool) {
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
