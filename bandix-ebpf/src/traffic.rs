use crate::utils::network_utils::is_subnet_ip;
use crate::MAC_IP_MAPPING;
use crate::MAC_TRAFFIC;

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

pub fn monitor_traffic(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    data_len: u64,
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
) {
    if is_subnet_ip(&src_ip) {
        update_traffic_stats(&src_mac, data_len, false);
        let _ = MAC_IP_MAPPING.insert(&src_mac, &src_ip, 0);
    }

    if is_subnet_ip(&dst_ip) {
        update_traffic_stats(&dst_mac, data_len, true);
        let _ = MAC_IP_MAPPING.insert(&dst_mac, &dst_ip, 0);
    }
}
