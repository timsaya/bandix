use crate::utils::network_utils::is_subnet_ip;
use crate::MAC_IP_MAPPING;
use crate::MAC_TRAFFIC;

#[inline]
fn update_traffic_stats(mac: &[u8; 6], data_len: u64, is_rx: bool, is_local: bool) {
    let traffic = MAC_TRAFFIC.get_ptr_mut(mac);

    match traffic {
        Some(t) => unsafe {
            if is_local {
                if is_rx {
                    // 局域网内部接收字节数
                    (*t)[1] = (*t)[1] + data_len;
                } else {
                    // 局域网内部发送字节数
                    (*t)[0] = (*t)[0] + data_len;
                }
            } else {
                if is_rx {
                    // 跨网络接收字节数
                    (*t)[3] = (*t)[3] + data_len;
                } else {
                    // 跨网络发送字节数
                    (*t)[2] = (*t)[2] + data_len;
                }
            }
        },
        None => {
            let mut stats = [0u64; 4];
            if is_local {
                if is_rx {
                    stats[1] = data_len; // 局域网内部接收字节数
                } else {
                    stats[0] = data_len; // 局域网内部发送字节数
                }
            } else {
                if is_rx {
                    stats[3] = data_len; // 跨网络接收字节数
                } else {
                    stats[2] = data_len; // 跨网络发送字节数
                }
            }
            let _ = MAC_TRAFFIC.insert(mac, &stats, 0);
        }
    }
}

#[inline]
pub fn monitor_traffic(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    data_len: u64,
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
) {
    // check if source ip and destination ip are in local network
    let src_is_local = is_subnet_ip(&src_ip);
    let dst_is_local = is_subnet_ip(&dst_ip);

    if src_is_local {
        // source ip is in local network, this is local network traffic
        let is_local_traffic = dst_is_local;
        update_traffic_stats(&src_mac, data_len, false, is_local_traffic);
        let _ = MAC_IP_MAPPING.insert(&src_mac, &src_ip, 0);
    }

    if dst_is_local {
        // destination ip is in local network, this is local network traffic
        let is_local_traffic = src_is_local;
        update_traffic_stats(&dst_mac, data_len, true, is_local_traffic);
        let _ = MAC_IP_MAPPING.insert(&dst_mac, &dst_ip, 0);
    }
}
