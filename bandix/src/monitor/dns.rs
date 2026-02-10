use crate::monitor::{DnsModuleContext, DnsQueryRecord};
use anyhow::Result;
use aya::maps::{MapData, RingBuf};
use bandix_common::PacketHeader;
use trust_dns_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::RData,
    serialize::binary::BinDecodable,
};

/// DNS 监控模块的具体实现
pub struct DnsMonitor;

impl DnsMonitor {
    pub fn new() -> Self {
        DnsMonitor
    }

    /// 启动 DNS 监控（包括内部循环）
    pub async fn start(&self, ctx: &mut DnsModuleContext, shutdown_notify: std::sync::Arc<tokio::sync::Notify>) -> Result<()> {
        // 从 eBPF 获取 RingBuf
        let mut ringbuf = if let Some(map) = ctx.dns_map.take() {
            // 使用预获取的映射（与其他模块共享 eBPF 时）
            log::debug!("Using pre-acquired DNS RingBuf map");
            RingBuf::<MapData>::try_from(map)?
        } else {
            let egress_backup = ctx.egress_ebpf.take();
            let ingress_ebpf = ctx
                .ingress_ebpf
                .take()
                .ok_or_else(|| anyhow::anyhow!("Ingress eBPF program not initialized"))?;

            drop(egress_backup);

            // 尝试 unwrap，丢弃 egress_backup 后应能成功
            // 若失败说明仍有其他引用（如 ModuleContext 被 clone）
            let mut ebpf = match std::sync::Arc::try_unwrap(ingress_ebpf) {
                Ok(ebpf) => ebpf,
                Err(arc) => {
                    // unwrap 失败则还原 Arc 并返回错误
                    // 可能因 ModuleContext 被 clone 而产生额外 Arc 引用
                    ctx.ingress_ebpf = Some(arc);
                    // 用 ingress 重新创建 egress 引用（指向同一对象）
                    ctx.egress_ebpf = ctx.ingress_ebpf.as_ref().map(|e| std::sync::Arc::clone(e));
                    return Err(anyhow::anyhow!(
                        "Cannot get exclusive access to eBPF object. \
                        Arc reference count is still > 1. \
                        This may happen if ModuleContext was cloned or if there are other references to the eBPF object. \
                        Please ensure DNS module context is not cloned before starting monitoring."
                    ));
                }
            };

            // 获取 DNS_DATA RingBuf 映射（取得所有权）
            let map = ebpf
                .take_map("DNS_DATA")
                .ok_or_else(|| anyhow::anyhow!("Cannot find DNS_DATA map. Make sure DNS eBPF programs are loaded correctly."))?;

            // 还原 Arc 引用（均指向同一 eBPF 对象）
            // 映射已取出，但 eBPF 对象仍需保留以维持程序挂载
            let ebpf_shared = std::sync::Arc::new(ebpf);
            ctx.ingress_ebpf = Some(std::sync::Arc::clone(&ebpf_shared));
            ctx.egress_ebpf = Some(ebpf_shared);

            log::debug!("DNS RingBuf map acquired successfully");

            RingBuf::<MapData>::try_from(map)?
        };

        log::debug!("DNS monitoring started, waiting for DNS packets...");

        // 启动监控循环
        self.start_monitoring_loop(&mut ringbuf, ctx, shutdown_notify).await
    }

    /// DNS 监控内部循环
    async fn start_monitoring_loop(
        &self,
        ringbuf: &mut RingBuf<MapData>,
        ctx: &DnsModuleContext,
        shutdown_notify: std::sync::Arc<tokio::sync::Notify>,
    ) -> Result<()> {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(10));
        
        let mut flush_interval = if ctx.options.dns_enable_storage() {
            let flush_secs = ctx.options.dns_flush_interval();
            Some(tokio::time::interval(tokio::time::Duration::from_secs(flush_secs)))
        } else {
            None
        };

        loop {
            tokio::select! {
                _ = shutdown_notify.notified() => {
                    log::debug!("DNS monitoring module received shutdown signal, stopping...");
                    
                    if ctx.options.dns_enable_storage() {
                        log::debug!("Saving DNS records before shutdown...");
                        self.save_dns_records(ctx);
                    }
                    
                    break;
                }
                _ = interval.tick() => {
                    self.process_ringbuf_events(ringbuf, ctx).await;
                }
                _ = async {
                    if let Some(ref mut fi) = flush_interval {
                        fi.tick().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                }, if flush_interval.is_some() => {
                    log::debug!("Periodic DNS records flush triggered");
                    self.save_dns_records(ctx);
                }
            }
        }

        Ok(())
    }
    
    fn save_dns_records(&self, ctx: &DnsModuleContext) {
        let base_dir = ctx.options.data_dir();
        let max_records = ctx.options.dns_max_records();
        
        let records = match ctx.dns_queries.lock() {
            Ok(guard) => guard.clone(),
            Err(e) => {
                log::error!("Failed to lock dns_queries for saving: {}", e);
                return;
            }
        };
        
        match crate::storage::dns::save_dns_queries(base_dir, &records, max_records) {
            Ok(_) => {
                log::debug!("Successfully saved {} DNS records to storage", records.len());
            }
            Err(e) => {
                log::error!("Failed to save DNS records to storage: {}", e);
            }
        }
    }

    /// 处理来自 RingBuf 的事件
    async fn process_ringbuf_events(&self, ringbuf: &mut RingBuf<MapData>, ctx: &DnsModuleContext) {
        let mut packet_count = 0;
        while let Some(item) = ringbuf.next() {
            packet_count += 1;
            let bytes: &[u8] = item.as_ref();
            let header_size = std::mem::size_of::<PacketHeader>();

            // 确保数据长度至少为 PacketHeader 大小
            if bytes.len() < header_size {
                log::warn!(
                    "DNS RingBuf item too small: {} bytes (expected at least {})",
                    bytes.len(),
                    header_size
                );
                continue;
            }

            // 解析 PacketHeader
            let header: PacketHeader = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const PacketHeader) };

            // 从 Record 结构取出载荷
            let payload_all = &bytes[header_size..];

            // 用 captured_len 确定实际数据长度
            let cap_len = std::cmp::min(payload_all.len(), header.captured_len as usize);
            let payload = &payload_all[..cap_len];

            // 解析 DNS 包
            match self.parse_dns_packet_from_ethernet(payload, header.timestamp, ctx) {
                Some(dns_info) => {
                    let direction_str = if header.direction == 0 { "Ingress" } else { "Egress" };
                    log::debug!(
                        "DNS [{}] [Timestamp:{}ns] [Interface:{}] [Length:{}/{}] => {}",
                        direction_str,
                        header.timestamp,
                        header.ifindex,
                        cap_len,
                        header.packet_len,
                        dns_info
                    );
                }
                None => {
                    // 非 DNS 包，eBPF 过滤正常时不应出现
                    if cap_len >= 14 {
                        let eth_type = u16::from_be_bytes([payload[12], payload[13]]);
                        let direction_str = if header.direction == 0 { "Ingress" } else { "Egress" };

                        // 常规情况下的简单告警
                        log::warn!(
                            "Received non-DNS packet [{}] [EthType:0x{:04X}] - eBPF filtering may have issues",
                            direction_str,
                            eth_type
                        );

                        // 详细调试信息（仅开启 debug 日志时输出）
                        if log::max_level() >= log::Level::Debug {
                            // 解析更多细节便于调试
                            let mut detail_info = String::new();

                            // 尝试解析 IP 层信息
                            match eth_type {
                                0x0800 => {
                                    // IPv4
                                    detail_info.push_str("IPv4");
                                    if cap_len >= 14 + 20 {
                                        let ip_start = 14;
                                        let protocol = payload[ip_start + 9];
                                        let src_ip = format!(
                                            "{}.{}.{}.{}",
                                            payload[ip_start + 12],
                                            payload[ip_start + 13],
                                            payload[ip_start + 14],
                                            payload[ip_start + 15]
                                        );
                                        let dst_ip = format!(
                                            "{}.{}.{}.{}",
                                            payload[ip_start + 16],
                                            payload[ip_start + 17],
                                            payload[ip_start + 18],
                                            payload[ip_start + 19]
                                        );

                                        let protocol_name = match protocol {
                                            1 => "ICMP",
                                            6 => "TCP",
                                            17 => "UDP",
                                            _ => "Unknown",
                                        };

                                        detail_info.push_str(&format!(" Protocol:{} {}->{}", protocol_name, src_ip, dst_ip));

                                        // 尝试解析 TCP/UDP 端口
                                        let ihl = (payload[ip_start] & 0x0F) as usize;
                                        let ip_header_len = ihl * 4;
                                        let transport_start = ip_start + ip_header_len;

                                        if (protocol == 6 || protocol == 17) && cap_len >= transport_start + 4 {
                                            let src_port = u16::from_be_bytes([payload[transport_start], payload[transport_start + 1]]);
                                            let dst_port = u16::from_be_bytes([payload[transport_start + 2], payload[transport_start + 3]]);
                                            detail_info.push_str(&format!(" Port:{}->{}", src_port, dst_port));
                                        }
                                    }
                                }
                                0x86DD => {
                                    // IPv6
                                    detail_info.push_str("IPv6");
                                    if cap_len >= 14 + 40 {
                                        let ip_start = 14;
                                        let next_header = payload[ip_start + 6];
                                        let src_ip = self.format_ipv6(&payload[ip_start + 8..ip_start + 24]);
                                        let dst_ip = self.format_ipv6(&payload[ip_start + 24..ip_start + 40]);

                                        let protocol_name = match next_header {
                                            1 => "ICMPv6",
                                            6 => "TCP",
                                            17 => "UDP",
                                            58 => "ICMPv6",
                                            _ => "Unknown",
                                        };

                                        detail_info.push_str(&format!(" Protocol:{} {}->{}", protocol_name, src_ip, dst_ip));

                                        // 尝试解析 TCP/UDP 端口
                                        let transport_start = ip_start + 40;
                                        if (next_header == 6 || next_header == 17) && cap_len >= transport_start + 4 {
                                            let src_port = u16::from_be_bytes([payload[transport_start], payload[transport_start + 1]]);
                                            let dst_port = u16::from_be_bytes([payload[transport_start + 2], payload[transport_start + 3]]);
                                            detail_info.push_str(&format!(" Port:{}->{}", src_port, dst_port));
                                        }
                                    }
                                }
                                0x0806 => detail_info.push_str("ARP"),
                                _ => detail_info.push_str(&format!("Unknown(0x{:04X})", eth_type)),
                            }

                            // 添加包十六进制 dump（前 64 字节或更少）
                            let dump_len = std::cmp::min(cap_len, 64);
                            let hex_dump: String = payload[..dump_len]
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<Vec<_>>()
                                .chunks(16)
                                .map(|chunk| chunk.join(" "))
                                .collect::<Vec<_>>()
                                .join("\n                        ");

                            log::debug!(
                                "Non-DNS packet details:\n\
                                 Direction: {}\n\
                                 Timestamp: {}ns\n\
                                 Interface: {}\n\
                                 Length: {}/{} bytes\n\
                                 EthType: 0x{:04X}\n\
                                 Info: {}\n\
                                 Packet dump (first {} bytes):\n\
                                 {}{}",
                                direction_str,
                                header.timestamp,
                                header.ifindex,
                                cap_len,
                                header.packet_len,
                                eth_type,
                                detail_info,
                                dump_len,
                                hex_dump,
                                if dump_len < cap_len {
                                    format!("\n                        ... ({} more bytes)", cap_len - dump_len)
                                } else {
                                    String::new()
                                }
                            );
                        }
                    } else {
                        log::warn!("Received packet too short: {} bytes", cap_len);

                        if log::max_level() >= log::Level::Debug {
                            log::debug!(
                                "Short packet details:\n\
                                 Timestamp: {}ns\n\
                                 Interface: {}\n\
                                 Length: {}/{} bytes",
                                header.timestamp,
                                header.ifindex,
                                cap_len,
                                header.packet_len
                            );
                        }
                    }
                }
            }
        }

        // 若本批处理了包则打日志（调试用）
        if packet_count > 0 && log::max_level() >= log::Level::Debug {
            log::debug!("Processed {} packets in this batch", packet_count);
        }
    }

    /// 从以太网帧解析 DNS 包
    /// 若是 DNS 包返回 Some(String)，否则 None
    /// 支持 IPv4 与 IPv6
    fn parse_dns_packet_from_ethernet(&self, data: &[u8], timestamp: u64, ctx: &DnsModuleContext) -> Option<String> {
        // 至少需要以太网头（14 字节）
        if data.len() < 14 {
            return None;
        }

        // 解析以太网头
        let eth_type = u16::from_be_bytes([data[12], data[13]]);

        // 处理 IPv4 与 IPv6
        match eth_type {
            0x0800 => self.parse_dns_ipv4(data, timestamp, ctx),
            0x86DD => self.parse_dns_ipv6(data, timestamp, ctx),
            _ => None, // 非 IP 包
        }
    }

    /// 解析 IPv4 DNS 包（支持 UDP 与 TCP）
    fn parse_dns_ipv4(&self, data: &[u8], timestamp: u64, ctx: &DnsModuleContext) -> Option<String> {
        // IPv4 头起始位置（以太网头之后）
        let ip_header_start = 14;

        // 至少需要 IPv4 头最小长度（20 字节）
        if data.len() < ip_header_start + 20 {
            return None;
        }

        // 读取 IPv4 头长度（IHL），IHL 在首字节低 4 位，单位为 4 字节
        let ihl = (data[ip_header_start] & 0x0F) as usize;
        let ip_header_len = ihl * 4;

        // 校验 IPv4 头长度（最小 20 字节，最大 60 字节）
        if ip_header_len < 20 || ip_header_len > 60 {
            return None;
        }

        // 检查包长度是否足够
        if data.len() < ip_header_start + ip_header_len {
            return None;
        }

        // 检查协议类型，DNS 使用 UDP(17) 或 TCP(6)
        let protocol = data[ip_header_start + 9];

        // 解析 IP 地址（IPv4 头中的源、目的地址）
        let src_ip = format!(
            "{}.{}.{}.{}",
            data[ip_header_start + 12],
            data[ip_header_start + 13],
            data[ip_header_start + 14],
            data[ip_header_start + 15]
        );
        let dst_ip = format!(
            "{}.{}.{}.{}",
            data[ip_header_start + 16],
            data[ip_header_start + 17],
            data[ip_header_start + 18],
            data[ip_header_start + 19]
        );

        match protocol {
            17 => {
                // UDP DNS
                let udp_header_start = ip_header_start + ip_header_len;

                // 检查 UDP 头长度（至少 8 字节）
                if data.len() < udp_header_start + 8 {
                    return None;
                }

                // 解析 UDP 端口
                let src_port = u16::from_be_bytes([data[udp_header_start], data[udp_header_start + 1]]);
                let dst_port = u16::from_be_bytes([data[udp_header_start + 2], data[udp_header_start + 3]]);

                // 判断是否为 DNS 包（端口 53）
                if src_port == 53 || dst_port == 53 {
                    // DNS 数据起始位置（UDP 头后，偏移 8 字节）
                    let dns_offset = udp_header_start + 8;
                    Some(self.parse_dns_packet(data, dns_offset, &src_ip, &dst_ip, src_port, dst_port, timestamp, ctx, "UDP"))
                } else {
                    None
                }
            }
            6 => {
                // TCP DNS
                let tcp_header_start = ip_header_start + ip_header_len;

                // 检查 TCP 头最小长度（20 字节）
                if data.len() < tcp_header_start + 20 {
                    return None;
                }

                // 解析 TCP 端口
                let src_port = u16::from_be_bytes([data[tcp_header_start], data[tcp_header_start + 1]]);
                let dst_port = u16::from_be_bytes([data[tcp_header_start + 2], data[tcp_header_start + 3]]);

                // 判断是否为 DNS 包（端口 53）
                if src_port == 53 || dst_port == 53 {
                    // 取 TCP 头长度（数据偏移字段，第 12 字节高 4 位）
                    let data_offset = ((data[tcp_header_start + 12] >> 4) & 0x0F) as usize;
                    let tcp_header_len = data_offset * 4;

                    // 校验 TCP 头长度
                    if tcp_header_len < 20 || data.len() < tcp_header_start + tcp_header_len {
                        return None;
                    }

                    // TCP DNS 数据起始位置（TCP 头之后）
                    let tcp_data_start = tcp_header_start + tcp_header_len;

                    // TCP DNS 消息带 2 字节长度前缀
                    if data.len() < tcp_data_start + 2 {
                        return None;
                    }

                    // 跳过 2 字节长度前缀得到 DNS 数据
                    let dns_offset = tcp_data_start + 2;

                    // 检查是否有实际 DNS 数据
                    if data.len() <= dns_offset {
                        return None;
                    }

                    Some(self.parse_dns_packet(data, dns_offset, &src_ip, &dst_ip, src_port, dst_port, timestamp, ctx, "TCP"))
                } else {
                    None
                }
            }
            _ => {
                // 非 UDP 或 TCP
                None
            }
        }
    }

    /// 解析 IPv6 DNS 包（支持 UDP 与 TCP）
    fn parse_dns_ipv6(&self, data: &[u8], timestamp: u64, ctx: &DnsModuleContext) -> Option<String> {
        const IPV6_HEADER_START: usize = 14;
        const IPV6_HEADER_LEN: usize = 40;

        // 至少需要 IPv6 头
        if data.len() < IPV6_HEADER_START + IPV6_HEADER_LEN {
            return None;
        }

        // 解析 IPv6 地址
        // IPv6 头：[版本(4)+流类型(4)][流标签(20)][载荷长(16)][下一头(8)][跳限(8)][源地址(128)][目的地址(128)]
        // 源地址相对 IPv6 头起始偏移 8，目的地址偏移 24
        if data.len() < IPV6_HEADER_START + 40 {
            return None;
        }
        let src_ip = self.format_ipv6(&data[IPV6_HEADER_START + 8..IPV6_HEADER_START + 24]);
        let dst_ip = self.format_ipv6(&data[IPV6_HEADER_START + 24..IPV6_HEADER_START + 40]);

        // IPv6 下一头部字段在相对 IPv6 头偏移 6
        let mut next_header: u8 = data[IPV6_HEADER_START + 6];
        let mut offset = IPV6_HEADER_START + IPV6_HEADER_LEN;

        // 处理扩展头（简化，仅处理常见情况）
        // 多数 DNS 包有 0～1 个扩展头
        let mut max_ext_headers = 3;
        while next_header != 17 && next_header != 6 && max_ext_headers > 0 && offset + 8 <= data.len() {
            if next_header >= 60 {
                return None; // 无效下一头部
            }

            let ext_len = data[offset + 1] as usize;
            let ext_total = 8 + (ext_len * 8);

            if offset + ext_total > data.len() {
                return None;
            }

            next_header = data[offset];
            offset += ext_total;
            max_ext_headers -= 1;
        }

        // 同时支持 UDP 与 TCP
        match next_header {
            17 => {
                // UDP DNS
                // 检查 UDP 头长度（至少 8 字节）
                if data.len() < offset + 8 {
                    return None;
                }

                // 解析 UDP 端口
                let src_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
                let dst_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);

                // 判断是否为 DNS 包（端口 53）
                if src_port == 53 || dst_port == 53 {
                    // DNS 数据起始位置（UDP 头后，偏移 8 字节）
                    let dns_offset = offset + 8;
                    Some(self.parse_dns_packet(data, dns_offset, &src_ip, &dst_ip, src_port, dst_port, timestamp, ctx, "UDP"))
                } else {
                    None
                }
            }
            6 => {
                // TCP DNS
                // 检查 TCP 头最小长度（20 字节）
                if data.len() < offset + 20 {
                    return None;
                }

                // 解析 TCP 端口
                let src_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
                let dst_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);

                // 判断是否为 DNS 包（端口 53）
                if src_port == 53 || dst_port == 53 {
                    // 取 TCP 头长度（数据偏移字段，第 12 字节高 4 位）
                    let data_offset = ((data[offset + 12] >> 4) & 0x0F) as usize;
                    let tcp_header_len = data_offset * 4;

                    // 校验 TCP 头长度
                    if tcp_header_len < 20 || data.len() < offset + tcp_header_len {
                        return None;
                    }

                    // TCP DNS 数据起始位置（TCP 头之后）
                    let tcp_data_start = offset + tcp_header_len;

                    // TCP DNS 消息带 2 字节长度前缀
                    if data.len() < tcp_data_start + 2 {
                        return None;
                    }

                    // 跳过 2 字节长度前缀得到 DNS 数据
                    let dns_offset = tcp_data_start + 2;

                    // 检查是否有实际 DNS 数据
                    if data.len() <= dns_offset {
                        return None;
                    }

                    Some(self.parse_dns_packet(data, dns_offset, &src_ip, &dst_ip, src_port, dst_port, timestamp, ctx, "TCP"))
                } else {
                    None
                }
            }
            _ => {
                // 非 UDP 或 TCP
                None
            }
        }
    }

    /// 从字节格式化 IPv6 地址
    fn format_ipv6(&self, bytes: &[u8]) -> String {
        if bytes.len() < 16 {
            return "::".to_string();
        }
        // 将字节转为 IPv6 地址
        let mut ipv6_bytes = [0u8; 16];
        ipv6_bytes.copy_from_slice(&bytes[..16]);
        let ipv6 = std::net::Ipv6Addr::from(ipv6_bytes);
        ipv6.to_string()
    }

    /// 根据 IP 获取设备信息（MAC 与主机名）
    /// 支持 IPv4 与 IPv6
    fn get_device_info(&self, ip: &str, ctx: &DnsModuleContext) -> (String, String) {
        use crate::utils::network_utils;

        // 先尝试 IPv4
        if let Ok(ipv4_addr) = ip.parse::<std::net::Ipv4Addr>() {
            let ip_bytes = ipv4_addr.octets();

            // 从 ARP 表获取 MAC
            let ip_mac_mapping = match network_utils::get_ip_mac_mapping() {
                Ok(mapping) => mapping,
                Err(_) => return ("".to_string(), "".to_string()),
            };

            // 取 MAC 地址
            let mac = match ip_mac_mapping.get(&ip_bytes) {
                Some(mac) => *mac,
                None => return ("".to_string(), "".to_string()),
            };

            // 格式化 MAC 地址
            let mac_str = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            );

            // 从绑定表取主机名
            let hostname = if let Ok(bindings) = ctx.hostname_bindings.lock() {
                bindings.get(&mac).cloned().unwrap_or_else(|| "".to_string())
            } else {
                "".to_string()
            };

            return (mac_str, hostname);
        }

        // 再尝试 IPv6
        if let Ok(ipv6_addr) = ip.parse::<std::net::Ipv6Addr>() {
            let ipv6_bytes = ipv6_addr.octets();

            // 从 IPv6 邻居表获取 MAC
            let ipv6_neighbors = match network_utils::get_ipv6_neighbors() {
                Ok(mapping) => mapping,
                Err(_) => return ("".to_string(), "".to_string()),
            };

            // 按匹配的 IPv6 地址查找 MAC
            let mut mac: Option<[u8; 6]> = None;
            for (mac_addr, ipv6_list) in ipv6_neighbors.iter() {
                if ipv6_list.iter().any(|&addr| addr == ipv6_bytes) {
                    mac = Some(*mac_addr);
                    break;
                }
            }

            let mac = match mac {
                Some(mac) => mac,
                None => return ("".to_string(), "".to_string()),
            };

            // 格式化 MAC 地址
            let mac_str = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            );

            // 从绑定表取主机名
            let hostname = if let Ok(bindings) = ctx.hostname_bindings.lock() {
                bindings.get(&mac).cloned().unwrap_or_else(|| "".to_string())
            } else {
                "".to_string()
            };

            return (mac_str, hostname);
        }

        // 既非 IPv4 也非 IPv6，返回空
        ("".to_string(), "".to_string())
    }

    /// 解析 DNS 包（使用 trust-dns-proto）
    fn parse_dns_packet(
        &self,
        data: &[u8],
        dns_offset: usize,
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        timestamp: u64,
        ctx: &DnsModuleContext,
        protocol: &str, // "UDP" 或 "TCP"
    ) -> String {
        // 检查 DNS 数据长度（至少需要 12 字节 DNS 头）
        if data.len() < dns_offset + 12 {
            return format!(
                "DNS {}:{} -> {}:{} (DNS header incomplete, data length: {}, required: {})",
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                data.len(),
                dns_offset + 12
            );
        }

        // 取出 DNS 数据段
        let dns_data = &data[dns_offset..];

        // 用 trust-dns-proto 解析 DNS 消息
        let message = match Message::from_bytes(dns_data) {
            Ok(msg) => msg,
            Err(e) => {
                return format!(
                    "DNS {}:{} -> {}:{} [Parse failed: {}] [DNS data length: {}] [DNS offset: {}]",
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    e,
                    dns_data.len(),
                    dns_offset
                );
            }
        };

        let direction = if dst_port == 53 { "Query" } else { "Response" };
        let transaction_id = message.id();
        let is_query = matches!(message.message_type(), MessageType::Query);

        // 解析查询域名与类型
        let mut domain_name = String::new();
        let mut query_type = String::new();
        if let Some(question) = message.queries().first() {
            domain_name = question.name().to_string();
            query_type = format!("{:?}", question.query_type());
        }

        // 解析应答记录（A、AAAA、CNAME 等）
        let mut response_ips = Vec::new();
        let mut response_records = Vec::new();
        if !is_query {
            // 为应答包
            let answer_count = message.answer_count();

            // 空应答时打调试日志
            if answer_count == 0 && log::max_level() >= log::Level::Debug {
                log::debug!(
                    "DNS response has no answers: Domain={}, Type={}, ResponseCode={:?}",
                    domain_name,
                    query_type,
                    message.response_code()
                );
            }

            // 处理 answer 区
            for answer in message.answers() {
                let record_type = answer.record_type();

                if let Some(rdata) = answer.data() {
                    match rdata {
                        RData::A(ipv4) => {
                            response_ips.push(ipv4.to_string());
                            response_records.push(format!("A:{}", ipv4));
                        }
                        RData::AAAA(ipv6) => {
                            response_ips.push(ipv6.to_string());
                            response_records.push(format!("AAAA:{}", ipv6));
                        }
                        RData::CNAME(cname) => {
                            response_records.push(format!("CNAME:{}", cname));
                        }
                        RData::MX(mx) => {
                            response_records.push(format!("MX:{} (Priority:{})", mx.exchange(), mx.preference()));
                        }
                        RData::TXT(txt) => {
                            let txt_str: String = txt
                                .iter()
                                .map(|bytes| String::from_utf8_lossy(bytes))
                                .collect::<Vec<_>>()
                                .join(" ");
                            response_records.push(format!("TXT:{}", txt_str));
                        }
                        RData::NS(ns) => {
                            response_records.push(format!("NS:{}", ns));
                        }
                        RData::PTR(ptr) => {
                            response_records.push(format!("PTR:{}", ptr));
                        }
                        RData::SOA(soa) => {
                            response_records.push(format!("SOA:{}", soa.mname()));
                        }
                        RData::SRV(srv) => {
                            response_records.push(format!(
                                "SRV:{} (Priority:{} Weight:{} Port:{})",
                                srv.target(),
                                srv.priority(),
                                srv.weight(),
                                srv.port()
                            ));
                        }
                        _ => {
                            // 处理其他记录类型（含 HTTPS、SVCB 及未知类型）
                            // 格式：RecordType:<hex data> 便于查看
                            let rdata_str = format!("{:?}", rdata);
                            // 限制长度避免过长
                            let rdata_display = if rdata_str.len() > 100 {
                                format!("{}...", &rdata_str[..100])
                            } else {
                                rdata_str
                            };
                            response_records.push(format!("{}:{}", record_type, rdata_display));

                            // 调试用，便于排查 HTTPS 等特殊记录类型
                            if log::max_level() >= log::Level::Debug
                                && (format!("{:?}", record_type).contains("HTTPS") || 
                                format!("{:?}", record_type).contains("SVCB") ||
                                format!("{:?}", record_type) == "Unknown(65)" ||  // HTTPS 类型码
                                format!("{:?}", record_type) == "Unknown(64)")
                            {
                                // SVCB 类型码
                                log::debug!(
                                    "DNS special record: Domain={}, Type={:?}, Data={}",
                                    domain_name,
                                    record_type,
                                    rdata_display
                                );
                            }
                        }
                    }
                } else {
                    // answer 无数据（不应出现，仅作调试日志）
                    log::warn!(
                        "DNS answer has no data: Type={:?}, Name={}, Domain={}",
                        record_type,
                        answer.name(),
                        domain_name
                    );
                    response_records.push(format!("{}:<no data>", record_type));
                }
            }

            // 同时检查 authority 区（NODATA 应答可能含 SOA/NS）
            for authority in message.name_servers() {
                if let Some(rdata) = authority.data() {
                    match rdata {
                        RData::SOA(soa) => {
                            response_records.push(format!("Authority-SOA:{}", soa.mname()));
                        }
                        RData::NS(ns) => {
                            response_records.push(format!("Authority-NS:{}", ns));
                        }
                        _ => {
                            response_records.push(format!("Authority-{:?}:{:?}", authority.record_type(), rdata));
                        }
                    }
                }
            }
        }

        // 取应答状态
        let response_code = if !is_query {
            match message.response_code() {
                ResponseCode::NoError => "Success",
                ResponseCode::FormErr => "Format error",
                ResponseCode::ServFail => "Server failure",
                ResponseCode::NXDomain => "Domain not found",
                ResponseCode::NotImp => "Not implemented",
                ResponseCode::Refused => "Refused",
                _ => "Other error",
            }
        } else {
            ""
        };

        // 存储 DNS 查询记录
        if !domain_name.is_empty() {
            // 按包类型取设备信息：查询用源 IP（发起方），应答用目的 IP（接收方）
            let device_ip = if is_query { src_ip } else { dst_ip };
            let (device_mac, device_name) = self.get_device_info(device_ip, ctx);

            let mut record = DnsQueryRecord {
                timestamp,
                domain: domain_name.clone(),
                query_type: query_type.clone(),
                response_code: response_code.to_string(),
                source_ip: src_ip.to_string(),
                destination_ip: dst_ip.to_string(),
                source_port: src_port,
                destination_port: dst_port,
                transaction_id,
                is_query,
                response_ips: response_ips.clone(),
                response_records: response_records.clone(),
                response_time_ms: None,
                device_mac,
                device_name,
            };

            // 尝试与已有记录匹配并计算响应时间
            if let Ok(mut queries) = ctx.dns_queries.lock() {
                if is_query {
                    // 这是查询，稍后应答到达时再匹配
                    record.response_time_ms = None;
                } else {
                    // 这是应答，查找匹配的查询（从末尾用 rposition 找最近一条）
                    if let Some(matching_query_idx) = queries.iter().rposition(|q| {
                        q.transaction_id == transaction_id
                            && q.source_ip == dst_ip
                            && q.destination_ip == src_ip
                            && q.source_port == dst_port
                            && q.destination_port == src_port
                            && q.domain == domain_name
                            && q.query_type == query_type
                            && q.is_query
                            && q.response_time_ms.is_none()
                            && timestamp > q.timestamp
                    }) {
                        let query_timestamp = queries[matching_query_idx].timestamp;
                        let diff_ns = timestamp - query_timestamp;
                        let response_time_ms = if diff_ns < 1_000_000 {
                            // 不足 1ms 按 1ms 显示（0ms 表示未匹配到应答）
                            1
                        } else {
                            diff_ns / 1_000_000
                        };

                        // 更新查询记录的 response_time_ms 表示已应答，避免后续同 ID 应答再次匹配
                        queries[matching_query_idx].response_time_ms = Some(response_time_ms);

                        record.response_time_ms = Some(response_time_ms);

                        log::debug!(
                            "Matched DNS query/response: domain={}, transaction_id={}, query_ts={}ns, response_ts={}ns, diff={}ns, response_time={}ms",
                            domain_name, transaction_id, query_timestamp, timestamp, diff_ns, response_time_ms
                        );
                    } else {
                        log::debug!(
                            "DNS response not matched: domain={}, transaction_id={}, src={}:{}, dst={}:{}",
                            domain_name,
                            transaction_id,
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port
                        );
                    }
                }

                // 写入新记录（查询与应答都存）
                queries.push(record);
                // 只保留最近 N 条（由 --dns-max-records 配置）
                let max_records = ctx.options.dns_max_records();
                if queries.len() > max_records {
                    queries.remove(0);
                }
            }
        }

        // 拼输出字符串
        let mut result = format!(
            "DNS/{} {} {}:{} -> {}:{} [ID:0x{:04X}]",
            protocol, direction, src_ip, src_port, dst_ip, dst_port, transaction_id
        );

        // 若有查询类型则追加（对 PTR 等有用）
        if !query_type.is_empty() {
            result.push_str(&format!(" [Type:{}]", query_type));
        }

        // 追加域名（查询或应答中）
        if !domain_name.is_empty() {
            result.push_str(&format!(" Domain:{}", domain_name));
        }

        // 应答包追加应答信息
        if !is_query {
            // 追加应答状态（应答包始终显示）
            result.push_str(&format!(" [{}]", response_code));

            // 追加记录数量
            let answer_count = message.answer_count();
            let authority_count = message.name_server_count();
            let additional_count = message.additional_count();

            if answer_count > 0 || authority_count > 0 || additional_count > 0 {
                result.push_str(&format!(" [Answers:{}", answer_count));
                if authority_count > 0 {
                    result.push_str(&format!(" Authority:{}", authority_count));
                }
                if additional_count > 0 {
                    result.push_str(&format!(" Additional:{}", additional_count));
                }
                result.push_str("]");
            }

            // 追加应答记录
            if !response_ips.is_empty() {
                result.push_str(&format!(" => IP:{}", response_ips.join(",")));

                // 其他非 IP 记录单独列出
                let non_ip_records: Vec<_> = response_records
                    .iter()
                    .filter(|r| !r.starts_with("A:") && !r.starts_with("AAAA:"))
                    .collect();
                if !non_ip_records.is_empty() {
                    result.push_str(&format!(
                        " Other:{}",
                        non_ip_records.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", ")
                    ));
                }
            } else if !response_records.is_empty() {
                // 无 IP 时列出全部记录（CNAME、PTR、MX 等）
                result.push_str(&format!(" => {}", response_records.join(", ")));
            }
        }

        result
    }
}
