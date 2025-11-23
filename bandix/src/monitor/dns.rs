use crate::monitor::{DnsModuleContext, DnsQueryRecord};
use anyhow::Result;
use aya::maps::{MapData, RingBuf};
use bandix_common::PacketHeader;
use trust_dns_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::RData,
    serialize::binary::BinDecodable,
};

/// Specific implementation of DNS monitoring module
pub struct DnsMonitor;

impl DnsMonitor {
    pub fn new() -> Self {
        DnsMonitor
    }

    /// Start DNS monitoring (includes internal loop)
    pub async fn start(
        &self,
        ctx: &mut DnsModuleContext,
        shutdown_notify: std::sync::Arc<tokio::sync::Notify>,
    ) -> Result<()> {
        // Get RingBuf from eBPF
        // If dns_map is already pre-acquired (when sharing eBPF with other modules), use it
        // Otherwise, try to acquire it from eBPF object (legacy path for standalone DNS module)
        let mut ringbuf = if let Some(map) = ctx.dns_map.take() {
            // Use pre-acquired map (when sharing eBPF with traffic module)
            log::debug!("Using pre-acquired DNS RingBuf map");
            RingBuf::<MapData>::try_from(map)?
        } else {
            // Legacy path: acquire map from eBPF object
            // Note: DNS_DATA is a shared map used by both ingress and egress programs,
            // so we can read from either one to get all DNS packets
            // Since both ingress_ebpf and egress_ebpf are Arc references to the same eBPF object,
            // we need to temporarily drop all references to get exclusive access
            let egress_backup = ctx.egress_ebpf.take();
            let ingress_ebpf = ctx
                .ingress_ebpf
                .take()
                .ok_or_else(|| anyhow::anyhow!("Ingress eBPF program not initialized"))?;

            // Drop egress_backup to reduce Arc reference count to 1
            // This is necessary because both ingress_ebpf and egress_backup point to the same Arc
            drop(egress_backup);

            // Now try to unwrap - this should succeed since we dropped egress_backup
            // If it fails, it means there are still other references (e.g., from ModuleContext clone)
            let mut ebpf = match std::sync::Arc::try_unwrap(ingress_ebpf) {
                Ok(ebpf) => ebpf,
                Err(arc) => {
                    // If unwrap fails, put back the Arc and return error
                    // This can happen if ModuleContext was cloned, creating additional Arc references
                    ctx.ingress_ebpf = Some(arc);
                    // Recreate egress reference from ingress (they point to the same object)
                    ctx.egress_ebpf = ctx.ingress_ebpf.as_ref().map(|e| std::sync::Arc::clone(e));
                    return Err(anyhow::anyhow!(
                        "Cannot get exclusive access to eBPF object. \
                        Arc reference count is still > 1. \
                        This may happen if ModuleContext was cloned or if there are other references to the eBPF object. \
                        Please ensure DNS module context is not cloned before starting monitoring."
                    ));
                }
            };

            // Get DNS_DATA RingBuf map (take ownership)
            let map = ebpf.take_map("DNS_DATA").ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot find DNS_DATA map. Make sure DNS eBPF programs are loaded correctly."
                )
            })?;

            // Put back the Arc references (both point to the same underlying eBPF object)
            // Note: The map has been taken out, but the eBPF object is still needed to keep programs attached
            let ebpf_shared = std::sync::Arc::new(ebpf);
            ctx.ingress_ebpf = Some(std::sync::Arc::clone(&ebpf_shared));
            ctx.egress_ebpf = Some(ebpf_shared);

            log::debug!("DNS RingBuf map acquired successfully");

            RingBuf::<MapData>::try_from(map)?
        };

        log::debug!("DNS monitoring started, waiting for DNS packets...");

        // Start monitoring loop
        self.start_monitoring_loop(&mut ringbuf, ctx, shutdown_notify)
            .await
    }

    /// DNS monitoring internal loop
    async fn start_monitoring_loop(
        &self,
        ringbuf: &mut RingBuf<MapData>,
        ctx: &DnsModuleContext,
        shutdown_notify: std::sync::Arc<tokio::sync::Notify>,
    ) -> Result<()> {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(10));
        
        loop {
            tokio::select! {
                _ = shutdown_notify.notified() => {
                    log::debug!("DNS monitoring module received shutdown signal, stopping...");
                    break;
                }
                _ = interval.tick() => {
                    // Process RingBuf events
                    self.process_ringbuf_events(ringbuf, ctx).await;
                }
            }
        }

        Ok(())
    }

    /// Process events from RingBuf
    async fn process_ringbuf_events(&self, ringbuf: &mut RingBuf<MapData>, ctx: &DnsModuleContext) {
        let mut packet_count = 0;
        while let Some(item) = ringbuf.next() {
            packet_count += 1;
            let bytes: &[u8] = item.as_ref();
            let header_size = std::mem::size_of::<PacketHeader>();

            // Ensure data length is at least PacketHeader size
            if bytes.len() < header_size {
                log::warn!(
                    "DNS RingBuf item too small: {} bytes (expected at least {})",
                    bytes.len(),
                    header_size
                );
                continue;
            }

            // Parse PacketHeader
            let header: PacketHeader =
                unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const PacketHeader) };

            // Extract payload from Record structure
            let payload_all = &bytes[header_size..];

            // Use captured_len to determine actual data length
            let cap_len = std::cmp::min(payload_all.len(), header.captured_len as usize);
            let payload = &payload_all[..cap_len];

            // Parse DNS packet
            match self.parse_dns_packet_from_ethernet(payload, header.timestamp, ctx) {
                Some(dns_info) => {
                    let direction_str = if header.direction == 0 {
                        "Ingress"
                    } else {
                        "Egress"
                    };
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
                    // Not a DNS packet - this shouldn't happen if eBPF filtering works correctly
                    if cap_len >= 14 {
                        let eth_type = u16::from_be_bytes([payload[12], payload[13]]);
                        let direction_str = if header.direction == 0 {
                            "Ingress"
                        } else {
                            "Egress"
                        };

                        // Simple warning for normal operations
                        log::warn!(
                            "Received non-DNS packet [{}] [EthType:0x{:04X}] - eBPF filtering may have issues",
                            direction_str, eth_type
                        );

                        // Detailed debug information (only shown when debug logging is enabled)
                        if log::max_level() >= log::Level::Debug {
                            // Parse more details for better debugging
                            let mut detail_info = String::new();

                            // Try to parse IP layer information
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

                                        detail_info.push_str(&format!(
                                            " Protocol:{} {}->{}",
                                            protocol_name, src_ip, dst_ip
                                        ));

                                        // Try to parse port information for TCP/UDP
                                        let ihl = (payload[ip_start] & 0x0F) as usize;
                                        let ip_header_len = ihl * 4;
                                        let transport_start = ip_start + ip_header_len;

                                        if (protocol == 6 || protocol == 17)
                                            && cap_len >= transport_start + 4
                                        {
                                            let src_port = u16::from_be_bytes([
                                                payload[transport_start],
                                                payload[transport_start + 1],
                                            ]);
                                            let dst_port = u16::from_be_bytes([
                                                payload[transport_start + 2],
                                                payload[transport_start + 3],
                                            ]);
                                            detail_info.push_str(&format!(
                                                " Port:{}->{}",
                                                src_port, dst_port
                                            ));
                                        }
                                    }
                                }
                                0x86DD => {
                                    // IPv6
                                    detail_info.push_str("IPv6");
                                    if cap_len >= 14 + 40 {
                                        let ip_start = 14;
                                        let next_header = payload[ip_start + 6];
                                        let src_ip =
                                            self.format_ipv6(&payload[ip_start + 8..ip_start + 24]);
                                        let dst_ip = self
                                            .format_ipv6(&payload[ip_start + 24..ip_start + 40]);

                                        let protocol_name = match next_header {
                                            1 => "ICMPv6",
                                            6 => "TCP",
                                            17 => "UDP",
                                            58 => "ICMPv6",
                                            _ => "Unknown",
                                        };

                                        detail_info.push_str(&format!(
                                            " Protocol:{} {}->{}",
                                            protocol_name, src_ip, dst_ip
                                        ));

                                        // Try to parse port information for TCP/UDP
                                        let transport_start = ip_start + 40;
                                        if (next_header == 6 || next_header == 17)
                                            && cap_len >= transport_start + 4
                                        {
                                            let src_port = u16::from_be_bytes([
                                                payload[transport_start],
                                                payload[transport_start + 1],
                                            ]);
                                            let dst_port = u16::from_be_bytes([
                                                payload[transport_start + 2],
                                                payload[transport_start + 3],
                                            ]);
                                            detail_info.push_str(&format!(
                                                " Port:{}->{}",
                                                src_port, dst_port
                                            ));
                                        }
                                    }
                                }
                                0x0806 => detail_info.push_str("ARP"),
                                _ => detail_info.push_str(&format!("Unknown(0x{:04X})", eth_type)),
                            }

                            // Add packet hex dump (first 64 bytes or less)
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
                                    format!(
                                        "\n                        ... ({} more bytes)",
                                        cap_len - dump_len
                                    )
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

        // Log if we processed any packets (for debugging)
        if packet_count > 0 && log::max_level() >= log::Level::Debug {
            log::debug!("Processed {} packets in this batch", packet_count);
        }
    }

    /// Parse DNS packet from Ethernet frame
    /// Returns Some(String) if DNS packet, None otherwise
    /// Supports both IPv4 and IPv6
    fn parse_dns_packet_from_ethernet(
        &self,
        data: &[u8],
        timestamp: u64,
        ctx: &DnsModuleContext,
    ) -> Option<String> {
        // At least need Ethernet header (14 bytes)
        if data.len() < 14 {
            return None;
        }

        // Parse Ethernet header
        let eth_type = u16::from_be_bytes([data[12], data[13]]);

        // Handle IPv4 and IPv6
        match eth_type {
            0x0800 => self.parse_dns_ipv4(data, timestamp, ctx),
            0x86DD => self.parse_dns_ipv6(data, timestamp, ctx),
            _ => None, // Not IP packet
        }
    }

    /// Parse IPv4 DNS packet (supports both UDP and TCP)
    fn parse_dns_ipv4(
        &self,
        data: &[u8],
        timestamp: u64,
        ctx: &DnsModuleContext,
    ) -> Option<String> {
        // IPv4 header start position (after Ethernet header)
        let ip_header_start = 14;

        // At least need IPv4 header minimum length (20 bytes)
        if data.len() < ip_header_start + 20 {
            return None;
        }

        // Read IPv4 header length (IHL, Internet Header Length)
        // IHL is in the lower 4 bits of the first byte, unit is 4 bytes
        let ihl = (data[ip_header_start] & 0x0F) as usize;
        let ip_header_len = ihl * 4;

        // Validate IPv4 header length (minimum 20 bytes, maximum 60 bytes)
        if ip_header_len < 20 || ip_header_len > 60 {
            return None;
        }

        // Check if packet length is sufficient
        if data.len() < ip_header_start + ip_header_len {
            return None;
        }

        // Check protocol type, DNS uses UDP (17) or TCP (6)
        let protocol = data[ip_header_start + 9];

        // Parse IP addresses (source and destination addresses in IPv4 header)
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

                // Check UDP header length (at least 8 bytes)
                if data.len() < udp_header_start + 8 {
                    return None;
                }

                // Parse UDP ports
                let src_port =
                    u16::from_be_bytes([data[udp_header_start], data[udp_header_start + 1]]);
                let dst_port =
                    u16::from_be_bytes([data[udp_header_start + 2], data[udp_header_start + 3]]);

                // Check if DNS packet (port 53)
                if src_port == 53 || dst_port == 53 {
                    // DNS data start position (after UDP header, offset 8 bytes)
                    let dns_offset = udp_header_start + 8;
                    Some(self.parse_dns_packet(
                        data, dns_offset, &src_ip, &dst_ip, src_port, dst_port, timestamp, ctx,
                        "UDP",
                    ))
                } else {
                    None
                }
            }
            6 => {
                // TCP DNS
                let tcp_header_start = ip_header_start + ip_header_len;

                // Check TCP header minimum length (20 bytes)
                if data.len() < tcp_header_start + 20 {
                    return None;
                }

                // Parse TCP ports
                let src_port =
                    u16::from_be_bytes([data[tcp_header_start], data[tcp_header_start + 1]]);
                let dst_port =
                    u16::from_be_bytes([data[tcp_header_start + 2], data[tcp_header_start + 3]]);

                // Check if DNS packet (port 53)
                if src_port == 53 || dst_port == 53 {
                    // Get TCP header length (data offset field, upper 4 bits of byte 12)
                    let data_offset = ((data[tcp_header_start + 12] >> 4) & 0x0F) as usize;
                    let tcp_header_len = data_offset * 4;

                    // Validate TCP header length
                    if tcp_header_len < 20 || data.len() < tcp_header_start + tcp_header_len {
                        return None;
                    }

                    // TCP DNS data start position (after TCP header)
                    let tcp_data_start = tcp_header_start + tcp_header_len;

                    // TCP DNS messages have a 2-byte length prefix
                    if data.len() < tcp_data_start + 2 {
                        return None;
                    }

                    // Skip the 2-byte length prefix to get to DNS data
                    let dns_offset = tcp_data_start + 2;

                    // Check if there's actual DNS data
                    if data.len() <= dns_offset {
                        return None;
                    }

                    Some(self.parse_dns_packet(
                        data, dns_offset, &src_ip, &dst_ip, src_port, dst_port, timestamp, ctx,
                        "TCP",
                    ))
                } else {
                    None
                }
            }
            _ => {
                // Not UDP or TCP
                None
            }
        }
    }

    /// Parse IPv6 DNS packet (supports both UDP and TCP)
    fn parse_dns_ipv6(
        &self,
        data: &[u8],
        timestamp: u64,
        ctx: &DnsModuleContext,
    ) -> Option<String> {
        const IPV6_HEADER_START: usize = 14;
        const IPV6_HEADER_LEN: usize = 40;

        // At least need IPv6 header
        if data.len() < IPV6_HEADER_START + IPV6_HEADER_LEN {
            return None;
        }

        // Parse IPv6 addresses
        // IPv6 header: [version(4) + traffic class(4)][flow label(20)][payload len(16)][next header(8)][hop limit(8)][src addr(128)][dst addr(128)]
        // Source address starts at offset 8 (relative to IPv6 header start)
        // Destination address starts at offset 24 (relative to IPv6 header start)
        if data.len() < IPV6_HEADER_START + 40 {
            return None;
        }
        let src_ip = self.format_ipv6(&data[IPV6_HEADER_START + 8..IPV6_HEADER_START + 24]);
        let dst_ip = self.format_ipv6(&data[IPV6_HEADER_START + 24..IPV6_HEADER_START + 40]);

        // IPv6 Next Header field is at offset 6 (relative to IPv6 header)
        let mut next_header: u8 = data[IPV6_HEADER_START + 6];
        let mut offset = IPV6_HEADER_START + IPV6_HEADER_LEN;

        // Process extension headers (simplified, handle common cases)
        // Most DNS packets have 0-1 extension headers
        let mut max_ext_headers = 3;
        while next_header != 17
            && next_header != 6
            && max_ext_headers > 0
            && offset + 8 <= data.len()
        {
            if next_header >= 60 {
                return None; // Invalid next header
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

        // Support both UDP and TCP
        match next_header {
            17 => {
                // UDP DNS
                // Check UDP header length (at least 8 bytes)
                if data.len() < offset + 8 {
                    return None;
                }

                // Parse UDP ports
                let src_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
                let dst_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);

                // Check if DNS packet (port 53)
                if src_port == 53 || dst_port == 53 {
                    // DNS data start position (after UDP header, offset 8 bytes)
                    let dns_offset = offset + 8;
                    Some(self.parse_dns_packet(
                        data, dns_offset, &src_ip, &dst_ip, src_port, dst_port, timestamp, ctx,
                        "UDP",
                    ))
                } else {
                    None
                }
            }
            6 => {
                // TCP DNS
                // Check TCP header minimum length (20 bytes)
                if data.len() < offset + 20 {
                    return None;
                }

                // Parse TCP ports
                let src_port = u16::from_be_bytes([data[offset], data[offset + 1]]);
                let dst_port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);

                // Check if DNS packet (port 53)
                if src_port == 53 || dst_port == 53 {
                    // Get TCP header length (data offset field, upper 4 bits of byte 12)
                    let data_offset = ((data[offset + 12] >> 4) & 0x0F) as usize;
                    let tcp_header_len = data_offset * 4;

                    // Validate TCP header length
                    if tcp_header_len < 20 || data.len() < offset + tcp_header_len {
                        return None;
                    }

                    // TCP DNS data start position (after TCP header)
                    let tcp_data_start = offset + tcp_header_len;

                    // TCP DNS messages have a 2-byte length prefix
                    if data.len() < tcp_data_start + 2 {
                        return None;
                    }

                    // Skip the 2-byte length prefix to get to DNS data
                    let dns_offset = tcp_data_start + 2;

                    // Check if there's actual DNS data
                    if data.len() <= dns_offset {
                        return None;
                    }

                    Some(self.parse_dns_packet(
                        data, dns_offset, &src_ip, &dst_ip, src_port, dst_port, timestamp, ctx,
                        "TCP",
                    ))
                } else {
                    None
                }
            }
            _ => {
                // Not UDP or TCP
                None
            }
        }
    }

    /// Format IPv6 address from bytes
    fn format_ipv6(&self, bytes: &[u8]) -> String {
        if bytes.len() < 16 {
            return "::".to_string();
        }
        // Convert bytes to IPv6 address
        let mut ipv6_bytes = [0u8; 16];
        ipv6_bytes.copy_from_slice(&bytes[..16]);
        let ipv6 = std::net::Ipv6Addr::from(ipv6_bytes);
        ipv6.to_string()
    }

    /// Get device information (MAC and hostname) from IP address
    /// Supports both IPv4 and IPv6 addresses
    fn get_device_info(&self, ip: &str, ctx: &DnsModuleContext) -> (String, String) {
        use crate::utils::network_utils;

        // Try IPv4 first
        if let Ok(ipv4_addr) = ip.parse::<std::net::Ipv4Addr>() {
            let ip_bytes = ipv4_addr.octets();

            // Try to get MAC address from ARP table
            let ip_mac_mapping = match network_utils::get_ip_mac_mapping() {
                Ok(mapping) => mapping,
                Err(_) => return ("".to_string(), "".to_string()),
            };

            // Get MAC address
            let mac = match ip_mac_mapping.get(&ip_bytes) {
                Some(mac) => *mac,
                None => return ("".to_string(), "".to_string()),
            };

            // Format MAC address
            let mac_str = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            );

            // Get hostname from bindings
            let hostname = if let Ok(bindings) = ctx.hostname_bindings.lock() {
                bindings
                    .get(&mac)
                    .cloned()
                    .unwrap_or_else(|| "".to_string())
            } else {
                "".to_string()
            };

            return (mac_str, hostname);
        }

        // Try IPv6
        if let Ok(ipv6_addr) = ip.parse::<std::net::Ipv6Addr>() {
            let ipv6_bytes = ipv6_addr.octets();

            // Try to get MAC address from IPv6 neighbor table
            let ipv6_neighbors = match network_utils::get_ipv6_neighbors() {
                Ok(mapping) => mapping,
                Err(_) => return ("".to_string(), "".to_string()),
            };

            // Find MAC address by searching for matching IPv6 address
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

            // Format MAC address
            let mac_str = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            );

            // Get hostname from bindings
            let hostname = if let Ok(bindings) = ctx.hostname_bindings.lock() {
                bindings
                    .get(&mac)
                    .cloned()
                    .unwrap_or_else(|| "".to_string())
            } else {
                "".to_string()
            };

            return (mac_str, hostname);
        }

        // Neither IPv4 nor IPv6, return empty
        ("".to_string(), "".to_string())
    }

    /// Parse DNS packet (using trust-dns-proto library)
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
        protocol: &str, // "UDP" or "TCP"
    ) -> String {
        // Check DNS data length (at least need 12 bytes DNS header)
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

        // Extract DNS data portion
        let dns_data = &data[dns_offset..];

        // Parse DNS message using trust-dns-proto
        let message =
            match Message::from_bytes(dns_data) {
                Ok(msg) => msg,
                Err(e) => {
                    return format!(
                    "DNS {}:{} -> {}:{} [Parse failed: {}] [DNS data length: {}] [DNS offset: {}]",
                    src_ip, src_port, dst_ip, dst_port, e, dns_data.len(), dns_offset
                );
                }
            };

        let direction = if dst_port == 53 { "Query" } else { "Response" };
        let transaction_id = message.id();
        let is_query = matches!(message.message_type(), MessageType::Query);

        // Parse query domain name and type
        let mut domain_name = String::new();
        let mut query_type = String::new();
        if let Some(question) = message.queries().first() {
            domain_name = question.name().to_string();
            query_type = format!("{:?}", question.query_type());
        }

        // Parse response records (A, AAAA, CNAME, etc.)
        let mut response_ips = Vec::new();
        let mut response_records = Vec::new();
        if !is_query {
            // This is a response packet
            let answer_count = message.answer_count();

            // Log for debugging empty responses
            if answer_count == 0 && log::max_level() >= log::Level::Debug {
                log::debug!(
                    "DNS response has no answers: Domain={}, Type={}, ResponseCode={:?}",
                    domain_name,
                    query_type,
                    message.response_code()
                );
            }

            // Process answer section
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
                            response_records.push(format!(
                                "MX:{} (Priority:{})",
                                mx.exchange(),
                                mx.preference()
                            ));
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
                        _ => {
                            // Handle other record types (including HTTPS, SVCB, and unknown ones)
                            // Format: RecordType:<hex data> for better visibility
                            let rdata_str = format!("{:?}", rdata);
                            // Limit output to avoid very long strings
                            let rdata_display = if rdata_str.len() > 100 {
                                format!("{}...", &rdata_str[..100])
                            } else {
                                rdata_str
                            };
                            response_records.push(format!("{}:{}", record_type, rdata_display));

                            // Log for debugging to help diagnose HTTPS and other special record types
                            if log::max_level() >= log::Level::Debug
                                && (format!("{:?}", record_type).contains("HTTPS") || 
                                format!("{:?}", record_type).contains("SVCB") ||
                                format!("{:?}", record_type) == "Unknown(65)" ||  // HTTPS type code
                                format!("{:?}", record_type) == "Unknown(64)")
                            {
                                // SVCB type code
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
                    // No data in answer (should not happen, but log it for debugging)
                    log::warn!(
                        "DNS answer has no data: Type={:?}, Name={}, Domain={}",
                        record_type,
                        answer.name(),
                        domain_name
                    );
                    response_records.push(format!("{}:<no data>", record_type));
                }
            }

            // Also check authority section (may contain SOA or NS records for NODATA responses)
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
                            response_records.push(format!(
                                "Authority-{:?}:{:?}",
                                authority.record_type(),
                                rdata
                            ));
                        }
                    }
                }
            }
        }

        // Get response status
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

        // Store DNS query record
        if !domain_name.is_empty() {
            // Get device information based on packet type:
            // - For queries: use source IP (the device making the query)
            // - For responses: use destination IP (the device receiving the response)
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

            // Try to match with existing records and calculate response time
            if let Ok(mut queries) = ctx.dns_queries.lock() {
                if is_query {
                    // This is a query, try to find matching response (response might come after)
                    // We'll match it when the response arrives
                    record.response_time_ms = None;
                } else {
                    // This is a response, try to find matching query
                    if let Some(matching_query_idx) = queries.iter().position(|q| {
                        // Match criteria:
                        // 1. Transaction ID matches
                        q.transaction_id == transaction_id &&
                        // 2. IP addresses are swapped
                        q.source_ip == dst_ip &&
                        q.destination_ip == src_ip &&
                        // 3. Ports are swapped
                        q.source_port == dst_port &&
                        q.destination_port == src_port &&
                        // 4. Domain and query type match
                        q.domain == domain_name &&
                        q.query_type == query_type &&
                        // 5. It's a query (not a response)
                        q.is_query &&
                        // 6. Response time hasn't been set yet (not needed anymore, but keep for consistency)
                        q.response_time_ms.is_none() &&
                        // 7. Response timestamp is after query timestamp
                        timestamp > q.timestamp
                    }) {
                        // Calculate response time in milliseconds
                        let query_timestamp = queries[matching_query_idx].timestamp;
                        // Calculate response time: convert nanoseconds to milliseconds
                        // Use floating point division then round to avoid precision loss
                        let diff_ns = timestamp - query_timestamp;
                        let response_time_ms = if diff_ns < 1_000_000 {
                            // If difference is less than 1ms, round up to 1ms for visibility
                            // (0ms would indicate no response matched)
                            1
                        } else {
                            diff_ns / 1_000_000
                        };

                        // Don't update the query record's response_time_ms - queries should never have response time
                        // Only set response time for this response record
                        record.response_time_ms = Some(response_time_ms);

                        log::debug!(
                            "Matched DNS query/response: domain={}, transaction_id={}, query_ts={}ns, response_ts={}ns, diff={}ns, response_time={}ms",
                            domain_name, transaction_id, query_timestamp, timestamp, diff_ns, response_time_ms
                        );
                    } else {
                        log::debug!(
                            "DNS response not matched: domain={}, transaction_id={}, src={}:{}, dst={}:{}",
                            domain_name, transaction_id, src_ip, src_port, dst_ip, dst_port
                        );
                    }
                }

                // Store the new record (both query and response are stored)
                queries.push(record);
                // Keep only last N records (configurable via --dns-max-records)
                let max_records = ctx.options.dns_max_records();
                if queries.len() > max_records {
                    queries.remove(0);
                }
            }
        }

        // Build output string
        let mut result = format!(
            "DNS/{} {} {}:{} -> {}:{} [ID:0x{:04X}]",
            protocol, direction, src_ip, src_port, dst_ip, dst_port, transaction_id
        );

        // Add query type if present (especially useful for PTR queries)
        if !query_type.is_empty() {
            result.push_str(&format!(" [Type:{}]", query_type));
        }

        // Add domain name (in query or response)
        if !domain_name.is_empty() {
            result.push_str(&format!(" Domain:{}", domain_name));
        }

        // Add response information for response packets
        if !is_query {
            // Add response status (always show for responses)
            result.push_str(&format!(" [{}]", response_code));

            // Add record count
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

            // Add response records
            if !response_ips.is_empty() {
                // Has IP addresses (A/AAAA records)
                result.push_str(&format!(" => IP:{}", response_ips.join(",")));

                // Show other non-IP records separately
                let non_ip_records: Vec<_> = response_records
                    .iter()
                    .filter(|r| !r.starts_with("A:") && !r.starts_with("AAAA:"))
                    .collect();
                if !non_ip_records.is_empty() {
                    result.push_str(&format!(
                        " Other:{}",
                        non_ip_records
                            .iter()
                            .map(|s| s.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
            } else if !response_records.is_empty() {
                // No IP addresses, show all records (CNAME, PTR, MX, etc.)
                result.push_str(&format!(" => {}", response_records.join(", ")));
            }
        }

        result
    }
}
