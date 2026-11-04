use super::{ip_key, Owners};
use crate::{command::SubnetInfo, utils::network_utils};
use anyhow::{Context, Result};
use aya::maps::{Array, HashMap as BpfMap, MapData};
use bandix_common::attribution::{arp_target_on_subnet, ndp_target_on_prefix, NEIGHBOR_PENDING_CAPACITY};
use std::collections::HashMap;
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

const PROBES_PER_TICK: usize = 8;
const RETRY_INTERVAL: Duration = Duration::from_secs(30);

pub(super) struct NeighborResolver {
    pending: BpfMap<MapData, [u8; 17], u8>,
    ifindex: u32,
    recent: HashMap<[u8; 17], Instant>,
}

impl NeighborResolver {
    pub(super) fn new(ebpf: &mut aya::Ebpf, iface: &str, subnet: &SubnetInfo) -> Result<Self> {
        let name = CString::new(iface)?;
        let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
        anyhow::ensure!(ifindex != 0, "Cannot resolve interface index for {iface}: {}", std::io::Error::last_os_error());
        let pending = BpfMap::try_from(ebpf.take_map("NEIGHBOR_RESOLVE_PENDING").context("missing NEIGHBOR_RESOLVE_PENDING")?)?;
        let mut config: Array<MapData, [u8; 12]> = Array::try_from(ebpf.take_map("NEIGHBOR_RESOLVE_CONFIG").context("missing NEIGHBOR_RESOLVE_CONFIG")?)?;
        let mut value = [0u8; 12];
        value[..4].copy_from_slice(&subnet.interface_ip);
        value[4..8].copy_from_slice(&subnet.subnet_mask);
        value[8] = 1;
        config.set(0, value, 0)?;
        Ok(Self { pending, ifindex, recent: HashMap::new() })
    }

    pub(super) fn resolve_pending(&mut self, owners: &Owners, iface: &str, subnet: &SubnetInfo) -> Result<()> {
        let now = Instant::now();
        self.recent.retain(|_, attempted| now.duration_since(*attempted) < RETRY_INTERVAL);
        let ipv6_addresses = network_utils::get_interface_ipv6_info(iface);
        let addresses = self.pending.keys().collect::<Result<Vec<_>, _>>()?;
        let mut attempts = 0;
        for key in addresses {
            if attempts >= PROBES_PER_TICK {
                break;
            }
            // Keep all work bounded even if packets arrive while this batch is processed.
            self.pending.remove(&key)?;
            let Some(ip) = key_address(&key) else { continue };
            if owners.contains_key(&ip_key(ip))
                || !target_on_interface(ip, subnet, &ipv6_addresses)
                || self.recent.contains_key(&key)
                || self.recent.len() >= NEIGHBOR_PENDING_CAPACITY as usize
            {
                continue;
            }
            // Failed requests also cool down, avoiding tight retries of unreachable hosts.
            self.recent.insert(key, now);
            attempts += 1;
            if let Err(err) = request_neighbor(self.ifindex, ip) {
                log::warn!("Requesting neighbor resolution for {ip} failed: {err}");
            }
        }
        Ok(())
    }
}

fn key_address(key: &[u8; 17]) -> Option<IpAddr> {
    match key[0] {
        4 => Some(IpAddr::V4(Ipv4Addr::new(key[1], key[2], key[3], key[4]))),
        16 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&key[1..]).ok()?))),
        _ => None,
    }
}

fn target_on_interface(ip: IpAddr, subnet: &SubnetInfo, ipv6_addresses: &[([u8; 16], u8)]) -> bool {
    match ip {
        IpAddr::V4(ip) => arp_target_on_subnet(&ip.octets(), &subnet.interface_ip, &subnet.subnet_mask),
        IpAddr::V6(ip) => {
            let ip = ip.octets();
            !ipv6_addresses.iter().any(|(local, _)| *local == ip)
                && ipv6_addresses.iter().any(|(local, bits)| ndp_target_on_prefix(&ip, local, *bits))
        }
    }
}

fn neighbor_request(ifindex: u32, ip: IpAddr) -> Vec<u8> {
    // nlmsghdr + ndmsg + NDA_DST. NTF_USE asks the kernel to resolve the
    // neighbor on this link, independent of any gateway route for the address.
    let (family, address) = match ip {
        IpAddr::V4(ip) => (libc::AF_INET, ip.octets().to_vec()),
        IpAddr::V6(ip) => (libc::AF_INET6, ip.octets().to_vec()),
    };
    let mut message = vec![0u8; 32 + address.len()];
    let length = message.len() as u32;
    message[0..4].copy_from_slice(&length.to_ne_bytes());
    message[4..6].copy_from_slice(&(libc::RTM_NEWNEIGH as u16).to_ne_bytes());
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16;
    message[6..8].copy_from_slice(&flags.to_ne_bytes());
    message[8..12].copy_from_slice(&1u32.to_ne_bytes());
    message[16] = family as u8;
    message[20..24].copy_from_slice(&ifindex.to_ne_bytes());
    message[26] = 1; // NTF_USE
    message[27] = 1; // RTN_UNICAST
    message[28..30].copy_from_slice(&(4u16 + address.len() as u16).to_ne_bytes());
    message[30..32].copy_from_slice(&1u16.to_ne_bytes()); // NDA_DST
    message[32..].copy_from_slice(&address);
    message
}

fn request_neighbor(ifindex: u32, ip: IpAddr) -> Result<()> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
    anyhow::ensure!(fd >= 0, "Opening neighbor netlink socket: {}", std::io::Error::last_os_error());
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let timeout = libc::timeval { tv_sec: 0, tv_usec: 100_000 };
    let result = unsafe {
        libc::setsockopt(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO,
            &timeout as *const _ as *const libc::c_void, std::mem::size_of_val(&timeout) as libc::socklen_t)
    };
    anyhow::ensure!(result == 0, "Setting netlink receive timeout: {}", std::io::Error::last_os_error());
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let message = neighbor_request(ifindex, ip);
    let sent = unsafe {
        libc::sendto(socket.as_raw_fd(), message.as_ptr().cast(), message.len(), 0,
            &kernel as *const _ as *const libc::sockaddr, std::mem::size_of_val(&kernel) as libc::socklen_t)
    };
    anyhow::ensure!(sent == message.len() as isize, "Sending neighbor request: {}", std::io::Error::last_os_error());
    let mut response = [0u8; 256];
    let received = unsafe { libc::recv(socket.as_raw_fd(), response.as_mut_ptr().cast(), response.len(), 0) };
    anyhow::ensure!(received >= 20, "Receiving neighbor acknowledgement: {}", std::io::Error::last_os_error());
    anyhow::ensure!(u16::from_ne_bytes(response[4..6].try_into()?) == libc::NLMSG_ERROR as u16
        && u32::from_ne_bytes(response[8..12].try_into()?) == 1, "Unexpected neighbor acknowledgement");
    let error = i32::from_ne_bytes(response[16..20].try_into()?);
    // A neighbor can appear between reading the table and sending this request.
    // EXCL preserves that entry, including administrator-installed permanent MACs.
    if error != 0 && error != -libc::EEXIST {
        return Err(std::io::Error::from_raw_os_error(-error).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_request_uses_the_same_interface_and_a_full_destination_address() {
        let ip: IpAddr = "fe80::1234".parse().unwrap();
        let message = neighbor_request(23, ip);
        assert_eq!(message.len(), 48);
        assert_eq!(message[16], libc::AF_INET6 as u8);
        assert_eq!(u32::from_ne_bytes(message[20..24].try_into().unwrap()), 23);
        assert_eq!(u16::from_ne_bytes(message[28..30].try_into().unwrap()), 20);
        assert_eq!(&message[32..], &"fe80::1234".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(key_address(&ip_key(ip)), Some(ip));
    }

    #[test]
    fn current_prefixes_exclude_all_local_addresses_and_withdrawn_prefixes() {
        let subnet = SubnetInfo {
            interface_ip: [192, 168, 1, 1],
            subnet_mask: [255, 255, 255, 0],
            interface_mac: [2; 6],
            ipv6_addresses: Vec::new(),
        };
        let first = "fd00:1::1".parse::<Ipv6Addr>().unwrap().octets();
        let second = "fd00:1::2".parse::<Ipv6Addr>().unwrap().octets();
        let peer: IpAddr = "fd00:1::100".parse().unwrap();
        let prefixes = [(first, 64), (second, 64)];
        assert!(target_on_interface(peer, &subnet, &prefixes));
        assert!(!target_on_interface(IpAddr::from(second), &subnet, &prefixes));
        assert!(!target_on_interface(peer, &subnet, &[]));
        assert!(!target_on_interface(peer, &subnet, &[("fd00:2::1".parse::<Ipv6Addr>().unwrap().octets(), 64)]));
    }

    #[test]
    fn request_resolves_on_the_interface_without_replacing_a_known_mac() {
        let message = neighbor_request(23, "192.168.1.100".parse().unwrap());
        assert_eq!(u32::from_ne_bytes(message[..4].try_into().unwrap()), message.len() as u32);
        let flags = u16::from_ne_bytes(message[6..8].try_into().unwrap());
        assert_eq!(flags & libc::NLM_F_REPLACE as u16, 0);
        assert_ne!(flags & libc::NLM_F_EXCL as u16, 0);
        assert_eq!(u32::from_ne_bytes(message[20..24].try_into().unwrap()), 23);
        assert_eq!(message[26], 1);
        assert_eq!(&message[32..36], &[192, 168, 1, 100]);
    }
}
