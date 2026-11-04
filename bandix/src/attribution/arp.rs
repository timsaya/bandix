use super::{ip_key, Owners};
use crate::command::SubnetInfo;
use anyhow::{Context, Result};
use aya::maps::{Array, HashMap as BpfMap, MapData};
use bandix_common::attribution::{arp_target_on_subnet, ARP_PENDING_CAPACITY};
use std::collections::HashMap;
use std::ffi::CString;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

const PROBES_PER_TICK: usize = 8;
const RETRY_INTERVAL: Duration = Duration::from_secs(30);

pub(super) struct ArpResolver {
    pending: BpfMap<MapData, [u8; 4], u8>,
    ifindex: u32,
    recent: HashMap<[u8; 4], Instant>,
}

impl ArpResolver {
    pub(super) fn new(ebpf: &mut aya::Ebpf, iface: &str, subnet: &SubnetInfo) -> Result<Self> {
        let name = CString::new(iface)?;
        let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
        anyhow::ensure!(ifindex != 0, "Cannot resolve interface index for {iface}: {}", std::io::Error::last_os_error());
        let pending = BpfMap::try_from(ebpf.take_map("ARP_RESOLVE_PENDING").context("missing ARP_RESOLVE_PENDING")?)?;
        let mut config: Array<MapData, [u8; 12]> = Array::try_from(ebpf.take_map("ARP_RESOLVE_CONFIG").context("missing ARP_RESOLVE_CONFIG")?)?;
        let mut value = [0u8; 12];
        value[..4].copy_from_slice(&subnet.interface_ip);
        value[4..8].copy_from_slice(&subnet.subnet_mask);
        value[8] = 1;
        config.set(0, value, 0)?;
        Ok(Self { pending, ifindex, recent: HashMap::new() })
    }

    pub(super) fn resolve_pending(&mut self, owners: &Owners, subnet: &SubnetInfo) -> Result<()> {
        let now = Instant::now();
        self.recent.retain(|_, attempted| now.duration_since(*attempted) < RETRY_INTERVAL);
        let addresses = self.pending.keys().collect::<Result<Vec<_>, _>>()?;
        let mut attempts = 0;
        for ip in addresses {
            if attempts >= PROBES_PER_TICK {
                break;
            }
            // Keep all work bounded even if packets arrive while this batch is processed.
            self.pending.remove(&ip)?;
            if owners.contains_key(&ip_key(IpAddr::from(ip)))
                || !arp_target_on_subnet(&ip, &subnet.interface_ip, &subnet.subnet_mask)
                || self.recent.contains_key(&ip)
                || self.recent.len() >= ARP_PENDING_CAPACITY as usize
            {
                continue;
            }
            // Failed requests also cool down, avoiding tight retries of unreachable hosts.
            self.recent.insert(ip, now);
            attempts += 1;
            if let Err(err) = request_neighbor(self.ifindex, ip) {
                log::warn!("Requesting ARP resolution for {} failed: {err}", std::net::Ipv4Addr::from(ip));
            }
        }
        Ok(())
    }
}

fn neighbor_request(ifindex: u32, ip: [u8; 4]) -> [u8; 36] {
    // nlmsghdr + ndmsg + NDA_DST. NTF_USE asks the kernel to resolve the
    // neighbor on this link, independent of any gateway route for the address.
    let mut message = [0u8; 36];
    message[0..4].copy_from_slice(&36u32.to_ne_bytes());
    message[4..6].copy_from_slice(&(libc::RTM_NEWNEIGH as u16).to_ne_bytes());
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16;
    message[6..8].copy_from_slice(&flags.to_ne_bytes());
    message[8..12].copy_from_slice(&1u32.to_ne_bytes());
    message[16] = libc::AF_INET as u8;
    message[20..24].copy_from_slice(&ifindex.to_ne_bytes());
    message[26] = 1; // NTF_USE
    message[27] = 1; // RTN_UNICAST
    message[28..30].copy_from_slice(&8u16.to_ne_bytes());
    message[30..32].copy_from_slice(&1u16.to_ne_bytes()); // NDA_DST
    message[32..36].copy_from_slice(&ip);
    message
}

fn request_neighbor(ifindex: u32, ip: [u8; 4]) -> Result<()> {
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
    fn request_resolves_on_the_interface_without_replacing_a_known_mac() {
        let message = neighbor_request(23, [192, 168, 1, 100]);
        assert_eq!(u32::from_ne_bytes(message[..4].try_into().unwrap()), message.len() as u32);
        let flags = u16::from_ne_bytes(message[6..8].try_into().unwrap());
        assert_eq!(flags & libc::NLM_F_REPLACE as u16, 0);
        assert_ne!(flags & libc::NLM_F_EXCL as u16, 0);
        assert_eq!(u32::from_ne_bytes(message[20..24].try_into().unwrap()), 23);
        assert_eq!(message[26], 1);
        assert_eq!(&message[32..36], &[192, 168, 1, 100]);
    }
}
