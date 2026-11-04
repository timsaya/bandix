use crate::{command::SubnetInfo, utils::network_utils};
use anyhow::{Context, Result};
use aya::maps::{HashMap as BpfMap, MapData};
use bandix_common::attribution::{address_key, encode_mac, mac_key, EXCLUDED, MODE_KEY};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::process::Command;
use std::time::Duration;

type Mac = [u8; 6];
type Owners = HashMap<[u8; 17], Mac>;

fn ip_key(ip: IpAddr) -> [u8; 17] {
    match ip {
        IpAddr::V4(ip) => address_key(&ip.octets()),
        IpAddr::V6(ip) => address_key(&ip.octets()),
    }
}

fn ownership(neighbors: &[(IpAddr, Mac)], excluded: &[IpAddr]) -> Owners {
    let excluded: HashSet<_> = excluded.iter().copied().collect();
    let mut relays = HashSet::new();
    let mut resolved = HashSet::new();
    for &(ip, mac) in neighbors {
        if excluded.contains(&ip) {
            relays.insert(mac);
            resolved.insert(ip);
        }
    }
    let mut owners = Owners::new();
    for &(ip, mac) in neighbors {
        let owner = if relays.contains(&mac) { EXCLUDED } else { mac };
        owners.insert(mac_key(&mac), owner);
        // Ambiguous neighbor (e.g. duplicate IPv6 link-local address): skip
        // rather than depending on the order in which ip neigh listed it.
        owners.entry(ip_key(ip)).and_modify(|v| {
            if *v != owner {
                *v = EXCLUDED;
            }
        }).or_insert(owner);
    }
    for &ip in &excluded {
        owners.insert(ip_key(ip), EXCLUDED);
    }
    owners.insert(MODE_KEY, [u8::from(resolved.len() == excluded.len()); 6]);
    owners
}

fn read_neighbors(iface: &str, subnet: &SubnetInfo) -> Result<Vec<(IpAddr, Mac)>> {
    let mut neighbors = Vec::new();
    for family in ["-4", "-6"] {
        let output = Command::new("ip").args([family, "neigh", "show", "dev", iface]).output()?;
        anyhow::ensure!(output.status.success(), "ip {family} neigh show failed: {}", String::from_utf8_lossy(&output.stderr));
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let mut words = line.split_whitespace();
            let Some(ip) = words.next().and_then(|v| v.parse().ok()) else { continue };
            let mut mac = None;
            let mut failed = false;
            while let Some(word) = words.next() {
                match word {
                    "lladdr" => mac = words.next().and_then(|value| network_utils::parse_mac_address(value).ok()),
                    "FAILED" | "INCOMPLETE" => failed = true,
                    _ => {}
                }
            }
            if !failed {
                if let Some(mac) = mac.filter(|mac| *mac != EXCLUDED && mac[0] & 1 == 0) {
                    neighbors.push((ip, mac));
                }
            }
        }
    }
    // Local addresses are absent from ARP/NDP neighbor dumps.
    if subnet.interface_mac != EXCLUDED {
        neighbors.push((IpAddr::from(subnet.interface_ip), subnet.interface_mac));
        for (ip, _) in network_utils::get_interface_ipv6_info(iface) {
            neighbors.push((IpAddr::from(ip), subnet.interface_mac));
        }
    }
    Ok(neighbors)
}

struct OwnerMap {
    map: BpfMap<MapData, [u8; 17], u64>,
    installed: Owners,
}

impl OwnerMap {
    fn refresh(&mut self, iface: &str, subnet: &SubnetInfo, excluded: &[IpAddr]) -> Result<()> {
        let next = ownership(&read_neighbors(iface, subnet)?, excluded);
        // Track each successful syscall so a partial update can be retried.
        for key in self.installed.keys().filter(|key| !next.contains_key(*key)).copied().collect::<Vec<_>>() {
            self.map.remove(&key)?;
            self.installed.remove(&key);
        }
        for (key, value) in next {
            if self.installed.get(&key) != Some(&value) {
                self.map.insert(key, encode_mac(&value), 0)?;
                self.installed.insert(key, value);
            }
        }
        Ok(())
    }
}

pub fn configure(ebpf: &mut aya::Ebpf, iface: &str, subnet: &SubnetInfo, excluded: &[IpAddr]) -> Result<()> {
    let map = BpfMap::try_from(ebpf.take_map("TRAFFIC_OWNERS").context("missing TRAFFIC_OWNERS")?)?;
    let mut owners = OwnerMap { map, installed: Owners::new() };
    if let Err(err) = owners.refresh(iface, subnet, excluded) {
        if !excluded.is_empty() {
            return Err(err);
        }
        log::warn!("Initializing traffic attribution neighbors failed: {err}");
    }
    let (iface, subnet, excluded) = (iface.to_owned(), subnet.clone(), excluded.to_vec());
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if let Err(err) = owners.refresh(&iface, &subnet, &excluded) {
                log::warn!("Refreshing traffic attribution neighbors failed: {err}");
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_exclusions_preserve_ipv4_and_ipv6_owners() {
        let relay = [4; 6];
        let client = [2; 6];
        let neighbors = [
            ("192.168.1.2".parse().unwrap(), relay),
            ("fd00::2".parse().unwrap(), relay),
            ("192.168.1.100".parse().unwrap(), client),
            ("fd00::100".parse().unwrap(), client),
        ];
        let owners = ownership(&neighbors, &[]);
        for (ip, mac) in neighbors {
            assert_eq!(owners[&ip_key(ip)], mac);
            assert_eq!(owners[&mac_key(&mac)], mac);
        }
        assert_ne!(owners[&MODE_KEY][0], 0);
    }

    #[test]
    fn refresh_uses_all_addresses_and_current_owner_of_relay_ip() {
        let relay_ip: IpAddr = "192.168.1.2".parse().unwrap();
        let client_ip: IpAddr = "192.168.1.100".parse().unwrap();
        let alias: IpAddr = "fd00::2".parse().unwrap();
        let client = [2; 6];
        let relay = [4; 6];
        let neighbors = [(relay_ip, relay), (alias, relay), (client_ip, client)];
        let owners = ownership(&neighbors, &[relay_ip]);
        assert_eq!(owners[&ip_key(client_ip)], client);
        assert_eq!(owners[&ip_key(alias)], EXCLUDED);
        assert_eq!(owners[&mac_key(&relay)], EXCLUDED);
        assert_ne!(owners[&MODE_KEY][0], 0);
        let changed = ownership(&[(relay_ip, client), (alias, relay)], &[relay_ip]);
        assert_eq!(changed[&mac_key(&client)], EXCLUDED);
        assert_eq!(changed[&mac_key(&relay)], relay);
        assert_eq!(ownership(&[], &[alias])[&ip_key(alias)], EXCLUDED);
    }
}
