// Keys are tagged so IPv4, IPv6, MAC and mode entries never alias.
pub const MODE_KEY: [u8; 17] = [0; 17];
pub const EXCLUDED: [u8; 6] = [0; 6];
pub const UNKNOWN: u64 = u64::MAX;
pub const ARP_PENDING_CAPACITY: u32 = 256;

#[inline(always)]
pub fn arp_target_on_subnet(ip: &[u8; 4], interface_ip: &[u8; 4], mask: &[u8; 4]) -> bool {
    let address = u32::from_be_bytes(*ip);
    let local = u32::from_be_bytes(*interface_ip);
    let mask = u32::from_be_bytes(*mask);
    let host_mask = !mask;
    ip[0] != 0 && ip[0] != 127 && ip[0] < 224
        && address != local
        && address & mask == local & mask
        // RFC 3021 point-to-point /31 links have no network or broadcast host.
        && (host_mask <= 1 || (address & host_mask != 0 && address & host_mask != host_mask))
}

#[inline(always)]
pub fn encode_mac(mac: &[u8; 6]) -> u64 {
    u64::from_le_bytes([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0, 0])
}

#[inline(always)]
pub fn decode_mac(value: u64) -> [u8; 6] {
    let b = value.to_le_bytes();
    [b[0], b[1], b[2], b[3], b[4], b[5]]
}

#[inline(always)]
pub fn address_key<const N: usize>(bytes: &[u8; N]) -> [u8; 17] {
    let mut key = [0; 17];
    key[0] = N as u8;
    key[1..1 + N].copy_from_slice(bytes);
    key
}

#[inline(always)]
pub fn mac_key(mac: &[u8; 6]) -> [u8; 17] {
    address_key(mac)
}

#[inline(always)]
pub fn accounting_mac(wire_mac: u64, ip_owner: u64, hop_owner: u64, all_relays_resolved: bool) -> u64 {
    if ip_owner != UNKNOWN {
        // Either a resolved client or zero for an explicitly excluded/ambiguous endpoint.
        return ip_owner;
    }
    if hop_owner == 0 || (hop_owner == UNKNOWN && !all_relays_resolved) {
        return 0;
    }
    wire_mac
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arp_targets_are_unicast_peers_on_the_direct_subnet() {
        let local = [192, 168, 1, 1];
        let mask = [255, 255, 255, 0];
        assert!(arp_target_on_subnet(&[192, 168, 1, 100], &local, &mask));
        for address in [[192, 168, 1, 0], [192, 168, 1, 255], local, [192, 168, 2, 100], [0; 4], [127, 0, 0, 1], [224, 0, 0, 1], [255; 4]] {
            assert!(!arp_target_on_subnet(&address, &local, &mask));
        }
        assert!(arp_target_on_subnet(&[192, 168, 1, 0], &local, &[255, 255, 255, 254]));
    }

    #[test]
    fn automatic_attribution_preserves_the_relay_and_credits_the_client() {
        let client = encode_mac(&[0x10; 6]);
        let relay = encode_mac(&[0x20; 6]);
        assert_eq!(accounting_mac(relay, client, relay, true), client);
        assert_eq!(accounting_mac(relay, relay, relay, true), relay);
        assert_eq!(accounting_mac(client, client, client, true), client);
    }

    #[test]
    fn forwarded_endpoint_never_charges_the_excluded_hop() {
        let client = encode_mac(&[0x10; 6]);
        let relay = encode_mac(&[0x20; 6]);
        assert_eq!(accounting_mac(relay, client, 0, true), client);
        assert_eq!(accounting_mac(relay, UNKNOWN, 0, true), 0);
        assert_eq!(accounting_mac(relay, 0, UNKNOWN, true), 0); // SNAT
        assert_eq!(accounting_mac(relay, client, UNKNOWN, false), client);
        assert_eq!(accounting_mac(relay, client, relay, false), client);
        assert_eq!(accounting_mac(relay, UNKNOWN, UNKNOWN, false), 0);
        assert_eq!(accounting_mac(client, UNKNOWN, client, false), client);
        assert_eq!(accounting_mac(client, UNKNOWN, UNKNOWN, true), client);
        assert_eq!(decode_mac(encode_mac(&[1, 2, 3, 4, 5, 6])), [1, 2, 3, 4, 5, 6]);
    }
}
