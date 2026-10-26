use super::model::*;
use anyhow::{bail, Context, Result};
use maxminddb::{Mmap, Reader};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

pub struct Database {
    pub info: DatabaseInfo,
    pub reader: Reader<Mmap>,
}
impl Database {
    pub fn open(path: &Path, expected: Option<Kind>, verify: bool) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(path).context("Cannot read database file")?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_FILE_BYTES {
            bail!("Database must be a regular MMDB file smaller than 128 MiB");
        }
        // Files in an active generation are immutable. Updates always create a
        // new directory and atomically replace the settings pointer, never the inode.
        let reader = unsafe { Reader::open_mmap(path) }.context("Invalid MMDB database")?;
        let kind = Kind::from_database_type(&reader.metadata().database_type)
            .context("Unsupported database type; use a Country, City or ASN MMDB")?;
        if expected.is_some_and(|expected| expected != kind) {
            bail!("Database type does not match the selected file");
        }
        if verify {
            reader.verify().context("Database integrity validation failed")?;
        }
        Ok(Self {
            info: DatabaseInfo {
                kind,
                bytes: metadata.len(),
                build_epoch: reader.metadata().build_epoch,
                database_type: reader.metadata().database_type.clone(),
            },
            reader,
        })
    }
}
#[derive(Default, Deserialize)]
#[serde(default)]
struct Names {
    iso_code: Option<String>,
    names: BTreeMap<String, String>,
}
#[derive(Default, Deserialize)]
#[serde(default)]
struct Location {
    country: Option<Names>,
    subdivisions: Vec<Names>,
    city: Option<Names>,
}
#[derive(Default, Deserialize)]
#[serde(default)]
struct Asn {
    autonomous_system_number: Option<u32>,
    autonomous_system_organization: Option<String>,
}

pub fn lookup(databases: &[Database], ip: IpAddr) -> GeoInfo {
    let mut result = GeoInfo::scope("unknown");
    for db in databases {
        let Ok(record) = db.reader.lookup(ip) else {
            continue;
        };
        match db.info.kind {
            Kind::Country | Kind::City => {
                if let Ok(Some(location)) = record.decode::<Location>() {
                    if let Some(country) = location.country {
                        result.country_code = country.iso_code;
                        result.country_names = country.names;
                    }
                    if let Some(region) = location.subdivisions.into_iter().next() {
                        result.region_names = region.names;
                    }
                    if let Some(city) = location.city {
                        result.city_names = city.names;
                    }
                }
            }
            Kind::Asn => {
                if let Ok(Some(asn)) = record.decode::<Asn>() {
                    result.asn = asn.autonomous_system_number;
                    result.organization = asn.autonomous_system_organization;
                }
            }
        }
    }
    if result.country_code.is_some() || result.asn.is_some() {
        result.scope = "public".into();
    }
    result
}

pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(ip)),
        _ => ip,
    }
}
pub fn special_scope(ip: IpAddr) -> Option<&'static str> {
    let ip = normalize(ip);
    if ip.is_unspecified() {
        return Some("unspecified");
    }
    if ip.is_loopback() {
        return Some("loopback");
    }
    if ip.is_multicast() {
        return Some("multicast");
    }
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, _, _] = ip.octets();
            if ip.is_private() {
                Some("private")
            } else if ip.is_link_local() {
                Some("link_local")
            } else if a == 100 && (64..=127).contains(&b) {
                Some("shared")
            } else if ip.is_documentation() {
                Some("documentation")
            } else if a == 0 || a >= 240 || ip == Ipv4Addr::BROADCAST || (a == 198 && (b == 18 || b == 19)) {
                Some("reserved")
            } else {
                None
            }
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            if s[0] & 0xfe00 == 0xfc00 {
                Some("private")
            } else if s[0] & 0xffc0 == 0xfe80 {
                Some("link_local")
            } else if s[0] == 0x2001 && s[1] == 0x0db8 {
                Some("documentation")
            } else if s[0] & 0xe000 != 0x2000 {
                Some("reserved")
            } else {
                None
            }
        }
    }
}
