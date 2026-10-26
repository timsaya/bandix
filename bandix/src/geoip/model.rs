use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;
pub const UPLOAD_PATH: &str = "/tmp/bandix-geoip-upload.mmdb";
pub const CACHE_ENTRIES: usize = 2048;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    #[default]
    Country,
    CountryAsn,
    CityAsn,
    City,
}
impl Profile {
    pub fn files(self) -> &'static [Kind] {
        match self {
            Self::Country => &[Kind::Country],
            Self::CountryAsn => &[Kind::Country, Kind::Asn],
            Self::CityAsn => &[Kind::City, Kind::Asn],
            Self::City => &[Kind::City],
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Country,
    City,
    Asn,
}
impl Kind {
    pub fn filename(self) -> &'static str {
        match self {
            Self::Country => "GeoLite2-Country.mmdb",
            Self::City => "GeoLite2-City.mmdb",
            Self::Asn => "GeoLite2-ASN.mmdb",
        }
    }
    pub fn from_database_type(value: &str) -> Option<Self> {
        match value {
            "GeoLite2-Country" | "GeoIP2-Country" => Some(Self::Country),
            "GeoLite2-City" | "GeoIP2-City" => Some(Self::City),
            "GeoLite2-ASN" => Some(Self::Asn),
            _ => None,
        }
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Settings {
    pub enabled: bool,
    pub profile: Profile,
    pub active: Option<String>,
    pub version: String,
    pub source: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct DatabaseInfo {
    pub kind: Kind,
    pub bytes: u64,
    pub build_epoch: u64,
    pub database_type: String,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct Job {
    pub id: u64,
    pub busy: bool,
    pub profile: Option<Profile>,
    pub phase: String,
    pub downloaded_bytes: u64,
    pub total_bytes: Option<u64>,
    pub required_bytes: Option<u64>,
    pub current_file: Option<String>,
    pub error: Option<String>,
    pub error_phase: Option<String>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct GeoInfo {
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub country_names: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub region_names: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub city_names: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
}
impl GeoInfo {
    pub fn scope(value: &str) -> Self {
        Self {
            scope: value.to_string(),
            ..Self::default()
        }
    }
}
#[derive(Serialize)]
pub struct Status {
    pub enabled: bool,
    pub profile: Profile,
    pub directory: String,
    pub free_bytes: Option<u64>,
    pub installed_bytes: u64,
    pub version: String,
    pub source: String,
    pub databases: Vec<DatabaseInfo>,
    pub job: Job,
    pub load_error: Option<String>,
    pub upload_path: &'static str,
    pub upload_max_bytes: u64,
}
