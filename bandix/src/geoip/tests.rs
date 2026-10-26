use super::download::{Asset, Prepared, Release};
use super::*;
use std::str::FromStr;

fn fixture(kind: Kind) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/geoip")
        .join(match kind {
            Kind::Country => "country.mmdb",
            Kind::City => "city.mmdb",
            Kind::Asn => "asn.mmdb",
        })
}
fn prepared(manager: &GeoIpManager, profile: Profile) -> Prepared {
    fs::create_dir_all(&manager.directory).unwrap();
    let directory = tempfile::Builder::new()
        .prefix(".download-")
        .tempdir_in(&manager.directory)
        .unwrap();
    for kind in profile.files() {
        fs::copy(fixture(*kind), directory.path().join(kind.filename())).unwrap();
    }
    Prepared {
        directory,
        profile,
        version: "test-version".into(),
        source: "fixture".into(),
    }
}
#[test]
fn activation_is_persistent_and_lookup_is_optional_cached_and_local_aware() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("geoip");
    let manager = GeoIpManager::new(path.clone());
    assert!(!path.exists());
    assert!(!manager.enabled());
    assert!(manager.set_enabled(true).is_err());
    manager.activate(prepared(&manager, Profile::CityAsn)).unwrap();
    assert!(manager.enabled());
    assert_eq!(manager.status().databases.len(), 2);
    let address = IpAddr::from_str("81.2.69.160").unwrap();
    let info = manager.lookup(address, false);
    assert_eq!(info.country_code.as_deref(), Some("GB"));
    assert!(info.city_names.get("en").is_some());
    assert_eq!(manager.lookup(address, true).scope, "local");
    assert_eq!(manager.lookup(address, false), info);
    assert_eq!(manager.state.lock().unwrap().cache.len(), 1);
    let reopened = GeoIpManager::new(path.clone());
    assert!(reopened.enabled());
    assert_eq!(reopened.lookup(address, false), info);
    reopened.set_enabled(false).unwrap();
    assert!(!GeoIpManager::new(path.clone()).enabled());
    reopened.set_enabled(true).unwrap();
    reopened.delete().unwrap();
    assert!(!GeoIpManager::new(path).enabled());
    assert!(reopened.status().databases.is_empty());
}
#[test]
fn failed_generation_preserves_active_database_and_success_clears_cache_and_old_files() {
    let root = tempfile::tempdir().unwrap();
    let manager = GeoIpManager::new(root.path().join("geoip"));
    manager.activate(prepared(&manager, Profile::Country)).unwrap();
    let old = manager.state.lock().unwrap().settings.active.clone().unwrap();
    let invalid = prepared(&manager, Profile::CountryAsn);
    fs::write(invalid.directory.path().join(Kind::Asn.filename()), b"not an mmdb").unwrap();
    assert!(manager.activate(invalid).is_err());
    assert!(manager.directory.join(&old).exists());
    assert_eq!(manager.status().databases.len(), 1);
    manager.lookup("81.2.69.160".parse().unwrap(), false);
    manager.activate(prepared(&manager, Profile::CountryAsn)).unwrap();
    assert!(!manager.directory.join(old).exists());
    assert!(manager.state.lock().unwrap().cache.is_empty());
    assert_eq!(manager.status().databases.len(), 2);
}
#[test]
fn private_special_ipv6_and_mapped_addresses_are_classified_without_a_database() {
    for (ip, scope) in [
        ("10.0.0.1", "private"),
        ("192.168.1.1", "private"),
        ("100.64.0.1", "shared"),
        ("127.0.0.1", "loopback"),
        ("169.254.1.2", "link_local"),
        ("0.0.0.0", "unspecified"),
        ("224.0.0.1", "multicast"),
        ("192.0.2.1", "documentation"),
        ("::1", "loopback"),
        ("fc00::1", "private"),
        ("fe80::1", "link_local"),
        ("ff02::1", "multicast"),
        ("2001:db8::1", "documentation"),
        ("::ffff:10.1.2.3", "private"),
    ] {
        assert_eq!(database::special_scope(ip.parse().unwrap()), Some(scope), "{ip}");
    }
    assert_eq!(database::special_scope("8.8.8.8".parse().unwrap()), None);
    assert_eq!(database::special_scope("2001:4860:4860::8888".parse().unwrap()), None);
}
#[test]
fn cache_including_misses_is_bounded_and_reusing_an_ip_does_not_grow_it() {
    let root = tempfile::tempdir().unwrap();
    let manager = GeoIpManager::new(root.path().join("geoip"));
    manager.activate(prepared(&manager, Profile::Country)).unwrap();
    for n in 0..CACHE_ENTRIES + 20 {
        manager.lookup(
            IpAddr::V4(std::net::Ipv4Addr::new(11, 0, (n / 256) as u8, (n % 256) as u8)),
            false,
        );
    }
    let state = manager.state.lock().unwrap();
    assert_eq!(state.cache.len(), CACHE_ENTRIES);
    assert_eq!(state.order.len(), CACHE_ENTRIES);
}
#[test]
fn file_types_integrity_and_release_checksums_are_enforced() {
    for kind in [Kind::Country, Kind::City, Kind::Asn] {
        assert!(Database::open(&fixture(kind), Some(kind), true).is_ok());
    }
    assert!(Database::open(&fixture(Kind::City), Some(Kind::Country), true).is_err());
    let release = Release {
        tag_name: "2026.10.22".into(),
        assets: vec![Asset {
            name: Kind::Country.filename().into(),
            size: 42,
            digest: Some(format!("sha256:{}", "a".repeat(64))),
            browser_download_url: format!(
                "https://github.com/P3TERX/GeoLite.mmdb/releases/download/2026.10.22/{}",
                Kind::Country.filename()
            ),
        }],
    };
    let selected = release.selected(Profile::Country).unwrap();
    let asset = &selected[0].1;
    assert!(download::verify_digest(asset, 42, &"a".repeat(64)).is_ok());
    assert!(download::verify_digest(asset, 41, &"a".repeat(64)).is_err());
    assert!(download::verify_digest(asset, 42, &"b".repeat(64)).is_err());
    assert!(release.selected(Profile::CountryAsn).is_err());
    let bad = Release {
        tag_name: "../escape".into(),
        assets: vec![],
    };
    assert!(bad.selected(Profile::Country).is_err());
}
#[test]
fn only_one_job_runs_and_cancellation_does_not_disable_existing_data() {
    let root = tempfile::tempdir().unwrap();
    let manager = GeoIpManager::new(root.path().join("geoip"));
    manager.activate(prepared(&manager, Profile::Country)).unwrap();
    let cancel = manager.begin_job("downloading").unwrap();
    assert!(manager.begin_job("downloading").is_err());
    assert!(manager.delete().is_err());
    assert!(manager.set_enabled(false).is_err());
    manager.cancel().unwrap();
    assert!(cancel.check().is_err());
    assert!(manager.enabled());
}
#[test]
fn invalid_state_cannot_escape_directory_and_broken_database_does_not_break_startup() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("state.json"), br#"{"enabled":true,"active":"../escape"}"#).unwrap();
    let manager = GeoIpManager::new(root.path().to_path_buf());
    assert!(!manager.enabled());
    assert!(manager.status().load_error.is_some());
    assert!(download::ensure_space(root.path(), u64::MAX).is_err());
}

#[tokio::test]
#[ignore = "downloads published databases from GitHub; run explicitly for release verification"]
async fn live_country_asn_download_progress_reload_and_update_check() {
    let root = tempfile::tempdir().unwrap();
    let manager = GeoIpManager::new(root.path().join("geoip"));
    let profile = if std::env::var_os("BANDIX_GEOIP_LIVE_CITY").is_some() {
        Profile::CityAsn
    } else {
        Profile::CountryAsn
    };
    manager.start_download(profile).unwrap();
    let mut previous = 0;
    tokio::time::timeout(std::time::Duration::from_secs(240), async {
        loop {
            let status = manager.status();
            assert!(status.job.downloaded_bytes >= previous);
            previous = status.job.downloaded_bytes;
            if !status.job.busy {
                assert_eq!(status.job.phase, "completed", "{:?}", status.job.error);
                assert_eq!(status.job.total_bytes, Some(status.job.downloaded_bytes));
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    let status = manager.status();
    eprintln!(
        "GeoIP release {}: {} bytes, {} files",
        status.version,
        status.installed_bytes,
        status.databases.len()
    );
    assert_eq!(status.databases.len(), 2);
    assert!(manager.lookup("8.8.8.8".parse().unwrap(), false).asn.is_some());
    manager.start_download(profile).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(40), async {
        while manager.status().job.busy {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(manager.status().job.phase, "up_to_date", "{:?}", manager.status().job.error);
    assert!(GeoIpManager::new(manager.directory.clone()).enabled());
}

#[tokio::test]
async fn uploaded_files_are_validated_and_merged_without_touching_the_active_generation() {
    let root = tempfile::tempdir().unwrap();
    let manager = GeoIpManager::new(root.path().join("geoip"));
    fs::create_dir_all(&manager.directory).unwrap();
    let cancel = Cancel::new();
    let asn = manager.import_path(&fixture(Kind::Asn), &cancel).await;
    assert!(asn.is_err());
    assert!(!manager.enabled());
    let city = manager.import_path(&fixture(Kind::City), &cancel).await.unwrap();
    assert_eq!(city.profile, Profile::City);
    manager.activate(city).unwrap();
    let before = manager.lookup("81.2.69.160".parse().unwrap(), false);
    let with_asn = manager.import_path(&fixture(Kind::Asn), &cancel).await.unwrap();
    assert_eq!(with_asn.profile, Profile::CityAsn);
    assert_eq!(manager.status().databases.len(), 1);
    manager.activate(with_asn).unwrap();
    assert_eq!(manager.status().databases.len(), 2);
    assert_eq!(
        manager.lookup("81.2.69.160".parse().unwrap(), false).country_code,
        before.country_code
    );
    let invalid = root.path().join("invalid.mmdb");
    fs::write(&invalid, "invalid").unwrap();
    assert!(manager.import_path(&invalid, &cancel).await.is_err());
    assert_eq!(manager.status().databases.len(), 2);
    let symlink = root.path().join("link.mmdb");
    std::os::unix::fs::symlink(fixture(Kind::City), &symlink).unwrap();
    assert!(manager.import_path(&symlink, &cancel).await.is_err());
}

#[test]
fn deleting_after_a_broken_startup_removes_owned_files_but_preserves_unrelated_data() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("geoip");
    let manager = GeoIpManager::new(path.clone());
    manager.activate(prepared(&manager, Profile::Country)).unwrap();
    fs::write(path.join("keep.txt"), "unrelated").unwrap();
    fs::create_dir(path.join("db-unrelated")).unwrap();
    fs::create_dir(path.join(".download-my-own")).unwrap();
    let active = manager.state.lock().unwrap().settings.active.clone().unwrap();
    drop(manager);
    fs::write(path.join(&active).join(Kind::Country.filename()), "broken").unwrap();
    let manager = GeoIpManager::new(path.clone());
    assert!(manager.status().load_error.is_some());
    manager.delete().unwrap();
    assert!(!path.join(active).exists());
    assert!(path.join("db-unrelated").exists());
    assert!(path.join(".download-my-own").exists());
    assert_eq!(fs::read_to_string(path.join("keep.txt")).unwrap(), "unrelated");
}

#[test]
fn updating_a_disabled_database_preserves_the_users_enable_preference() {
    let root = tempfile::tempdir().unwrap();
    let manager = GeoIpManager::new(root.path().join("geoip"));
    manager.activate(prepared(&manager, Profile::Country)).unwrap();
    manager.set_enabled(false).unwrap();
    manager.activate(prepared(&manager, Profile::CountryAsn)).unwrap();
    assert!(!manager.enabled());
    assert_eq!(manager.status().databases.len(), 2);
}
