use super::*;
use crate::command::SubnetInfo;
use crate::device::DeviceManager;
use clap::Parser;
use serde_json::{json, Value};

const FIRST: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0xaa];
const SECOND: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0xbb];

fn handler(directory: &tempfile::TempDir) -> TrafficApiHandler {
    let base = directory.path().to_str().unwrap();
    traffic::ensure_schema(base).unwrap();
    let options = Options::parse_from(["bandix", "--iface", "test0", "--data-dir", base]);
    let bindings = Arc::new(Mutex::new(HashMap::new()));
    let devices = Arc::new(DeviceManager::new(
        "test0".into(),
        SubnetInfo {
            interface_ip: [192, 168, 1, 1],
            subnet_mask: [255, 255, 255, 0],
            interface_mac: [0x02, 0, 0, 0, 0, 1],
            ipv6_addresses: Vec::new(),
        },
        vec![([192, 168, 1, 0], [255, 255, 255, 0])],
        bindings.clone(),
        false,
    ));
    for mac in [FIRST, SECOND] {
        devices.add_offline_device(mac, Some([192, 168, 1, mac[5]]));
    }
    TrafficApiHandler::new_with_rate_limit_whitelist(
        Arc::new(Mutex::new(Vec::new())),
        bindings,
        Arc::new(Mutex::new(HashSet::new())),
        Arc::new(AtomicBool::new(true)),
        Arc::new(Mutex::new([1024, 2048])),
        Arc::new(Mutex::new(TrafficQuotaManager::new(base))),
        Arc::new(RealtimeRingManager::new(base.into(), 600)),
        Arc::new(LongTermRingManager::new(base.into(), 600)),
        devices,
        None,
        Arc::new(Mutex::new(HashMap::new())),
        options,
    )
}

fn request(method: &str, path: &str, body: Option<String>) -> HttpRequest {
    HttpRequest {
        method: method.into(),
        path: path.into(),
        query_params: HashMap::new(),
        body,
    }
}

fn batch(body: Value) -> HttpRequest {
    request("DELETE", "/api/traffic/devices/batch", Some(body.to_string()))
}

#[tokio::test]
async fn batch_deletion_routes_deduplicates_and_reports_missing_devices() {
    let directory = tempfile::tempdir().unwrap();
    let handler = handler(&directory);
    let mut router = super::super::ApiRouter::new(crate::geoip::GeoIpManager::new(directory.path().join("geoip")));
    router.register_handler(super::super::ApiHandler::Traffic(handler.clone()));
    let req = batch(json!({"macs": [format_mac(&FIRST), format_mac(&FIRST).to_uppercase(),
        "02:11:22:33:44:cc", format_mac(&SECOND)]}));
    let response = router.route_request(&req).await.unwrap();
    assert_eq!(response.status, 200);
    let body: Value = serde_json::from_str(&response.body).unwrap();
    assert_eq!(body["status"], "success");
    assert_eq!(body["data"]["deleted"], json!([format_mac(&FIRST), format_mac(&SECOND)]));
    assert_eq!(body["data"]["not_found"], json!(["02:11:22:33:44:cc"]));
    assert_eq!(body["data"]["failed"], json!([]));
    assert!(handler.device_manager.get_all_devices_with_mac().is_empty());

    let repeat = router.route_request(&req).await.unwrap();
    let body: Value = serde_json::from_str(&repeat.body).unwrap();
    assert_eq!(body["data"]["deleted"], json!([]));
    assert_eq!(body["data"]["not_found"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn invalid_batch_requests_do_not_delete_any_devices() {
    let directory = tempfile::tempdir().unwrap();
    let handler = handler(&directory);
    for body in [
        None,
        Some("{".into()),
        Some("{}".into()),
        Some(json!({"macs": "02:11:22:33:44:aa"}).to_string()),
        Some(json!({"macs": []}).to_string()),
        Some(json!({"macs": [format_mac(&FIRST), "invalid"]}).to_string()),
        Some(json!({"macs": [format_mac(&FIRST), 123]}).to_string()),
        Some(json!({"macs": vec![format_mac(&FIRST); 1001]}).to_string()),
    ] {
        let response = handler
            .handle_request(&request("DELETE", "/api/traffic/devices/batch", body))
            .await
            .unwrap();
        assert_eq!(response.status, 400, "{}", response.body);
        assert_eq!(handler.device_manager.get_all_devices_with_mac().len(), 2);
    }
    let response = handler
        .handle_request(&request("POST", "/api/traffic/devices/batch", None))
        .await
        .unwrap();
    assert_eq!(response.status, 405);
    assert_eq!(handler.device_manager.get_all_devices_with_mac().len(), 2);
}

#[tokio::test]
async fn batch_deletion_cleans_history_and_persisted_policies_only_for_selected_devices() {
    let directory = tempfile::tempdir().unwrap();
    let handler = handler(&directory);
    let base = directory.path().to_str().unwrap();
    let now = chrono::Local::now();
    for mac in [FIRST, SECOND] {
        handler.hostname_bindings.lock().unwrap().insert(mac, "test-device".into());
        traffic::upsert_hostname_binding(base, &mac, "test-device").unwrap();
        handler.rate_limit_whitelist.lock().unwrap().insert(mac);
        handler
            .scheduled_rate_limits
            .lock()
            .unwrap()
            .push(ScheduledRateLimit::new(mac, TimeSlot::all_time(), 10, 20));
        let mut quotas = handler.traffic_quota_manager.lock().unwrap();
        quotas.set_quota(
            mac,
            TrafficQuota {
                total_bytes: 100,
                ..Default::default()
            },
            &now,
        );
        quotas.record_usage(&mac, 50, &now);
        handler.last_ebpf_traffic.lock().unwrap().insert(mac, [1; 4]);
    }
    save_all_scheduled_limits(base, &handler.scheduled_rate_limits.lock().unwrap()).unwrap();
    handler.traffic_quota_manager.lock().unwrap().save().unwrap();
    let rows = handler.device_manager.get_all_devices_with_mac();
    // An hourly boundary creates both in-memory history and real ring files.
    handler.realtime_manager.insert_metrics_batch(3_600_000, &rows).unwrap();
    handler.long_term_manager.insert_metrics_batch(3_600_000, &rows).unwrap();
    handler.long_term_manager.insert_metrics_batch(3_601_000, &rows).unwrap();
    handler.long_term_manager.save_accumulators().unwrap();
    assert_eq!(handler.long_term_manager.load_from_files().unwrap().len(), 2);

    let response = handler
        .handle_request(&batch(json!({"macs": [format_mac(&FIRST)]})))
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    let body: Value = serde_json::from_str(&response.body).unwrap();
    assert_eq!(body["data"]["deleted"], json!([format_mac(&FIRST)]));
    assert!(handler.device_manager.get_device_by_mac(&FIRST).is_none());
    assert!(handler.device_manager.get_device_by_mac(&SECOND).is_some());
    assert!(handler
        .realtime_manager
        .query_metrics_by_mac(&FIRST, 0, u64::MAX)
        .unwrap()
        .is_empty());
    assert!(!handler
        .realtime_manager
        .query_metrics_by_mac(&SECOND, 0, u64::MAX)
        .unwrap()
        .is_empty());
    assert!(handler
        .long_term_manager
        .query_stats_by_mac(&FIRST, 0, u64::MAX)
        .unwrap()
        .is_empty());
    assert!(!handler
        .long_term_manager
        .get_active_accumulators_with_stats()
        .contains_key(&FIRST));
    let remaining = handler.long_term_manager.load_from_files().unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].0, SECOND);
    let restored_history = LongTermRingManager::new(base.into(), 600);
    restored_history.load_accumulators().unwrap();
    let restored = restored_history.get_active_accumulators_with_stats();
    assert!(!restored.contains_key(&FIRST));
    assert!(restored.contains_key(&SECOND));
    assert!(!handler.hostname_bindings.lock().unwrap().contains_key(&FIRST));
    assert_eq!(
        crate::storage::hostname::load_hostname_bindings(base).unwrap(),
        vec![(SECOND, "test-device".into())]
    );
    assert_eq!(
        traffic::load_rate_limit_policy(base).unwrap().whitelist,
        HashSet::from([SECOND])
    );
    assert_eq!(handler.rate_limit_whitelist.lock().unwrap().clone(), HashSet::from([SECOND]));
    assert_eq!(handler.scheduled_rate_limits.lock().unwrap().len(), 1);
    assert_eq!(traffic::load_all_scheduled_limits(base).unwrap()[0].mac, SECOND);
    assert!(handler.traffic_quota_manager.lock().unwrap().status(&FIRST, &now).is_none());
    let mut reloaded = TrafficQuotaManager::new(base);
    reloaded.load().unwrap();
    assert!(reloaded.status(&FIRST, &now).is_none());
    assert_eq!(reloaded.status(&SECOND, &now).unwrap().total_used_bytes, 50);
    assert!(!handler.last_ebpf_traffic.lock().unwrap().contains_key(&FIRST));
    assert!(handler.last_ebpf_traffic.lock().unwrap().contains_key(&SECOND));

    handler.handle_request(&batch(json!({"macs": [format_mac(&SECOND)]}))).await.unwrap();
    assert!(!directory.path().join("metrics/longterm/accumulator.json").exists());
}

#[tokio::test]
async fn batch_deletion_reports_cleanup_failures_and_continues() {
    let directory = tempfile::tempdir().unwrap();
    let handler = handler(&directory);
    // A directory at the ring-file path makes remove_file fail for FIRST only.
    let filename = format!("{}.ring", format_mac(&FIRST).replace(':', ""));
    std::fs::create_dir(directory.path().join("metrics/longterm").join(filename)).unwrap();
    let response = handler
        .handle_request(&batch(json!({"macs": [format_mac(&FIRST), format_mac(&SECOND)]})))
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    let body: Value = serde_json::from_str(&response.body).unwrap();
    assert_eq!(body["data"]["deleted"], json!([format_mac(&SECOND)]));
    assert_eq!(body["data"]["failed"].as_array().unwrap().len(), 1);
    assert_eq!(body["data"]["failed"][0]["mac"], format_mac(&FIRST));
    assert!(!body["data"]["failed"][0]["message"].as_str().unwrap().is_empty());
    assert!(handler.device_manager.get_device_by_mac(&SECOND).is_none());
}

#[tokio::test]
async fn single_device_deletion_keeps_existing_response_contract() {
    let directory = tempfile::tempdir().unwrap();
    let handler = handler(&directory);
    let req = request(
        "DELETE",
        "/api/traffic/devices",
        Some(json!({"mac": format_mac(&FIRST)}).to_string()),
    );
    let response = handler.handle_request(&req).await.unwrap();
    assert_eq!(response.status, 200);
    let body: Value = serde_json::from_str(&response.body).unwrap();
    assert_eq!(body["status"], "success");
    assert!(body["data"].is_null());
    assert_eq!(handler.handle_request(&req).await.unwrap().status, 404);
    assert!(handler.device_manager.get_device_by_mac(&SECOND).is_some());
}
