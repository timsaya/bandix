use super::{ApiResponse, HttpRequest, HttpResponse};
use crate::geoip::{GeoIpManager, Profile};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    Download { profile: Profile },
    Cancel,
    Enable { enabled: bool },
    Delete,
    Import,
}

pub async fn handle_request(manager: &Arc<GeoIpManager>, request: &HttpRequest) -> anyhow::Result<HttpResponse> {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/api/geoip/status") => Ok(HttpResponse::ok(serde_json::to_string(&ApiResponse::success(
            manager.status(),
        ))?)),
        ("POST", "/api/geoip/manage") => {
            let action = match serde_json::from_str::<Action>(request.body.as_deref().unwrap_or("")) {
                Ok(action) => action,
                Err(_) => return Ok(HttpResponse::error(400, "Invalid GeoIP action".into())),
            };
            let result = match action {
                Action::Download { profile } => manager.start_download(profile),
                Action::Cancel => manager.cancel(),
                Action::Enable { enabled } => manager.set_enabled(enabled),
                Action::Delete => manager.delete(),
                Action::Import => manager.start_import(),
            };
            match result {
                Ok(()) => Ok(HttpResponse::ok(serde_json::to_string(&ApiResponse::success(
                    manager.status(),
                ))?)),
                Err(error) => Ok(HttpResponse::error(400, format!("{error:#}"))),
            }
        }
        _ => Ok(HttpResponse::not_found()),
    }
}
