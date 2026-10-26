use super::{ApiResponse, HttpRequest, HttpResponse};
use serde::Serialize;

#[derive(Serialize)]
struct SystemInfo {
    version: &'static str,
}

pub fn handle_request(request: &HttpRequest) -> anyhow::Result<HttpResponse> {
    if request.path != "/api/system/info" {
        return Ok(HttpResponse::not_found());
    }
    if request.method != "GET" {
        return Ok(HttpResponse::error(405, "Method not allowed".into()));
    }

    let info = SystemInfo {
        version: env!("CARGO_PKG_VERSION"),
    };
    Ok(HttpResponse::ok(serde_json::to_string(&ApiResponse::success(info))?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ApiRouter;
    use serde_json::json;
    use std::collections::HashMap;

    #[tokio::test]
    async fn version_is_available_without_monitors_and_other_methods_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let geoip_path = directory.path().join("geoip");
        let router = ApiRouter::new(crate::geoip::GeoIpManager::new(geoip_path.clone()));
        let mut request = HttpRequest {
            method: "GET".into(),
            path: "/api/system/info".into(),
            query_params: HashMap::new(),
            body: None,
        };
        let response = router.route_request(&request).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.content_type, "application/json");
        let body: serde_json::Value = serde_json::from_str(&response.body).unwrap();
        assert_eq!(
            body,
            json!({"status": "success", "data": {"version": env!("CARGO_PKG_VERSION")}, "message": null})
        );

        for method in ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] {
            request.method = method.into();
            assert_eq!(router.route_request(&request).await.unwrap().status, 405, "{method}");
        }
        request.method = "GET".into();
        request.path = "/api/system/info/extra".into();
        assert_eq!(router.route_request(&request).await.unwrap().status, 404);
        assert!(!geoip_path.exists());
    }
}
