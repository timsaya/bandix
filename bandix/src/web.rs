use crate::api::{parse_http_request, send_http_response, ApiRouter};
use crate::command::Options;
use chrono::Local;
use log::{debug, error, info};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

// 简单的 HTTP 服务器，仅依赖 tokio
pub async fn start_server(options: Options, api_router: ApiRouter, shutdown_notify: Arc<tokio::sync::Notify>) -> Result<(), anyhow::Error> {
    let addr = SocketAddr::new(options.host(), options.port());
    let listener = TcpListener::bind(addr).await?;
    info!("HTTP server listening on {}", listener.local_addr()?);

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let api_router = api_router.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, api_router).await {
                                error!("Error handling connection: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
            _ = shutdown_notify.notified() => {
                info!("Web server received shutdown signal, stopping...");
                break;
            }
        }
    }

    Ok(())
}

async fn handle_connection(mut stream: TcpStream, api_router: ApiRouter) -> Result<(), anyhow::Error> {
    // A JSON body can arrive in a later TCP read than its headers.
    let request = match tokio::time::timeout(std::time::Duration::from_secs(5), read_request(&mut stream))
        .await
        .map_err(anyhow::Error::from)
        .and_then(|result| result)
    {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to parse HTTP request: {}", e);
            let response = crate::api::HttpResponse::error(400, "Bad Request".to_string());
            send_http_response(&mut stream, &response).await?;
            return Ok(());
        }
    };

    // LuCI RPC runs on this router. When bound to a specific LAN address,
    // a local request uses that address as both its source and destination.
    if request.path == "/api/geoip/manage" && !is_local_management_peer(stream.peer_addr()?.ip(), stream.local_addr()?.ip()) {
        send_http_response(
            &mut stream,
            &crate::api::HttpResponse::error(403, "Local GeoIP management only".into()),
        )
        .await?;
        return Ok(());
    }

    // Log web request (always at DEBUG level, controlled by log_level parameter)
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    let query = if request.query_params.is_empty() {
        String::new()
    } else {
        request
            .query_params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&")
    };

    if query.is_empty() {
        debug!("[{}] {} {}", timestamp, request.method, request.path);
    } else {
        debug!("[{}] {} {} | params: {}", timestamp, request.method, request.path, query);
    }

    // Route request to appropriate handler
    let response = match api_router.route_request(&request).await {
        Ok(resp) => resp,
        Err(e) => {
            error!("Error handling request: {}", e);
            crate::api::HttpResponse::error(500, "Internal Server Error".to_string())
        }
    };

    // Log web response (always at DEBUG level, controlled by log_level parameter)
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    debug!("[{}] Response: {} | Body: {}", timestamp, response.status, response.body);

    // Send response
    send_http_response(&mut stream, &response).await?;

    Ok(())
}

fn is_local_management_peer(peer: IpAddr, local: IpAddr) -> bool {
    let peer = peer.to_canonical();
    peer.is_loopback() || peer == local.to_canonical()
}

/// Read one bounded Content-Length request, including fragmented JSON bodies.
async fn read_request<R: tokio::io::AsyncRead + Unpin>(stream: &mut R) -> anyhow::Result<crate::api::HttpRequest> {
    use anyhow::{bail, Context};
    const MAX_HEADERS: usize = 16 * 1024;
    const MAX_BODY: usize = 64 * 1024;
    let mut bytes = Vec::with_capacity(4096);
    let mut expected = None;
    loop {
        let mut chunk = [0; 4096];
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            bail!("Incomplete HTTP request");
        }
        bytes.extend_from_slice(&chunk[..count]);
        if expected.is_none() {
            if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                if end > MAX_HEADERS {
                    bail!("HTTP headers too large");
                }
                let headers = std::str::from_utf8(&bytes[..end])?;
                let mut content_length = None;
                for header in headers.split("\r\n").skip(1) {
                    let (name, value) = header.split_once(':').context("Invalid HTTP header")?;
                    if name.eq_ignore_ascii_case("transfer-encoding") {
                        bail!("Transfer-Encoding is not supported");
                    }
                    if name.eq_ignore_ascii_case("content-length") {
                        if content_length.is_some() {
                            bail!("Duplicate Content-Length");
                        }
                        let length = value.trim().parse::<usize>()?;
                        if length > MAX_BODY {
                            bail!("HTTP body too large");
                        }
                        content_length = Some(length);
                    }
                }
                expected = Some(end + 4 + content_length.unwrap_or(0));
            } else if bytes.len() > MAX_HEADERS {
                bail!("HTTP headers too large");
            }
        }
        if let Some(length) = expected {
            if bytes.len() >= length {
                return parse_http_request(&bytes[..length]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn management_accepts_router_itself_but_rejects_remote_peers() {
        for (peer, local, allowed) in [
            ("127.0.0.1", "192.168.2.1", true),
            ("192.168.2.1", "192.168.2.1", true),
            ("192.168.2.2", "192.168.2.1", false),
            ("::1", "fd00::1", true),
            ("fd00::1", "fd00::1", true),
            ("fd00::2", "fd00::1", false),
            ("::ffff:127.0.0.1", "::ffff:192.168.2.1", true),
            ("::ffff:192.168.2.2", "::ffff:192.168.2.1", false),
        ] {
            assert_eq!(
                is_local_management_peer(peer.parse().unwrap(), local.parse().unwrap()),
                allowed,
                "{peer} -> {local}"
            );
        }
    }

    #[tokio::test]
    async fn configured_ipv4_and_ipv6_hosts_serve_http_and_shutdown() {
        for host in ["127.0.0.2", "::1"] {
            // Reserve a free port without needing to load the eBPF modules.
            let reservation = TcpListener::bind(SocketAddr::new(host.parse().unwrap(), 0)).await.unwrap();
            let address = reservation.local_addr().unwrap();
            let options =
                Options::try_parse_from(["bandix", "--iface", "lo", "--host", host, "--port", &address.port().to_string()]).unwrap();
            let directory = tempfile::tempdir().unwrap();
            let router = ApiRouter::new(crate::geoip::GeoIpManager::new(directory.path().join("geoip")));
            let shutdown = Arc::new(tokio::sync::Notify::new());
            drop(reservation);
            let server = tokio::spawn(start_server(options, router, shutdown.clone()));
            let client = reqwest::Client::builder().no_proxy().build().unwrap();
            let response = tokio::time::timeout(std::time::Duration::from_secs(3), async {
                loop {
                    match client.get(format!("http://{address}/api/geoip/status")).send().await {
                        Ok(response) => break response,
                        Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
                    }
                }
            })
            .await;
            shutdown.notify_one();
            tokio::time::timeout(std::time::Duration::from_secs(1), server)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(response.unwrap().status(), 200, "{address}");
        }
    }

    #[tokio::test]
    async fn json_body_split_across_tcp_reads_is_complete() {
        let (mut sender, mut receiver) = tokio::io::duplex(128);
        let body = r#"{"action":"download","profile":"country_asn"}"#;
        let writer = tokio::spawn(async move {
            sender
                .write_all(
                    format!(
                        "POST /api/geoip/manage HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            tokio::task::yield_now().await;
            for chunk in body.as_bytes().chunks(7) {
                sender.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let request = read_request(&mut receiver).await.unwrap();
        assert_eq!(request.body.as_deref(), Some(body));
        writer.await.unwrap();
    }
    #[tokio::test]
    async fn oversized_and_ambiguous_requests_are_rejected() {
        for headers in [
            "Content-Length: 65537",
            "Content-Length: 1\r\nContent-Length: 1",
            "Transfer-Encoding: chunked",
        ] {
            let (mut sender, mut receiver) = tokio::io::duplex(512);
            sender
                .write_all(format!("POST /api/geoip/manage HTTP/1.1\r\n{headers}\r\n\r\n").as_bytes())
                .await
                .unwrap();
            assert!(read_request(&mut receiver).await.is_err());
        }
    }
}

#[cfg(test)]
mod geoip_http_tests {
    use super::*;
    #[tokio::test]
    async fn management_requests_round_trip_through_the_http_router_without_ebpf() {
        let directory = tempfile::tempdir().unwrap();
        let router = ApiRouter::new(crate::geoip::GeoIpManager::new(directory.path().join("geoip")));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..4 {
                let (stream, _) = listener.accept().await.unwrap();
                handle_connection(stream, router.clone()).await.unwrap();
            }
        });
        let client = reqwest::Client::new();
        let status: serde_json::Value = client
            .get(format!("http://{address}/api/geoip/status"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(status["data"]["enabled"], false);
        for (action, expected_status) in [
            (serde_json::json!({"action":"enable","enabled":true}), 400),
            (serde_json::json!({"action":"download","profile":"invalid"}), 400),
            (serde_json::json!({"action":"enable","enabled":false}), 200),
        ] {
            let response = client
                .post(format!("http://{address}/api/geoip/manage"))
                .json(&action)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), expected_status);
            let body: serde_json::Value = response.json().await.unwrap();
            assert_eq!(body["status"], if expected_status == 200 { "success" } else { "error" });
        }
        server.await.unwrap();
    }
}
