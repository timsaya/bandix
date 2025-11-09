use crate::api::{parse_http_request, send_http_response, ApiRouter};
use crate::command::Options;
use chrono::Local;
use log::{debug, error, info};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

// Simple HTTP server, only depends on tokio
pub async fn start_server(
    options: Options,
    api_router: ApiRouter,
    shutdown_notify: Arc<tokio::sync::Notify>,
) -> Result<(), anyhow::Error> {
    // In release mode, only listen on localhost for security
    // In debug mode, listen on all interfaces for easier development
    let host = if cfg!(debug_assertions) {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    };
    let addr = format!("{}:{}", host, options.port());
    let listener = TcpListener::bind(&addr).await?;
    info!("HTTP server listening on {}", addr);

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

async fn handle_connection(
    mut stream: TcpStream,
    api_router: ApiRouter,
) -> Result<(), anyhow::Error> {
    let mut buffer = [0; 4096]; // Increase buffer size to handle larger requests
    let n = stream.read(&mut buffer).await?;

    // Parse HTTP request
    let request = match parse_http_request(&buffer[..n]) {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to parse HTTP request: {}", e);
            let response = crate::api::HttpResponse::error(400, "Bad Request".to_string());
            send_http_response(&mut stream, &response).await?;
            return Ok(());
        }
    };

    // Log web request (always at DEBUG level, controlled by log_level parameter)
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    let query = if request.query_params.is_empty() {
        String::new()
    } else {
        request.query_params.iter()
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
    let response_body_preview = if response.body.len() > 200 {
        format!("{}...", &response.body[..200])
    } else {
        response.body.clone()
    };
    debug!("[{}] Response: {} | Body: {}", timestamp, response.status, response_body_preview);

    // Send response
    send_http_response(&mut stream, &response).await?;

    Ok(())
}

