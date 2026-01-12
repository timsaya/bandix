pub mod connection;
pub mod dns;
pub mod traffic;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::net::TcpStream;

/// API 响应结构
#[derive(Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub status: String,
    pub data: Option<T>,
    pub message: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            status: "success".to_string(),
            data: Some(data),
            message: None,
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            status: "error".to_string(),
            data: None,
            message: Some(message),
        }
    }
}

/// HTTP 请求信息
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub query_params: HashMap<String, String>,
    pub body: Option<String>,
}

/// HTTP 响应
#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: String,
    pub body: String,
}

impl HttpResponse {
    pub fn ok(body: String) -> Self {
        Self {
            status: 200,
            content_type: "application/json".to_string(),
            body,
        }
    }

    pub fn error(status: u16, message: String) -> Self {
        let error_response = ApiResponse::<()>::error(message);
        let body = serde_json::to_string(&error_response)
            .unwrap_or_else(|_| r#"{"status":"error","message":"JSON serialization failed"}"#.to_string());
        Self {
            status,
            content_type: "application/json".to_string(),
            body,
        }
    }

    pub fn not_found() -> Self {
        Self {
            status: 404,
            content_type: "text/plain".to_string(),
            body: "Not Found".to_string(),
        }
    }
}

/// 不同模块的 API 处理程序枚举
#[derive(Clone)]
pub enum ApiHandler {
    Traffic(crate::api::traffic::TrafficApiHandler),
    Dns(crate::api::dns::DnsApiHandler),
    Connection(crate::api::connection::ConnectionApiHandler),
}

impl ApiHandler {
    pub fn module_name(&self) -> &'static str {
        match self {
            ApiHandler::Traffic(_) => "traffic",
            ApiHandler::Dns(_) => "dns",
            ApiHandler::Connection(_) => "connection",
        }
    }

    pub fn supported_routes(&self) -> Vec<&'static str> {
        match self {
            ApiHandler::Traffic(handler) => handler.supported_routes(),
            ApiHandler::Dns(handler) => handler.supported_routes(),
            ApiHandler::Connection(handler) => handler.supported_routes(),
        }
    }

    pub async fn handle_request(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        match self {
            ApiHandler::Traffic(handler) => handler.handle_request(request).await,
            ApiHandler::Dns(handler) => handler.handle_request(request).await,
            ApiHandler::Connection(handler) => handler.handle_request(request).await,
        }
    }
}

/// API 路由器，用于管理模块 API 处理程序
#[derive(Clone)]
pub struct ApiRouter {
    handlers: HashMap<String, ApiHandler>,
}

impl ApiRouter {
    pub fn new() -> Self {
        Self { handlers: HashMap::new() }
    }

    /// Register an API handler for a module
    pub fn register_handler(&mut self, handler: ApiHandler) {
        self.handlers.insert(handler.module_name().to_string(), handler);
    }

    /// Route a request to the appropriate handler
    pub async fn route_request(&self, request: &HttpRequest) -> Result<HttpResponse, anyhow::Error> {
        // Try to find a handler that supports this route
        for handler in self.handlers.values() {
            for route in handler.supported_routes() {
                if request.path.starts_with(route) {
                    return handler.handle_request(request).await;
                }
            }
        }

        // No handler found
        Ok(HttpResponse::not_found())
    }
}

/// 从原始字节解析 HTTP 请求
pub fn parse_http_request(request_bytes: &[u8]) -> Result<HttpRequest, anyhow::Error> {
    let request_str = String::from_utf8_lossy(request_bytes);
    let lines: Vec<&str> = request_str.lines().collect();

    if lines.is_empty() {
        return Err(anyhow::anyhow!("Empty request"));
    }

    // 解析request line
    let parts: Vec<&str> = lines[0].split_whitespace().collect();
    if parts.len() < 2 {
        return Err(anyhow::anyhow!("Invalid request line"));
    }

    let method = parts[0].to_string();
    let path_with_query = parts[1];

    // 分割path and query parameters
    let (path, query_str) = if let Some(pos) = path_with_query.find('?') {
        (path_with_query[..pos].to_string(), Some(&path_with_query[pos + 1..]))
    } else {
        (path_with_query.to_string(), None)
    };

    // 解析query parameters
    let mut query_params = HashMap::new();
    if let Some(query) = query_str {
        for param in query.split('&') {
            if let Some(eq_pos) = param.find('=') {
                let key = param[..eq_pos].to_string();
                let value = param[eq_pos + 1..].to_string();
                query_params.insert(key, value);
            }
        }
    }

    // 解析body (if present)
    let body = if let Some(body_start) = request_str.find("\r\n\r\n") {
        Some(request_str[body_start + 4..].to_string())
    } else {
        None
    };

    Ok(HttpRequest {
        method,
        path,
        query_params,
        body,
    })
}

/// 向客户端发送 HTTP 响应
pub async fn send_http_response(stream: &mut TcpStream, response: &HttpResponse) -> Result<(), anyhow::Error> {
    use tokio::io::AsyncWriteExt;

    let status_text = match response.status {
        200 => "OK",
        400 => "BAD REQUEST",
        404 => "Not Found",
        500 => "INTERNAL SERVER ERROR",
        _ => "UNKNOWN",
    };

    let http_response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n{}",
        response.status,
        status_text,
        response.content_type,
        response.body.len(),
        response.body
    );

    stream.write_all(http_response.as_bytes()).await?;
    Ok(())
}
