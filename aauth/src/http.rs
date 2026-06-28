use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::Value;

use crate::error::{HttpError, Result};

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn text(&self) -> Result<String> {
        String::from_utf8(self.body.clone())
            .map_err(|e| crate::error::AAuthError::Message(e.to_string()))
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body)
            .map_err(|e| crate::error::AAuthError::Message(e.to_string()))
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&lower))
            .map(|(_, v)| v.as_str())
    }

    pub fn ok(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

#[derive(Debug, Clone, Default)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn send(&self, request: HttpRequest) -> std::result::Result<HttpResponse, HttpError>;
}

#[cfg(feature = "client")]
pub struct ReqwestClient {
    inner: reqwest::Client,
}

#[cfg(feature = "client")]
impl Default for ReqwestClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "client")]
impl ReqwestClient {
    pub fn new() -> Self {
        Self {
            inner: reqwest::Client::new(),
        }
    }
}

#[cfg(feature = "client")]
#[async_trait]
impl HttpClient for ReqwestClient {
    async fn send(&self, request: HttpRequest) -> std::result::Result<HttpResponse, HttpError> {
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|e| HttpError::Request(e.to_string()))?;
        let mut builder = self.inner.request(method, &request.url);
        for (key, value) in request.headers {
            builder = builder.header(key, value);
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        let response = builder
            .send()
            .await
            .map_err(|e| HttpError::Request(e.to_string()))?;
        let status = response.status().as_u16();
        let mut headers = HashMap::new();
        for (key, value) in response.headers().iter() {
            if let Ok(v) = value.to_str() {
                headers.insert(key.as_str().to_string(), v.to_string());
            }
        }
        let body = response
            .bytes()
            .await
            .map_err(|e| HttpError::Request(e.to_string()))?
            .to_vec();
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

/// In-memory HTTP router for integration tests.
pub type RouteHandler =
    Arc<dyn Fn(HttpRequest) -> std::result::Result<HttpResponse, HttpError> + Send + Sync>;

#[derive(Clone, Default)]
pub struct MockHttpClient {
    routes: Arc<Mutex<Vec<(String, RouteHandler)>>>,
    fallback: Arc<Mutex<Option<RouteHandler>>>,
}

impl MockHttpClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn on<F>(self, prefix: impl Into<String>, handler: F) -> Self
    where
        F: Fn(HttpRequest) -> std::result::Result<HttpResponse, HttpError> + Send + Sync + 'static,
    {
        self.routes
            .lock()
            .unwrap()
            .push((prefix.into(), Arc::new(handler)));
        self
    }

    pub fn fallback<F>(self, handler: F) -> Self
    where
        F: Fn(HttpRequest) -> std::result::Result<HttpResponse, HttpError> + Send + Sync + 'static,
    {
        *self.fallback.lock().unwrap() = Some(Arc::new(handler));
        self
    }
}

#[async_trait]
impl HttpClient for MockHttpClient {
    async fn send(&self, request: HttpRequest) -> std::result::Result<HttpResponse, HttpError> {
        let routes = self.routes.lock().unwrap().clone();
        for (prefix, handler) in routes {
            if request.url.starts_with(&prefix) || request.url.contains(&prefix) {
                return handler(request);
            }
        }
        if let Some(fallback) = self.fallback.lock().unwrap().clone() {
            return fallback(request);
        }
        Err(HttpError::Status {
            status: 404,
            body: format!("no route for {}", request.url),
        })
    }
}

pub fn json_response(status: u16, value: &Value) -> HttpResponse {
    HttpResponse {
        status,
        headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
        body: serde_json::to_vec(value).unwrap_or_default(),
    }
}

pub fn empty_response(status: u16) -> HttpResponse {
    HttpResponse {
        status,
        headers: HashMap::new(),
        body: Vec::new(),
    }
}

pub fn response_with_headers(status: u16, headers: HashMap<String, String>) -> HttpResponse {
    HttpResponse {
        status,
        headers,
        body: Vec::new(),
    }
}
