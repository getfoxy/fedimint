use std::sync::Arc;

use async_trait::async_trait;
use fedimint_core::module::{ApiMethod, ApiRequestErased};
#[cfg(not(target_family = "wasm"))]
use fedimint_core::rustls::install_crypto_provider;
use fedimint_core::util::{FmtCompact as _, SafeUrl};
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_logging::LOG_NET_WS;
use jsonrpsee_core::client::ClientT;
pub use jsonrpsee_core::client::Error as JsonRpcClientError;
use jsonrpsee_types::ErrorCode;
#[cfg(target_family = "wasm")]
use jsonrpsee_wasm_client::{Client as WsClient, WasmClientBuilder as WsClientBuilder};
#[allow(unused)]
#[cfg(not(target_family = "wasm"))]
use jsonrpsee_ws_client::{WsClient, WsClientBuilder};
use serde_json::Value;
use tracing::trace;
pub type JsonRpcResult<T> = Result<T, JsonRpcClientError>;

use super::Connector;
use crate::error::ConnectorError;
use crate::{
    Connectivity, DynGatewayConnection, DynGuaridianConnection, IConnection, IGuardianConnection,
    ServerError, ServerResult,
};

#[derive(Debug, Clone)]
pub struct WebsocketConnector {
    /// When set, every WebSocket is opened through this SOCKS5 proxy, with
    /// the host name resolved by the proxy (SOCKS5 "domain name" address).
    socks5: Option<std::net::SocketAddr>,
}

impl WebsocketConnector {
    pub fn new() -> Self {
        Self { socks5: None }
    }

    pub fn with_socks5(proxy: std::net::SocketAddr) -> Self {
        Self {
            socks5: Some(proxy),
        }
    }

    async fn make_new_connection(
        &self,
        url: &SafeUrl,
        api_secret: Option<&str>,
    ) -> ServerResult<Arc<WsClient>> {
        trace!(target: LOG_NET_WS, %url, "Creating new websocket connection");

        #[cfg(not(target_family = "wasm"))]
        let mut client = {
            use jsonrpsee_ws_client::{CustomCertStore, WsClientBuilder};
            use tokio_rustls::rustls::RootCertStore;

            install_crypto_provider().await;
            let webpki_roots = webpki_roots::TLS_SERVER_ROOTS.iter().cloned();
            let mut root_certs = RootCertStore::empty();
            root_certs.extend(webpki_roots);

            let tls_cfg = CustomCertStore::builder()
                .with_root_certificates(root_certs)
                .with_no_client_auth();

            WsClientBuilder::default()
                .max_concurrent_requests(u16::MAX as usize)
                .with_custom_cert_store(tls_cfg)
        };

        #[cfg(target_family = "wasm")]
        let client = WsClientBuilder::default().max_concurrent_requests(u16::MAX as usize);

        if let Some(api_secret) = api_secret {
            #[cfg(not(target_family = "wasm"))]
            {
                // on native platforms, jsonrpsee-client ignores `user:pass@...` in the Url,
                // but we can set up the headers manually

                use base64::Engine as _;
                use jsonrpsee_ws_client::{HeaderMap, HeaderValue};
                let mut headers = HeaderMap::new();

                let auth = base64::engine::general_purpose::STANDARD
                    .encode(format!("fedimint:{api_secret}"));

                headers.insert(
                    "Authorization",
                    HeaderValue::from_str(&format!("Basic {auth}")).expect("Can't fail"),
                );

                client = client.set_headers(headers);
            }
            #[cfg(target_family = "wasm")]
            {
                // on wasm, url will be handled by the browser, which should take care of
                // `user:pass@...`
                let mut url = url.clone();
                url.set_username("fedimint")
                    .map_err(|_| ServerError::InvalidEndpoint("Invalid username".into()))?;
                url.set_password(Some(&api_secret))
                    .map_err(|_| ServerError::InvalidEndpoint("Invalid secret".into()))?;

                let client = client
                    .build(url.as_str())
                    .await
                    .map_err(jsonrpc_error_to_peer_error)?;

                return Ok(Arc::new(client));
            }
        }

        #[cfg(not(target_family = "wasm"))]
        if let Some(proxy) = self.socks5 {
            return socks5_ws(proxy, url, client).await;
        }

        let client = client
            .build(url.as_str())
            .await
            .map_err(jsonrpc_error_to_peer_error)?;

        Ok(Arc::new(client))
    }
}

/// Open `url` through a SOCKS5 proxy, then TLS (for `wss`), then WebSocket.
#[cfg(not(target_family = "wasm"))]
async fn socks5_ws(
    proxy: std::net::SocketAddr,
    url: &SafeUrl,
    client: WsClientBuilder,
) -> ServerResult<Arc<WsClient>> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let conn_err = |e: String| ServerError::Connection(e.into());
    let host = url
        .host_str()
        .ok_or_else(|| ServerError::InvalidEndpoint("Expected host str".into()))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| ServerError::InvalidEndpoint("Expected port number".into()))?;
    if host.len() > 255 {
        return Err(ServerError::InvalidEndpoint("Host name too long".into()));
    }

    trace!(target: LOG_NET_WS, %proxy, %host, port, "SOCKS5 connect");
    let mut s = tokio::net::TcpStream::connect(proxy)
        .await
        .map_err(|e| conn_err(format!("SOCKS5 proxy {proxy}: {e}")))?;
    // Greeting: version 5, one method, "no authentication".
    s.write_all(&[5, 1, 0]).await.map_err(|e| conn_err(e.to_string()))?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await.map_err(|e| conn_err(e.to_string()))?;
    if reply != [5, 0] {
        return Err(conn_err(format!("SOCKS5 greeting refused: {reply:?}")));
    }
    // CONNECT by domain name, so the proxy (Tor) does the name lookup.
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.map_err(|e| conn_err(e.to_string()))?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.map_err(|e| conn_err(e.to_string()))?;
    if head[1] != 0 {
        return Err(conn_err(format!("SOCKS5 connect to {host}:{port} failed, code {}", head[1])));
    }
    let skip = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await.map_err(|e| conn_err(e.to_string()))?;
            usize::from(len[0]) + 2
        }
        other => return Err(conn_err(format!("SOCKS5 bad address type {other}"))),
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest).await.map_err(|e| conn_err(e.to_string()))?;

    let ws = match url.scheme() {
        "ws" => client.build_with_stream(url.as_str(), s).await,
        "wss" => {
            use tokio_rustls::TlsConnector;
            use tokio_rustls::rustls::{ClientConfig, RootCertStore};
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let tls = TlsConnector::from(Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            ));
            let name = rustls_pki_types::ServerName::try_from(host)
                .map_err(|e| ServerError::InvalidEndpoint(e.into()))?;
            let tls_stream = tls
                .connect(name, s)
                .await
                .map_err(|e| conn_err(e.to_string()))?;
            client.build_with_stream(url.as_str(), tls_stream).await
        }
        other => {
            return Err(ServerError::InvalidEndpoint(
                format!("Unsupported scheme: {other}").into(),
            ));
        }
    }
    .map_err(|e| conn_err(e.to_string()))?;
    Ok(Arc::new(ws))
}

impl Default for WebsocketConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Connector for WebsocketConnector {
    async fn connect_guardian(
        &self,
        url: &SafeUrl,
        api_secret: Option<&str>,
    ) -> ServerResult<DynGuaridianConnection> {
        let client = self.make_new_connection(url, api_secret).await?;
        Ok(client.into_dyn())
    }

    async fn connect_gateway(
        &self,
        _url: &SafeUrl,
    ) -> Result<DynGatewayConnection, ConnectorError> {
        Err(ConnectorError::GatewayUnsupported)
    }

    fn connectivity(&self, _url: &SafeUrl) -> Connectivity {
        Connectivity::Direct
    }
}

#[apply(async_trait_maybe_send!)]
impl IConnection for WsClient {
    async fn await_disconnection(&self) {
        self.on_disconnect().await;
    }

    fn is_connected(&self) -> bool {
        WsClient::is_connected(self)
    }
}

#[async_trait]
impl IGuardianConnection for WsClient {
    async fn request(&self, method: ApiMethod, request: ApiRequestErased) -> ServerResult<Value> {
        let method = match method {
            ApiMethod::Core(method) => method,
            ApiMethod::Module(module_id, method) => format!("module_{module_id}_{method}"),
        };

        Ok(ClientT::request(self, &method, [request.to_json()])
            .await
            .map_err(jsonrpc_error_to_peer_error)?)
    }
}

#[apply(async_trait_maybe_send!)]
impl IConnection for Arc<WsClient> {
    async fn await_disconnection(&self) {
        self.on_disconnect().await;
    }

    fn is_connected(&self) -> bool {
        WsClient::is_connected(self)
    }
}

#[async_trait]
impl IGuardianConnection for Arc<WsClient> {
    async fn request(&self, method: ApiMethod, request: ApiRequestErased) -> ServerResult<Value> {
        let method = match method {
            ApiMethod::Core(method) => method,
            ApiMethod::Module(module_id, method) => format!("module_{module_id}_{method}"),
        };

        Ok(
            ClientT::request(self.as_ref(), &method, [request.to_json()])
                .await
                .map_err(jsonrpc_error_to_peer_error)?,
        )
    }
}

fn jsonrpc_error_to_peer_error(jsonrpc_error: JsonRpcClientError) -> ServerError {
    match jsonrpc_error {
        JsonRpcClientError::Call(error_object) => {
            let message = error_object.message().to_owned();
            match ErrorCode::from(error_object.code()) {
                ErrorCode::ParseError | ErrorCode::OversizedRequest | ErrorCode::InvalidRequest => {
                    ServerError::InvalidRequest(message)
                }
                ErrorCode::MethodNotFound => ServerError::InvalidRpcId(message),
                ErrorCode::InvalidParams => ServerError::InvalidRequest(message),
                ErrorCode::InternalError | ErrorCode::ServerIsBusy | ErrorCode::ServerError(_) => {
                    ServerError::ServerError(message)
                }
            }
        }
        JsonRpcClientError::Transport(error) => ServerError::Transport(error),
        JsonRpcClientError::RestartNeeded(arc) => {
            ServerError::Transport(arc.fmt_compact().to_string().into())
        }
        JsonRpcClientError::ParseError(error) => {
            ServerError::InvalidResponse(error.fmt_compact().to_string())
        }
        JsonRpcClientError::InvalidSubscriptionId => {
            ServerError::Transport("Invalid subscription id".into())
        }
        JsonRpcClientError::InvalidRequestId(invalid_request_id) => {
            ServerError::InvalidRequest(invalid_request_id.fmt_compact().to_string())
        }
        JsonRpcClientError::RequestTimeout => ServerError::Transport("Request timeout".into()),
        JsonRpcClientError::Custom(e) => ServerError::Transport(e.into()),
        JsonRpcClientError::HttpNotImplemented => {
            ServerError::ServerError("Http not implemented".to_string())
        }
        JsonRpcClientError::EmptyBatchRequest(empty_batch_request) => {
            ServerError::InvalidRequest(empty_batch_request.fmt_compact().to_string())
        }
        JsonRpcClientError::RegisterMethod(register_method_error) => {
            ServerError::InvalidResponse(register_method_error.fmt_compact().to_string())
        }
    }
}
