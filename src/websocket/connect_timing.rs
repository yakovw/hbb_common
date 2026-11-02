//! Opt-in connection spans, with the pinned connector and no endpoint/payload data.
use std::{future::Future, sync::Arc, time::{Duration, Instant}};
use tokio::{io::{AsyncRead, AsyncWrite}, net::TcpStream};
use tokio_tungstenite::{client_async_tls_with_config, client_async_with_config,
    Connector, MaybeTlsStream, WebSocketStream};
use tungstenite::{client::uri_mode, error::{Error, TlsError, UrlError},
    handshake::client::{Request, Response}, protocol::WebSocketConfig, stream::Mode};

pub struct ConnectEvent {
    pub attempt: u8,
    pub phase: &'static str,
    pub backend: &'static str,
    pub accepts_invalid_certs: bool,
    pub started: Instant,
    pub elapsed: Duration,
    pub outcome: &'static str,
}
pub type ConnectObserver = Arc<dyn Fn(ConnectEvent) + Send + Sync>;

pub(super) struct Attempt {
    observer: Option<ConnectObserver>, index: u8, backend: &'static str, accepts_invalid_certs: bool,
}
impl Attempt {
    pub fn new(observer: Option<ConnectObserver>, index: u8, backend: &'static str, accepts_invalid_certs: bool) -> Self {
        Self { observer, index, backend, accepts_invalid_certs }
    }
    pub fn enabled(&self) -> bool { self.observer.is_some() }
    pub fn start(&self, phase: &'static str) -> Option<Span> {
        self.observer.as_ref().map(|observer| Span { observer:observer.clone(), phase, index:self.index,
            backend:self.backend, accepts_invalid_certs:self.accepts_invalid_certs,
            started:Instant::now(), outcome:"cancelled" })
    }
}
pub(super) struct Span {
    observer: ConnectObserver, phase: &'static str, index: u8, backend: &'static str,
    accepts_invalid_certs: bool, started: Instant, outcome: &'static str,
}
impl Span { pub fn finish(mut self, success: bool) { self.outcome = if success { "completed" } else { "failed" }; } }
impl Drop for Span {
    fn drop(&mut self) {
        (self.observer)(ConnectEvent { attempt:self.index, phase:self.phase, backend:self.backend,
            accepts_invalid_certs:self.accepts_invalid_certs, started:self.started,
            elapsed:self.started.elapsed(), outcome:self.outcome });
    }
}
pub(super) async fn measured<T, E>(attempt: &Attempt, phase: &'static str,
    future: impl Future<Output = Result<T, E>>) -> Result<T, E> {
    let span = attempt.start(phase);
    let result = future.await;
    if let Some(span) = span { span.finish(result.is_ok()); }
    result
}
fn domain(request: &Request) -> Result<String, Error> {
    // Same IPv6 normalization as pinned tokio-tungstenite c241b11::domain.
    match request.uri().host() {
        Some(host) if host.starts_with('[') && host.ends_with(']') => Ok(host[1..host.len()-1].to_owned()),
        Some(host) => Ok(host.to_owned()),
        None => Err(Error::Url(UrlError::NoHostName)),
    }
}
pub(super) async fn direct(request: Request, config: Option<WebSocketConfig>, disable_nagle: bool,
    connector: Option<Connector>, attempt: &Attempt)
    -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), Error> {
    let domain = domain(&request)?;
    let port = request.uri().port_u16().or_else(|| match request.uri().scheme_str() {
        Some("wss") => Some(443), Some("ws") => Some(80), _ => None,
    }).ok_or(Error::Url(UrlError::UnsupportedUrlScheme))?;
    // Tokio TcpStream::connect(String) uses the same lookup_host and sequential
    // address iteration. Preserve the pinned address formatting and NODELAY.
    let address = format!("{domain}:{port}");
    let addresses = measured(attempt, "dns", tokio::net::lookup_host(address.as_str())).await
        .map_err(Error::Io)?.collect::<Vec<_>>();
    let socket = measured(attempt, "tcp", TcpStream::connect(addresses.as_slice())).await.map_err(Error::Io)?;
    if disable_nagle { socket.set_nodelay(true)?; }
    handshake(request, socket, config, connector, attempt).await
}
pub(super) async fn handshake<S>(request: Request, socket: S, config: Option<WebSocketConfig>,
    connector: Option<Connector>, attempt: &Attempt)
    -> Result<(WebSocketStream<MaybeTlsStream<S>>, Response), Error>
where S: 'static + AsyncRead + AsyncWrite + Send + Unpin {
    let domain = domain(&request)?;
    let mode = uri_mode(request.uri())?;
    let stream = match (mode, connector) {
        (Mode::Plain, Some(Connector::Plain | Connector::NativeTls(_) | Connector::Rustls(_))) => MaybeTlsStream::Plain(socket),
        (Mode::Tls, Some(Connector::Plain)) => {
            return measured(attempt, "tls", async { Err(Error::Url(UrlError::TlsFeatureNotEnabled)) }).await;
        }
        (Mode::Tls, Some(Connector::NativeTls(connector))) => measured(attempt, "tls", async {
            tokio_native_tls::TlsConnector::from(connector).connect(&domain, socket).await
                .map(MaybeTlsStream::NativeTls).map_err(|error| Error::Tls(error.into()))
        }).await?,
        (Mode::Tls, Some(Connector::Rustls(config))) => measured(attempt, "tls", async {
            let domain = rustls_pki_types::ServerName::try_from(domain.as_str())
                .map_err(|_| TlsError::InvalidDnsName)?.to_owned();
            tokio_rustls::TlsConnector::from(config).connect(domain, socket).await
                .map(MaybeTlsStream::Rustls).map_err(Error::Io)
        }).await?,
        // None/future backends keep the exact original default/root policy.
        // They remain explicitly composite rather than inventing phase times.
        (_, other) => return measured(attempt, "delegated-tls-upgrade",
            client_async_tls_with_config(request, socket, config, other)).await,
    };
    measured(attempt, "upgrade", client_async_with_config(request, stream, config)).await
}
