use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt, stream::FuturesUnordered};
use quinn::{Endpoint, RecvStream, SendStream};
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::MaybeTlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{
    Message, client::IntoClientRequest, protocol::WebSocketConfig,
};
use warp_link_core::{ClientConfig, WarpLinkError};

const MAX_FRAME_LEN: usize = (32 * 1024) + 2;

#[derive(Debug)]
enum FrameReadState {
    Length { bytes: [u8; 4], read: usize },
    Payload { bytes: Vec<u8>, read: usize },
}

/// Cancellation-safe reader for the stream length-prefix framing used by warp-link.
///
/// The partial prefix and payload live in this value, so cancelling `read_frame` at any
/// `.await` point does not lose bytes that have already been consumed from the stream.
#[derive(Debug)]
pub struct FramedReader<R> {
    inner: R,
    state: FrameReadState,
}

impl<R> FramedReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            state: FrameReadState::Length {
                bytes: [0; 4],
                read: 0,
            },
        }
    }
}

impl<R> FramedReader<R>
where
    R: AsyncRead + Unpin,
{
    pub async fn read_frame(&mut self) -> Result<Vec<u8>, WarpLinkError> {
        loop {
            match &mut self.state {
                FrameReadState::Length { bytes, read } => {
                    let count = self
                        .inner
                        .read(&mut bytes[*read..])
                        .await
                        .map_err(|error| WarpLinkError::Transport(error.to_string()))?;
                    if count == 0 {
                        return Err(WarpLinkError::Transport(
                            "stream closed while reading frame length".to_string(),
                        ));
                    }
                    *read += count;
                    if *read != bytes.len() {
                        continue;
                    }
                    let len = u32::from_be_bytes(*bytes) as usize;
                    if len == 0 || len > MAX_FRAME_LEN {
                        return Err(WarpLinkError::Protocol(format!(
                            "invalid stream frame length {len}"
                        )));
                    }
                    self.state = FrameReadState::Payload {
                        bytes: vec![0; len],
                        read: 0,
                    };
                }
                FrameReadState::Payload { bytes, read } => {
                    let count = self
                        .inner
                        .read(&mut bytes[*read..])
                        .await
                        .map_err(|error| WarpLinkError::Transport(error.to_string()))?;
                    if count == 0 {
                        return Err(WarpLinkError::Transport(
                            "stream closed while reading frame payload".to_string(),
                        ));
                    }
                    *read += count;
                    if *read != bytes.len() {
                        continue;
                    }
                    let complete = std::mem::replace(
                        &mut self.state,
                        FrameReadState::Length {
                            bytes: [0; 4],
                            read: 0,
                        },
                    );
                    let FrameReadState::Payload { bytes, .. } = complete else {
                        unreachable!("payload state was matched above");
                    };
                    return Ok(bytes);
                }
            }
        }
    }
}

pub enum ClientIo {
    Quic {
        send: SendStream,
        recv: FramedReader<RecvStream>,
        _endpoint: Endpoint,
    },
    Tcp {
        writer: WriteHalf<TlsStream<TcpStream>>,
        reader: FramedReader<ReadHalf<TlsStream<TcpStream>>>,
    },
    Wss {
        stream: Box<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    },
}

impl ClientIo {
    pub async fn send_frame(
        &mut self,
        frame: &[u8],
        write_timeout_ms: u64,
    ) -> Result<(), WarpLinkError> {
        if frame.is_empty() || frame.len() > MAX_FRAME_LEN {
            return Err(WarpLinkError::Protocol(format!(
                "invalid frame len={} for stream",
                frame.len()
            )));
        }
        match self {
            ClientIo::Quic { send, .. } => {
                timeout(
                    Duration::from_millis(write_timeout_ms),
                    write_prefixed_frame(send, frame),
                )
                .await
                .map_err(|_| WarpLinkError::Timeout("quic write timeout".to_string()))??;
                Ok(())
            }
            ClientIo::Tcp { writer, .. } => {
                timeout(
                    Duration::from_millis(write_timeout_ms),
                    write_prefixed_frame(writer, frame),
                )
                .await
                .map_err(|_| WarpLinkError::Timeout("tcp write timeout".to_string()))??;
                Ok(())
            }
            ClientIo::Wss { stream } => {
                timeout(
                    Duration::from_millis(write_timeout_ms),
                    stream.send(Message::Binary(frame.to_vec().into())),
                )
                .await
                .map_err(|_| WarpLinkError::Timeout("wss write timeout".to_string()))
                .and_then(|result| result.map_err(|e| WarpLinkError::Transport(e.to_string())))?;
                Ok(())
            }
        }
    }

    pub async fn recv_frame(&mut self, idle_timeout_ms: u64) -> Result<Vec<u8>, WarpLinkError> {
        match self {
            ClientIo::Quic { recv, .. } => {
                timeout(Duration::from_millis(idle_timeout_ms), recv.read_frame())
                    .await
                    .map_err(|_| WarpLinkError::Timeout("quic read timeout".to_string()))?
            }
            ClientIo::Tcp { reader, .. } => {
                timeout(Duration::from_millis(idle_timeout_ms), reader.read_frame())
                    .await
                    .map_err(|_| WarpLinkError::Timeout("tcp read timeout".to_string()))?
            }
            ClientIo::Wss { stream } => loop {
                let next = timeout(Duration::from_millis(idle_timeout_ms), stream.next())
                    .await
                    .map_err(|_| WarpLinkError::Timeout("wss read timeout".to_string()))?;
                match next {
                    Some(Ok(Message::Binary(frame))) => {
                        if frame.is_empty() || frame.len() > MAX_FRAME_LEN {
                            return Err(WarpLinkError::Protocol(format!(
                                "invalid stream frame length {}",
                                frame.len()
                            )));
                        }
                        return Ok(frame.to_vec());
                    }
                    Some(Ok(Message::Text(_))) => {
                        return Err(WarpLinkError::Protocol(
                            "wss text frame is not supported".to_string(),
                        ));
                    }
                    Some(Ok(Message::Close(_))) => {
                        return Err(WarpLinkError::Transport("wss closed".to_string()));
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        stream
                            .send(Message::Pong(payload))
                            .await
                            .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
                    }
                    Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
                    Some(Err(err)) => return Err(WarpLinkError::Transport(err.to_string())),
                    None => return Err(WarpLinkError::Transport("wss closed".to_string())),
                }
            },
        }
    }
}

pub async fn connect_quic(config: &ClientConfig) -> Result<ClientIo, WarpLinkError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![config.quic_alpn.as_bytes().to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    let idle_timeout = quinn::IdleTimeout::try_from(Duration::from_secs(30))
        .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
    transport.max_idle_timeout(Some(idle_timeout));
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    client_config.transport_config(Arc::new(transport));

    let connect_timeout = Duration::from_millis(config.policy.connect_timeout_ms.max(1));
    let deadline = tokio::time::Instant::now() + connect_timeout;
    let addrs = timeout(
        connect_timeout,
        tokio::net::lookup_host((socket_host(config.host.as_str()), config.quic_port)),
    )
    .await
    .map_err(|_| WarpLinkError::Timeout("quic dns timeout".to_string()))?
    .map_err(|e| WarpLinkError::Transport(e.to_string()))?
    .take(16)
    .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(WarpLinkError::Transport(
            "cannot resolve quic host".to_string(),
        ));
    }
    let server_name = config
        .tls_server_name
        .as_deref()
        .unwrap_or_else(|| socket_host(config.host.as_str()))
        .to_string();
    let mut last_error = None;
    let mut attempts = FuturesUnordered::new();
    for addr in addrs {
        let bind_addr = if addr.is_ipv4() {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
        };
        let mut endpoint = match Endpoint::client(bind_addr) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                last_error = Some(WarpLinkError::Transport(error.to_string()));
                continue;
            }
        };
        endpoint.set_default_client_config(client_config.clone());
        let connecting = match endpoint.connect(addr, server_name.as_str()) {
            Ok(connecting) => connecting,
            Err(error) => {
                last_error = Some(WarpLinkError::Transport(error.to_string()));
                continue;
            }
        };
        attempts.push(async move {
            connecting
                .await
                .map(|connection| (endpoint, connection))
                .map_err(|error| WarpLinkError::Transport(error.to_string()))
        });
    }
    if attempts.is_empty() {
        return Err(last_error.unwrap_or_else(|| {
            WarpLinkError::Transport("cannot create a QUIC connection attempt".to_string())
        }));
    }
    let connected = timeout(
        deadline.saturating_duration_since(tokio::time::Instant::now()),
        async {
            while let Some(result) = attempts.next().await {
                match result {
                    Ok(connection) => return Ok(connection),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| {
                WarpLinkError::Transport("all QUIC connection attempts failed".to_string())
            }))
        },
    )
    .await
    .map_err(|_| WarpLinkError::Timeout("quic connect timeout".to_string()))?;
    let (endpoint, conn) = connected?;

    if let Some(pin) = resolve_cert_pin(
        config.quic_cert_pin_sha256.as_deref(),
        config.cert_pin_sha256.as_deref(),
    ) {
        verify_quic_pin(&conn, pin)?;
    }

    let (send, recv) = timeout(
        deadline.saturating_duration_since(tokio::time::Instant::now()),
        conn.open_bi(),
    )
    .await
    .map_err(|_| WarpLinkError::Timeout("quic open stream timeout".to_string()))
    .and_then(|r| r.map_err(|e| WarpLinkError::Transport(e.to_string())))?;

    Ok(ClientIo::Quic {
        send,
        recv: FramedReader::new(recv),
        _endpoint: endpoint,
    })
}

pub async fn connect_tcp(config: &ClientConfig) -> Result<ClientIo, WarpLinkError> {
    let connect_timeout = Duration::from_millis(config.policy.connect_timeout_ms.max(1));
    let deadline = tokio::time::Instant::now() + connect_timeout;
    let addrs = timeout(
        connect_timeout,
        tokio::net::lookup_host((socket_host(config.host.as_str()), config.tcp_port)),
    )
    .await
    .map_err(|_| WarpLinkError::Timeout("tcp dns timeout".to_string()))?
    .map_err(|e| WarpLinkError::Transport(e.to_string()))?
    .take(16)
    .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(WarpLinkError::Transport(
            "cannot resolve tcp host".to_string(),
        ));
    }
    let socket = timeout(
        deadline.saturating_duration_since(tokio::time::Instant::now()),
        TcpStream::connect(addrs.as_slice()),
    )
    .await
    .map_err(|_| WarpLinkError::Timeout("tcp connect timeout".to_string()))?
    .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
    socket
        .set_nodelay(true)
        .map_err(|e| WarpLinkError::Transport(e.to_string()))?;

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![config.tcp_alpn.as_bytes().to_vec()];

    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = config
        .tls_server_name
        .as_deref()
        .unwrap_or_else(|| socket_host(config.host.as_str()))
        .to_string();
    let server_name = ServerName::try_from(server_name)
        .map_err(|_| WarpLinkError::Transport("invalid tls server name".to_string()))?;

    let tls = timeout(
        deadline.saturating_duration_since(tokio::time::Instant::now()),
        connector.connect(server_name, socket),
    )
    .await
    .map_err(|_| WarpLinkError::Timeout("tcp tls handshake timeout".to_string()))
    .and_then(|r| r.map_err(|e| WarpLinkError::Transport(e.to_string())))?;

    if let Some(pin) = resolve_cert_pin(
        config.tcp_cert_pin_sha256.as_deref(),
        config.cert_pin_sha256.as_deref(),
    ) {
        verify_tls_pin(&tls, pin)?;
    }

    let (reader, writer) = tokio::io::split(tls);
    Ok(ClientIo::Tcp {
        writer,
        reader: FramedReader::new(reader),
    })
}

pub async fn connect_wss(config: &ClientConfig) -> Result<ClientIo, WarpLinkError> {
    let url = format!(
        "wss://{}:{}{}",
        url_host(config.host.as_str()),
        config.wss_port,
        normalize_wss_path(config.wss_path.as_str())
    );
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
    if let Some(token) = config.bearer_token.as_deref()
        && !token.trim().is_empty()
    {
        let value = format!("Bearer {}", token.trim());
        let parsed = value
            .parse()
            .map_err(|_| WarpLinkError::Internal("invalid bearer header".to_string()))?;
        request.headers_mut().insert("Authorization", parsed);
    }
    if let Some(subprotocol) = config.wss_subprotocol.as_deref()
        && !subprotocol.trim().is_empty()
    {
        let parsed = subprotocol
            .trim()
            .parse()
            .map_err(|_| WarpLinkError::Internal("invalid websocket subprotocol".to_string()))?;
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", parsed);
    }

    let websocket_config = WebSocketConfig::default()
        .read_buffer_size(MAX_FRAME_LEN.min(16 * 1024))
        .write_buffer_size(MAX_FRAME_LEN.min(16 * 1024))
        .max_write_buffer_size(MAX_FRAME_LEN * 2)
        .max_message_size(Some(MAX_FRAME_LEN))
        .max_frame_size(Some(MAX_FRAME_LEN));
    let (stream, _) = timeout(
        Duration::from_millis(config.policy.connect_timeout_ms.max(1)),
        tokio_tungstenite::connect_async_with_config(request, Some(websocket_config), true),
    )
    .await
    .map_err(|_| WarpLinkError::Timeout("wss connect timeout".to_string()))
    .and_then(|r| r.map_err(|e| WarpLinkError::Transport(e.to_string())))?;

    if let Some(pin) = resolve_cert_pin(
        config.wss_cert_pin_sha256.as_deref(),
        config.cert_pin_sha256.as_deref(),
    ) {
        verify_wss_pin(&stream, pin)?;
    }

    Ok(ClientIo::Wss {
        stream: Box::new(stream),
    })
}

fn socket_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host)
}

fn url_host(host: &str) -> String {
    let host = socket_host(host);
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

pub async fn write_prefixed_frame<W>(writer: &mut W, frame: &[u8]) -> Result<(), WarpLinkError>
where
    W: AsyncWrite + Unpin,
{
    if frame.is_empty() || frame.len() > MAX_FRAME_LEN {
        return Err(WarpLinkError::Protocol(format!(
            "invalid frame len={} for stream",
            frame.len()
        )));
    }
    let len = frame.len() as u32;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
    writer
        .write_all(frame)
        .await
        .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
    Ok(())
}

/// Compatibility helper for callers that perform one uninterrupted frame read.
///
/// Cancellation drops partial framing state. Long-lived or timeout-wrapped callers must keep a
/// [`FramedReader`] and call [`FramedReader::read_frame`] instead.
#[deprecated(note = "use FramedReader::read_frame for cancellation-safe framed reads")]
pub async fn read_prefixed_frame<R>(reader: &mut R) -> Result<Vec<u8>, WarpLinkError>
where
    R: AsyncRead + Unpin,
{
    FramedReader::new(reader).read_frame().await
}

fn normalize_wss_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return "/private/ws".to_string();
    }
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn normalize_pin(raw: &str) -> Option<String> {
    let normalized = raw
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(raw.trim())
        .replace(':', "")
        .to_lowercase();
    if normalized.len() != 64 {
        return None;
    }
    if !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(normalized)
}

fn resolve_cert_pin<'a>(specific: Option<&'a str>, shared: Option<&'a str>) -> Option<&'a str> {
    match specific.map(str::trim) {
        Some(pin) if !pin.is_empty() => Some(pin),
        _ => shared.map(str::trim).filter(|pin| !pin.is_empty()),
    }
}

fn cert_sha256_hex(cert: &[u8]) -> String {
    let digest = Sha256::digest(cert);
    hex::encode(digest)
}

fn verify_quic_pin(conn: &quinn::Connection, raw_pin: &str) -> Result<(), WarpLinkError> {
    let expected = normalize_pin(raw_pin)
        .ok_or_else(|| WarpLinkError::Protocol("invalid certificate pin".to_string()))?;
    let identity = conn
        .peer_identity()
        .ok_or_else(|| WarpLinkError::Protocol("missing quic peer identity".to_string()))?;
    let certs = identity
        .downcast_ref::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok_or_else(|| WarpLinkError::Protocol("unexpected quic peer identity type".to_string()))?;
    let leaf = certs
        .first()
        .ok_or_else(|| WarpLinkError::Protocol("missing quic peer certificate".to_string()))?;
    let actual = cert_sha256_hex(leaf.as_ref());
    if actual != expected {
        return Err(WarpLinkError::Protocol(
            "certificate pin mismatch".to_string(),
        ));
    }
    Ok(())
}

fn verify_tls_pin(tls: &TlsStream<TcpStream>, raw_pin: &str) -> Result<(), WarpLinkError> {
    let expected = normalize_pin(raw_pin)
        .ok_or_else(|| WarpLinkError::Protocol("invalid certificate pin".to_string()))?;
    let (_, conn) = tls.get_ref();
    let certs = conn
        .peer_certificates()
        .ok_or_else(|| WarpLinkError::Protocol("missing tls peer certificate".to_string()))?;
    let leaf = certs
        .first()
        .ok_or_else(|| WarpLinkError::Protocol("missing tls leaf certificate".to_string()))?;
    let actual = cert_sha256_hex(leaf.as_ref());
    if actual != expected {
        return Err(WarpLinkError::Protocol(
            "certificate pin mismatch".to_string(),
        ));
    }
    Ok(())
}

fn verify_wss_pin(
    stream: &WebSocketStream<MaybeTlsStream<TcpStream>>,
    raw_pin: &str,
) -> Result<(), WarpLinkError> {
    let expected = normalize_pin(raw_pin)
        .ok_or_else(|| WarpLinkError::Protocol("invalid certificate pin".to_string()))?;
    match stream.get_ref() {
        MaybeTlsStream::Rustls(tls) => {
            let (_, conn) = tls.get_ref();
            let certs = conn.peer_certificates().ok_or_else(|| {
                WarpLinkError::Protocol("missing wss peer certificate".to_string())
            })?;
            let leaf = certs.first().ok_or_else(|| {
                WarpLinkError::Protocol("missing wss leaf certificate".to_string())
            })?;
            let actual = cert_sha256_hex(leaf.as_ref());
            if actual != expected {
                return Err(WarpLinkError::Protocol(
                    "certificate pin mismatch".to_string(),
                ));
            }
            Ok(())
        }
        _ => Err(WarpLinkError::Protocol(
            "certificate pin requires rustls websocket stream".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_wss_path_applies_default_and_leading_slash() {
        assert_eq!(normalize_wss_path(""), "/private/ws");
        assert_eq!(normalize_wss_path("private/ws"), "/private/ws");
        assert_eq!(normalize_wss_path("/private/ws"), "/private/ws");
    }

    #[test]
    fn normalize_pin_accepts_sha256_prefix_and_colons() {
        let normalized = normalize_pin(
            "sha256:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
        )
        .expect("pin should normalize");
        assert_eq!(
            normalized,
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        );
        assert!(normalize_pin("sha256:xyz").is_none());
    }

    #[test]
    fn resolve_cert_pin_prefers_specific_then_shared() {
        assert_eq!(
            resolve_cert_pin(Some("  specific  "), Some("shared")),
            Some("specific")
        );
        assert_eq!(resolve_cert_pin(Some(""), Some("shared")), Some("shared"));
        assert_eq!(resolve_cert_pin(None, Some(" shared ")), Some("shared"));
        assert_eq!(resolve_cert_pin(None, None), None);
    }

    #[test]
    fn cert_sha256_hex_is_deterministic() {
        let digest1 = cert_sha256_hex(b"cert-bytes");
        let digest2 = cert_sha256_hex(b"cert-bytes");
        let digest3 = cert_sha256_hex(b"other-cert-bytes");
        assert_eq!(digest1, digest2);
        assert_ne!(digest1, digest3);
        assert_eq!(digest1.len(), 64);
    }

    #[tokio::test]
    async fn framed_reader_preserves_partial_prefix_and_payload_across_cancellation() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut reader = FramedReader::new(reader);

        writer
            .write_all(&[0, 0])
            .await
            .expect("partial prefix should write");
        assert!(
            timeout(Duration::from_millis(10), reader.read_frame())
                .await
                .is_err(),
            "partial prefix should time out"
        );

        writer
            .write_all(&[0, 3, b'a'])
            .await
            .expect("remaining prefix and partial payload should write");
        assert!(
            timeout(Duration::from_millis(10), reader.read_frame())
                .await
                .is_err(),
            "partial payload should time out"
        );

        writer
            .write_all(b"bc")
            .await
            .expect("remaining payload should write");
        let frame = timeout(Duration::from_millis(100), reader.read_frame())
            .await
            .expect("complete frame should not time out")
            .expect("complete frame should decode");
        assert_eq!(frame, b"abc");
    }

    #[tokio::test]
    async fn framed_reader_rejects_oversized_length_before_payload_allocation() {
        let (mut writer, reader) = tokio::io::duplex(16);
        let mut reader = FramedReader::new(reader);
        writer
            .write_all(&((MAX_FRAME_LEN as u32) + 1).to_be_bytes())
            .await
            .expect("length prefix should write");

        let error = reader
            .read_frame()
            .await
            .expect_err("oversized frame should be rejected");
        assert!(matches!(error, WarpLinkError::Protocol(_)));
    }

    #[test]
    fn ipv6_literals_are_normalized_for_sockets_and_urls() {
        assert_eq!(socket_host("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(socket_host("gateway.example"), "gateway.example");
        assert_eq!(url_host("2001:db8::1"), "[2001:db8::1]");
        assert_eq!(url_host("[2001:db8::1]"), "[2001:db8::1]");
        assert_eq!(url_host("gateway.example"), "gateway.example");
    }
}
