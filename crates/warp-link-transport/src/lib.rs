use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
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
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};
use warp_link_core::{ClientConfig, WarpLinkError};

const MAX_FRAME_LEN: usize = (32 * 1024) + 2;

pub enum ClientIo {
    Quic {
        send: SendStream,
        recv: RecvStream,
        _endpoint: Endpoint,
    },
    Tcp {
        writer: WriteHalf<TlsStream<TcpStream>>,
        reader: ReadHalf<TlsStream<TcpStream>>,
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
            ClientIo::Quic { recv, .. } => timeout(
                Duration::from_millis(idle_timeout_ms),
                read_prefixed_frame(recv),
            )
            .await
            .map_err(|_| WarpLinkError::Timeout("quic read timeout".to_string()))?,
            ClientIo::Tcp { reader, .. } => timeout(
                Duration::from_millis(idle_timeout_ms),
                read_prefixed_frame(reader),
            )
            .await
            .map_err(|_| WarpLinkError::Timeout("tcp read timeout".to_string()))?,
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

    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    let mut endpoint =
        Endpoint::client(bind_addr).map_err(|e| WarpLinkError::Transport(e.to_string()))?;
    endpoint.set_default_client_config(client_config);

    let mut addrs = tokio::net::lookup_host((config.host.as_str(), config.quic_port))
        .await
        .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
    let addr = addrs
        .next()
        .ok_or_else(|| WarpLinkError::Transport("cannot resolve quic host".to_string()))?;
    let server_name = config
        .tls_server_name
        .as_deref()
        .unwrap_or(config.host.as_str())
        .to_string();
    let connecting = endpoint
        .connect(addr, server_name.as_str())
        .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
    let conn = timeout(
        Duration::from_millis(config.policy.connect_timeout_ms),
        connecting,
    )
    .await
    .map_err(|_| WarpLinkError::Timeout("quic connect timeout".to_string()))
    .and_then(|r| r.map_err(|e| WarpLinkError::Transport(e.to_string())))?;

    if let Some(pin) = resolve_cert_pin(
        config.quic_cert_pin_sha256.as_deref(),
        config.cert_pin_sha256.as_deref(),
    ) {
        verify_quic_pin(&conn, pin)?;
    }

    let (send, recv) = timeout(
        Duration::from_millis(config.policy.connect_timeout_ms),
        conn.open_bi(),
    )
    .await
    .map_err(|_| WarpLinkError::Timeout("quic open stream timeout".to_string()))
    .and_then(|r| r.map_err(|e| WarpLinkError::Transport(e.to_string())))?;

    Ok(ClientIo::Quic {
        send,
        recv,
        _endpoint: endpoint,
    })
}

pub async fn connect_tcp(config: &ClientConfig) -> Result<ClientIo, WarpLinkError> {
    let mut addrs = tokio::net::lookup_host((config.host.as_str(), config.tcp_port))
        .await
        .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
    let addr = addrs
        .next()
        .ok_or_else(|| WarpLinkError::Transport("cannot resolve tcp host".to_string()))?;

    let socket = timeout(
        Duration::from_millis(config.policy.connect_timeout_ms),
        TcpStream::connect(addr),
    )
    .await
    .map_err(|_| WarpLinkError::Timeout("tcp connect timeout".to_string()))
    .and_then(|r| r.map_err(|e| WarpLinkError::Transport(e.to_string())))?;
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
        .unwrap_or(config.host.as_str())
        .to_string();
    let server_name = ServerName::try_from(server_name)
        .map_err(|_| WarpLinkError::Transport("invalid tls server name".to_string()))?;

    let tls = timeout(
        Duration::from_millis(config.policy.connect_timeout_ms),
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
    Ok(ClientIo::Tcp { writer, reader })
}

pub async fn connect_wss(config: &ClientConfig) -> Result<ClientIo, WarpLinkError> {
    let url = format!(
        "wss://{}:{}{}",
        config.host,
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

    let (stream, _) = timeout(
        Duration::from_millis(config.policy.connect_timeout_ms),
        tokio_tungstenite::connect_async(request),
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

pub async fn read_prefixed_frame<R>(reader: &mut R) -> Result<Vec<u8>, WarpLinkError>
where
    R: AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 4];
    reader
        .read_exact(&mut len_bytes)
        .await
        .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len == 0 || len > MAX_FRAME_LEN {
        return Err(WarpLinkError::Protocol(format!(
            "invalid stream frame length {}",
            len
        )));
    }
    let mut frame = vec![0u8; len];
    reader
        .read_exact(&mut frame)
        .await
        .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
    Ok(frame)
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
