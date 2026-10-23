//! Local socket evidence for the production TCP/TLS path, not upstream verifier fixtures.
//!
//! The synthetic CA and server key exist only in test memory. The public client still
//! uses built-in WebPKI roots; only the private test seam receives the synthetic CA.

use super::*;
use bytes::Bytes;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use warp_link_core::*;

const WAIT: Duration = Duration::from_secs(5);
const SERVER_NAME: &str = "private-loopback.invalid";
const ALPN: &[u8] = b"pushgo-tcp";

struct SyntheticIdentity {
    root: CertificateDer<'static>,
    leaf: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

impl SyntheticIdentity {
    fn new() -> Self {
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec![SERVER_NAME.to_owned()])
            .unwrap()
            .signed_by(&leaf_key, &ca)
            .unwrap();
        Self {
            root: ca.der().clone(),
            leaf: leaf.der().clone(),
            key: PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
        }
    }

    fn roots(&self) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.root.clone()).unwrap();
        roots
    }

    async fn server(&self) -> (SocketAddr, JoinHandle<ServerObservation>) {
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![self.leaf.clone()], self.key.clone_key())
            .unwrap();
        config.alpn_protocols = vec![ALPN.to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (socket, _) = timeout(WAIT, listener.accept()).await.unwrap().unwrap();
            match timeout(WAIT, acceptor.accept(socket)).await.unwrap() {
                Ok(tls) => {
                    let alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
                    let mut reader = FramedReader::new(tls);
                    let frame = timeout(WAIT, reader.read_frame())
                        .await
                        .expect("client must exchange a frame or close")
                        .ok();
                    if frame.is_some() {
                        write_prefixed_frame(&mut reader.inner, b"server reply")
                            .await
                            .unwrap();
                    }
                    ServerObservation { alpn, frame }
                }
                Err(_) => ServerObservation {
                    alpn: None,
                    frame: None,
                },
            }
        });
        (address, task)
    }
}

struct ServerObservation {
    alpn: Option<Vec<u8>>,
    frame: Option<Vec<u8>>,
}

fn client_config(address: SocketAddr, hostname: &str, pin: String) -> ClientConfig {
    ClientConfig {
        host: address.ip().to_string(),
        tcp_port: address.port(),
        quic_port: 0,
        wss_port: 0,
        wss_path: "/unused".into(),
        quic_alpn: "unused".into(),
        tcp_alpn: String::from_utf8(ALPN.to_vec()).unwrap(),
        wss_subprotocol: None,
        tls_server_name: Some(hostname.into()),
        bearer_token: None,
        cert_pin_sha256: None,
        tcp_cert_pin_sha256: Some(pin),
        quic_cert_pin_sha256: None,
        wss_cert_pin_sha256: None,
        policy: ClientPolicy {
            connect_timeout_ms: WAIT.as_millis() as u64,
            ..ClientPolicy::default()
        },
        wire_profile: Arc::new(UnusedWireProfile),
    }
}

#[tokio::test]
async fn tcp_tls_valid_chain_hostname_alpn_and_pin_exchange_frames() {
    let identity = SyntheticIdentity::new();
    let (address, server) = identity.server().await;
    let config = client_config(address, SERVER_NAME, cert_sha256_hex(&identity.leaf));
    let mut client = connect_tcp_with_roots(&config, identity.roots())
        .await
        .expect("trusted chain, matching hostname and pin must connect");
    client.send_frame(b"client message", 1_000).await.unwrap();
    assert_eq!(client.recv_frame(1_000).await.unwrap(), b"server reply");
    let observed = timeout(WAIT, server).await.unwrap().unwrap();
    assert_eq!(observed.alpn.as_deref(), Some(ALPN));
    assert_eq!(
        observed.frame.as_deref(),
        Some(b"client message".as_slice())
    );
}

#[tokio::test]
async fn tcp_tls_untrusted_chain_is_rejected_even_with_matching_pin() {
    let identity = SyntheticIdentity::new();
    let (address, server) = identity.server().await;
    let config = client_config(address, SERVER_NAME, cert_sha256_hex(&identity.leaf));
    // Exercise the public entry point and its unchanged built-in roots.
    let result = connect_tcp(&config).await;
    assert!(matches!(
        result,
        Err(WarpLinkError::Transport(ref error)) if error.contains("UnknownIssuer")
    ));
    let observed = timeout(WAIT, server).await.unwrap().unwrap();
    assert!(
        observed.frame.is_none(),
        "no application frame before trust"
    );
}

#[tokio::test]
async fn tcp_tls_trusted_chain_with_wrong_hostname_is_rejected() {
    let identity = SyntheticIdentity::new();
    let (address, server) = identity.server().await;
    let config = client_config(
        address,
        "wrong-host.invalid",
        cert_sha256_hex(&identity.leaf),
    );
    let result = connect_tcp_with_roots(&config, identity.roots()).await;
    assert!(
        matches!(
            result,
            Err(WarpLinkError::Transport(ref error)) if error == "invalid peer certificate: certificate not valid for name \"wrong-host.invalid\"; certificate is only valid for DnsName(\"private-loopback.invalid\")"
        ),
        "hostname failure must identify the name mismatch: {:?}",
        result.as_ref().err()
    );
    let observed = timeout(WAIT, server).await.unwrap().unwrap();
    assert!(
        observed.frame.is_none(),
        "pin cannot bypass hostname verification"
    );
}

#[tokio::test]
async fn tcp_tls_trusted_chain_with_wrong_pin_is_rejected_after_handshake() {
    let identity = SyntheticIdentity::new();
    let (address, server) = identity.server().await;
    let config = client_config(address, SERVER_NAME, "00".repeat(32));
    let result = connect_tcp_with_roots(&config, identity.roots()).await;
    assert!(matches!(
        result,
        Err(WarpLinkError::Protocol(ref error)) if error == "certificate pin mismatch"
    ));
    let observed = timeout(WAIT, server).await.unwrap().unwrap();
    assert_eq!(observed.alpn.as_deref(), Some(ALPN));
    assert!(
        observed.frame.is_none(),
        "no application frame before pin acceptance"
    );
}

// TCP/TLS transport never invokes a wire profile. Keep this test-only implementation
// fail-closed so a future accidental dependency on one is visible.
struct UnusedWireProfile;

impl WireProfile for UnusedWireProfile {
    fn encode_client_hello(&self, _: &HelloCtx) -> Result<Bytes, WireError> {
        unreachable!()
    }
    fn decode_server_frame(&self, _: &[u8]) -> Result<DecodedServerFrame, WireError> {
        unreachable!()
    }
    fn encode_client_ack(&self, _: &AckMsg) -> Result<Bytes, WireError> {
        unreachable!()
    }
    fn encode_client_ping(&self) -> Bytes {
        unreachable!()
    }
    fn encode_client_pong(&self) -> Bytes {
        unreachable!()
    }
    fn decode_client_frame(&self, _: &[u8]) -> Result<DecodedClientFrame, WireError> {
        unreachable!()
    }
    fn encode_server_welcome(&self, _: &WelcomeMsg) -> Result<Bytes, WireError> {
        unreachable!()
    }
    fn encode_server_deliver(&self, _: &DeliverMsg) -> Result<Bytes, WireError> {
        unreachable!()
    }
    fn encode_server_ping(&self) -> Bytes {
        unreachable!()
    }
    fn encode_server_pong(&self) -> Bytes {
        unreachable!()
    }
    fn encode_server_goaway(&self, _: &str) -> Result<Bytes, WireError> {
        unreachable!()
    }
    fn encode_server_error(&self, _: &str, _: &str) -> Result<Bytes, WireError> {
        unreachable!()
    }
}
