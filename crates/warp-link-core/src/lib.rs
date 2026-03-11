use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Quic,
    Wss,
    Tcp,
}

impl fmt::Display for TransportKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportKind::Quic => write!(f, "quic"),
            TransportKind::Wss => write!(f, "wss"),
            TransportKind::Tcp => write!(f, "tcp"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientPolicy {
    pub connect_budget_ms: u64,
    pub wss_delay_ms: u64,
    pub tcp_delay_ms: u64,
    pub connect_timeout_ms: u64,
    pub write_timeout_ms: u64,
    pub backoff_min_ms: u64,
    pub backoff_max_ms: u64,
    pub upgrade_probe_enabled: bool,
    pub upgrade_probe_timeout_ms: u64,
    pub upgrade_probe_foreground_interval_secs: u16,
    pub upgrade_probe_background_interval_secs: u16,
    pub upgrade_probe_min_dwell_secs: u16,
    pub power: ClientPowerPolicy,
}

impl Default for ClientPolicy {
    fn default() -> Self {
        Self {
            connect_budget_ms: 1_500,
            wss_delay_ms: 300,
            tcp_delay_ms: 650,
            connect_timeout_ms: 4_000,
            write_timeout_ms: 5_000,
            backoff_min_ms: 2_000,
            backoff_max_ms: 60_000,
            upgrade_probe_enabled: true,
            upgrade_probe_timeout_ms: 2_000,
            upgrade_probe_foreground_interval_secs: 45,
            upgrade_probe_background_interval_secs: 180,
            upgrade_probe_min_dwell_secs: 20,
            power: ClientPowerPolicy::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientPowerPolicy {
    pub auto_enabled: bool,
    pub idle_to_low_after_secs: u16,
    pub message_burst_high_secs: u16,
    pub min_update_interval_secs: u16,
    pub foreground_default_tier: ClientPowerTier,
    pub background_default_tier: ClientPowerTier,
}

impl Default for ClientPowerPolicy {
    fn default() -> Self {
        Self {
            auto_enabled: true,
            idle_to_low_after_secs: 45,
            message_burst_high_secs: 15,
            min_update_interval_secs: 5,
            foreground_default_tier: ClientPowerTier::Balanced,
            background_default_tier: ClientPowerTier::Low,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientPowerTier {
    High,
    Balanced,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAppStateHint {
    Foreground,
    Background,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientPowerHint {
    pub app_state: ClientAppStateHint,
    pub preferred_tier: Option<ClientPowerTier>,
}

#[derive(Clone)]
pub struct ClientConfig {
    pub host: String,
    pub quic_port: u16,
    pub wss_port: u16,
    pub tcp_port: u16,
    pub wss_path: String,
    pub quic_alpn: String,
    pub tcp_alpn: String,
    pub wss_subprotocol: Option<String>,
    pub tls_server_name: Option<String>,
    pub bearer_token: Option<String>,
    /// Shared certificate pin fallback when transport-specific pins are not set.
    pub cert_pin_sha256: Option<String>,
    /// Optional QUIC-only certificate pin.
    pub quic_cert_pin_sha256: Option<String>,
    /// Optional TCP(TLS)-only certificate pin.
    pub tcp_cert_pin_sha256: Option<String>,
    /// Optional WSS(TLS)-only certificate pin.
    pub wss_cert_pin_sha256: Option<String>,
    pub policy: ClientPolicy,
    pub wire_profile: Arc<dyn WireProfile>,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub quic_listen_addr: Option<String>,
    pub tcp_listen_addr: Option<String>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub quic_alpn: String,
    pub tcp_alpn: String,
    pub quic_tls_mode: TlsMode,
    pub tcp_tls_mode: TlsMode,
    pub hello_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub max_outbound_wait_ms: u64,
    pub min_outbound_wait_ms: u64,
    pub coord_lease_ttl_secs: u64,
    pub coord_renew_before_secs: u64,
    pub write_timeout_ms: u64,
    /// Transport-side session cap used to protect runtime resources under connection storms.
    pub max_concurrent_sessions: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            quic_listen_addr: None,
            tcp_listen_addr: None,
            tls_cert_path: None,
            tls_key_path: None,
            quic_alpn: "pushgo-quic".to_string(),
            tcp_alpn: "pushgo-tcp".to_string(),
            quic_tls_mode: TlsMode::TerminateInWarp,
            tcp_tls_mode: TlsMode::TerminateInWarp,
            hello_timeout_ms: 8_000,
            idle_timeout_ms: 72_000,
            max_outbound_wait_ms: 15_000,
            min_outbound_wait_ms: 5,
            coord_lease_ttl_secs: 30,
            coord_renew_before_secs: 10,
            write_timeout_ms: 5_000,
            max_concurrent_sessions: 4_096,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    TerminateInWarp,
    OffloadAtEdge,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HelloCtx {
    pub identity: String,
    pub auth_token: Option<String>,
    pub resume_token: Option<String>,
    pub last_acked_seq: Option<u64>,
    pub supported_wire_versions: Vec<u8>,
    pub supported_payload_versions: Vec<u8>,
    pub perf_tier: Option<String>,
    pub app_state: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct WelcomeMsg {
    pub session_id: String,
    pub identity: String,
    pub resume_token: Option<String>,
    pub heartbeat_secs: u16,
    pub ping_interval_secs: u16,
    pub idle_timeout_secs: u16,
    pub max_backoff_secs: u16,
    pub auth_expires_at_unix_secs: Option<i64>,
    pub auth_refresh_before_secs: u16,
    pub max_frame_bytes: u32,
    pub negotiated_wire_version: u8,
    pub negotiated_payload_version: u8,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct DeliverMsg {
    pub seq: Option<u64>,
    pub id: String,
    pub payload: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckStatus {
    Ok,
    InvalidPayload,
    Error,
}

#[derive(Debug, Clone)]
pub struct AckMsg {
    pub seq: Option<u64>,
    pub id: String,
    pub status: AckStatus,
}

#[derive(Debug, Clone)]
pub struct PeerMeta {
    pub transport: TransportKind,
    pub remote_addr: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SessionCtx {
    pub session_id: String,
    pub identity: String,
    pub resume_token: Option<String>,
    pub heartbeat_secs: u16,
    pub ping_interval_secs: u16,
    pub idle_timeout_secs: u16,
    pub max_backoff_secs: u16,
    pub auth_expires_at_unix_secs: Option<i64>,
    pub auth_refresh_before_secs: u16,
    pub max_frame_bytes: u32,
    pub negotiated_wire_version: u8,
    pub negotiated_payload_version: u8,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct OutboundMsg {
    pub seq: Option<u64>,
    pub id: String,
    pub payload: Bytes,
}

#[derive(Debug, Clone)]
pub enum DisconnectReason {
    RemoteClosed,
    IdleTimeout,
    TransportError(String),
    ProtocolError(String),
    GoAway(String),
}

#[derive(Debug, Clone)]
pub enum SessionAuthState {
    Valid,
    Renewed {
        auth_expires_at_unix_secs: Option<i64>,
        auth_refresh_before_secs: u16,
    },
    RefreshRequired(String),
    Revoked(String),
    Expired(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthCheckPhase {
    Connect,
    RefreshWindow,
    InBandReauth,
}

#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub phase: AuthCheckPhase,
    pub session: Option<SessionCtx>,
    pub hello: Option<HelloCtx>,
    pub peer: Option<PeerMeta>,
}

#[derive(Debug, Clone)]
pub enum AuthResponse {
    ConnectAccepted(SessionCtx),
    State(SessionAuthState),
}

#[doc(hidden)]
pub trait SessionControlOps: Send + Sync + 'static {
    fn set_auth_expiry(
        &self,
        auth_expires_at_unix_secs: Option<i64>,
        auth_refresh_before_secs: u16,
    );
}

#[derive(Clone)]
pub struct SessionControl {
    inner: Arc<dyn SessionControlOps>,
}

impl SessionControl {
    #[doc(hidden)]
    pub fn from_ops(inner: Arc<dyn SessionControlOps>) -> Self {
        Self { inner }
    }

    pub fn set_auth_expiry(
        &self,
        auth_expires_at_unix_secs: Option<i64>,
        auth_refresh_before_secs: u16,
    ) {
        self.inner
            .set_auth_expiry(auth_expires_at_unix_secs, auth_refresh_before_secs);
    }

    pub fn expire_now(&self) {
        self.inner.set_auth_expiry(Some(0), 0);
    }
}

#[derive(Debug, Clone)]
pub enum ClientEvent {
    Connected {
        transport: TransportKind,
    },
    Welcome {
        welcome: WelcomeMsg,
    },
    Message {
        transport: TransportKind,
        msg: DeliverMsg,
    },
    Disconnected {
        transport: TransportKind,
        reason: String,
    },
    Reconnecting {
        attempt: u32,
        backoff_ms: u64,
    },
    Fatal {
        error: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppDecision {
    AckOk,
    AckInvalidPayload,
    Ignore,
}

pub trait ClientApp: Send + Sync + 'static {
    fn on_hello(&self) -> HelloCtx;
    fn on_event(&self, event: ClientEvent) -> AppDecision;
    fn power_hint(&self) -> Option<ClientPowerHint> {
        None
    }
}

#[async_trait]
pub trait ServerApp: Send + Sync + 'static {
    fn wire_profile(&self) -> Arc<dyn WireProfile>;
    /// Business-layer authentication hook.
    ///
    /// Transport orchestration (accept, timeout, keepalive, reconnect) stays inside warp-link.
    /// Integrators implement policy decisions such as token/device validation here.
    async fn auth(&self, request: AuthRequest) -> Result<AuthResponse, AuthError>;
    /// Business-layer outbound source hook.
    ///
    /// `max_wait_ms` is a transport-side budget provided by warp-link so integrators can block
    /// briefly on their queue/backend without leaking transport scheduling policy outward.
    async fn wait_outbound(&self, session: &SessionCtx, max_wait_ms: u64) -> Option<OutboundMsg>;
    /// Business callback for ACK side effects (store commit, metrics, etc.).
    async fn on_ack(&self, session: &SessionCtx, ack: AckMsg);
    /// Business callback for final session teardown bookkeeping.
    async fn on_disconnect(&self, session: &SessionCtx, reason: DisconnectReason);
    async fn on_handshake_failure(&self, _peer: PeerMeta, _error: &WarpLinkError) {}
    fn on_session_control(&self, _session: &SessionCtx, _control: SessionControl) {}
    fn session_coordinator(&self) -> Option<Arc<dyn SessionCoordinator>> {
        None
    }
    fn session_coord_owner(&self) -> Option<String> {
        None
    }
    fn session_coord_key(&self, hello: &HelloCtx) -> Option<String> {
        Some(hello.identity.clone())
    }
}

pub trait WireProfile: Send + Sync + 'static {
    fn encode_client_hello(&self, hello: &HelloCtx) -> Result<Bytes, WireError>;
    fn decode_server_frame(&self, frame: &[u8]) -> Result<DecodedServerFrame, WireError>;
    fn encode_client_ack(&self, ack: &AckMsg) -> Result<Bytes, WireError>;
    fn encode_client_ping(&self) -> Bytes;
    fn encode_client_pong(&self) -> Bytes;

    fn decode_client_frame(&self, frame: &[u8]) -> Result<DecodedClientFrame, WireError>;
    fn encode_server_welcome(&self, welcome: &WelcomeMsg) -> Result<Bytes, WireError>;
    fn encode_server_deliver(&self, msg: &DeliverMsg) -> Result<Bytes, WireError>;
    fn encode_server_ping(&self) -> Bytes;
    fn encode_server_pong(&self) -> Bytes;
    fn encode_server_goaway(&self, reason: &str) -> Result<Bytes, WireError>;
    fn encode_server_error(&self, code: &str, message: &str) -> Result<Bytes, WireError>;
}

#[derive(Debug, Clone)]
pub enum DecodedServerFrame {
    Welcome(WelcomeMsg),
    Deliver(DeliverMsg),
    Ping,
    Pong,
    GoAway(Option<String>),
    Error { code: String, message: String },
    Unknown,
}

#[derive(Debug, Clone)]
pub enum DecodedClientFrame {
    Hello(HelloCtx),
    Ack(AckMsg),
    Ping,
    Pong,
    GoAway(Option<String>),
    Unknown,
}

#[derive(Debug, thiserror::Error, Clone)]
pub enum WireError {
    #[error("decode failed: {0}")]
    Decode(String),
    #[error("encode failed: {0}")]
    Encode(String),
    #[error("invalid frame: {0}")]
    InvalidFrame(String),
    #[error("version incompatible: {0}")]
    VersionIncompatible(String),
}

#[derive(Debug, thiserror::Error, Clone)]
pub enum AuthError {
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("internal: {0}")]
    Internal(String),
}

#[derive(Debug, Clone)]
pub struct SessionLease {
    pub key: String,
    pub owner: String,
    pub epoch: u64,
    pub expires_at_unix_secs: i64,
}

#[derive(Debug, thiserror::Error, Clone)]
pub enum CoordinationError {
    #[error("lease conflict: {0}")]
    Conflict(String),
    #[error("coordination backend: {0}")]
    Backend(String),
}

#[async_trait]
pub trait SessionCoordinator: Send + Sync + 'static {
    async fn acquire(
        &self,
        key: &str,
        owner: &str,
        ttl_secs: u64,
    ) -> Result<SessionLease, CoordinationError>;
    async fn renew(
        &self,
        key: &str,
        owner: &str,
        epoch: u64,
        ttl_secs: u64,
    ) -> Result<SessionLease, CoordinationError>;
    async fn release(&self, key: &str, owner: &str, epoch: u64) -> Result<(), CoordinationError>;
}

#[derive(Debug, thiserror::Error, Clone)]
pub enum WarpLinkError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("wire error: {0}")]
    Wire(#[from] WireError),
    #[error("auth error: {0}")]
    Auth(#[from] AuthError),
    #[error("coordination error: {0}")]
    Coordination(#[from] CoordinationError),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("timeout: {0}")]
    Timeout(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("internal error: {0}")]
    Internal(String),
}
