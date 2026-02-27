#[cfg(any(feature = "quic", feature = "tcp", feature = "wss"))]
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
#[cfg(feature = "wss")]
use futures_util::{SinkExt, StreamExt};
#[cfg(feature = "quic")]
use quinn::Endpoint;
use rand::RngExt as _;
#[cfg(any(feature = "quic", feature = "tcp", feature = "wss"))]
use rustls::pki_types::pem::PemObject;
#[cfg(any(feature = "quic", feature = "tcp", feature = "wss"))]
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
#[cfg(feature = "wss")]
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(feature = "tcp")]
use tokio::io::{ReadHalf, WriteHalf};
#[cfg(any(feature = "tcp", feature = "wss"))]
use tokio::net::TcpListener;
#[cfg(feature = "tcp")]
use tokio::net::TcpStream;
#[cfg(any(feature = "quic", feature = "tcp", feature = "wss"))]
use tokio::sync::Semaphore;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout};
#[cfg(any(feature = "tcp", feature = "wss"))]
use tokio_rustls::TlsAcceptor;
#[cfg(feature = "tcp")]
use tokio_rustls::server::TlsStream as ServerTlsStream;
#[cfg(feature = "wss")]
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async,
    tungstenite::{
        Message as WsMessage,
        handshake::server::{
            ErrorResponse as WsErrorResponse, Request as WsRequest, Response as WsResponse,
        },
        http::StatusCode as WsStatusCode,
    },
};
use warp_link_core::{
    AckMsg, AckStatus, AppDecision, AuthCheckPhase, AuthError, AuthRequest, AuthResponse,
    ClientApp, ClientAppStateHint, ClientConfig, ClientEvent, ClientPowerPolicy, ClientPowerTier,
    DecodedClientFrame, DecodedServerFrame, DisconnectReason, HelloCtx, OutboundMsg, PeerMeta,
    ServerApp, ServerConfig, SessionAuthState, SessionControl, SessionControlOps, TlsMode,
    TransportKind, WarpLinkError,
};
use warp_link_transport::ClientIo;
#[cfg(feature = "quic")]
use warp_link_transport::connect_quic;
#[cfg(feature = "tcp")]
use warp_link_transport::connect_tcp;
#[cfg(feature = "wss")]
use warp_link_transport::connect_wss;
#[cfg(any(feature = "quic", feature = "tcp"))]
use warp_link_transport::{read_prefixed_frame, write_prefixed_frame};

pub use warp_link_core;
pub use warp_link_transport;

const TRANSPORT_MAX_FRAME_BYTES: u32 = ((32 * 1024) + 2) as u32;

pub async fn client_run(config: ClientConfig, app: impl ClientApp) -> Result<(), WarpLinkError> {
    let (_tx, rx) = watch::channel(false);
    client_run_with_shutdown(config, app, rx).await
}

pub async fn client_run_once(
    config: &ClientConfig,
    app: Arc<dyn ClientApp>,
) -> Result<(), WarpLinkError> {
    run_client_session_once(config, app).await
}

pub async fn client_run_with_shutdown(
    config: ClientConfig,
    app: impl ClientApp,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), WarpLinkError> {
    let app: Arc<dyn ClientApp> = Arc::new(app);
    let mut attempt: u32 = 0;
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        match run_client_session_once(&config, Arc::clone(&app)).await {
            Ok(()) => {
                attempt = 0;
            }
            Err(err) => {
                let _ = app.on_event(ClientEvent::Fatal {
                    error: err.to_string(),
                });
                attempt = attempt.saturating_add(1);
                let exp = attempt.saturating_sub(1).min(8);
                let base_backoff = config
                    .policy
                    .backoff_min_ms
                    .saturating_mul(1u64 << exp)
                    .min(
                        config
                            .policy
                            .backoff_max_ms
                            .max(config.policy.backoff_min_ms),
                    );
                let jitter = rand::rng().random_range(0..1000u64);
                let backoff = base_backoff.saturating_add(jitter);
                let _ = app.on_event(ClientEvent::Reconnecting {
                    attempt,
                    backoff_ms: backoff,
                });
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(backoff)) => {}
                    changed = shutdown.changed() => {
                        if changed.is_ok() && *shutdown.borrow() {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

async fn run_client_session_once(
    config: &ClientConfig,
    app: Arc<dyn ClientApp>,
) -> Result<(), WarpLinkError> {
    let (transport, mut io) = hedged_connect(config).await?;
    let _ = app.on_event(ClientEvent::Connected { transport });

    let mut power_runtime = ClientPowerRuntime::new(Instant::now());
    let hello = build_effective_hello(config, app.as_ref(), &mut power_runtime);
    let hello_frame = config.wire_profile.encode_client_hello(&hello)?;
    io.send_frame(&hello_frame, config.policy.write_timeout_ms)
        .await?;
    let mut inband_hello_snapshot = hello;

    let first = io.recv_frame(config.policy.connect_timeout_ms).await?;
    let welcome = match config.wire_profile.decode_server_frame(&first)? {
        DecodedServerFrame::Welcome(value) => value,
        DecodedServerFrame::Error { code, message } => {
            return Err(WarpLinkError::Protocol(format!(
                "gateway error: {code} {message}"
            )));
        }
        _ => {
            return Err(WarpLinkError::Protocol(
                "expected welcome frame from server".to_string(),
            ));
        }
    };
    let _ = app.on_event(ClientEvent::Welcome {
        welcome: welcome.clone(),
    });

    let idle_timeout_ms = u64::from(welcome.ping_interval_secs.clamp(5, 30)) * 1_000;
    let mut idle_timeout_streak = 0u8;

    loop {
        maybe_send_inband_hello_update(
            config,
            app.as_ref(),
            &mut io,
            &mut inband_hello_snapshot,
            &mut power_runtime,
        )
        .await?;
        let frame = match io.recv_frame(idle_timeout_ms).await {
            Ok(frame) => {
                idle_timeout_streak = 0;
                frame
            }
            Err(WarpLinkError::Timeout(_)) => {
                idle_timeout_streak = idle_timeout_streak.saturating_add(1);
                if idle_timeout_streak >= 4 {
                    let _ = app.on_event(ClientEvent::Disconnected {
                        transport,
                        reason: "idle timeout".to_string(),
                    });
                    return Err(WarpLinkError::Timeout("idle timeout".to_string()));
                }
                let ping = config.wire_profile.encode_client_ping();
                io.send_frame(&ping, config.policy.write_timeout_ms).await?;
                continue;
            }
            Err(err) => {
                let _ = app.on_event(ClientEvent::Disconnected {
                    transport,
                    reason: err.to_string(),
                });
                return Err(err);
            }
        };

        match config.wire_profile.decode_server_frame(&frame)? {
            DecodedServerFrame::Deliver(msg) => {
                power_runtime.note_message(&config.policy.power, Instant::now());
                let decision = app.on_event(ClientEvent::Message {
                    transport,
                    msg: msg.clone(),
                });
                let status = match decision {
                    AppDecision::AckOk => Some(AckStatus::Ok),
                    AppDecision::AckInvalidPayload => Some(AckStatus::InvalidPayload),
                    AppDecision::Ignore => None,
                };
                if let Some(status) = status {
                    let ack = AckMsg {
                        seq: msg.seq,
                        id: msg.id,
                        status,
                    };
                    let bytes = config.wire_profile.encode_client_ack(&ack)?;
                    io.send_frame(&bytes, config.policy.write_timeout_ms)
                        .await?;
                }
            }
            DecodedServerFrame::Ping => {
                let pong = config.wire_profile.encode_client_pong();
                io.send_frame(&pong, config.policy.write_timeout_ms).await?;
            }
            DecodedServerFrame::Pong => {}
            DecodedServerFrame::GoAway(reason) => {
                let goaway_reason = reason.unwrap_or_else(|| "goaway".to_string());
                let _ = app.on_event(ClientEvent::Disconnected {
                    transport,
                    reason: goaway_reason.clone(),
                });
                if goaway_reason.starts_with("auth_expired")
                    || goaway_reason.starts_with("auth_revoked")
                {
                    return Err(WarpLinkError::Auth(AuthError::Unauthorized(goaway_reason)));
                }
                if goaway_reason.starts_with("auth_refresh_required") {
                    return Ok(());
                }
                return Ok(());
            }
            DecodedServerFrame::Error { code, message } => {
                return Err(WarpLinkError::Protocol(format!(
                    "gateway error: {code} {message}"
                )));
            }
            DecodedServerFrame::Welcome(_) => {
                return Err(WarpLinkError::Protocol(
                    "unexpected welcome frame after handshake".to_string(),
                ));
            }
            DecodedServerFrame::Unknown => {}
        }
    }
}

struct ClientPowerRuntime {
    last_message_at: Instant,
    high_until: Option<Instant>,
    last_power_push_at: Option<Instant>,
}

impl ClientPowerRuntime {
    fn new(now: Instant) -> Self {
        Self {
            last_message_at: now,
            high_until: None,
            last_power_push_at: None,
        }
    }

    fn note_message(&mut self, policy: &ClientPowerPolicy, now: Instant) {
        self.last_message_at = now;
        if policy.message_burst_high_secs > 0 {
            self.high_until =
                Some(now + Duration::from_secs(u64::from(policy.message_burst_high_secs)));
        }
    }

    fn select_auto(
        &mut self,
        policy: &ClientPowerPolicy,
        now: Instant,
    ) -> (ClientPowerTier, ClientAppStateHint) {
        if !policy.auto_enabled {
            return (
                policy.foreground_default_tier,
                ClientAppStateHint::Foreground,
            );
        }
        let idle_for = now.saturating_duration_since(self.last_message_at);
        let idle_secs = idle_for.as_secs();
        let idle_cutoff = u64::from(policy.idle_to_low_after_secs);
        let app_state = if idle_cutoff > 0 && idle_secs >= idle_cutoff {
            ClientAppStateHint::Background
        } else {
            ClientAppStateHint::Foreground
        };

        let mut tier = default_tier_for_state(policy, app_state);
        if let Some(high_until) = self.high_until {
            if now < high_until {
                tier = ClientPowerTier::High;
            } else {
                self.high_until = None;
            }
        }
        (tier, app_state)
    }

    fn can_push_power_update(&self, policy: &ClientPowerPolicy, now: Instant) -> bool {
        let min_interval = Duration::from_secs(u64::from(policy.min_update_interval_secs));
        if min_interval.is_zero() {
            return true;
        }
        let Some(last) = self.last_power_push_at else {
            return true;
        };
        now.saturating_duration_since(last) >= min_interval
    }

    fn mark_power_update(&mut self, now: Instant) {
        self.last_power_push_at = Some(now);
    }
}

fn build_effective_hello(
    config: &ClientConfig,
    app: &dyn ClientApp,
    power_runtime: &mut ClientPowerRuntime,
) -> HelloCtx {
    let mut hello = app.on_hello();
    if let Some(hint) = app.power_hint() {
        let tier = hint
            .preferred_tier
            .unwrap_or_else(|| default_tier_for_state(&config.policy.power, hint.app_state));
        apply_power_to_hello(&mut hello, tier, hint.app_state);
        return hello;
    }
    if hello.perf_tier.is_some() || hello.app_state.is_some() {
        return hello;
    }
    let (tier, app_state) = power_runtime.select_auto(&config.policy.power, Instant::now());
    apply_power_to_hello(&mut hello, tier, app_state);
    hello
}

fn apply_power_to_hello(
    hello: &mut HelloCtx,
    tier: ClientPowerTier,
    app_state: ClientAppStateHint,
) {
    hello.perf_tier = Some(power_tier_wire(tier).to_string());
    hello.app_state = Some(app_state_wire(app_state).to_string());
}

fn default_tier_for_state(
    policy: &ClientPowerPolicy,
    app_state: ClientAppStateHint,
) -> ClientPowerTier {
    match app_state {
        ClientAppStateHint::Foreground => policy.foreground_default_tier,
        ClientAppStateHint::Background => policy.background_default_tier,
    }
}

fn power_tier_wire(tier: ClientPowerTier) -> &'static str {
    match tier {
        ClientPowerTier::High => "high",
        ClientPowerTier::Balanced => "balanced",
        ClientPowerTier::Low => "low",
    }
}

fn app_state_wire(app_state: ClientAppStateHint) -> &'static str {
    match app_state {
        ClientAppStateHint::Foreground => "foreground",
        ClientAppStateHint::Background => "background",
    }
}

fn hello_equal_without_power(a: &HelloCtx, b: &HelloCtx) -> bool {
    a.identity == b.identity
        && a.auth_token == b.auth_token
        && a.resume_token == b.resume_token
        && a.last_acked_seq == b.last_acked_seq
        && a.supported_wire_versions == b.supported_wire_versions
        && a.supported_payload_versions == b.supported_payload_versions
        && a.metadata == b.metadata
}

async fn maybe_send_inband_hello_update(
    config: &ClientConfig,
    app: &dyn ClientApp,
    io: &mut ClientIo,
    snapshot: &mut HelloCtx,
    power_runtime: &mut ClientPowerRuntime,
) -> Result<(), WarpLinkError> {
    let latest = build_effective_hello(config, app, power_runtime);
    if latest.identity != snapshot.identity {
        return Ok(());
    }
    if latest == *snapshot {
        return Ok(());
    }
    let power_only_changed = hello_equal_without_power(snapshot, &latest);
    if power_only_changed {
        let now = Instant::now();
        if !power_runtime.can_push_power_update(&config.policy.power, now) {
            return Ok(());
        }
        power_runtime.mark_power_update(now);
    }
    let frame = config.wire_profile.encode_client_hello(&latest)?;
    io.send_frame(&frame, config.policy.write_timeout_ms)
        .await?;
    *snapshot = latest;
    Ok(())
}

async fn hedged_connect(config: &ClientConfig) -> Result<(TransportKind, ClientIo), WarpLinkError> {
    let mut attempts = JoinSet::new();

    #[cfg(feature = "quic")]
    {
        let quic_cfg = config.clone();
        attempts.spawn(async move { (TransportKind::Quic, connect_quic(&quic_cfg).await) });
    }

    #[cfg(feature = "wss")]
    {
        let wss_cfg = config.clone();
        attempts.spawn(async move {
            tokio::time::sleep(Duration::from_millis(wss_cfg.policy.wss_delay_ms)).await;
            (TransportKind::Wss, connect_wss(&wss_cfg).await)
        });
    }

    #[cfg(feature = "tcp")]
    {
        let tcp_cfg = config.clone();
        attempts.spawn(async move {
            tokio::time::sleep(Duration::from_millis(tcp_cfg.policy.tcp_delay_ms)).await;
            (TransportKind::Tcp, connect_tcp(&tcp_cfg).await)
        });
    }

    if attempts.is_empty() {
        return Err(WarpLinkError::Unsupported(
            "no client transport enabled; enable quic/tcp/wss features".to_string(),
        ));
    }

    let deadline = Instant::now() + Duration::from_millis(config.policy.connect_budget_ms);
    let mut last_err: Option<WarpLinkError> = None;

    while !attempts.is_empty() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remain = deadline.saturating_duration_since(now);
        let join = timeout(remain, attempts.join_next())
            .await
            .map_err(|_| WarpLinkError::Timeout("connect budget exceeded".to_string()))?;
        let Some(result) = join else {
            break;
        };
        let (transport, io_result) = result
            .map_err(|e| WarpLinkError::Internal(format!("connect task join failed: {e}")))?;
        match io_result {
            Ok(io) => {
                attempts.abort_all();
                return Ok((transport, io));
            }
            Err(err) => {
                last_err = Some(err);
            }
        }
    }

    attempts.abort_all();
    Err(last_err
        .unwrap_or_else(|| WarpLinkError::Timeout("all transport attempts failed".to_string())))
}

#[async_trait]
pub trait ServerSessionIo: Send {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), WarpLinkError>;
    async fn recv_frame(&mut self, timeout_ms: u64) -> Result<Vec<u8>, WarpLinkError>;
}

#[async_trait]
pub trait WsUpgradeIo: Send {
    async fn send_binary(&mut self, frame: Vec<u8>) -> Result<(), WarpLinkError>;
    async fn recv_binary(&mut self, timeout_ms: u64) -> Result<Vec<u8>, WarpLinkError>;
    fn remote_addr(&self) -> Option<String> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct WssStandaloneConfig {
    pub listen_addr: String,
    pub path: String,
    pub tls_mode: TlsMode,
    pub subprotocol: Option<String>,
    pub max_frame_bytes: usize,
}

impl Default for WssStandaloneConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8081".to_string(),
            path: "/private/ws".to_string(),
            tls_mode: TlsMode::OffloadAtEdge,
            subprotocol: None,
            max_frame_bytes: (32 * 1024) + 2,
        }
    }
}

#[derive(Clone, Copy)]
struct AuthExpiryUpdate {
    auth_expires_at_unix_secs: Option<i64>,
    auth_refresh_before_secs: u16,
}

struct RuntimeSessionControlOps {
    tx: watch::Sender<AuthExpiryUpdate>,
}

impl SessionControlOps for RuntimeSessionControlOps {
    fn set_auth_expiry(
        &self,
        auth_expires_at_unix_secs: Option<i64>,
        auth_refresh_before_secs: u16,
    ) {
        let _ = self.tx.send(AuthExpiryUpdate {
            auth_expires_at_unix_secs,
            auth_refresh_before_secs: normalize_refresh_before(
                auth_expires_at_unix_secs,
                auth_refresh_before_secs,
            ),
        });
    }
}

#[derive(Clone, Copy)]
struct AuthSchedule {
    auth_expires_at_unix_secs: Option<i64>,
    auth_refresh_before_secs: u16,
    refresh_checked: bool,
}

impl AuthSchedule {
    fn from_session(session: &warp_link_core::SessionCtx) -> Self {
        Self {
            auth_expires_at_unix_secs: session.auth_expires_at_unix_secs,
            auth_refresh_before_secs: session.auth_refresh_before_secs,
            refresh_checked: false,
        }
    }
}

struct ActiveLease {
    coordinator: Arc<dyn warp_link_core::SessionCoordinator>,
    key: String,
    owner: String,
    epoch: u64,
    expires_at_unix_secs: i64,
}

pub async fn run_server_session(
    config: &ServerConfig,
    app: Arc<dyn ServerApp>,
    io: &mut dyn ServerSessionIo,
    peer: PeerMeta,
) -> Result<(), WarpLinkError> {
    let profile = app.wire_profile();
    let hello_frame = match io.recv_frame(config.hello_timeout_ms).await {
        Ok(frame) => frame,
        Err(err) => {
            app.on_handshake_failure(peer.clone(), &err).await;
            return Err(err);
        }
    };
    let hello = match profile.decode_client_frame(&hello_frame) {
        Ok(DecodedClientFrame::Hello(value)) => value,
        Ok(_) => {
            let protocol_error = WarpLinkError::Protocol("expected client hello".to_string());
            app.on_handshake_failure(peer.clone(), &protocol_error)
                .await;
            let err = profile.encode_server_error("invalid_frame", "expected client hello")?;
            let _ = io.send_frame(&err).await;
            return Ok(());
        }
        Err(err) => {
            let wire = WarpLinkError::Wire(err);
            app.on_handshake_failure(peer.clone(), &wire).await;
            return Err(wire);
        }
    };
    let mut active_lease = if let Some(coordinator) = app.session_coordinator() {
        let Some(owner) = app.session_coord_owner() else {
            let error =
                WarpLinkError::Internal("session coordinator owner is required".to_string());
            app.on_handshake_failure(peer.clone(), &error).await;
            return Err(error);
        };
        let key = app
            .session_coord_key(&hello)
            .unwrap_or_else(|| hello.identity.clone());
        let lease = match coordinator
            .acquire(
                key.as_str(),
                owner.as_str(),
                config.coord_lease_ttl_secs.max(1),
            )
            .await
        {
            Ok(lease) => lease,
            Err(err) => {
                let (public_code, public_message) = match &err {
                    warp_link_core::CoordinationError::Conflict(_) => {
                        ("lease_conflict", "lease_conflict")
                    }
                    warp_link_core::CoordinationError::Backend(_) => {
                        ("lease_unavailable", "lease_unavailable")
                    }
                };
                let error: WarpLinkError = err.into();
                app.on_handshake_failure(peer.clone(), &error).await;
                if let Ok(frame) = profile.encode_server_error(public_code, public_message) {
                    let _ = io.send_frame(&frame).await;
                }
                return Err(error);
            }
        };
        Some(ActiveLease {
            coordinator,
            key,
            owner,
            epoch: lease.epoch,
            expires_at_unix_secs: lease.expires_at_unix_secs,
        })
    } else {
        None
    };
    let result = async {
        let mut session = match app
            .auth(AuthRequest {
                phase: AuthCheckPhase::Connect,
                session: None,
                hello: Some(hello.clone()),
                peer: Some(peer.clone()),
            })
            .await
        {
            Ok(AuthResponse::ConnectAccepted(session)) => session,
            Ok(AuthResponse::State(state)) => {
                let public_message = public_auth_state_message(&state);
                let reason = apply_auth_state_to_reason(state)
                    .unwrap_or_else(|| "connect state missing session".to_string());
                let auth_error: WarpLinkError = AuthError::Unauthorized(reason.clone()).into();
                app.on_handshake_failure(peer.clone(), &auth_error).await;
                if let Ok(frame) = profile.encode_server_error("auth_failed", public_message) {
                    let _ = io.send_frame(&frame).await;
                }
                return Err(auth_error);
            }
            Err(err) => {
                let public_message = public_auth_error_message(&err);
                let auth_error: WarpLinkError = err.clone().into();
                app.on_handshake_failure(peer.clone(), &auth_error).await;
                if let Ok(frame) = profile.encode_server_error("auth_failed", public_message) {
                    let _ = io.send_frame(&frame).await;
                }
                return Err(auth_error);
            }
        };
        session.max_frame_bytes = session.max_frame_bytes.clamp(2, TRANSPORT_MAX_FRAME_BYTES);
        if let Some(lease) = active_lease.as_ref() {
            session
                .metadata
                .insert("coord_key".to_string(), lease.key.clone());
            session
                .metadata
                .insert("coord_owner".to_string(), lease.owner.clone());
            session
                .metadata
                .insert("coord_epoch".to_string(), lease.epoch.to_string());
        }
        let welcome = warp_link_core::WelcomeMsg {
            session_id: session.session_id.clone(),
            identity: session.identity.clone(),
            resume_token: session.resume_token.clone(),
            heartbeat_secs: session.heartbeat_secs,
            ping_interval_secs: session.ping_interval_secs,
            idle_timeout_secs: session.idle_timeout_secs,
            max_backoff_secs: session.max_backoff_secs,
            auth_expires_at_unix_secs: session.auth_expires_at_unix_secs,
            auth_refresh_before_secs: session.auth_refresh_before_secs,
            max_frame_bytes: session.max_frame_bytes,
            negotiated_wire_version: session.negotiated_wire_version,
            negotiated_payload_version: session.negotiated_payload_version,
            metadata: session.metadata.clone(),
        };
        let welcome_frame = match profile.encode_server_welcome(&welcome) {
            Ok(frame) => frame,
            Err(err) => {
                let error: WarpLinkError = err.into();
                app.on_disconnect(&session, DisconnectReason::ProtocolError(error.to_string()))
                    .await;
                return Err(error);
            }
        };
        if let Err(err) = io.send_frame(&welcome_frame).await {
            app.on_disconnect(&session, DisconnectReason::TransportError(err.to_string()))
                .await;
            return Err(err);
        }

        session.auth_refresh_before_secs = normalize_refresh_before(
            session.auth_expires_at_unix_secs,
            session.auth_refresh_before_secs,
        );
        let (auth_ctl_tx, mut auth_ctl_rx) = watch::channel(AuthExpiryUpdate {
            auth_expires_at_unix_secs: session.auth_expires_at_unix_secs,
            auth_refresh_before_secs: session.auth_refresh_before_secs,
        });
        let control =
            SessionControl::from_ops(Arc::new(RuntimeSessionControlOps { tx: auth_ctl_tx }));
        app.on_session_control(&session, control);

        let session_idle_timeout_ms = u64::from(session.idle_timeout_secs.max(6)) * 1_000;
        let configured_idle_timeout_ms = config.idle_timeout_ms.max(1_000);
        let read_timeout_ms = session_idle_timeout_ms.min(configured_idle_timeout_ms);
        let mut idle_timeout_streak = 0u8;
        let mut auth_schedule = AuthSchedule::from_session(&session);
        let mut last_inbound_at = Instant::now();

        loop {
            let now = unix_now_secs();
            if let Some(lease) = active_lease.as_mut() {
                let renew_before = config.coord_renew_before_secs.max(1) as i64;
                if now >= lease.expires_at_unix_secs.saturating_sub(renew_before) {
                    match lease
                        .coordinator
                        .renew(
                            lease.key.as_str(),
                            lease.owner.as_str(),
                            lease.epoch,
                            config.coord_lease_ttl_secs.max(1),
                        )
                        .await
                    {
                        Ok(updated) => {
                            lease.epoch = updated.epoch;
                            lease.expires_at_unix_secs = updated.expires_at_unix_secs;
                            session
                                .metadata
                                .insert("coord_epoch".to_string(), lease.epoch.to_string());
                        }
                        Err(err) => {
                            let reason = auth_goaway_reason("coord_lost", err.to_string().as_str());
                            send_goaway_and_close(io, profile.as_ref(), &app, &session, reason)
                                .await;
                            return Ok(());
                        }
                    }
                }
            }
            if auth_schedule
                .auth_expires_at_unix_secs
                .is_some_and(|expires_at| now >= expires_at)
            {
                let reason = auth_goaway_reason("auth_expired", "session_expired");
                send_goaway_and_close(io, profile.as_ref(), &app, &session, reason).await;
                return Ok(());
            }
            if should_run_refresh_check(&auth_schedule, now) {
                auth_schedule.refresh_checked = true;
                let state = match app
                    .auth(AuthRequest {
                        phase: AuthCheckPhase::RefreshWindow,
                        session: Some(session.clone()),
                        hello: None,
                        peer: None,
                    })
                    .await
                {
                    Ok(AuthResponse::State(state)) => state,
                    Ok(AuthResponse::ConnectAccepted(_)) => {
                        SessionAuthState::RefreshRequired("invalid_refresh_response".to_string())
                    }
                    Err(AuthError::Unauthorized(reason)) => SessionAuthState::Revoked(reason),
                    Err(AuthError::Internal(reason)) => SessionAuthState::RefreshRequired(reason),
                };
                if let Some(reason) = apply_auth_state(&mut session, &mut auth_schedule, state) {
                    send_goaway_and_close(io, profile.as_ref(), &app, &session, reason).await;
                    return Ok(());
                }
            }

            let elapsed_idle_ms = last_inbound_at.elapsed().as_millis() as u64;
            if elapsed_idle_ms >= read_timeout_ms {
                idle_timeout_streak = idle_timeout_streak.saturating_add(1);
                if idle_timeout_streak >= 4 {
                    app.on_disconnect(&session, DisconnectReason::IdleTimeout)
                        .await;
                    return Err(WarpLinkError::Timeout(
                        "server session idle timeout".to_string(),
                    ));
                }
                if let Err(err) = io.send_frame(&profile.encode_server_ping()).await {
                    app.on_disconnect(&session, DisconnectReason::TransportError(err.to_string()))
                        .await;
                    return Err(err);
                }
                last_inbound_at = Instant::now();
                continue;
            }
            let remaining_idle_ms = read_timeout_ms.saturating_sub(elapsed_idle_ms).max(1);
            let auth_wait_ms = next_auth_wait_ms(&auth_schedule, now).unwrap_or(u64::MAX);
            let outbound_wait_ms = remaining_idle_ms
                .min(auth_wait_ms)
                .min(config.max_outbound_wait_ms.max(1))
                .max(config.min_outbound_wait_ms.max(1));

            tokio::select! {
                changed = auth_ctl_rx.changed() => {
                    if changed.is_err() {
                        continue;
                    }
                    let update = *auth_ctl_rx.borrow_and_update();
                    session.auth_expires_at_unix_secs = update.auth_expires_at_unix_secs;
                    session.auth_refresh_before_secs = normalize_refresh_before(
                        update.auth_expires_at_unix_secs,
                        update.auth_refresh_before_secs,
                    );
                    auth_schedule = AuthSchedule::from_session(&session);
                    if session
                        .auth_expires_at_unix_secs
                        .is_some_and(|expires_at| unix_now_secs() >= expires_at)
                    {
                        let reason = auth_goaway_reason("auth_expired", "control_expire");
                        send_goaway_and_close(io, profile.as_ref(), &app, &session, reason).await;
                        return Ok(());
                    }
                }
                inbound = io.recv_frame(remaining_idle_ms) => {
                    match inbound {
                        Ok(frame) => {
                            idle_timeout_streak = 0;
                            last_inbound_at = Instant::now();
                            let decoded = match profile.decode_client_frame(&frame) {
                                Ok(decoded) => decoded,
                                Err(err) => {
                                    let error: WarpLinkError = err.into();
                                    app.on_disconnect(&session, DisconnectReason::ProtocolError(error.to_string())).await;
                                    return Err(error);
                                }
                            };
                            match decoded {
                                DecodedClientFrame::Ack(ack) => {
                                    app.on_ack(&session, ack).await;
                                }
                                DecodedClientFrame::Ping => {
                                    if let Err(err) = io.send_frame(&profile.encode_server_pong()).await {
                                        app.on_disconnect(&session, DisconnectReason::TransportError(err.to_string())).await;
                                        return Err(err);
                                    }
                                }
                                DecodedClientFrame::Pong => {}
                                DecodedClientFrame::GoAway(reason) => {
                                    app.on_disconnect(&session, DisconnectReason::GoAway(reason.unwrap_or_else(|| "goaway".to_string()))).await;
                                    return Ok(());
                                }
                                DecodedClientFrame::Hello(hello) => {
                                    if hello.identity != session.identity {
                                        let reason = auth_goaway_reason("auth_reauth_failed", "identity_mismatch");
                                        send_goaway_and_close(io, profile.as_ref(), &app, &session, reason).await;
                                        return Ok(());
                                    }
                                    let state = app
                                        .auth(AuthRequest {
                                            phase: AuthCheckPhase::InBandReauth,
                                            session: Some(session.clone()),
                                            hello: Some(hello.clone()),
                                            peer: None,
                                        })
                                        .await;
                                    let state = match state {
                                        Ok(AuthResponse::State(state)) => state,
                                        Ok(AuthResponse::ConnectAccepted(_)) => {
                                            SessionAuthState::RefreshRequired("invalid_reauth_response".to_string())
                                        }
                                        Err(AuthError::Unauthorized(reason)) => SessionAuthState::Revoked(reason),
                                        Err(AuthError::Internal(reason)) => SessionAuthState::RefreshRequired(reason),
                                    };
                                    if let Some(reason) = apply_auth_state(&mut session, &mut auth_schedule, state) {
                                        send_goaway_and_close(io, profile.as_ref(), &app, &session, reason).await;
                                        return Ok(());
                                    }
                                }
                                DecodedClientFrame::Unknown => {}
                            }
                        }
                        Err(WarpLinkError::Timeout(_)) => {
                            idle_timeout_streak = idle_timeout_streak.saturating_add(1);
                            if idle_timeout_streak >= 4 {
                                app.on_disconnect(&session, DisconnectReason::IdleTimeout).await;
                                return Err(WarpLinkError::Timeout("server session idle timeout".to_string()));
                            }
                            if let Err(err) = io.send_frame(&profile.encode_server_ping()).await {
                                app.on_disconnect(&session, DisconnectReason::TransportError(err.to_string())).await;
                                return Err(err);
                            }
                            last_inbound_at = Instant::now();
                        }
                        Err(err) => {
                            app.on_disconnect(&session, DisconnectReason::TransportError(err.to_string())).await;
                            return Err(err);
                        }
                    }
                }
                outbound = app.wait_outbound(&session, outbound_wait_ms) => {
                    if let Some(outbound) = outbound {
                        send_outbound(io, profile.as_ref(), &app, &session, outbound).await?;
                    }
                }
            }
        }
    }.await;

    let release_result: Result<(), WarpLinkError> = match active_lease.take() {
        Some(lease) => lease
            .coordinator
            .release(lease.key.as_str(), lease.owner.as_str(), lease.epoch)
            .await
            .map_err(WarpLinkError::from),
        None => Ok(()),
    };

    match (result, release_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(error)) => Err(error),
    }
}

fn should_run_refresh_check(schedule: &AuthSchedule, now_unix_secs: i64) -> bool {
    if schedule.refresh_checked {
        return false;
    }
    let Some(expires_at) = schedule.auth_expires_at_unix_secs else {
        return false;
    };
    if now_unix_secs >= expires_at {
        return false;
    }
    let refresh_before = i64::from(schedule.auth_refresh_before_secs);
    if refresh_before <= 0 {
        return false;
    }
    let refresh_at = expires_at.saturating_sub(refresh_before);
    now_unix_secs >= refresh_at
}

fn next_auth_wait_ms(schedule: &AuthSchedule, now_unix_secs: i64) -> Option<u64> {
    let mut deadline = schedule.auth_expires_at_unix_secs;
    if !schedule.refresh_checked
        && let Some(expires_at) = schedule.auth_expires_at_unix_secs
    {
        let refresh_before = i64::from(schedule.auth_refresh_before_secs);
        if refresh_before > 0 {
            let refresh_at = expires_at.saturating_sub(refresh_before);
            deadline = Some(deadline.map_or(refresh_at, |value| value.min(refresh_at)));
        }
    }
    let deadline = deadline?;
    if deadline <= now_unix_secs {
        return Some(0);
    }
    Some(((deadline - now_unix_secs) as u64).saturating_mul(1000))
}

async fn send_outbound(
    io: &mut dyn ServerSessionIo,
    profile: &dyn warp_link_core::WireProfile,
    app: &Arc<dyn ServerApp>,
    session: &warp_link_core::SessionCtx,
    outbound: OutboundMsg,
) -> Result<(), WarpLinkError> {
    let frame = match profile.encode_server_deliver(&warp_link_core::DeliverMsg {
        seq: outbound.seq,
        id: outbound.id,
        payload: outbound.payload,
    }) {
        Ok(frame) => frame,
        Err(err) => {
            let error: WarpLinkError = err.into();
            app.on_disconnect(session, DisconnectReason::ProtocolError(error.to_string()))
                .await;
            return Err(error);
        }
    };
    if let Err(err) = io.send_frame(&frame).await {
        app.on_disconnect(session, DisconnectReason::TransportError(err.to_string()))
            .await;
        return Err(err);
    }
    Ok(())
}

fn apply_auth_state(
    session: &mut warp_link_core::SessionCtx,
    schedule: &mut AuthSchedule,
    state: SessionAuthState,
) -> Option<String> {
    match state {
        SessionAuthState::Valid => None,
        SessionAuthState::Renewed {
            auth_expires_at_unix_secs,
            auth_refresh_before_secs,
        } => {
            session.auth_expires_at_unix_secs = auth_expires_at_unix_secs;
            session.auth_refresh_before_secs =
                normalize_refresh_before(auth_expires_at_unix_secs, auth_refresh_before_secs);
            *schedule = AuthSchedule::from_session(session);
            None
        }
        SessionAuthState::RefreshRequired(message) => Some(auth_goaway_reason(
            "auth_refresh_required",
            message.as_str(),
        )),
        SessionAuthState::Revoked(message) => {
            Some(auth_goaway_reason("auth_revoked", message.as_str()))
        }
        SessionAuthState::Expired(message) => {
            Some(auth_goaway_reason("auth_expired", message.as_str()))
        }
    }
}

fn apply_auth_state_to_reason(state: SessionAuthState) -> Option<String> {
    match state {
        SessionAuthState::Valid => None,
        SessionAuthState::Renewed { .. } => None,
        SessionAuthState::RefreshRequired(message) => Some(auth_goaway_reason(
            "auth_refresh_required",
            message.as_str(),
        )),
        SessionAuthState::Revoked(message) => {
            Some(auth_goaway_reason("auth_revoked", message.as_str()))
        }
        SessionAuthState::Expired(message) => {
            Some(auth_goaway_reason("auth_expired", message.as_str()))
        }
    }
}

fn public_auth_state_message(state: &SessionAuthState) -> &'static str {
    match state {
        SessionAuthState::Valid | SessionAuthState::Renewed { .. } => "invalid_auth_state",
        SessionAuthState::RefreshRequired(_) => "refresh_required",
        SessionAuthState::Revoked(_) => "revoked",
        SessionAuthState::Expired(_) => "expired",
    }
}

fn public_auth_error_message(err: &AuthError) -> &'static str {
    match err {
        AuthError::Unauthorized(_) => "unauthorized",
        AuthError::Internal(_) => "internal_error",
    }
}

async fn send_goaway_and_close(
    io: &mut dyn ServerSessionIo,
    profile: &dyn warp_link_core::WireProfile,
    app: &Arc<dyn ServerApp>,
    session: &warp_link_core::SessionCtx,
    reason: String,
) {
    if let Ok(frame) = profile.encode_server_goaway(reason.as_str()) {
        let _ = io.send_frame(&frame).await;
    }
    app.on_disconnect(session, DisconnectReason::GoAway(reason))
        .await;
}

fn auth_goaway_reason(prefix: &str, message: &str) -> String {
    let detail = message.trim();
    if detail.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}:{detail}")
    }
}

fn unix_now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn normalize_refresh_before(expires_at_unix_secs: Option<i64>, refresh_before_secs: u16) -> u16 {
    let Some(expires_at) = expires_at_unix_secs else {
        return 0;
    };
    let now = unix_now_secs();
    let ttl = expires_at.saturating_sub(now).max(0);
    let capped = i64::from(refresh_before_secs).min(ttl.saturating_sub(1).max(0));
    capped.min(i64::from(u16::MAX)) as u16
}

#[cfg(feature = "quic")]
pub async fn serve_quic(config: ServerConfig, app: impl ServerApp) -> Result<(), WarpLinkError> {
    let app: Arc<dyn ServerApp> = Arc::new(app);
    serve_quic_with_app(config, app).await
}

#[cfg(not(feature = "quic"))]
pub async fn serve_quic(_config: ServerConfig, _app: impl ServerApp) -> Result<(), WarpLinkError> {
    Err(WarpLinkError::Unsupported(
        "quic server disabled at compile time (feature `quic`)".to_string(),
    ))
}

#[cfg(feature = "quic")]
pub async fn serve_quic_with_app(
    config: ServerConfig,
    app: Arc<dyn ServerApp>,
) -> Result<(), WarpLinkError> {
    if config.quic_tls_mode != TlsMode::TerminateInWarp {
        return Err(WarpLinkError::Unsupported(
            "quic requires TlsMode::TerminateInWarp (or external L4 passthrough)".to_string(),
        ));
    }
    let listen_addr: SocketAddr = config
        .quic_listen_addr
        .as_deref()
        .ok_or_else(|| WarpLinkError::Internal("quic_listen_addr is required".to_string()))?
        .parse()
        .map_err(|e| WarpLinkError::Internal(format!("invalid quic listen addr: {e}")))?;

    let quic_cfg = build_quic_server_config(&config)?;
    let endpoint = Endpoint::server(quic_cfg, listen_addr)
        .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
    let session_limiter = Arc::new(Semaphore::new(config.max_concurrent_sessions.max(1)));

    loop {
        let Some(incoming) = endpoint.accept().await else {
            return Ok(());
        };
        let app_clone = Arc::clone(&app);
        let cfg_clone = config.clone();
        let limiter = Arc::clone(&session_limiter);
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(conn) => conn,
                Err(err) => {
                    let peer = PeerMeta {
                        transport: TransportKind::Quic,
                        remote_addr: None,
                    };
                    let error = WarpLinkError::Transport(err.to_string());
                    app_clone.on_handshake_failure(peer, &error).await;
                    return;
                }
            };
            let remote = conn.remote_address().to_string();
            let permit = match limiter.try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    let peer = PeerMeta {
                        transport: TransportKind::Quic,
                        remote_addr: Some(remote),
                    };
                    let error = WarpLinkError::Transport(
                        "server busy: concurrent session limit reached".to_string(),
                    );
                    app_clone.on_handshake_failure(peer, &error).await;
                    return;
                }
            };
            let _permit = permit;
            loop {
                let bi = timeout(
                    Duration::from_millis(cfg_clone.hello_timeout_ms),
                    conn.accept_bi(),
                )
                .await;
                let (send, recv) = match bi {
                    Ok(Ok(streams)) => streams,
                    Ok(Err(err)) => {
                        let peer = PeerMeta {
                            transport: TransportKind::Quic,
                            remote_addr: Some(remote.clone()),
                        };
                        let error = WarpLinkError::Transport(err.to_string());
                        app_clone.on_handshake_failure(peer, &error).await;
                        break;
                    }
                    Err(_) => {
                        let peer = PeerMeta {
                            transport: TransportKind::Quic,
                            remote_addr: Some(remote.clone()),
                        };
                        let error =
                            WarpLinkError::Timeout("quic accept stream timeout".to_string());
                        app_clone.on_handshake_failure(peer, &error).await;
                        break;
                    }
                };
                let mut io = QuicServerIo {
                    send,
                    recv,
                    write_timeout_ms: cfg_clone.write_timeout_ms,
                };
                let peer = PeerMeta {
                    transport: TransportKind::Quic,
                    remote_addr: Some(remote.clone()),
                };
                let _ = run_server_session(&cfg_clone, Arc::clone(&app_clone), &mut io, peer).await;
            }
        });
    }
}

#[cfg(not(feature = "quic"))]
pub async fn serve_quic_with_app(
    _config: ServerConfig,
    _app: Arc<dyn ServerApp>,
) -> Result<(), WarpLinkError> {
    Err(WarpLinkError::Unsupported(
        "quic server disabled at compile time (feature `quic`)".to_string(),
    ))
}

#[cfg(feature = "tcp")]
pub async fn serve_tcp(config: ServerConfig, app: impl ServerApp) -> Result<(), WarpLinkError> {
    let app: Arc<dyn ServerApp> = Arc::new(app);
    serve_tcp_with_app(config, app).await
}

#[cfg(not(feature = "tcp"))]
pub async fn serve_tcp(_config: ServerConfig, _app: impl ServerApp) -> Result<(), WarpLinkError> {
    Err(WarpLinkError::Unsupported(
        "tcp server disabled at compile time (feature `tcp`)".to_string(),
    ))
}

#[cfg(feature = "tcp")]
pub async fn serve_tcp_with_app(
    config: ServerConfig,
    app: Arc<dyn ServerApp>,
) -> Result<(), WarpLinkError> {
    if config.tcp_tls_mode == TlsMode::OffloadAtEdge {
        return serve_tcp_plain_with_app(config, app).await;
    }
    let listen_addr: SocketAddr = config
        .tcp_listen_addr
        .as_deref()
        .ok_or_else(|| WarpLinkError::Internal("tcp_listen_addr is required".to_string()))?
        .parse()
        .map_err(|e| WarpLinkError::Internal(format!("invalid tcp listen addr: {e}")))?;

    let tls_config = build_tls_server_config(&config, config.tcp_alpn.as_str())?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
    let session_limiter = Arc::new(Semaphore::new(config.max_concurrent_sessions.max(1)));

    loop {
        let (socket, remote_addr) = listener
            .accept()
            .await
            .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
        let permit = match Arc::clone(&session_limiter).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let peer = PeerMeta {
                    transport: TransportKind::Tcp,
                    remote_addr: Some(remote_addr.to_string()),
                };
                let error = WarpLinkError::Transport(
                    "server busy: concurrent session limit reached".to_string(),
                );
                app.on_handshake_failure(peer, &error).await;
                continue;
            }
        };
        let app_clone = Arc::clone(&app);
        let cfg_clone = config.clone();
        let acceptor_clone = acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let tls = match acceptor_clone.accept(socket).await {
                Ok(tls) => tls,
                Err(err) => {
                    let peer = PeerMeta {
                        transport: TransportKind::Tcp,
                        remote_addr: Some(remote_addr.to_string()),
                    };
                    let error = WarpLinkError::Transport(err.to_string());
                    app_clone.on_handshake_failure(peer, &error).await;
                    return;
                }
            };
            let (reader, writer) = tokio::io::split(tls);
            let mut io = TcpServerIo {
                reader,
                writer,
                write_timeout_ms: cfg_clone.write_timeout_ms,
            };
            let peer = PeerMeta {
                transport: TransportKind::Tcp,
                remote_addr: Some(remote_addr.to_string()),
            };
            let _ = run_server_session(&cfg_clone, app_clone, &mut io, peer).await;
        });
    }
}

#[cfg(feature = "tcp")]
pub async fn serve_tcp_plain(
    config: ServerConfig,
    app: impl ServerApp,
) -> Result<(), WarpLinkError> {
    let app: Arc<dyn ServerApp> = Arc::new(app);
    serve_tcp_plain_with_app(config, app).await
}

#[cfg(not(feature = "tcp"))]
pub async fn serve_tcp_plain(
    _config: ServerConfig,
    _app: impl ServerApp,
) -> Result<(), WarpLinkError> {
    Err(WarpLinkError::Unsupported(
        "tcp server disabled at compile time (feature `tcp`)".to_string(),
    ))
}

#[cfg(feature = "tcp")]
pub async fn serve_tcp_plain_with_app(
    config: ServerConfig,
    app: Arc<dyn ServerApp>,
) -> Result<(), WarpLinkError> {
    let listen_addr: SocketAddr = config
        .tcp_listen_addr
        .as_deref()
        .ok_or_else(|| WarpLinkError::Internal("tcp_listen_addr is required".to_string()))?
        .parse()
        .map_err(|e| WarpLinkError::Internal(format!("invalid tcp listen addr: {e}")))?;

    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
    let session_limiter = Arc::new(Semaphore::new(config.max_concurrent_sessions.max(1)));

    loop {
        let (socket, remote_addr) = listener
            .accept()
            .await
            .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
        let permit = match Arc::clone(&session_limiter).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let peer = PeerMeta {
                    transport: TransportKind::Tcp,
                    remote_addr: Some(remote_addr.to_string()),
                };
                let error = WarpLinkError::Transport(
                    "server busy: concurrent session limit reached".to_string(),
                );
                app.on_handshake_failure(peer, &error).await;
                continue;
            }
        };
        let app_clone = Arc::clone(&app);
        let cfg_clone = config.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let (reader, writer) = tokio::io::split(socket);
            let mut io = PlainTcpServerIo {
                reader,
                writer,
                write_timeout_ms: cfg_clone.write_timeout_ms,
            };
            let peer = PeerMeta {
                transport: TransportKind::Tcp,
                remote_addr: Some(remote_addr.to_string()),
            };
            let _ = run_server_session(&cfg_clone, app_clone, &mut io, peer).await;
        });
    }
}

#[cfg(not(feature = "tcp"))]
pub async fn serve_tcp_plain_with_app(
    _config: ServerConfig,
    _app: Arc<dyn ServerApp>,
) -> Result<(), WarpLinkError> {
    Err(WarpLinkError::Unsupported(
        "tcp server disabled at compile time (feature `tcp`)".to_string(),
    ))
}

#[cfg(not(feature = "tcp"))]
pub async fn serve_tcp_with_app(
    _config: ServerConfig,
    _app: Arc<dyn ServerApp>,
) -> Result<(), WarpLinkError> {
    Err(WarpLinkError::Unsupported(
        "tcp server disabled at compile time (feature `tcp`)".to_string(),
    ))
}

#[cfg(feature = "wss")]
pub async fn serve_wss_embedded<I>(
    config: ServerConfig,
    app: impl ServerApp,
    io: I,
) -> Result<(), WarpLinkError>
where
    I: WsUpgradeIo,
{
    let app: Arc<dyn ServerApp> = Arc::new(app);
    serve_wss_embedded_with_app(config, app, io).await
}

#[cfg(not(feature = "wss"))]
pub async fn serve_wss_embedded<I>(
    _config: ServerConfig,
    _app: impl ServerApp,
    _io: I,
) -> Result<(), WarpLinkError>
where
    I: WsUpgradeIo,
{
    Err(WarpLinkError::Unsupported(
        "wss server disabled at compile time (feature `wss`)".to_string(),
    ))
}

#[cfg(feature = "wss")]
pub async fn serve_wss_embedded_with_app<I>(
    config: ServerConfig,
    app: Arc<dyn ServerApp>,
    io: I,
) -> Result<(), WarpLinkError>
where
    I: WsUpgradeIo,
{
    let peer = PeerMeta {
        transport: TransportKind::Wss,
        remote_addr: io.remote_addr(),
    };
    let mut session_io = WsServerIo {
        inner: io,
        write_timeout_ms: config.write_timeout_ms,
    };
    run_server_session(&config, app, &mut session_io, peer).await
}

#[cfg(not(feature = "wss"))]
pub async fn serve_wss_embedded_with_app<I>(
    _config: ServerConfig,
    _app: Arc<dyn ServerApp>,
    _io: I,
) -> Result<(), WarpLinkError>
where
    I: WsUpgradeIo,
{
    Err(WarpLinkError::Unsupported(
        "wss server disabled at compile time (feature `wss`)".to_string(),
    ))
}

#[cfg(feature = "wss")]
pub async fn serve_wss_standalone(
    config: ServerConfig,
    wss: WssStandaloneConfig,
    app: impl ServerApp,
) -> Result<(), WarpLinkError> {
    let app: Arc<dyn ServerApp> = Arc::new(app);
    serve_wss_standalone_with_app(config, wss, app).await
}

#[cfg(not(feature = "wss"))]
pub async fn serve_wss_standalone(
    _config: ServerConfig,
    _wss: WssStandaloneConfig,
    _app: impl ServerApp,
) -> Result<(), WarpLinkError> {
    Err(WarpLinkError::Unsupported(
        "wss server disabled at compile time (feature `wss`)".to_string(),
    ))
}

#[cfg(feature = "wss")]
pub async fn serve_wss_standalone_with_app(
    config: ServerConfig,
    wss: WssStandaloneConfig,
    app: Arc<dyn ServerApp>,
) -> Result<(), WarpLinkError> {
    let listen_addr: SocketAddr = wss
        .listen_addr
        .parse()
        .map_err(|e| WarpLinkError::Internal(format!("invalid wss listen addr: {e}")))?;
    if wss.path.trim().is_empty() || !wss.path.starts_with('/') {
        return Err(WarpLinkError::Internal(
            "wss path must start with '/'".to_string(),
        ));
    }
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
    let session_limiter = Arc::new(Semaphore::new(config.max_concurrent_sessions.max(1)));
    let tls_acceptor = match wss.tls_mode {
        TlsMode::OffloadAtEdge => None,
        TlsMode::TerminateInWarp => {
            let tls = build_tls_server_config(&config, "http/1.1")?;
            Some(TlsAcceptor::from(Arc::new(tls)))
        }
    };

    loop {
        let (socket, remote_addr) = listener
            .accept()
            .await
            .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
        let permit = match Arc::clone(&session_limiter).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let peer = PeerMeta {
                    transport: TransportKind::Wss,
                    remote_addr: Some(remote_addr.to_string()),
                };
                let error = WarpLinkError::Transport(
                    "server busy: concurrent session limit reached".to_string(),
                );
                app.on_handshake_failure(peer, &error).await;
                continue;
            }
        };
        let cfg_clone = config.clone();
        let app_clone = Arc::clone(&app);
        let path = wss.path.clone();
        let subprotocol = wss.subprotocol.clone();
        let max_frame_bytes = wss.max_frame_bytes.max(2);
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(acceptor) = tls_acceptor {
                match acceptor.accept(socket).await {
                    Ok(tls_stream) => {
                        run_standalone_wss_session(
                            tls_stream,
                            path.as_str(),
                            subprotocol.as_deref(),
                            max_frame_bytes,
                            remote_addr.to_string(),
                            cfg_clone,
                            app_clone,
                        )
                        .await;
                    }
                    Err(error) => {
                        let peer = PeerMeta {
                            transport: TransportKind::Wss,
                            remote_addr: Some(remote_addr.to_string()),
                        };
                        let err = WarpLinkError::Transport(error.to_string());
                        app_clone.on_handshake_failure(peer, &err).await;
                    }
                }
            } else {
                run_standalone_wss_session(
                    socket,
                    path.as_str(),
                    subprotocol.as_deref(),
                    max_frame_bytes,
                    remote_addr.to_string(),
                    cfg_clone,
                    app_clone,
                )
                .await;
            }
        });
    }
}

#[cfg(not(feature = "wss"))]
pub async fn serve_wss_standalone_with_app(
    _config: ServerConfig,
    _wss: WssStandaloneConfig,
    _app: Arc<dyn ServerApp>,
) -> Result<(), WarpLinkError> {
    Err(WarpLinkError::Unsupported(
        "wss server disabled at compile time (feature `wss`)".to_string(),
    ))
}

#[cfg(feature = "quic")]
struct QuicServerIo {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    write_timeout_ms: u64,
}

#[cfg(feature = "quic")]
#[async_trait]
impl ServerSessionIo for QuicServerIo {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), WarpLinkError> {
        timeout(
            Duration::from_millis(self.write_timeout_ms),
            write_prefixed_frame(&mut self.send, frame),
        )
        .await
        .map_err(|_| WarpLinkError::Timeout("quic write timeout".to_string()))??;
        Ok(())
    }

    async fn recv_frame(&mut self, timeout_ms: u64) -> Result<Vec<u8>, WarpLinkError> {
        timeout(
            Duration::from_millis(timeout_ms),
            read_prefixed_frame(&mut self.recv),
        )
        .await
        .map_err(|_| WarpLinkError::Timeout("quic read timeout".to_string()))?
    }
}

#[cfg(feature = "tcp")]
struct TcpServerIo {
    reader: ReadHalf<ServerTlsStream<TcpStream>>,
    writer: WriteHalf<ServerTlsStream<TcpStream>>,
    write_timeout_ms: u64,
}

#[cfg(feature = "tcp")]
#[async_trait]
impl ServerSessionIo for TcpServerIo {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), WarpLinkError> {
        timeout(
            Duration::from_millis(self.write_timeout_ms),
            write_prefixed_frame(&mut self.writer, frame),
        )
        .await
        .map_err(|_| WarpLinkError::Timeout("tcp write timeout".to_string()))??;
        Ok(())
    }

    async fn recv_frame(&mut self, timeout_ms: u64) -> Result<Vec<u8>, WarpLinkError> {
        timeout(
            Duration::from_millis(timeout_ms),
            read_prefixed_frame(&mut self.reader),
        )
        .await
        .map_err(|_| WarpLinkError::Timeout("tcp read timeout".to_string()))?
    }
}

#[cfg(feature = "tcp")]
struct PlainTcpServerIo {
    reader: ReadHalf<TcpStream>,
    writer: WriteHalf<TcpStream>,
    write_timeout_ms: u64,
}

#[cfg(feature = "tcp")]
#[async_trait]
impl ServerSessionIo for PlainTcpServerIo {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), WarpLinkError> {
        timeout(
            Duration::from_millis(self.write_timeout_ms),
            write_prefixed_frame(&mut self.writer, frame),
        )
        .await
        .map_err(|_| WarpLinkError::Timeout("tcp write timeout".to_string()))??;
        Ok(())
    }

    async fn recv_frame(&mut self, timeout_ms: u64) -> Result<Vec<u8>, WarpLinkError> {
        timeout(
            Duration::from_millis(timeout_ms),
            read_prefixed_frame(&mut self.reader),
        )
        .await
        .map_err(|_| WarpLinkError::Timeout("tcp read timeout".to_string()))?
    }
}

#[cfg(feature = "wss")]
struct WsServerIo<I: WsUpgradeIo> {
    inner: I,
    write_timeout_ms: u64,
}

#[cfg(feature = "wss")]
#[async_trait]
impl<I: WsUpgradeIo> ServerSessionIo for WsServerIo<I> {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<(), WarpLinkError> {
        timeout(
            Duration::from_millis(self.write_timeout_ms),
            self.inner.send_binary(frame.to_vec()),
        )
        .await
        .map_err(|_| WarpLinkError::Timeout("wss write timeout".to_string()))??;
        Ok(())
    }

    async fn recv_frame(&mut self, timeout_ms: u64) -> Result<Vec<u8>, WarpLinkError> {
        self.inner.recv_binary(timeout_ms).await
    }
}

#[cfg(feature = "wss")]
async fn run_standalone_wss_session<S>(
    stream: S,
    path: &str,
    expected_subprotocol: Option<&str>,
    max_frame_bytes: usize,
    remote_addr: String,
    config: ServerConfig,
    app: Arc<dyn ServerApp>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let peer = PeerMeta {
        transport: TransportKind::Wss,
        remote_addr: Some(remote_addr.clone()),
    };
    let ws = match accept_standalone_wss(stream, path, expected_subprotocol).await {
        Ok(ws) => ws,
        Err(err) => {
            app.on_handshake_failure(peer, &err).await;
            return;
        }
    };
    let io = TungsteniteWsIo {
        ws,
        remote_addr: Some(remote_addr),
        max_frame_bytes,
    };
    let _ = serve_wss_embedded_with_app(config, app, io).await;
}

#[cfg(feature = "wss")]
async fn accept_standalone_wss<S>(
    stream: S,
    expected_path: &str,
    expected_subprotocol: Option<&str>,
) -> Result<WebSocketStream<S>, WarpLinkError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let expected = expected_path.to_string();
    let expected_subprotocol = expected_subprotocol.map(|value| value.to_string());
    accept_hdr_async(stream, move |request: &WsRequest, response: WsResponse| {
        if request.uri().path() != expected {
            let err: WsErrorResponse = WsResponse::builder()
                .status(WsStatusCode::NOT_FOUND)
                .body(Some("path_not_found".to_string()))
                .expect("build wss error response");
            return Err(err);
        }
        let mut response = response;
        if let Some(expected_subprotocol) = expected_subprotocol.as_deref() {
            let requested = request
                .headers()
                .get("sec-websocket-protocol")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            let matched = requested_subprotocol_matches(requested, expected_subprotocol);
            if !matched {
                let err: WsErrorResponse = WsResponse::builder()
                    .status(WsStatusCode::BAD_REQUEST)
                    .body(Some("subprotocol_mismatch".to_string()))
                    .expect("build wss subprotocol error response");
                return Err(err);
            }
            if let Ok(value) = expected_subprotocol.parse() {
                response
                    .headers_mut()
                    .insert("Sec-WebSocket-Protocol", value);
            }
        }
        Ok(response)
    })
    .await
    .map_err(|e| WarpLinkError::Protocol(format!("wss upgrade failed: {e}")))
}

#[cfg(feature = "wss")]
fn requested_subprotocol_matches(requested: &str, expected: &str) -> bool {
    requested
        .split(',')
        .map(str::trim)
        .any(|value| value == expected)
}

#[cfg(feature = "wss")]
struct TungsteniteWsIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    ws: WebSocketStream<S>,
    remote_addr: Option<String>,
    max_frame_bytes: usize,
}

#[cfg(feature = "wss")]
#[async_trait]
impl<S> WsUpgradeIo for TungsteniteWsIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    async fn send_binary(&mut self, frame: Vec<u8>) -> Result<(), WarpLinkError> {
        self.ws
            .send(WsMessage::Binary(frame.into()))
            .await
            .map_err(|e| WarpLinkError::Transport(e.to_string()))
    }

    async fn recv_binary(&mut self, timeout_ms: u64) -> Result<Vec<u8>, WarpLinkError> {
        loop {
            let next = timeout(Duration::from_millis(timeout_ms), self.ws.next())
                .await
                .map_err(|_| WarpLinkError::Timeout("wss read timeout".to_string()))?;
            let message = next
                .ok_or_else(|| WarpLinkError::Transport("websocket closed".to_string()))?
                .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
            match message {
                WsMessage::Binary(data) => {
                    if data.len() > self.max_frame_bytes {
                        return Err(WarpLinkError::Protocol(format!(
                            "wss frame too large: {}",
                            data.len()
                        )));
                    }
                    return Ok(data.to_vec());
                }
                WsMessage::Ping(payload) => {
                    self.ws
                        .send(WsMessage::Pong(payload))
                        .await
                        .map_err(|e| WarpLinkError::Transport(e.to_string()))?;
                }
                WsMessage::Pong(_) => {}
                WsMessage::Close(_) => {
                    return Err(WarpLinkError::Transport("websocket closed".to_string()));
                }
                WsMessage::Text(_) => {
                    return Err(WarpLinkError::Protocol(
                        "wss text frame is not supported".to_string(),
                    ));
                }
                _ => {}
            }
        }
    }

    fn remote_addr(&self) -> Option<String> {
        self.remote_addr.clone()
    }
}

#[cfg(any(feature = "quic", feature = "tcp", feature = "wss"))]
fn build_tls_server_config(
    config: &ServerConfig,
    alpn: &str,
) -> Result<rustls::ServerConfig, WarpLinkError> {
    let cert_path = config
        .tls_cert_path
        .as_deref()
        .ok_or_else(|| WarpLinkError::Internal("tls_cert_path is required".to_string()))?;
    let key_path = config
        .tls_key_path
        .as_deref()
        .ok_or_else(|| WarpLinkError::Internal("tls_key_path is required".to_string()))?;
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| WarpLinkError::Internal(format!("invalid tls cert/key: {e}")))?;
    tls.alpn_protocols = vec![alpn.as_bytes().to_vec()];
    Ok(tls)
}

#[cfg(feature = "quic")]
fn build_quic_server_config(config: &ServerConfig) -> Result<quinn::ServerConfig, WarpLinkError> {
    let tls = build_tls_server_config(config, config.quic_alpn.as_str())?;
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| WarpLinkError::Internal(format!("invalid quic tls config: {e}")))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    let idle_timeout = quinn::IdleTimeout::try_from(Duration::from_secs(30))
        .map_err(|e| WarpLinkError::Internal(format!("invalid quic idle timeout: {e}")))?;
    transport.max_idle_timeout(Some(idle_timeout));
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}

#[cfg(any(feature = "quic", feature = "tcp", feature = "wss"))]
fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, WarpLinkError> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| WarpLinkError::Internal(format!("{path}: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| WarpLinkError::Internal(format!("read certs failed: {e}")))?;
    if certs.is_empty() {
        return Err(WarpLinkError::Internal(
            "empty certificate chain".to_string(),
        ));
    }
    Ok(certs)
}

#[cfg(any(feature = "quic", feature = "tcp", feature = "wss"))]
fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, WarpLinkError> {
    PrivateKeyDer::from_pem_file(path)
        .map_err(|e| WarpLinkError::Internal(format!("read private key failed: {e}")))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::Bytes;
    use pushgo_warp_profile::{FrameType, PushgoWireProfile, postcard_v1_flags};
    use warp_link_core::{
        ClientPolicy, ClientPowerHint, ClientPowerTier, HelloCtx, OutboundMsg, SessionCtx,
        WireProfile,
    };

    use super::*;

    #[derive(Debug)]
    enum InboundEvent {
        Frame(Vec<u8>),
        Timeout,
    }

    struct MockIo {
        inbound: VecDeque<InboundEvent>,
        outbound: Vec<Vec<u8>>,
        fail_send_after: Option<usize>,
        send_count: usize,
    }

    #[async_trait]
    impl ServerSessionIo for MockIo {
        async fn send_frame(&mut self, frame: &[u8]) -> Result<(), WarpLinkError> {
            if let Some(max_ok_sends) = self.fail_send_after
                && self.send_count >= max_ok_sends
            {
                return Err(WarpLinkError::Transport("mock send failure".to_string()));
            }
            self.outbound.push(frame.to_vec());
            self.send_count = self.send_count.saturating_add(1);
            Ok(())
        }

        async fn recv_frame(&mut self, _timeout_ms: u64) -> Result<Vec<u8>, WarpLinkError> {
            match self.inbound.pop_front() {
                Some(InboundEvent::Frame(frame)) => Ok(frame),
                Some(InboundEvent::Timeout) => {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                    Err(WarpLinkError::Timeout("mock timeout".into()))
                }
                None => Err(WarpLinkError::Transport("mock eof".into())),
            }
        }
    }

    struct MockCoordinator {
        acquire_count: AtomicUsize,
        renew_count: AtomicUsize,
        release_count: AtomicUsize,
    }

    impl MockCoordinator {
        fn new() -> Self {
            Self {
                acquire_count: AtomicUsize::new(0),
                renew_count: AtomicUsize::new(0),
                release_count: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl warp_link_core::SessionCoordinator for MockCoordinator {
        async fn acquire(
            &self,
            key: &str,
            owner: &str,
            ttl_secs: u64,
        ) -> Result<warp_link_core::SessionLease, warp_link_core::CoordinationError> {
            self.acquire_count.fetch_add(1, Ordering::SeqCst);
            Ok(warp_link_core::SessionLease {
                key: key.to_string(),
                owner: owner.to_string(),
                epoch: 1,
                expires_at_unix_secs: unix_now_secs().saturating_add(ttl_secs as i64),
            })
        }

        async fn renew(
            &self,
            key: &str,
            owner: &str,
            epoch: u64,
            ttl_secs: u64,
        ) -> Result<warp_link_core::SessionLease, warp_link_core::CoordinationError> {
            self.renew_count.fetch_add(1, Ordering::SeqCst);
            Ok(warp_link_core::SessionLease {
                key: key.to_string(),
                owner: owner.to_string(),
                epoch,
                expires_at_unix_secs: unix_now_secs().saturating_add(ttl_secs as i64),
            })
        }

        async fn release(
            &self,
            _key: &str,
            _owner: &str,
            _epoch: u64,
        ) -> Result<(), warp_link_core::CoordinationError> {
            self.release_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct MockServerApp {
        profile: Arc<PushgoWireProfile>,
        coordinator: Option<Arc<MockCoordinator>>,
        send_outbound: bool,
        reject_auth: bool,
        sent_once: Mutex<bool>,
        acked_ids: Mutex<Vec<String>>,
        disconnected: Mutex<Vec<String>>,
        handshake_failures: Mutex<Vec<String>>,
        forced_auth_state: Mutex<SessionAuthState>,
        session_control: Mutex<Option<SessionControl>>,
    }

    impl MockServerApp {
        fn new(send_outbound: bool, reject_auth: bool) -> Self {
            Self {
                profile: Arc::new(PushgoWireProfile::new()),
                coordinator: None,
                send_outbound,
                reject_auth,
                sent_once: Mutex::new(false),
                acked_ids: Mutex::new(Vec::new()),
                disconnected: Mutex::new(Vec::new()),
                handshake_failures: Mutex::new(Vec::new()),
                forced_auth_state: Mutex::new(SessionAuthState::Valid),
                session_control: Mutex::new(None),
            }
        }

        fn with_coordinator(
            send_outbound: bool,
            reject_auth: bool,
            coordinator: Arc<MockCoordinator>,
        ) -> Self {
            let mut app = Self::new(send_outbound, reject_auth);
            app.coordinator = Some(coordinator);
            app
        }

        fn set_auth_state(&self, state: SessionAuthState) {
            *self
                .forced_auth_state
                .lock()
                .expect("forced_auth_state lock should not be poisoned") = state;
        }
    }

    struct MockClientPowerApp {
        hello: Mutex<HelloCtx>,
        hint: Mutex<Option<ClientPowerHint>>,
    }

    impl MockClientPowerApp {
        fn new(hello: HelloCtx) -> Self {
            Self {
                hello: Mutex::new(hello),
                hint: Mutex::new(None),
            }
        }

        fn set_power_hint(&self, hint: Option<ClientPowerHint>) {
            *self.hint.lock().expect("hint lock should not be poisoned") = hint;
        }
    }

    impl ClientApp for MockClientPowerApp {
        fn on_hello(&self) -> HelloCtx {
            self.hello
                .lock()
                .expect("hello lock should not be poisoned")
                .clone()
        }

        fn on_event(&self, _event: ClientEvent) -> AppDecision {
            AppDecision::Ignore
        }

        fn power_hint(&self) -> Option<ClientPowerHint> {
            *self.hint.lock().expect("hint lock should not be poisoned")
        }
    }

    fn test_client_config() -> ClientConfig {
        ClientConfig {
            host: "push.local".to_string(),
            quic_port: 443,
            wss_port: 443,
            tcp_port: 5223,
            wss_path: "/private/ws".to_string(),
            quic_alpn: "pushgo-quic".to_string(),
            tcp_alpn: "pushgo-tcp".to_string(),
            wss_subprotocol: Some("pushgo-private.v1".to_string()),
            tls_server_name: None,
            bearer_token: None,
            cert_pin_sha256: None,
            quic_cert_pin_sha256: None,
            tcp_cert_pin_sha256: None,
            wss_cert_pin_sha256: None,
            policy: ClientPolicy::default(),
            wire_profile: Arc::new(PushgoWireProfile::new()),
        }
    }

    #[cfg(feature = "wss")]
    #[test]
    fn standalone_wss_subprotocol_allows_csv_header() {
        assert!(requested_subprotocol_matches(
            "chat, pushgo-private.v1",
            "pushgo-private.v1"
        ));
        assert!(!requested_subprotocol_matches(
            "chat, superchat",
            "pushgo-private.v1"
        ));
    }

    #[async_trait]
    impl ServerApp for MockServerApp {
        fn wire_profile(&self) -> Arc<dyn warp_link_core::WireProfile> {
            self.profile.clone()
        }

        async fn auth(&self, request: AuthRequest) -> Result<AuthResponse, AuthError> {
            match request.phase {
                AuthCheckPhase::Connect => {
                    if self.reject_auth {
                        return Err(AuthError::Unauthorized("mock auth rejected".to_string()));
                    }
                    let hello = request
                        .hello
                        .ok_or_else(|| AuthError::Internal("missing_connect_hello".to_string()))?;
                    Ok(AuthResponse::ConnectAccepted(SessionCtx {
                        session_id: "s-1".to_string(),
                        identity: hello.identity,
                        resume_token: Some("resume-1".to_string()),
                        heartbeat_secs: 12,
                        ping_interval_secs: 6,
                        idle_timeout_secs: 48,
                        max_backoff_secs: 30,
                        auth_expires_at_unix_secs: Some(unix_now_secs().saturating_add(30)),
                        auth_refresh_before_secs: 30,
                        max_frame_bytes: 32 * 1024,
                        negotiated_wire_version: 1,
                        negotiated_payload_version: 1,
                        metadata: std::collections::BTreeMap::new(),
                    }))
                }
                AuthCheckPhase::RefreshWindow | AuthCheckPhase::InBandReauth => {
                    let state = self
                        .forced_auth_state
                        .lock()
                        .expect("forced_auth_state lock should not be poisoned")
                        .clone();
                    Ok(AuthResponse::State(state))
                }
            }
        }

        async fn wait_outbound(
            &self,
            _session: &SessionCtx,
            max_wait_ms: u64,
        ) -> Option<OutboundMsg> {
            if !self.send_outbound {
                tokio::time::sleep(Duration::from_millis(max_wait_ms.max(1))).await;
                return None;
            }
            let mut sent = self
                .sent_once
                .lock()
                .expect("sent_once lock should not be poisoned");
            if *sent {
                return None;
            }
            *sent = true;
            Some(OutboundMsg {
                seq: Some(1),
                id: "m-1".to_string(),
                payload: Bytes::from_static(b"demo"),
            })
        }

        async fn on_ack(&self, _session: &SessionCtx, ack: AckMsg) {
            self.acked_ids
                .lock()
                .expect("acked_ids lock should not be poisoned")
                .push(ack.id);
        }

        async fn on_disconnect(&self, _session: &SessionCtx, reason: DisconnectReason) {
            self.disconnected
                .lock()
                .expect("disconnected lock should not be poisoned")
                .push(format!("{reason:?}"));
        }

        async fn on_handshake_failure(&self, _peer: PeerMeta, error: &WarpLinkError) {
            self.handshake_failures
                .lock()
                .expect("handshake_failures lock should not be poisoned")
                .push(error.to_string());
        }

        fn on_session_control(&self, _session: &SessionCtx, control: SessionControl) {
            *self
                .session_control
                .lock()
                .expect("session_control lock should not be poisoned") = Some(control);
        }

        fn session_coordinator(&self) -> Option<Arc<dyn warp_link_core::SessionCoordinator>> {
            self.coordinator
                .as_ref()
                .map(|value| Arc::clone(value) as Arc<dyn warp_link_core::SessionCoordinator>)
        }

        fn session_coord_owner(&self) -> Option<String> {
            self.coordinator.as_ref().map(|_| "test-node".to_string())
        }
    }

    fn encode_client_goaway(reason: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + reason.len());
        out.push(FrameType::GoAway as u8);
        out.push(postcard_v1_flags());
        out.extend_from_slice(reason.as_bytes());
        out
    }

    #[tokio::test]
    async fn server_session_handshake_deliver_ack_and_goaway() {
        let profile = PushgoWireProfile::new();
        let hello = profile
            .encode_client_hello(&HelloCtx {
                identity: "dev-1".to_string(),
                auth_token: Some("token".to_string()),
                ..HelloCtx::default()
            })
            .expect("encode hello should succeed")
            .to_vec();
        let ack = profile
            .encode_client_ack(&AckMsg {
                seq: Some(1),
                id: "m-1".to_string(),
                status: AckStatus::Ok,
            })
            .expect("encode ack should succeed")
            .to_vec();
        let goaway = encode_client_goaway("drain");

        let app = Arc::new(MockServerApp::new(true, false));
        let mut io = MockIo {
            inbound: VecDeque::from([
                InboundEvent::Frame(hello),
                InboundEvent::Timeout,
                InboundEvent::Frame(ack),
                InboundEvent::Timeout,
                InboundEvent::Frame(goaway),
            ]),
            outbound: Vec::new(),
            fail_send_after: None,
            send_count: 0,
        };
        let config = ServerConfig {
            idle_timeout_ms: 500,
            ..ServerConfig::default()
        };

        run_server_session(
            &config,
            app.clone(),
            &mut io,
            PeerMeta {
                transport: TransportKind::Wss,
                remote_addr: Some("127.0.0.1:12345".to_string()),
            },
        )
        .await
        .expect("session should finish on goaway");

        let mut saw_welcome = false;
        let mut saw_deliver = false;
        for frame in &io.outbound {
            match profile
                .decode_server_frame(frame.as_slice())
                .expect("server frame decode should succeed")
            {
                DecodedServerFrame::Welcome(_) => saw_welcome = true,
                DecodedServerFrame::Deliver(msg) if msg.id == "m-1" => saw_deliver = true,
                _ => {}
            }
        }
        assert!(saw_welcome, "must send welcome");
        assert!(saw_deliver, "must send at least one deliver frame");
        let acked = app
            .acked_ids
            .lock()
            .expect("acked ids lock should not be poisoned");
        assert_eq!(acked.as_slice(), &["m-1".to_string()]);
    }

    #[tokio::test]
    async fn server_session_disconnects_after_four_idle_timeouts() {
        let profile = PushgoWireProfile::new();
        let hello = profile
            .encode_client_hello(&HelloCtx {
                identity: "dev-1".to_string(),
                ..HelloCtx::default()
            })
            .expect("encode hello should succeed")
            .to_vec();
        let app = Arc::new(MockServerApp::new(false, false));
        let mut io = MockIo {
            inbound: VecDeque::from([
                InboundEvent::Frame(hello),
                InboundEvent::Timeout,
                InboundEvent::Timeout,
                InboundEvent::Timeout,
                InboundEvent::Timeout,
                InboundEvent::Timeout,
                InboundEvent::Timeout,
                InboundEvent::Timeout,
                InboundEvent::Timeout,
            ]),
            outbound: Vec::new(),
            fail_send_after: None,
            send_count: 0,
        };
        let config = ServerConfig {
            idle_timeout_ms: 200,
            ..ServerConfig::default()
        };

        let err = run_server_session(
            &config,
            app.clone(),
            &mut io,
            PeerMeta {
                transport: TransportKind::Tcp,
                remote_addr: Some("127.0.0.1:8080".to_string()),
            },
        )
        .await
        .expect_err("four timeouts should terminate the session");
        match err {
            WarpLinkError::Timeout(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
        let disconnected = app
            .disconnected
            .lock()
            .expect("disconnected lock should not be poisoned");
        assert!(
            disconnected
                .iter()
                .any(|value| value.contains("IdleTimeout")),
            "disconnect callback should include idle timeout"
        );
    }

    #[tokio::test]
    async fn server_session_disconnects_when_outbound_send_fails() {
        let profile = PushgoWireProfile::new();
        let hello = profile
            .encode_client_hello(&HelloCtx {
                identity: "dev-1".to_string(),
                ..HelloCtx::default()
            })
            .expect("encode hello should succeed")
            .to_vec();

        let app = Arc::new(MockServerApp::new(true, false));
        let mut io = MockIo {
            inbound: VecDeque::from([InboundEvent::Frame(hello), InboundEvent::Timeout]),
            outbound: Vec::new(),
            fail_send_after: Some(1),
            send_count: 0,
        };
        let config = ServerConfig::default();

        let err = run_server_session(
            &config,
            app.clone(),
            &mut io,
            PeerMeta {
                transport: TransportKind::Wss,
                remote_addr: Some("127.0.0.1:12345".to_string()),
            },
        )
        .await
        .expect_err("send failure should terminate the session");
        match err {
            WarpLinkError::Transport(message) => {
                assert!(message.contains("mock send failure"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
        let disconnected = app
            .disconnected
            .lock()
            .expect("disconnected lock should not be poisoned");
        assert!(
            disconnected
                .iter()
                .any(|value| value.contains("TransportError")),
            "disconnect callback should include transport failure"
        );
    }

    #[tokio::test]
    async fn server_session_reports_handshake_failure_on_auth_reject() {
        let profile = PushgoWireProfile::new();
        let hello = profile
            .encode_client_hello(&HelloCtx {
                identity: "dev-1".to_string(),
                ..HelloCtx::default()
            })
            .expect("encode hello should succeed")
            .to_vec();

        let app = Arc::new(MockServerApp::new(false, true));
        let mut io = MockIo {
            inbound: VecDeque::from([InboundEvent::Frame(hello)]),
            outbound: Vec::new(),
            fail_send_after: None,
            send_count: 0,
        };

        let err = run_server_session(
            &ServerConfig::default(),
            app.clone(),
            &mut io,
            PeerMeta {
                transport: TransportKind::Quic,
                remote_addr: Some("127.0.0.1:443".to_string()),
            },
        )
        .await
        .expect_err("auth reject should fail the handshake");
        match err {
            WarpLinkError::Auth(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }

        let failures = app
            .handshake_failures
            .lock()
            .expect("handshake_failures lock should not be poisoned");
        assert_eq!(
            failures.len(),
            1,
            "must report exactly one handshake failure"
        );
        assert!(
            failures[0].contains("auth error"),
            "handshake failure should carry auth error"
        );
    }

    #[tokio::test]
    async fn server_session_releases_lease_on_auth_reject() {
        let profile = PushgoWireProfile::new();
        let hello = profile
            .encode_client_hello(&HelloCtx {
                identity: "dev-1".to_string(),
                ..HelloCtx::default()
            })
            .expect("encode hello should succeed")
            .to_vec();
        let coordinator = Arc::new(MockCoordinator::new());
        let app = Arc::new(MockServerApp::with_coordinator(
            false,
            true,
            Arc::clone(&coordinator),
        ));
        let mut io = MockIo {
            inbound: VecDeque::from([InboundEvent::Frame(hello)]),
            outbound: Vec::new(),
            fail_send_after: None,
            send_count: 0,
        };

        let err = run_server_session(
            &ServerConfig::default(),
            app,
            &mut io,
            PeerMeta {
                transport: TransportKind::Quic,
                remote_addr: Some("127.0.0.1:443".to_string()),
            },
        )
        .await
        .expect_err("auth reject should fail the handshake");
        match err {
            WarpLinkError::Auth(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(
            coordinator.acquire_count.load(Ordering::SeqCst),
            1,
            "coordinator acquire should be called once"
        );
        assert_eq!(
            coordinator.release_count.load(Ordering::SeqCst),
            1,
            "lease must be released when handshake auth fails"
        );
    }

    #[tokio::test]
    async fn server_session_releases_lease_on_graceful_disconnect() {
        let profile = PushgoWireProfile::new();
        let hello = profile
            .encode_client_hello(&HelloCtx {
                identity: "dev-1".to_string(),
                ..HelloCtx::default()
            })
            .expect("encode hello should succeed")
            .to_vec();
        let goaway = encode_client_goaway("drain");
        let coordinator = Arc::new(MockCoordinator::new());
        let app = Arc::new(MockServerApp::with_coordinator(
            false,
            false,
            Arc::clone(&coordinator),
        ));
        let mut io = MockIo {
            inbound: VecDeque::from([InboundEvent::Frame(hello), InboundEvent::Frame(goaway)]),
            outbound: Vec::new(),
            fail_send_after: None,
            send_count: 0,
        };

        run_server_session(
            &ServerConfig::default(),
            app,
            &mut io,
            PeerMeta {
                transport: TransportKind::Wss,
                remote_addr: Some("127.0.0.1:443".to_string()),
            },
        )
        .await
        .expect("session should close gracefully");

        assert_eq!(
            coordinator.acquire_count.load(Ordering::SeqCst),
            1,
            "coordinator acquire should be called once"
        );
        assert_eq!(
            coordinator.release_count.load(Ordering::SeqCst),
            1,
            "lease must be released after session close"
        );
    }

    #[tokio::test]
    async fn server_session_control_expire_now_kicks_connection() {
        let profile = PushgoWireProfile::new();
        let hello = profile
            .encode_client_hello(&HelloCtx {
                identity: "dev-1".to_string(),
                ..HelloCtx::default()
            })
            .expect("encode hello should succeed")
            .to_vec();
        let app = Arc::new(MockServerApp::new(false, false));
        let mut io = MockIo {
            inbound: VecDeque::from([
                InboundEvent::Frame(hello),
                InboundEvent::Timeout,
                InboundEvent::Timeout,
                InboundEvent::Timeout,
                InboundEvent::Timeout,
            ]),
            outbound: Vec::new(),
            fail_send_after: None,
            send_count: 0,
        };
        let app_clone = Arc::clone(&app);
        let session = tokio::spawn(async move {
            run_server_session(
                &ServerConfig::default(),
                app_clone,
                &mut io,
                PeerMeta {
                    transport: TransportKind::Wss,
                    remote_addr: Some("127.0.0.1:443".to_string()),
                },
            )
            .await
        });

        let control = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Some(control) = app
                    .session_control
                    .lock()
                    .expect("session_control lock should not be poisoned")
                    .clone()
                {
                    break control;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("session control should be available quickly");
        control.expire_now();

        session
            .await
            .expect("session join should succeed")
            .expect("control expire should close gracefully");

        let disconnected = app
            .disconnected
            .lock()
            .expect("disconnected lock should not be poisoned");
        assert!(
            disconnected
                .iter()
                .any(|value| value.contains("GoAway(\"auth_expired:control_expire\")")),
            "expire_now must emit auth_expired goaway"
        );
    }

    #[tokio::test]
    async fn server_session_goaway_on_revoked_auth_state() {
        let profile = PushgoWireProfile::new();
        let hello = profile
            .encode_client_hello(&HelloCtx {
                identity: "dev-1".to_string(),
                ..HelloCtx::default()
            })
            .expect("encode hello should succeed")
            .to_vec();
        let reauth = profile
            .encode_client_hello(&HelloCtx {
                identity: "dev-1".to_string(),
                auth_token: Some("updated-token".to_string()),
                ..HelloCtx::default()
            })
            .expect("encode reauth hello should succeed")
            .to_vec();

        let app = Arc::new(MockServerApp::new(false, false));
        app.set_auth_state(SessionAuthState::Revoked("manual_revoke".to_string()));
        let mut io = MockIo {
            inbound: VecDeque::from([InboundEvent::Frame(hello), InboundEvent::Frame(reauth)]),
            outbound: Vec::new(),
            fail_send_after: None,
            send_count: 0,
        };
        let config = ServerConfig::default();

        run_server_session(
            &config,
            app.clone(),
            &mut io,
            PeerMeta {
                transport: TransportKind::Tcp,
                remote_addr: Some("127.0.0.1:5223".to_string()),
            },
        )
        .await
        .expect("revoked auth should close via goaway");

        let disconnected = app
            .disconnected
            .lock()
            .expect("disconnected lock should not be poisoned");
        assert!(
            disconnected
                .iter()
                .any(|value| value.contains("GoAway(\"auth_revoked:manual_revoke\")")),
            "disconnect callback should include auth revoked goaway"
        );
    }

    #[tokio::test]
    async fn server_session_keeps_connection_on_auth_renewed() {
        let profile = PushgoWireProfile::new();
        let hello = profile
            .encode_client_hello(&HelloCtx {
                identity: "dev-1".to_string(),
                ..HelloCtx::default()
            })
            .expect("encode hello should succeed")
            .to_vec();
        let goaway = encode_client_goaway("client_shutdown");

        let app = Arc::new(MockServerApp::new(false, false));
        app.set_auth_state(SessionAuthState::Renewed {
            auth_expires_at_unix_secs: Some(unix_now_secs().saturating_add(3_600)),
            auth_refresh_before_secs: 120,
        });
        let mut io = MockIo {
            inbound: VecDeque::from([
                InboundEvent::Frame(hello),
                InboundEvent::Timeout,
                InboundEvent::Frame(goaway),
            ]),
            outbound: Vec::new(),
            fail_send_after: None,
            send_count: 0,
        };
        let config = ServerConfig::default();

        run_server_session(
            &config,
            app.clone(),
            &mut io,
            PeerMeta {
                transport: TransportKind::Wss,
                remote_addr: Some("127.0.0.1:443".to_string()),
            },
        )
        .await
        .expect("renewed auth should not force disconnect");

        let disconnected = app
            .disconnected
            .lock()
            .expect("disconnected lock should not be poisoned");
        assert!(
            disconnected
                .iter()
                .any(|value| value.contains("GoAway(\"client_shutdown\")")),
            "session should close only on client goaway in this test"
        );
    }

    #[tokio::test]
    async fn server_session_closes_on_inband_reauth_identity_mismatch() {
        let profile = PushgoWireProfile::new();
        let hello = profile
            .encode_client_hello(&HelloCtx {
                identity: "dev-1".to_string(),
                ..HelloCtx::default()
            })
            .expect("encode hello should succeed")
            .to_vec();
        let reauth_bad_identity = profile
            .encode_client_hello(&HelloCtx {
                identity: "dev-2".to_string(),
                auth_token: Some("token-2".to_string()),
                ..HelloCtx::default()
            })
            .expect("encode reauth hello should succeed")
            .to_vec();

        let app = Arc::new(MockServerApp::new(false, false));
        let mut io = MockIo {
            inbound: VecDeque::from([
                InboundEvent::Frame(hello),
                InboundEvent::Frame(reauth_bad_identity),
            ]),
            outbound: Vec::new(),
            fail_send_after: None,
            send_count: 0,
        };
        let config = ServerConfig::default();

        run_server_session(
            &config,
            app.clone(),
            &mut io,
            PeerMeta {
                transport: TransportKind::Wss,
                remote_addr: Some("127.0.0.1:443".to_string()),
            },
        )
        .await
        .expect("identity mismatch should close with goaway");

        let disconnected = app
            .disconnected
            .lock()
            .expect("disconnected lock should not be poisoned");
        assert!(
            disconnected
                .iter()
                .any(|value| value.contains("GoAway(\"auth_reauth_failed:identity_mismatch\")")),
            "identity mismatch should produce auth_reauth_failed goaway"
        );
    }

    #[tokio::test]
    async fn server_session_accepts_inband_reauth_and_stays_connected() {
        let profile = PushgoWireProfile::new();
        let hello = profile
            .encode_client_hello(&HelloCtx {
                identity: "dev-1".to_string(),
                auth_token: Some("token-1".to_string()),
                ..HelloCtx::default()
            })
            .expect("encode hello should succeed")
            .to_vec();
        let reauth = profile
            .encode_client_hello(&HelloCtx {
                identity: "dev-1".to_string(),
                auth_token: Some("token-2".to_string()),
                ..HelloCtx::default()
            })
            .expect("encode reauth hello should succeed")
            .to_vec();
        let goaway = encode_client_goaway("client_shutdown");

        let app = Arc::new(MockServerApp::new(false, false));
        app.set_auth_state(SessionAuthState::Renewed {
            auth_expires_at_unix_secs: Some(unix_now_secs().saturating_add(1_800)),
            auth_refresh_before_secs: 60,
        });
        let mut io = MockIo {
            inbound: VecDeque::from([
                InboundEvent::Frame(hello),
                InboundEvent::Frame(reauth),
                InboundEvent::Frame(goaway),
            ]),
            outbound: Vec::new(),
            fail_send_after: None,
            send_count: 0,
        };
        let config = ServerConfig::default();

        run_server_session(
            &config,
            app.clone(),
            &mut io,
            PeerMeta {
                transport: TransportKind::Tcp,
                remote_addr: Some("127.0.0.1:5223".to_string()),
            },
        )
        .await
        .expect("in-band reauth should keep connection alive");

        let disconnected = app
            .disconnected
            .lock()
            .expect("disconnected lock should not be poisoned");
        assert!(
            disconnected
                .iter()
                .any(|value| value.contains("GoAway(\"client_shutdown\")")),
            "connection should still be closed by client goaway"
        );
        assert!(
            disconnected
                .iter()
                .all(|value| !value.contains("auth_reauth_failed")),
            "in-band reauth should not fail"
        );
    }

    #[test]
    fn client_power_hint_overrides_legacy_auto_fields() {
        let config = test_client_config();
        let app = MockClientPowerApp::new(HelloCtx {
            identity: "dev-1".to_string(),
            ..HelloCtx::default()
        });
        app.set_power_hint(Some(ClientPowerHint {
            app_state: ClientAppStateHint::Background,
            preferred_tier: Some(ClientPowerTier::Low),
        }));
        let mut runtime = ClientPowerRuntime::new(Instant::now());
        let hello = build_effective_hello(&config, &app, &mut runtime);
        assert_eq!(hello.app_state.as_deref(), Some("background"));
        assert_eq!(hello.perf_tier.as_deref(), Some("low"));
    }

    #[test]
    fn client_power_auto_switches_to_low_when_idle() {
        let mut config = test_client_config();
        config.policy.power.idle_to_low_after_secs = 1;
        let app = MockClientPowerApp::new(HelloCtx {
            identity: "dev-1".to_string(),
            ..HelloCtx::default()
        });
        let mut runtime = ClientPowerRuntime::new(Instant::now());
        runtime.last_message_at = Instant::now() - Duration::from_secs(10);
        let hello = build_effective_hello(&config, &app, &mut runtime);
        assert_eq!(hello.app_state.as_deref(), Some("background"));
        assert_eq!(hello.perf_tier.as_deref(), Some("low"));
    }

    #[test]
    fn client_power_keeps_explicit_hello_tier_when_no_hint() {
        let config = test_client_config();
        let app = MockClientPowerApp::new(HelloCtx {
            identity: "dev-1".to_string(),
            perf_tier: Some("high".to_string()),
            app_state: Some("foreground".to_string()),
            ..HelloCtx::default()
        });
        let mut runtime = ClientPowerRuntime::new(Instant::now());
        let hello = build_effective_hello(&config, &app, &mut runtime);
        assert_eq!(hello.app_state.as_deref(), Some("foreground"));
        assert_eq!(hello.perf_tier.as_deref(), Some("high"));
    }
}
