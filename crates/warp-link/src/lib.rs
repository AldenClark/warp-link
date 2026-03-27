use std::collections::VecDeque;
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
    DecisionTrace, DecisionWinnerLayer, DecodedClientFrame, DecodedServerFrame, DisconnectReason,
    HelloCtx, OutboundMsg, PeerMeta, PolicyInput, ProbeRttSource, SchedulerState, ServerApp,
    ServerConfig, SessionAuthState, SessionControl, SessionControlOps, TlsMode, TransportKind,
    WarpLinkError,
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

#[derive(Default)]
struct ClientContinuityState {
    resume_token: Option<String>,
    last_acked_seq: Option<u64>,
}

impl ClientContinuityState {
    fn apply_to_hello(&self, hello: &mut HelloCtx) {
        if let Some(resume_token) = self.resume_token.as_ref() {
            hello.resume_token = Some(resume_token.clone());
        }
        if let Some(seq) = self.last_acked_seq {
            hello.last_acked_seq = Some(hello.last_acked_seq.unwrap_or(seq).max(seq));
        }
    }

    fn note_welcome(&mut self, resume_token: Option<&str>) {
        if let Some(value) = resume_token
            && !value.trim().is_empty()
        {
            self.resume_token = Some(value.to_string());
        }
    }

    fn note_acked_seq(&mut self, seq: Option<u64>) {
        let Some(seq) = seq else {
            return;
        };
        self.last_acked_seq = Some(self.last_acked_seq.unwrap_or(seq).max(seq));
    }

    fn can_switch_without_loss(&self) -> bool {
        self.resume_token.is_some()
    }
}

#[derive(Debug, Clone)]
struct TransportPlan {
    attempts: Vec<(TransportKind, u64)>,
    suppressed_candidates: Vec<TransportKind>,
    winner_layer: DecisionWinnerLayer,
    reason_code: &'static str,
}

fn epoch_millis_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis() as i64)
        .unwrap_or(0)
}

fn pinned_transport_active(policy: &PolicyInput) -> Option<TransportKind> {
    let pinned = policy.pinned_transport.as_ref()?;
    let now_ms = epoch_millis_now();
    if let Some(expires_at_unix_ms) = pinned.expires_at_unix_ms
        && now_ms >= expires_at_unix_ms
    {
        return None;
    }
    Some(pinned.transport)
}

fn transport_disabled_by_policy(policy: &PolicyInput, transport: TransportKind) -> bool {
    policy
        .disabled_transports
        .iter()
        .any(|disabled| *disabled == transport)
}

fn default_transport_order() -> Vec<TransportKind> {
    let mut order = Vec::new();
    #[cfg(feature = "quic")]
    {
        order.push(TransportKind::Quic);
    }
    #[cfg(feature = "tcp")]
    {
        order.push(TransportKind::Tcp);
    }
    #[cfg(feature = "wss")]
    {
        order.push(TransportKind::Wss);
    }
    order
}

fn transport_start_delay_ms(
    config: &ClientConfig,
    transport: TransportKind,
    position: usize,
) -> u64 {
    if position == 0 {
        return 0;
    }
    match transport {
        TransportKind::Quic => 0,
        TransportKind::Tcp => config.policy.tcp_delay_ms,
        TransportKind::Wss => config.policy.wss_delay_ms,
    }
}

fn build_transport_plan(config: &ClientConfig, policy: &PolicyInput) -> TransportPlan {
    let base_order = default_transport_order();
    let pinned = pinned_transport_active(policy);
    let mut suppressed = Vec::new();

    if let Some(pinned_transport) = pinned {
        if transport_disabled_by_policy(policy, pinned_transport) {
            return TransportPlan {
                attempts: Vec::new(),
                suppressed_candidates: vec![pinned_transport],
                winner_layer: DecisionWinnerLayer::AppPolicy,
                reason_code: "pinned_transport_disabled",
            };
        }
        return TransportPlan {
            attempts: vec![(pinned_transport, 0)],
            suppressed_candidates: base_order
                .into_iter()
                .filter(|candidate| *candidate != pinned_transport)
                .collect(),
            winner_layer: DecisionWinnerLayer::UserCommand,
            reason_code: "user_pin_transport",
        };
    }

    let mut allowed = Vec::new();
    for transport in base_order {
        if transport_disabled_by_policy(policy, transport) {
            suppressed.push(transport);
            continue;
        }
        let delay_ms = transport_start_delay_ms(config, transport, allowed.len());
        allowed.push((transport, delay_ms));
    }

    if allowed.is_empty() {
        return TransportPlan {
            attempts: Vec::new(),
            suppressed_candidates: suppressed,
            winner_layer: DecisionWinnerLayer::AppPolicy,
            reason_code: "all_transports_blocked_by_policy",
        };
    }

    let winner_layer = if suppressed.is_empty() {
        DecisionWinnerLayer::AdaptiveScheduler
    } else {
        DecisionWinnerLayer::AppPolicy
    };
    let reason_code = if suppressed.is_empty() {
        "adaptive_transport_plan"
    } else {
        "policy_disabled_transports"
    };

    TransportPlan {
        attempts: allowed,
        suppressed_candidates: suppressed,
        winner_layer,
        reason_code,
    }
}

fn emit_scheduler_state(app: &dyn ClientApp, state: SchedulerState, reason_code: &str) {
    let _ = app.on_event(ClientEvent::SchedulerStateChanged {
        state,
        reason_code: reason_code.to_string(),
    });
}

fn emit_decision_trace(
    app: &dyn ClientApp,
    decision_id: u64,
    winner_layer: DecisionWinnerLayer,
    reason_code: &str,
    selected_transport: Option<TransportKind>,
    suppressed_candidates: Vec<TransportKind>,
    inputs_digest: String,
) {
    let trace = DecisionTrace {
        decision_id,
        winner_layer,
        reason_code: reason_code.to_string(),
        selected_transport,
        inputs_digest,
        suppressed_candidates,
    };
    let _ = app.on_event(ClientEvent::DecisionTrace { trace });
}

struct HealthTracker {
    recv_total: u64,
    recv_timeout: u64,
    ack_total: u64,
    ack_non_ok: u64,
    last_progress_at: Instant,
    rtt_ewma_ms: Option<f64>,
    rtt_jitter_ewma_ms: Option<f64>,
    last_probe_rtt_ms: Option<u64>,
}

impl HealthTracker {
    fn new(now: Instant) -> Self {
        Self {
            recv_total: 0,
            recv_timeout: 0,
            ack_total: 0,
            ack_non_ok: 0,
            last_progress_at: now,
            rtt_ewma_ms: None,
            rtt_jitter_ewma_ms: None,
            last_probe_rtt_ms: None,
        }
    }

    fn note_timeout(&mut self) {
        self.recv_total = self.recv_total.saturating_add(1);
        self.recv_timeout = self.recv_timeout.saturating_add(1);
    }

    fn note_frame_progress(&mut self, now: Instant) {
        self.recv_total = self.recv_total.saturating_add(1);
        self.last_progress_at = now;
    }

    fn note_ack(&mut self, status: AckStatus, now: Instant) {
        self.ack_total = self.ack_total.saturating_add(1);
        if status != AckStatus::Ok {
            self.ack_non_ok = self.ack_non_ok.saturating_add(1);
        }
        self.last_progress_at = now;
    }

    fn note_probe_rtt(&mut self, rtt_ms: u64) {
        let sample = rtt_ms as f64;
        let alpha = 0.2;
        let next_ewma = self
            .rtt_ewma_ms
            .map(|prev| prev + alpha * (sample - prev))
            .unwrap_or(sample);
        let jitter_sample = self
            .last_probe_rtt_ms
            .map(|prev| prev.abs_diff(rtt_ms) as f64)
            .unwrap_or(0.0);
        let next_jitter = self
            .rtt_jitter_ewma_ms
            .map(|prev| prev + alpha * (jitter_sample - prev))
            .unwrap_or(jitter_sample);
        self.rtt_ewma_ms = Some(next_ewma);
        self.rtt_jitter_ewma_ms = Some(next_jitter);
        self.last_probe_rtt_ms = Some(rtt_ms);
    }

    fn snapshot(&self, now: Instant) -> warp_link_core::TransportHealthSnapshot {
        let timeout_rate = if self.recv_total == 0 {
            None
        } else {
            Some((self.recv_timeout as f32) / (self.recv_total as f32))
        };
        let ack_non_ok_ratio = if self.ack_total == 0 {
            None
        } else {
            Some((self.ack_non_ok as f32) / (self.ack_total as f32))
        };
        warp_link_core::TransportHealthSnapshot {
            timeout_rate,
            ack_non_ok_ratio,
            dead_air_secs: Some(
                now.saturating_duration_since(self.last_progress_at)
                    .as_secs(),
            ),
            rtt_ewma_ms: self.rtt_ewma_ms.map(|v| v as u64),
            rtt_jitter_ms: self.rtt_jitter_ewma_ms.map(|v| v as u64),
        }
    }
}

struct MobilityTracker {
    enabled: bool,
    active: bool,
    volatility_score: u8,
    last_signal_at: Instant,
    last_probe_rtt_ms: Option<u64>,
}

impl MobilityTracker {
    fn new(now: Instant, enabled: bool) -> Self {
        Self {
            enabled,
            active: false,
            volatility_score: 0,
            last_signal_at: now,
            last_probe_rtt_ms: None,
        }
    }

    fn note_timeout(&mut self, now: Instant) {
        self.note_signal(now, 1);
    }

    fn note_disconnect(&mut self, now: Instant) {
        self.note_signal(now, 1);
    }

    fn note_probe_rtt(&mut self, now: Instant, rtt_ms: u64) {
        if let Some(last) = self.last_probe_rtt_ms
            && last.abs_diff(rtt_ms) >= 120
        {
            self.note_signal(now, 1);
        }
        self.last_probe_rtt_ms = Some(rtt_ms);
    }

    fn in_mode(&mut self, now: Instant) -> bool {
        if !self.enabled {
            self.active = false;
            self.volatility_score = 0;
            return false;
        }
        if now.saturating_duration_since(self.last_signal_at) > Duration::from_secs(120) {
            self.active = false;
            self.volatility_score = 0;
        } else if self.volatility_score >= 3 {
            self.active = true;
        }
        self.active
    }

    fn note_signal(&mut self, now: Instant, weight: u8) {
        if now.saturating_duration_since(self.last_signal_at) > Duration::from_secs(60) {
            self.volatility_score = weight.min(8);
        } else {
            self.volatility_score = self.volatility_score.saturating_add(weight).min(8);
        }
        self.last_signal_at = now;
    }
}

fn health_gate_passes(
    policy: &warp_link_core::ClientPolicy,
    snapshot: &warp_link_core::TransportHealthSnapshot,
) -> bool {
    if let Some(timeout_rate) = snapshot.timeout_rate
        && timeout_rate > policy.health_timeout_rate_threshold
    {
        return false;
    }
    if let Some(ack_non_ok_ratio) = snapshot.ack_non_ok_ratio
        && ack_non_ok_ratio > policy.health_ack_non_ok_ratio_threshold
    {
        return false;
    }
    if let Some(dead_air_secs) = snapshot.dead_air_secs
        && dead_air_secs > u64::from(policy.health_dead_air_secs)
    {
        return false;
    }
    true
}

fn stability_score(snapshot: &warp_link_core::TransportHealthSnapshot) -> f64 {
    let timeout_penalty = snapshot.timeout_rate.unwrap_or(0.0).min(1.0) as f64 * 45.0;
    let ack_penalty = snapshot.ack_non_ok_ratio.unwrap_or(0.0).min(1.0) as f64 * 35.0;
    let dead_air_penalty = snapshot.dead_air_secs.unwrap_or(0).min(60) as f64 * 0.4;
    (100.0 - timeout_penalty - ack_penalty - dead_air_penalty).clamp(0.0, 100.0)
}

fn performance_score(
    transport: TransportKind,
    connect_elapsed_ms: Option<u64>,
    snapshot: &warp_link_core::TransportHealthSnapshot,
) -> f64 {
    let transport_base = match transport {
        TransportKind::Quic => 86.0,
        TransportKind::Tcp => 74.0,
        TransportKind::Wss => 62.0,
    };
    let rtt_penalty = snapshot.rtt_ewma_ms.unwrap_or(0).min(800) as f64 * 0.04;
    let jitter_penalty = snapshot.rtt_jitter_ms.unwrap_or(0).min(400) as f64 * 0.03;
    let connect_bonus = connect_elapsed_ms
        .map(|value| (130.0 - (value.min(4_000) as f64 / 45.0)).clamp(0.0, 50.0))
        .unwrap_or(12.0);
    (transport_base + connect_bonus - rtt_penalty - jitter_penalty).clamp(0.0, 100.0)
}

fn combined_score(
    transport: TransportKind,
    connect_elapsed_ms: Option<u64>,
    snapshot: &warp_link_core::TransportHealthSnapshot,
) -> f64 {
    let stability = stability_score(snapshot);
    let performance = performance_score(transport, connect_elapsed_ms, snapshot);
    (stability * 0.65) + (performance * 0.35)
}

fn required_upgrade_windows(policy: &warp_link_core::ClientPolicy, mobility_mode: bool) -> u8 {
    if mobility_mode {
        policy.mobility_upgrade_confirm_windows.max(1)
    } else {
        policy.scheduler_upgrade_confirm_windows.max(1)
    }
}

fn effective_min_dwell_secs(policy: &warp_link_core::ClientPolicy, mobility_mode: bool) -> u16 {
    if mobility_mode {
        policy
            .upgrade_probe_min_dwell_secs
            .max(policy.mobility_min_dwell_secs)
            .max(1)
    } else {
        policy.upgrade_probe_min_dwell_secs.max(1)
    }
}

fn purge_old_migrations(history: &mut VecDeque<Instant>, now: Instant) {
    while let Some(front) = history.front().copied() {
        if now.saturating_duration_since(front) > Duration::from_secs(300) {
            let _ = history.pop_front();
        } else {
            break;
        }
    }
}

fn migration_blocked_by_cooldown(
    history: &mut VecDeque<Instant>,
    cooldown_until: &mut Option<Instant>,
    now: Instant,
    policy: &warp_link_core::ClientPolicy,
) -> bool {
    purge_old_migrations(history, now);
    if cooldown_until.is_some_and(|until| now < until) {
        return true;
    }
    if history.len() >= usize::from(policy.scheduler_max_migrations_per_5m.max(1)) {
        *cooldown_until =
            Some(now + Duration::from_secs(u64::from(policy.scheduler_cooldown_secs.max(1))));
        return true;
    }
    false
}

pub async fn client_run(config: ClientConfig, app: impl ClientApp) -> Result<(), WarpLinkError> {
    let (_tx, rx) = watch::channel(false);
    client_run_with_shutdown(config, app, rx).await
}

pub async fn client_run_once(
    config: &ClientConfig,
    app: Arc<dyn ClientApp>,
) -> Result<(), WarpLinkError> {
    let mut continuity = ClientContinuityState::default();
    run_client_session_once(config, app, &mut continuity).await
}

pub async fn client_run_with_shutdown(
    config: ClientConfig,
    app: impl ClientApp,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), WarpLinkError> {
    let app: Arc<dyn ClientApp> = Arc::new(app);
    let mut attempt: u32 = 0;
    let mut continuity = ClientContinuityState::default();
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        match run_client_session_once(&config, Arc::clone(&app), &mut continuity).await {
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
    continuity: &mut ClientContinuityState,
) -> Result<(), WarpLinkError> {
    let mut decision_id_seq: u64 = 1;
    if config.policy.scheduler_v2_enabled {
        emit_scheduler_state(
            app.as_ref(),
            SchedulerState::PrimaryConnecting,
            "session_start",
        );
    }
    let initial_policy = if config.policy.scheduler_v2_enabled {
        app.scheduler_policy()
    } else {
        PolicyInput::default()
    };
    let connect_plan = build_transport_plan(config, &initial_policy);
    if connect_plan.attempts.is_empty() {
        if config.policy.scheduler_v2_enabled {
            emit_scheduler_state(
                app.as_ref(),
                SchedulerState::BlockedByPolicy,
                connect_plan.reason_code,
            );
            emit_decision_trace(
                app.as_ref(),
                decision_id_seq,
                connect_plan.winner_layer,
                connect_plan.reason_code,
                None,
                connect_plan.suppressed_candidates.clone(),
                format!(
                    "force_reconnect_nonce={} pinned={} disabled_count={}",
                    initial_policy.force_reconnect_nonce,
                    pinned_transport_active(&initial_policy)
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    initial_policy.disabled_transports.len()
                ),
            );
        }
        return Err(WarpLinkError::Unsupported(
            "all transports blocked by scheduler policy".to_string(),
        ));
    }
    let (mut transport, mut io) = hedged_connect(config, &connect_plan).await?;
    emit_decision_trace(
        app.as_ref(),
        decision_id_seq,
        connect_plan.winner_layer,
        connect_plan.reason_code,
        Some(transport),
        connect_plan.suppressed_candidates.clone(),
        format!(
            "force_reconnect_nonce={} pinned={} disabled_count={}",
            initial_policy.force_reconnect_nonce,
            pinned_transport_active(&initial_policy)
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_string()),
            initial_policy.disabled_transports.len()
        ),
    );
    decision_id_seq = decision_id_seq.saturating_add(1);
    let _ = app.on_event(ClientEvent::Connected { transport });
    if config.policy.scheduler_v2_enabled {
        emit_scheduler_state(
            app.as_ref(),
            SchedulerState::PrimaryActive,
            "primary_connected",
        );
    }

    let mut power_runtime = ClientPowerRuntime::new(Instant::now());
    let mut hello = build_effective_hello(config, app.as_ref(), &mut power_runtime);
    continuity.apply_to_hello(&mut hello);
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
    continuity.note_welcome(welcome.resume_token.as_deref());

    let mut idle_timeout_ms = u64::from(welcome.ping_interval_secs.clamp(5, 30)) * 1_000;
    let mut idle_timeout_streak = 0u8;
    let mut last_idle_ping_at = Instant::now();
    let mut pending_ping_sent_at: Option<Instant> = None;
    let mut pending_ping_source: Option<ProbeRttSource> = None;
    let mut health_tracker = HealthTracker::new(Instant::now());
    let mut mobility_tracker = MobilityTracker::new(Instant::now(), config.policy.mobility_enabled);
    let mut adaptive_upgrade_streak: u8 = 0;
    let mut migration_history: VecDeque<Instant> = VecDeque::new();
    let mut migration_cooldown_until: Option<Instant> = None;
    let mut upgrade_probe_runtime = UpgradeProbeRuntime::new(transport, Instant::now());
    let mobility_mode = mobility_tracker.in_mode(Instant::now());
    upgrade_probe_runtime.schedule_next(
        config,
        app.as_ref(),
        &power_runtime,
        Instant::now(),
        mobility_mode,
    );
    let last_force_reconnect_nonce = initial_policy.force_reconnect_nonce;

    loop {
        maybe_send_inband_hello_update(
            config,
            app.as_ref(),
            &mut io,
            &mut inband_hello_snapshot,
            &mut power_runtime,
            continuity,
        )
        .await?;
        if config.policy.scheduler_v2_enabled {
            let policy_input = app.scheduler_policy();
            if policy_input.force_reconnect_nonce != last_force_reconnect_nonce {
                emit_decision_trace(
                    app.as_ref(),
                    decision_id_seq,
                    DecisionWinnerLayer::UserCommand,
                    "force_reconnect",
                    Some(transport),
                    Vec::new(),
                    format!(
                        "force_reconnect_nonce={} current_transport={}",
                        policy_input.force_reconnect_nonce, transport
                    ),
                );
                emit_scheduler_state(
                    app.as_ref(),
                    SchedulerState::Recovering,
                    "force_reconnect_requested",
                );
                return Ok(());
            }
            if transport_disabled_by_policy(&policy_input, transport) {
                emit_decision_trace(
                    app.as_ref(),
                    decision_id_seq,
                    DecisionWinnerLayer::AppPolicy,
                    "current_transport_disabled_by_policy",
                    Some(transport),
                    vec![transport],
                    format!("current_transport={} disabled=1", transport),
                );
                emit_scheduler_state(
                    app.as_ref(),
                    SchedulerState::Recovering,
                    "policy_transport_blocked",
                );
                return Ok(());
            }
            if let Some(pinned_transport) = pinned_transport_active(&policy_input)
                && pinned_transport != transport
                && continuity.can_switch_without_loss()
            {
                emit_decision_trace(
                    app.as_ref(),
                    decision_id_seq,
                    DecisionWinnerLayer::UserCommand,
                    "pin_transport_requires_cutover",
                    Some(pinned_transport),
                    vec![transport],
                    format!("from={} to={}", transport, pinned_transport),
                );
                if let Some(candidate_io) = connect_transport(config, pinned_transport).await.ok()
                    && let Some(candidate_welcome) = commit_candidate_cutover(
                        config,
                        Arc::clone(&app),
                        continuity,
                        &mut power_runtime,
                        &mut transport,
                        &mut io,
                        pinned_transport,
                        candidate_io,
                        decision_id_seq,
                    )
                    .await?
                {
                    continuity.note_welcome(candidate_welcome.resume_token.as_deref());
                    idle_timeout_ms =
                        u64::from(candidate_welcome.ping_interval_secs.clamp(5, 30)) * 1_000;
                    idle_timeout_streak = 0;
                    last_idle_ping_at = Instant::now();
                    inband_hello_snapshot =
                        build_effective_hello(config, app.as_ref(), &mut power_runtime);
                    continuity.apply_to_hello(&mut inband_hello_snapshot);
                    upgrade_probe_runtime = UpgradeProbeRuntime::new(transport, Instant::now());
                    let mobility_mode = mobility_tracker.in_mode(Instant::now());
                    upgrade_probe_runtime.schedule_next(
                        config,
                        app.as_ref(),
                        &power_runtime,
                        Instant::now(),
                        mobility_mode,
                    );
                    purge_old_migrations(&mut migration_history, Instant::now());
                    migration_history.push_back(Instant::now());
                    decision_id_seq = decision_id_seq.saturating_add(1);
                    continue;
                }
                decision_id_seq = decision_id_seq.saturating_add(1);
            }
        }
        if app.take_probe_request() && pending_ping_sent_at.is_none() {
            let ping = config.wire_profile.encode_client_ping();
            io.send_frame(&ping, config.policy.write_timeout_ms).await?;
            pending_ping_sent_at = Some(Instant::now());
            pending_ping_source = Some(ProbeRttSource::Manual);
        }
        let now = Instant::now();
        let mobility_mode = mobility_tracker.in_mode(now);
        let recv_timeout_ms =
            next_recv_timeout_ms(config, &upgrade_probe_runtime, now, mobility_mode)
                .unwrap_or(idle_timeout_ms)
                .min(idle_timeout_ms)
                .max(1);
        let frame = match io.recv_frame(recv_timeout_ms).await {
            Ok(frame) => {
                idle_timeout_streak = 0;
                last_idle_ping_at = Instant::now();
                health_tracker.note_frame_progress(Instant::now());
                frame
            }
            Err(WarpLinkError::Timeout(_)) => {
                let now = Instant::now();
                health_tracker.note_timeout();
                mobility_tracker.note_timeout(now);
                if upgrade_probe_runtime.should_probe(config, now, mobility_mode) {
                    if continuity.can_switch_without_loss() {
                        let policy_input = if config.policy.scheduler_v2_enabled {
                            app.scheduler_policy()
                        } else {
                            PolicyInput::default()
                        };
                        let probe_started_at = Instant::now();
                        let probe_candidate =
                            probe_higher_priority_transport(config, transport, &policy_input).await;
                        if let Some((target, candidate_io)) = probe_candidate {
                            let candidate_connect_elapsed_ms = duration_ms(
                                Instant::now().saturating_duration_since(probe_started_at),
                            );
                            let primary_snapshot = health_tracker.snapshot(now);
                            let candidate_snapshot = warp_link_core::TransportHealthSnapshot {
                                timeout_rate: Some(0.0),
                                ack_non_ok_ratio: Some(0.0),
                                dead_air_secs: Some(0),
                                rtt_ewma_ms: Some(candidate_connect_elapsed_ms),
                                rtt_jitter_ms: Some(0),
                            };
                            let gate_ok = health_gate_passes(&config.policy, &primary_snapshot)
                                && health_gate_passes(&config.policy, &candidate_snapshot);
                            let primary_score = combined_score(transport, None, &primary_snapshot);
                            let candidate_score = combined_score(
                                target,
                                Some(candidate_connect_elapsed_ms),
                                &candidate_snapshot,
                            );
                            let required_margin = 1.0
                                + (f64::from(config.policy.scheduler_hysteresis_percent) / 100.0);
                            let beats =
                                gate_ok && candidate_score >= (primary_score * required_margin);
                            if beats {
                                adaptive_upgrade_streak = adaptive_upgrade_streak.saturating_add(1);
                            } else {
                                adaptive_upgrade_streak = 0;
                            }
                            let required_windows =
                                required_upgrade_windows(&config.policy, mobility_mode);
                            if adaptive_upgrade_streak >= required_windows {
                                if migration_blocked_by_cooldown(
                                    &mut migration_history,
                                    &mut migration_cooldown_until,
                                    now,
                                    &config.policy,
                                ) {
                                    emit_decision_trace(
                                        app.as_ref(),
                                        decision_id_seq,
                                        DecisionWinnerLayer::AdaptiveScheduler,
                                        "migration_cooldown_active",
                                        Some(target),
                                        Vec::new(),
                                        format!(
                                            "score_primary={:.2} score_candidate={:.2} streak={} required={}",
                                            primary_score,
                                            candidate_score,
                                            adaptive_upgrade_streak,
                                            required_windows
                                        ),
                                    );
                                    adaptive_upgrade_streak = 0;
                                } else if let Some(candidate_welcome) = commit_candidate_cutover(
                                    config,
                                    Arc::clone(&app),
                                    continuity,
                                    &mut power_runtime,
                                    &mut transport,
                                    &mut io,
                                    target,
                                    candidate_io,
                                    decision_id_seq,
                                )
                                .await?
                                {
                                    emit_decision_trace(
                                        app.as_ref(),
                                        decision_id_seq,
                                        DecisionWinnerLayer::AdaptiveScheduler,
                                        "adaptive_upgrade_probe",
                                        Some(target),
                                        Vec::new(),
                                        format!(
                                            "score_primary={:.2} score_candidate={:.2} streak={} required={}",
                                            primary_score,
                                            candidate_score,
                                            adaptive_upgrade_streak,
                                            required_windows
                                        ),
                                    );
                                    continuity
                                        .note_welcome(candidate_welcome.resume_token.as_deref());
                                    idle_timeout_ms = u64::from(
                                        candidate_welcome.ping_interval_secs.clamp(5, 30),
                                    ) * 1_000;
                                    idle_timeout_streak = 0;
                                    last_idle_ping_at = Instant::now();
                                    inband_hello_snapshot = build_effective_hello(
                                        config,
                                        app.as_ref(),
                                        &mut power_runtime,
                                    );
                                    continuity.apply_to_hello(&mut inband_hello_snapshot);
                                    upgrade_probe_runtime =
                                        UpgradeProbeRuntime::new(transport, Instant::now());
                                    let mobility_mode = mobility_tracker.in_mode(Instant::now());
                                    upgrade_probe_runtime.schedule_next(
                                        config,
                                        app.as_ref(),
                                        &power_runtime,
                                        Instant::now(),
                                        mobility_mode,
                                    );
                                    purge_old_migrations(&mut migration_history, Instant::now());
                                    migration_history.push_back(Instant::now());
                                    adaptive_upgrade_streak = 0;
                                    decision_id_seq = decision_id_seq.saturating_add(1);
                                    continue;
                                }
                            } else {
                                emit_decision_trace(
                                    app.as_ref(),
                                    decision_id_seq,
                                    DecisionWinnerLayer::AdaptiveScheduler,
                                    "hysteresis_wait",
                                    Some(target),
                                    Vec::new(),
                                    format!(
                                        "score_primary={:.2} score_candidate={:.2} streak={} required={}",
                                        primary_score,
                                        candidate_score,
                                        adaptive_upgrade_streak,
                                        required_windows
                                    ),
                                );
                            }
                        }
                        upgrade_probe_runtime.note_probe_failure(
                            config,
                            app.as_ref(),
                            &power_runtime,
                            now,
                            mobility_mode,
                        );
                    } else {
                        upgrade_probe_runtime.note_probe_skip(
                            config,
                            app.as_ref(),
                            &power_runtime,
                            now,
                            mobility_mode,
                        );
                    }
                }

                if now.saturating_duration_since(last_idle_ping_at)
                    >= Duration::from_millis(idle_timeout_ms)
                {
                    idle_timeout_streak = idle_timeout_streak.saturating_add(1);
                    let dead_air_secs = health_tracker
                        .snapshot(now)
                        .dead_air_secs
                        .unwrap_or_default();
                    if idle_timeout_streak >= 3
                        && dead_air_secs >= u64::from(config.policy.health_dead_air_secs)
                        && upgrade_probe_runtime.probe_failure_streak
                            >= config.policy.dead_connection_probe_failure_threshold
                    {
                        let _ = app.on_event(ClientEvent::DeadConnectionDetected {
                            transport,
                            reason_code: "multi_signal_dead_connection".to_string(),
                        });
                        let _ = app.on_event(ClientEvent::RecoveryTierEntered {
                            tier: 1,
                            reason_code: "same_transport_rehandshake".to_string(),
                        });
                        if continuity.can_switch_without_loss() {
                            let policy_input = if config.policy.scheduler_v2_enabled {
                                app.scheduler_policy()
                            } else {
                                PolicyInput::default()
                            };
                            let alternate =
                                probe_alternate_transport(config, transport, &policy_input).await;
                            if let Some((target, candidate_io)) = alternate
                                && let Some(candidate_welcome) = commit_candidate_cutover(
                                    config,
                                    Arc::clone(&app),
                                    continuity,
                                    &mut power_runtime,
                                    &mut transport,
                                    &mut io,
                                    target,
                                    candidate_io,
                                    decision_id_seq,
                                )
                                .await?
                            {
                                let _ = app.on_event(ClientEvent::RecoveryTierEntered {
                                    tier: 2,
                                    reason_code: "alternate_transport_recovery".to_string(),
                                });
                                continuity.note_welcome(candidate_welcome.resume_token.as_deref());
                                idle_timeout_ms =
                                    u64::from(candidate_welcome.ping_interval_secs.clamp(5, 30))
                                        * 1_000;
                                idle_timeout_streak = 0;
                                last_idle_ping_at = Instant::now();
                                inband_hello_snapshot =
                                    build_effective_hello(config, app.as_ref(), &mut power_runtime);
                                continuity.apply_to_hello(&mut inband_hello_snapshot);
                                upgrade_probe_runtime =
                                    UpgradeProbeRuntime::new(transport, Instant::now());
                                let mobility_mode = mobility_tracker.in_mode(Instant::now());
                                upgrade_probe_runtime.schedule_next(
                                    config,
                                    app.as_ref(),
                                    &power_runtime,
                                    Instant::now(),
                                    mobility_mode,
                                );
                                continue;
                            }
                        }
                        return Ok(());
                    }
                    if idle_timeout_streak >= 4 {
                        let _ = app.on_event(ClientEvent::Disconnected {
                            transport,
                            reason: "idle timeout".to_string(),
                        });
                        return Err(WarpLinkError::Timeout("idle timeout".to_string()));
                    }
                    let ping = config.wire_profile.encode_client_ping();
                    io.send_frame(&ping, config.policy.write_timeout_ms).await?;
                    last_idle_ping_at = now;
                    if pending_ping_sent_at.is_none() {
                        pending_ping_sent_at = Some(now);
                        pending_ping_source = Some(ProbeRttSource::IdleKeepalive);
                    }
                }
                continue;
            }
            Err(err) => {
                mobility_tracker.note_disconnect(Instant::now());
                let _ = app.on_event(ClientEvent::Disconnected {
                    transport,
                    reason: err.to_string(),
                });
                return Err(err);
            }
        };

        let control = handle_primary_frame(
            config,
            app.as_ref(),
            continuity,
            &mut power_runtime,
            &mut io,
            transport,
            frame,
            &mut pending_ping_sent_at,
            &mut pending_ping_source,
            &mut health_tracker,
            &mut mobility_tracker,
        )
        .await?;
        if matches!(control, FrameLoopControl::TerminateOk) {
            return Ok(());
        }
    }
}

enum FrameLoopControl {
    Continue,
    TerminateOk,
}

async fn handle_primary_frame(
    config: &ClientConfig,
    app: &dyn ClientApp,
    continuity: &mut ClientContinuityState,
    power_runtime: &mut ClientPowerRuntime,
    io: &mut ClientIo,
    transport: TransportKind,
    frame: Vec<u8>,
    pending_ping_sent_at: &mut Option<Instant>,
    pending_ping_source: &mut Option<ProbeRttSource>,
    health_tracker: &mut HealthTracker,
    mobility_tracker: &mut MobilityTracker,
) -> Result<FrameLoopControl, WarpLinkError> {
    match config.wire_profile.decode_server_frame(&frame)? {
        DecodedServerFrame::Deliver(msg) => {
            power_runtime.note_message(&config.policy.power, Instant::now());
            health_tracker.note_frame_progress(Instant::now());
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
                continuity.note_acked_seq(msg.seq);
                health_tracker.note_ack(status, Instant::now());
            }
            Ok(FrameLoopControl::Continue)
        }
        DecodedServerFrame::Ping => {
            health_tracker.note_frame_progress(Instant::now());
            let pong = config.wire_profile.encode_client_pong();
            io.send_frame(&pong, config.policy.write_timeout_ms).await?;
            Ok(FrameLoopControl::Continue)
        }
        DecodedServerFrame::Pong => {
            health_tracker.note_frame_progress(Instant::now());
            if let Some(sent_at) = pending_ping_sent_at.take() {
                let source = pending_ping_source.take().unwrap_or(ProbeRttSource::Manual);
                let rtt_ms = Instant::now()
                    .saturating_duration_since(sent_at)
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX);
                health_tracker.note_probe_rtt(rtt_ms);
                mobility_tracker.note_probe_rtt(Instant::now(), rtt_ms);
                let _ = app.on_event(ClientEvent::ProbeRtt {
                    transport,
                    rtt_ms,
                    source,
                });
            }
            Ok(FrameLoopControl::Continue)
        }
        DecodedServerFrame::GoAway(reason) => {
            mobility_tracker.note_disconnect(Instant::now());
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
                return Ok(FrameLoopControl::TerminateOk);
            }
            Ok(FrameLoopControl::TerminateOk)
        }
        DecodedServerFrame::Error { code, message } => Err(WarpLinkError::Protocol(format!(
            "gateway error: {code} {message}"
        ))),
        DecodedServerFrame::Welcome(_) => Err(WarpLinkError::Protocol(
            "unexpected welcome frame after handshake".to_string(),
        )),
        DecodedServerFrame::Unknown => Ok(FrameLoopControl::Continue),
    }
}

async fn commit_candidate_cutover(
    config: &ClientConfig,
    app: Arc<dyn ClientApp>,
    continuity: &mut ClientContinuityState,
    power_runtime: &mut ClientPowerRuntime,
    transport: &mut TransportKind,
    io: &mut ClientIo,
    target: TransportKind,
    mut candidate_io: ClientIo,
    decision_id: u64,
) -> Result<Option<warp_link_core::WelcomeMsg>, WarpLinkError> {
    let from_transport = *transport;
    emit_scheduler_state(
        app.as_ref(),
        SchedulerState::CandidateConnecting,
        "candidate_connecting",
    );
    let _ = app.on_event(ClientEvent::CandidateStarted {
        from: from_transport,
        to: target,
        decision_id,
    });
    let candidate_welcome = match initialize_candidate_transport(
        config,
        app.as_ref(),
        continuity,
        power_runtime,
        &mut candidate_io,
    )
    .await
    {
        Ok(value) => value,
        Err(_) => {
            emit_scheduler_state(
                app.as_ref(),
                SchedulerState::PrimaryActive,
                "candidate_failed_precommit",
            );
            return Ok(None);
        }
    };

    emit_scheduler_state(
        app.as_ref(),
        SchedulerState::CutoverReady,
        "candidate_ready",
    );
    let _ = app.on_event(ClientEvent::CandidateReady {
        from: from_transport,
        to: target,
        decision_id,
    });
    let old_io = std::mem::replace(io, candidate_io);
    *transport = target;
    emit_scheduler_state(
        app.as_ref(),
        SchedulerState::DrainingOld,
        "cutover_committed",
    );
    let _ = app.on_event(ClientEvent::CutoverCommitted {
        from: from_transport,
        to: target,
        decision_id,
    });

    if let Err(err) = cutover_guard(config, app.as_ref(), continuity, io, target).await {
        let _ = app.on_event(ClientEvent::CutoverRollback {
            restored: from_transport,
            failed: target,
            decision_id,
            reason: err.to_string(),
        });
        emit_scheduler_state(
            app.as_ref(),
            SchedulerState::Recovering,
            "cutover_guard_failed",
        );
        let _failed_io = std::mem::replace(io, old_io);
        *transport = from_transport;
        return Ok(None);
    }

    spawn_old_primary_drain(config.clone(), Arc::clone(&app), from_transport, old_io);
    emit_scheduler_state(
        app.as_ref(),
        SchedulerState::PrimaryActive,
        "cutover_completed",
    );
    Ok(Some(candidate_welcome))
}

async fn cutover_guard(
    config: &ClientConfig,
    app: &dyn ClientApp,
    continuity: &mut ClientContinuityState,
    io: &mut ClientIo,
    transport: TransportKind,
) -> Result<(), WarpLinkError> {
    if config.policy.cutover_guard_ms == 0 {
        return Ok(());
    }
    let ping = config.wire_profile.encode_client_ping();
    io.send_frame(&ping, config.policy.write_timeout_ms).await?;
    let frame = io.recv_frame(config.policy.cutover_guard_ms).await?;
    match config.wire_profile.decode_server_frame(&frame)? {
        DecodedServerFrame::Deliver(msg) => {
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
                continuity.note_acked_seq(msg.seq);
            }
            Ok(())
        }
        DecodedServerFrame::Ping => {
            let pong = config.wire_profile.encode_client_pong();
            io.send_frame(&pong, config.policy.write_timeout_ms).await?;
            Ok(())
        }
        DecodedServerFrame::Pong | DecodedServerFrame::Unknown => Ok(()),
        DecodedServerFrame::GoAway(reason) => Err(WarpLinkError::Protocol(format!(
            "cutover guard goaway: {}",
            reason.unwrap_or_else(|| "goaway".to_string())
        ))),
        DecodedServerFrame::Error { code, message } => Err(WarpLinkError::Protocol(format!(
            "cutover guard gateway error: {code} {message}"
        ))),
        DecodedServerFrame::Welcome(_) => Err(WarpLinkError::Protocol(
            "unexpected welcome during cutover guard".to_string(),
        )),
    }
}

fn spawn_old_primary_drain(
    config: ClientConfig,
    app: Arc<dyn ClientApp>,
    transport: TransportKind,
    mut io: ClientIo,
) {
    if config.policy.drain_timeout_ms == 0 {
        return;
    }
    let drain_timeout_ms = config.policy.drain_timeout_ms;
    tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_millis(drain_timeout_ms);
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let remain_ms = duration_ms(deadline.saturating_duration_since(now)).min(400);
            let frame = match io.recv_frame(remain_ms).await {
                Ok(frame) => frame,
                Err(WarpLinkError::Timeout(_)) => break,
                Err(_) => break,
            };
            let decoded = match config.wire_profile.decode_server_frame(&frame) {
                Ok(value) => value,
                Err(_) => break,
            };
            match decoded {
                DecodedServerFrame::Deliver(msg) => {
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
                        if let Ok(bytes) = config.wire_profile.encode_client_ack(&ack) {
                            let _ = io.send_frame(&bytes, config.policy.write_timeout_ms).await;
                        }
                    }
                }
                DecodedServerFrame::Ping => {
                    let pong = config.wire_profile.encode_client_pong();
                    let _ = io.send_frame(&pong, config.policy.write_timeout_ms).await;
                }
                DecodedServerFrame::GoAway(_) | DecodedServerFrame::Error { .. } => break,
                DecodedServerFrame::Pong
                | DecodedServerFrame::Welcome(_)
                | DecodedServerFrame::Unknown => {}
            }
        }
    });
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

    fn current_auto_state(&self, policy: &ClientPowerPolicy, now: Instant) -> ClientAppStateHint {
        if !policy.auto_enabled {
            return ClientAppStateHint::Foreground;
        }
        let idle_for = now.saturating_duration_since(self.last_message_at);
        let idle_secs = idle_for.as_secs();
        let idle_cutoff = u64::from(policy.idle_to_low_after_secs);
        if idle_cutoff > 0 && idle_secs >= idle_cutoff {
            ClientAppStateHint::Background
        } else {
            ClientAppStateHint::Foreground
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

struct UpgradeProbeRuntime {
    transport: TransportKind,
    connected_at: Instant,
    next_probe_at: Option<Instant>,
    probe_failure_streak: u8,
}

impl UpgradeProbeRuntime {
    fn new(transport: TransportKind, now: Instant) -> Self {
        Self {
            transport,
            connected_at: now,
            next_probe_at: None,
            probe_failure_streak: 0,
        }
    }

    fn should_probe(&self, config: &ClientConfig, now: Instant, mobility_mode: bool) -> bool {
        let Some(next_probe_at) = self.next_probe_at else {
            return false;
        };
        if !config.policy.upgrade_probe_enabled || !has_higher_priority_transport(self.transport) {
            return false;
        }
        let dwell = Duration::from_secs(u64::from(effective_min_dwell_secs(
            &config.policy,
            mobility_mode,
        )));
        if now.saturating_duration_since(self.connected_at) < dwell {
            return false;
        }
        now >= next_probe_at
    }

    fn schedule_next(
        &mut self,
        config: &ClientConfig,
        app: &dyn ClientApp,
        power_runtime: &ClientPowerRuntime,
        now: Instant,
        mobility_mode: bool,
    ) {
        if !config.policy.upgrade_probe_enabled || !has_higher_priority_transport(self.transport) {
            self.next_probe_at = None;
            return;
        }
        let base = upgrade_probe_interval(config, app, power_runtime, now, mobility_mode);
        let exp = u32::from(self.probe_failure_streak.min(6));
        let mut interval = base.saturating_mul(1u32 << exp);
        let jitter_span = duration_ms(base / 4).max(1);
        let jitter = rand::rng().random_range(0..=jitter_span);
        interval = interval.saturating_add(Duration::from_millis(jitter));
        self.next_probe_at = Some(now + interval);
    }

    fn note_probe_failure(
        &mut self,
        config: &ClientConfig,
        app: &dyn ClientApp,
        power_runtime: &ClientPowerRuntime,
        now: Instant,
        mobility_mode: bool,
    ) {
        self.probe_failure_streak = self.probe_failure_streak.saturating_add(1);
        self.schedule_next(config, app, power_runtime, now, mobility_mode);
    }

    fn note_probe_skip(
        &mut self,
        config: &ClientConfig,
        app: &dyn ClientApp,
        power_runtime: &ClientPowerRuntime,
        now: Instant,
        mobility_mode: bool,
    ) {
        self.schedule_next(config, app, power_runtime, now, mobility_mode);
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
    continuity: &ClientContinuityState,
) -> Result<(), WarpLinkError> {
    let mut latest = build_effective_hello(config, app, power_runtime);
    continuity.apply_to_hello(&mut latest);
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

fn next_recv_timeout_ms(
    config: &ClientConfig,
    probe_runtime: &UpgradeProbeRuntime,
    now: Instant,
    mobility_mode: bool,
) -> Option<u64> {
    let next_probe_at = probe_runtime.next_probe_at?;
    if !config.policy.upgrade_probe_enabled
        || !has_higher_priority_transport(probe_runtime.transport)
    {
        return None;
    }
    let dwell = Duration::from_secs(u64::from(effective_min_dwell_secs(
        &config.policy,
        mobility_mode,
    )));
    let earliest_probe_at = probe_runtime.connected_at + dwell;
    let effective_probe_at = next_probe_at.max(earliest_probe_at);
    if effective_probe_at <= now {
        return Some(1);
    }
    let remaining = effective_probe_at.saturating_duration_since(now);
    Some(duration_ms(remaining))
}

fn duration_ms(value: Duration) -> u64 {
    value.as_millis().try_into().unwrap_or(u64::MAX).max(1)
}

fn upgrade_probe_interval(
    config: &ClientConfig,
    app: &dyn ClientApp,
    power_runtime: &ClientPowerRuntime,
    now: Instant,
    mobility_mode: bool,
) -> Duration {
    let app_state = app
        .power_hint()
        .map(|value| value.app_state)
        .unwrap_or_else(|| power_runtime.current_auto_state(&config.policy.power, now));
    let secs = if mobility_mode {
        match app_state {
            ClientAppStateHint::Foreground => {
                config
                    .policy
                    .mobility_upgrade_probe_foreground_interval_secs
            }
            ClientAppStateHint::Background => {
                config
                    .policy
                    .mobility_upgrade_probe_background_interval_secs
            }
        }
    } else {
        match app_state {
            ClientAppStateHint::Foreground => config.policy.upgrade_probe_foreground_interval_secs,
            ClientAppStateHint::Background => config.policy.upgrade_probe_background_interval_secs,
        }
    };
    Duration::from_secs(u64::from(secs.max(1)))
}

fn has_higher_priority_transport(transport: TransportKind) -> bool {
    !matches!(transport, TransportKind::Quic)
}

fn transport_priority(transport: TransportKind) -> u8 {
    match transport {
        TransportKind::Quic => 0,
        TransportKind::Tcp => 1,
        TransportKind::Wss => 2,
    }
}

async fn probe_higher_priority_transport(
    config: &ClientConfig,
    current: TransportKind,
    policy: &PolicyInput,
) -> Option<(TransportKind, ClientIo)> {
    let mut attempts: JoinSet<(TransportKind, Result<ClientIo, WarpLinkError>)> = JoinSet::new();
    let pinned = pinned_transport_active(policy);
    let mut candidates: Vec<TransportKind> = if let Some(pinned_transport) = pinned {
        if pinned_transport == current || transport_disabled_by_policy(policy, pinned_transport) {
            Vec::new()
        } else {
            vec![pinned_transport]
        }
    } else {
        let current_priority = transport_priority(current);
        default_transport_order()
            .into_iter()
            .filter(|candidate| transport_priority(*candidate) < current_priority)
            .filter(|candidate| !transport_disabled_by_policy(policy, *candidate))
            .collect()
    };

    for (index, transport) in candidates.drain(..).enumerate() {
        let candidate_config = config.clone();
        let delay_ms = transport_start_delay_ms(config, transport, index);
        attempts.spawn(async move {
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            (
                transport,
                connect_transport(&candidate_config, transport).await,
            )
        });
    }

    if attempts.is_empty() {
        return None;
    }

    let deadline = Instant::now() + Duration::from_millis(config.policy.upgrade_probe_timeout_ms);
    while !attempts.is_empty() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remain = deadline.saturating_duration_since(now);
        let join = match timeout(remain, attempts.join_next()).await {
            Ok(value) => value,
            Err(_) => break,
        };
        let Some(result) = join else {
            break;
        };
        let Ok((transport, io_result)) = result else {
            continue;
        };
        if let Ok(io) = io_result {
            attempts.abort_all();
            return Some((transport, io));
        }
    }

    attempts.abort_all();
    None
}

async fn probe_alternate_transport(
    config: &ClientConfig,
    current: TransportKind,
    policy: &PolicyInput,
) -> Option<(TransportKind, ClientIo)> {
    let mut attempts: JoinSet<(TransportKind, Result<ClientIo, WarpLinkError>)> = JoinSet::new();
    let pinned = pinned_transport_active(policy);
    let mut candidates: Vec<TransportKind> = default_transport_order()
        .into_iter()
        .filter(|candidate| *candidate != current)
        .filter(|candidate| !transport_disabled_by_policy(policy, *candidate))
        .collect();
    if let Some(pinned_transport) = pinned
        && pinned_transport != current
        && !transport_disabled_by_policy(policy, pinned_transport)
    {
        candidates.retain(|candidate| *candidate != pinned_transport);
        candidates.insert(0, pinned_transport);
    }
    for (index, transport) in candidates.drain(..).enumerate() {
        let candidate_config = config.clone();
        let delay_ms = transport_start_delay_ms(config, transport, index);
        attempts.spawn(async move {
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            (
                transport,
                connect_transport(&candidate_config, transport).await,
            )
        });
    }
    if attempts.is_empty() {
        return None;
    }
    let deadline = Instant::now() + Duration::from_millis(config.policy.upgrade_probe_timeout_ms);
    while !attempts.is_empty() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remain = deadline.saturating_duration_since(now);
        let join = match timeout(remain, attempts.join_next()).await {
            Ok(value) => value,
            Err(_) => break,
        };
        let Some(result) = join else {
            break;
        };
        let Ok((transport, io_result)) = result else {
            continue;
        };
        if let Ok(io) = io_result {
            attempts.abort_all();
            return Some((transport, io));
        }
    }
    attempts.abort_all();
    None
}

async fn initialize_candidate_transport(
    config: &ClientConfig,
    app: &dyn ClientApp,
    continuity: &ClientContinuityState,
    power_runtime: &mut ClientPowerRuntime,
    io: &mut ClientIo,
) -> Result<warp_link_core::WelcomeMsg, WarpLinkError> {
    let mut hello = build_effective_hello(config, app, power_runtime);
    continuity.apply_to_hello(&mut hello);
    let hello_frame = config.wire_profile.encode_client_hello(&hello)?;
    io.send_frame(&hello_frame, config.policy.write_timeout_ms)
        .await?;
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
    let _ = app.on_event(ClientEvent::Connected {
        transport: io_transport_kind(io),
    });
    let _ = app.on_event(ClientEvent::Welcome {
        welcome: welcome.clone(),
    });
    Ok(welcome)
}

fn io_transport_kind(io: &ClientIo) -> TransportKind {
    match io {
        ClientIo::Quic { .. } => TransportKind::Quic,
        ClientIo::Tcp { .. } => TransportKind::Tcp,
        ClientIo::Wss { .. } => TransportKind::Wss,
    }
}

async fn connect_transport(
    config: &ClientConfig,
    transport: TransportKind,
) -> Result<ClientIo, WarpLinkError> {
    match transport {
        #[cfg(feature = "quic")]
        TransportKind::Quic => connect_quic(config).await,
        #[cfg(not(feature = "quic"))]
        TransportKind::Quic => Err(WarpLinkError::Unsupported(
            "quic transport disabled".to_string(),
        )),

        #[cfg(feature = "tcp")]
        TransportKind::Tcp => connect_tcp(config).await,
        #[cfg(not(feature = "tcp"))]
        TransportKind::Tcp => Err(WarpLinkError::Unsupported(
            "tcp transport disabled".to_string(),
        )),

        #[cfg(feature = "wss")]
        TransportKind::Wss => connect_wss(config).await,
        #[cfg(not(feature = "wss"))]
        TransportKind::Wss => Err(WarpLinkError::Unsupported(
            "wss transport disabled".to_string(),
        )),
    }
}

async fn hedged_connect(
    config: &ClientConfig,
    plan: &TransportPlan,
) -> Result<(TransportKind, ClientIo), WarpLinkError> {
    let mut attempts = JoinSet::new();

    for (transport, delay_ms) in plan.attempts.iter().copied() {
        let candidate_config = config.clone();
        attempts.spawn(async move {
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            (
                transport,
                connect_transport(&candidate_config, transport).await,
            )
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
#[expect(
    clippy::result_large_err,
    reason = "tokio-tungstenite callback signature requires WsErrorResponse as Err"
)]
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
        let mut response = response;
        if let Some(err) = validate_wss_upgrade_request(
            request,
            &mut response,
            expected.as_str(),
            expected_subprotocol.as_deref(),
        ) {
            return Err(err);
        }
        Ok(response)
    })
    .await
    .map_err(|e| WarpLinkError::Protocol(format!("wss upgrade failed: {e}")))
}

#[cfg(feature = "wss")]
fn validate_wss_upgrade_request(
    request: &WsRequest,
    response: &mut WsResponse,
    expected_path: &str,
    expected_subprotocol: Option<&str>,
) -> Option<WsErrorResponse> {
    if request.uri().path() != expected_path {
        let err = WsResponse::builder()
            .status(WsStatusCode::NOT_FOUND)
            .body(Some("path_not_found".to_string()))
            .expect("build wss error response");
        return Some(err);
    }
    if let Some(expected_subprotocol) = expected_subprotocol {
        let requested = request
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let matched = requested_subprotocol_matches(requested, expected_subprotocol);
        if !matched {
            let err = WsResponse::builder()
                .status(WsStatusCode::BAD_REQUEST)
                .body(Some("subprotocol_mismatch".to_string()))
                .expect("build wss subprotocol error response");
            return Some(err);
        }
        if let Ok(value) = expected_subprotocol.parse() {
            response
                .headers_mut()
                .insert("Sec-WebSocket-Protocol", value);
        }
    }
    None
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
    use super::{
        ClientContinuityState, MobilityTracker, build_transport_plan, default_transport_order,
        effective_min_dwell_secs, health_gate_passes, migration_blocked_by_cooldown,
        pinned_transport_active, required_upgrade_windows,
    };
    use std::collections::VecDeque;
    use tokio::time::{Duration, Instant};
    use warp_link_core::{
        ClientConfig, DecisionWinnerLayer, PinnedTransport, PolicyInput, TransportKind, WireProfile,
    };

    #[derive(Default)]
    struct NoopProfile;

    impl WireProfile for NoopProfile {
        fn encode_client_hello(
            &self,
            _hello: &warp_link_core::HelloCtx,
        ) -> Result<bytes::Bytes, warp_link_core::WireError> {
            Ok(bytes::Bytes::new())
        }

        fn decode_server_frame(
            &self,
            _frame: &[u8],
        ) -> Result<warp_link_core::DecodedServerFrame, warp_link_core::WireError> {
            Ok(warp_link_core::DecodedServerFrame::Unknown)
        }

        fn encode_client_ack(
            &self,
            _ack: &warp_link_core::AckMsg,
        ) -> Result<bytes::Bytes, warp_link_core::WireError> {
            Ok(bytes::Bytes::new())
        }

        fn encode_client_ping(&self) -> bytes::Bytes {
            bytes::Bytes::new()
        }

        fn encode_client_pong(&self) -> bytes::Bytes {
            bytes::Bytes::new()
        }

        fn decode_client_frame(
            &self,
            _frame: &[u8],
        ) -> Result<warp_link_core::DecodedClientFrame, warp_link_core::WireError> {
            Ok(warp_link_core::DecodedClientFrame::Unknown)
        }

        fn encode_server_welcome(
            &self,
            _welcome: &warp_link_core::WelcomeMsg,
        ) -> Result<bytes::Bytes, warp_link_core::WireError> {
            Ok(bytes::Bytes::new())
        }

        fn encode_server_deliver(
            &self,
            _msg: &warp_link_core::DeliverMsg,
        ) -> Result<bytes::Bytes, warp_link_core::WireError> {
            Ok(bytes::Bytes::new())
        }

        fn encode_server_ping(&self) -> bytes::Bytes {
            bytes::Bytes::new()
        }

        fn encode_server_pong(&self) -> bytes::Bytes {
            bytes::Bytes::new()
        }

        fn encode_server_goaway(
            &self,
            _reason: &str,
        ) -> Result<bytes::Bytes, warp_link_core::WireError> {
            Ok(bytes::Bytes::new())
        }

        fn encode_server_error(
            &self,
            _code: &str,
            _message: &str,
        ) -> Result<bytes::Bytes, warp_link_core::WireError> {
            Ok(bytes::Bytes::new())
        }
    }

    fn sample_client_config() -> ClientConfig {
        ClientConfig {
            host: "localhost".to_string(),
            quic_port: 443,
            wss_port: 443,
            tcp_port: 5223,
            wss_path: "/private/ws".to_string(),
            quic_alpn: "pushgo-quic".to_string(),
            tcp_alpn: "pushgo-tcp".to_string(),
            wss_subprotocol: Some("pushgo-private.v1".to_string()),
            tls_server_name: Some("localhost".to_string()),
            bearer_token: None,
            cert_pin_sha256: None,
            quic_cert_pin_sha256: None,
            tcp_cert_pin_sha256: None,
            wss_cert_pin_sha256: None,
            policy: warp_link_core::ClientPolicy::default(),
            wire_profile: std::sync::Arc::new(NoopProfile),
        }
    }

    #[test]
    fn continuity_state_tracks_resume_token_and_ack_seq() {
        let mut state = ClientContinuityState::default();
        assert!(!state.can_switch_without_loss());

        state.note_welcome(Some("resume-1"));
        assert!(state.can_switch_without_loss());

        state.note_acked_seq(Some(3));
        state.note_acked_seq(Some(10));
        state.note_acked_seq(Some(7));
        assert_eq!(state.last_acked_seq, Some(10));
    }

    #[test]
    fn continuity_state_ignores_empty_resume_token() {
        let mut state = ClientContinuityState::default();
        state.note_welcome(Some(" "));
        assert!(!state.can_switch_without_loss());
    }

    #[test]
    fn pinned_transport_ignores_expired_pin() {
        let policy = PolicyInput {
            pinned_transport: Some(PinnedTransport {
                transport: TransportKind::Quic,
                expires_at_unix_ms: Some(1),
            }),
            ..PolicyInput::default()
        };
        assert!(pinned_transport_active(&policy).is_none());
    }

    #[test]
    fn build_transport_plan_respects_pin_transport() {
        let config = sample_client_config();
        let available = default_transport_order();
        if available.is_empty() {
            return;
        }
        let pinned = available[0];
        let policy = PolicyInput {
            pinned_transport: Some(PinnedTransport {
                transport: pinned,
                expires_at_unix_ms: None,
            }),
            ..PolicyInput::default()
        };
        let plan = build_transport_plan(&config, &policy);
        assert_eq!(plan.attempts.len(), 1);
        assert_eq!(plan.attempts[0].0, pinned);
        assert_eq!(plan.winner_layer, DecisionWinnerLayer::UserCommand);
    }

    #[test]
    fn build_transport_plan_blocks_all_when_disabled() {
        let config = sample_client_config();
        let disabled = default_transport_order();
        if disabled.is_empty() {
            return;
        }
        let policy = PolicyInput {
            disabled_transports: disabled.clone(),
            ..PolicyInput::default()
        };
        let plan = build_transport_plan(&config, &policy);
        assert!(plan.attempts.is_empty());
        assert_eq!(plan.suppressed_candidates, disabled);
    }

    #[test]
    fn health_gate_rejects_threshold_breach() {
        let policy = warp_link_core::ClientPolicy::default();
        let snapshot_ok = warp_link_core::TransportHealthSnapshot {
            timeout_rate: Some(policy.health_timeout_rate_threshold),
            ack_non_ok_ratio: Some(policy.health_ack_non_ok_ratio_threshold),
            dead_air_secs: Some(u64::from(policy.health_dead_air_secs)),
            rtt_ewma_ms: Some(100),
            rtt_jitter_ms: Some(10),
        };
        assert!(health_gate_passes(&policy, &snapshot_ok));

        let snapshot_bad_timeout = warp_link_core::TransportHealthSnapshot {
            timeout_rate: Some(policy.health_timeout_rate_threshold + 0.01),
            ..snapshot_ok.clone()
        };
        assert!(!health_gate_passes(&policy, &snapshot_bad_timeout));

        let snapshot_bad_ack = warp_link_core::TransportHealthSnapshot {
            ack_non_ok_ratio: Some(policy.health_ack_non_ok_ratio_threshold + 0.01),
            ..snapshot_ok.clone()
        };
        assert!(!health_gate_passes(&policy, &snapshot_bad_ack));

        let snapshot_bad_dead_air = warp_link_core::TransportHealthSnapshot {
            dead_air_secs: Some(u64::from(policy.health_dead_air_secs) + 1),
            ..snapshot_ok
        };
        assert!(!health_gate_passes(&policy, &snapshot_bad_dead_air));
    }

    #[test]
    fn migration_cooldown_blocks_when_limit_hit_and_recovers_after_window() {
        let mut policy = warp_link_core::ClientPolicy::default();
        policy.scheduler_max_migrations_per_5m = 2;
        policy.scheduler_cooldown_secs = 90;
        let now = Instant::now();
        let mut history = VecDeque::from(vec![
            now - Duration::from_secs(10),
            now - Duration::from_secs(5),
        ]);
        let mut cooldown_until: Option<Instant> = None;

        assert!(migration_blocked_by_cooldown(
            &mut history,
            &mut cooldown_until,
            now,
            &policy
        ));
        let cooldown_mark = cooldown_until.expect("cooldown should be set");
        assert!(cooldown_mark > now);

        assert!(migration_blocked_by_cooldown(
            &mut history,
            &mut cooldown_until,
            now + Duration::from_secs(30),
            &policy
        ));

        let much_later = now + Duration::from_secs(420);
        history.push_back(now - Duration::from_secs(380));
        history.push_back(now - Duration::from_secs(370));
        cooldown_until = None;
        assert!(!migration_blocked_by_cooldown(
            &mut history,
            &mut cooldown_until,
            much_later,
            &policy
        ));
    }

    #[test]
    fn mobility_tracker_enters_and_exits_mode_with_signal_decay() {
        let start = Instant::now();
        let mut tracker = MobilityTracker::new(start, true);
        assert!(!tracker.in_mode(start));

        tracker.note_timeout(start + Duration::from_secs(1));
        tracker.note_disconnect(start + Duration::from_secs(2));
        tracker.note_timeout(start + Duration::from_secs(3));
        assert!(tracker.in_mode(start + Duration::from_secs(4)));

        assert!(!tracker.in_mode(start + Duration::from_secs(130)));
    }

    #[test]
    fn mobility_mode_uses_stricter_upgrade_windows_and_dwell() {
        let mut policy = warp_link_core::ClientPolicy::default();
        policy.scheduler_upgrade_confirm_windows = 3;
        policy.mobility_upgrade_confirm_windows = 5;
        policy.upgrade_probe_min_dwell_secs = 25;
        policy.mobility_min_dwell_secs = 60;

        assert_eq!(required_upgrade_windows(&policy, false), 3);
        assert_eq!(required_upgrade_windows(&policy, true), 5);
        assert_eq!(effective_min_dwell_secs(&policy, false), 25);
        assert_eq!(effective_min_dwell_secs(&policy, true), 60);
    }
}
