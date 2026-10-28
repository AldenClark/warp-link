//! Real loopback WebSocket IO around the private cutover seam; these do not run
//! the outer client reconnect loop or the four scheduler decision branches.
use super::*;
use bytes::Bytes;
use pushgo_warp_profile::PushgoWireProfile;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, accept_async, client_async};
use warp_link_core::handoff;
use warp_link_core::{ClientPowerHint, DeliverMsg, WelcomeMsg, WireProfile};

// The production loop passes its existing trackers. This seam fixture owns
// fresh trackers for a single operation; it never adds a production owner.
async fn commit_candidate_cutover(
    config: &ClientConfig,
    app: Arc<dyn ClientApp>,
    active: ActiveTransport<'_>,
    target: TransportKind,
    candidate: ClientIo,
    decision_id: u64,
) -> Result<Option<WelcomeMsg>, WarpLinkError> {
    let mut ping = None;
    let mut source = None;
    let mut health = HealthTracker::new(Instant::now());
    let mut mobility = MobilityTracker::new(Instant::now(), config.policy.mobility_enabled);
    super::commit_candidate_cutover(
        config,
        app,
        active,
        target,
        candidate,
        decision_id,
        PrimaryProgress {
            pending_ping_sent_at: &mut ping,
            pending_ping_source: &mut source,
            health_tracker: &mut health,
            mobility_tracker: &mut mobility,
        },
    )
    .await
}

struct RecordingApp {
    events: Mutex<Vec<ClientEvent>>,
    hello: Mutex<HelloCtx>,
    power: Mutex<Option<ClientPowerHint>>,
    policy: Mutex<PolicyInput>,
    hello_calls: AtomicUsize,
    decisions: Mutex<BTreeMap<u64, AppDecision>>,
    persisted: Mutex<Vec<u64>>,
    control: watch::Sender<u64>,
    block_lower: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    callback_started: watch::Sender<bool>,
}

impl RecordingApp {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            hello: Mutex::new(HelloCtx {
                identity: "device".into(),
                supported_wire_versions: vec![2],
                supported_payload_versions: vec![1],
                ..HelloCtx::default()
            }),
            power: Mutex::new(None),
            policy: Mutex::new(PolicyInput::default()),
            hello_calls: AtomicUsize::new(0),
            decisions: Mutex::new(BTreeMap::new()),
            persisted: Mutex::new(Vec::new()),
            control: watch::channel(0).0,
            block_lower: Mutex::new(None),
            callback_started: watch::channel(false).0,
        }
    }

    fn count(&self, predicate: impl Fn(&ClientEvent) -> bool) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| predicate(e))
            .count()
    }
}

impl ClientApp for RecordingApp {
    fn on_hello(&self) -> HelloCtx {
        self.hello_calls.fetch_add(1, Ordering::SeqCst);
        self.hello.lock().unwrap().clone()
    }

    fn on_event(&self, event: ClientEvent) -> AppDecision {
        let decision = match &event {
            ClientEvent::Message { msg, .. } => {
                if msg.seq == Some(8)
                    && let Some(release) = self.block_lower.lock().unwrap().take()
                {
                    self.callback_started.send_replace(true);
                    release
                        .recv()
                        .expect("test must release the pending persistence callback");
                }
                let decision = msg
                    .seq
                    .and_then(|seq| self.decisions.lock().unwrap().get(&seq).copied())
                    .unwrap_or(AppDecision::AckOk);
                if decision == AppDecision::AckOk {
                    self.persisted.lock().unwrap().push(msg.seq.unwrap());
                }
                decision
            }
            _ => AppDecision::AckOk,
        };
        self.events.lock().unwrap().push(event);
        decision
    }

    fn scheduler_policy(&self) -> PolicyInput {
        PolicyInput {
            control_epoch: *self.control.borrow(),
            ..self.policy.lock().unwrap().clone()
        }
    }

    fn wait_for_control_change(
        &self,
        epoch: u64,
    ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let mut changed = self.control.subscribe();
        Box::pin(async move {
            while *changed.borrow_and_update() == epoch {
                if changed.changed().await.is_err() {
                    return;
                }
            }
        })
    }

    fn power_hint(&self) -> Option<ClientPowerHint> {
        *self.power.lock().unwrap()
    }
}

type Peer = WsServerIo<TungsteniteWsIo<TcpStream>>;

async fn loopback_pair() -> (ClientIo, Peer) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, server) = tokio::join!(
        async {
            let socket = TcpStream::connect(addr).await.unwrap();
            client_async(
                format!("ws://{addr}/private/ws"),
                MaybeTlsStream::Plain(socket),
            )
            .await
            .unwrap()
            .0
        },
        async {
            let (socket, _) = listener.accept().await.unwrap();
            accept_async(socket).await.unwrap()
        }
    );
    (
        ClientIo::Wss {
            stream: Box::new(client),
        },
        WsServerIo {
            inner: TungsteniteWsIo {
                ws: server,
                remote_addr: Some(addr.to_string()),
                max_frame_bytes: TRANSPORT_MAX_FRAME_BYTES as usize,
            },
            write_timeout_ms: 1_000,
        },
    )
}

fn config() -> ClientConfig {
    let mut config = ClientConfig {
        host: "127.0.0.1".into(),
        quic_port: 0,
        tcp_port: 0,
        wss_port: 0,
        wss_path: "/private/ws".into(),
        quic_alpn: "pushgo-quic".into(),
        tcp_alpn: "pushgo-tcp".into(),
        wss_subprotocol: None,
        tls_server_name: None,
        bearer_token: None,
        cert_pin_sha256: None,
        quic_cert_pin_sha256: None,
        tcp_cert_pin_sha256: None,
        wss_cert_pin_sha256: None,
        policy: warp_link_core::ClientPolicy::default(),
        wire_profile: Arc::new(PushgoWireProfile),
    };
    config.wire_profile = Arc::new(PushgoWireProfile);
    config.policy.connect_timeout_ms = 1_000;
    config.policy.cutover_guard_ms = 1_000;
    config.policy.write_timeout_ms = 1_000;
    config
}

fn welcome() -> WelcomeMsg {
    WelcomeMsg {
        session_id: "candidate".into(),
        identity: "device".into(),
        resume_token: Some("new-resume".into()),
        heartbeat_secs: 30,
        ping_interval_secs: 1,
        idle_timeout_secs: 90,
        max_backoff_secs: 60,
        auth_expires_at_unix_secs: None,
        auth_refresh_before_secs: 0,
        max_frame_bytes: TRANSPORT_MAX_FRAME_BYTES,
        negotiated_wire_version: 2,
        negotiated_payload_version: 1,
        metadata: Default::default(),
    }
}

async fn recv(peer: &mut Peer, profile: &dyn WireProfile) -> DecodedClientFrame {
    let bytes = peer.recv_frame(1_000).await.unwrap();
    profile.decode_client_frame(&bytes).unwrap()
}

async fn expect_closed(peer: &mut Peer) {
    let result = peer.recv_frame(1_000).await;
    assert!(
        matches!(result, Err(WarpLinkError::Transport(_))),
        "peer must observe closure rather than an open idle socket: {result:?}"
    );
}

async fn send(peer: &mut Peer, frame: Bytes) {
    peer.send_frame(&frame).await.unwrap();
}

fn continuity() -> ClientContinuityState {
    ClientContinuityState {
        resume_token: Some("old-resume".into()),
        last_acked_seq: Some(7),
        handoff_session: Some("old-session".into()),
        handoff_supported: true,
    }
}

fn phase(hello: &HelloCtx) -> Option<&str> {
    hello.metadata.get(handoff::PHASE_KEY).map(String::as_str)
}

fn receipt(hello: &HelloCtx, phase: &str, session: &str) -> WelcomeMsg {
    let mut value = welcome();
    value.session_id = session.into();
    value.resume_token = hello.resume_token.clone();
    value.metadata = hello.metadata.clone();
    value
        .metadata
        .insert(handoff::PHASE_KEY.into(), phase.into());
    value
}

async fn receive_hello(peer: &mut Peer, expected: &str) -> HelloCtx {
    let DecodedClientFrame::Hello(hello) = recv(peer, &PushgoWireProfile).await else {
        panic!("expected {expected} HELLO");
    };
    assert_eq!(phase(&hello), Some(expected));
    assert_eq!(
        hello.last_acked_seq, None,
        "no max hint is cumulative persistence proof"
    );
    assert_eq!(
        hello.metadata.get(handoff::VERSION_KEY).map(String::as_str),
        Some(handoff::VERSION)
    );
    hello
}

async fn prepare(peer: &mut Peer) -> HelloCtx {
    let hello = receive_hello(peer, "prepare").await;
    assert_eq!(hello.resume_token.as_deref(), Some("old-resume"));
    assert_eq!(
        hello.metadata.get(handoff::PEER_KEY).map(String::as_str),
        Some("old-session")
    );
    send(
        peer,
        PushgoWireProfile
            .encode_server_welcome(&receipt(&hello, "prepared", "candidate"))
            .unwrap(),
    )
    .await;
    hello
}

async fn guard_ok(peer: &mut Peer) {
    assert!(matches!(
        recv(peer, &PushgoWireProfile).await,
        DecodedClientFrame::Ping
    ));
    send(peer, PushgoWireProfile.encode_server_pong()).await;
}

async fn freeze_and_fence(peer: &mut Peer, deliveries: &[(u64, &str)]) {
    let freeze = receive_hello(peer, "freeze").await;
    assert_eq!(
        freeze.metadata.get(handoff::PEER_KEY).map(String::as_str),
        Some("candidate")
    );
    for (seq, id) in deliveries {
        send_delivery(peer, *seq, id, Bytes::from_static(b"earlier")).await;
    }
    // This authenticated receipt is ordered after every old-stream delivery.
    send(
        peer,
        PushgoWireProfile
            .encode_server_welcome(&receipt(&freeze, "drained", "old-session"))
            .unwrap(),
    )
    .await;
    for (seq, id) in deliveries {
        expect_ack(peer, *seq, id).await;
    }
    assert!(matches!(
        recv(peer, &PushgoWireProfile).await,
        DecodedClientFrame::Ping
    ));
    send(peer, PushgoWireProfile.encode_server_pong()).await;
}

async fn activate(peer: &mut Peer, prepared: &HelloCtx) {
    let hello = receive_hello(peer, "activate").await;
    assert_eq!(
        hello.metadata.get(handoff::ID_KEY),
        prepared.metadata.get(handoff::ID_KEY)
    );
    assert_eq!(
        hello.metadata.get(handoff::PEER_KEY).map(String::as_str),
        Some("old-session")
    );
    send(
        peer,
        PushgoWireProfile
            .encode_server_welcome(&receipt(&hello, "active", "candidate"))
            .unwrap(),
    )
    .await;
}

async fn send_delivery(peer: &mut Peer, seq: u64, id: &str, payload: Bytes) {
    send(
        peer,
        PushgoWireProfile
            .encode_server_deliver(&DeliverMsg {
                seq: Some(seq),
                id: id.into(),
                payload,
            })
            .unwrap(),
    )
    .await;
}

async fn expect_ack(peer: &mut Peer, seq: u64, id: &str) {
    let frame = timeout(Duration::from_millis(500), recv(peer, &PushgoWireProfile))
        .await
        .expect("candidate readiness must not prevent a live primary wire ACK");
    let DecodedClientFrame::Ack(ack) = frame else {
        panic!("expected ACK, got {frame:?}");
    };
    assert_eq!(ack.seq, Some(seq));
    assert_eq!(ack.id, id);
    assert_eq!(ack.status, AckStatus::Ok);
}

async fn primary_delivery_requires_wire_ack(peer: &mut Peer, seq: u64) {
    send_delivery(
        peer,
        seq,
        &format!("live-{seq}"),
        Bytes::from_static(b"fixed-content"),
    )
    .await;
    expect_ack(peer, seq, &format!("live-{seq}")).await;
}

async fn process_active_delivery(
    config: &ClientConfig,
    app: Arc<RecordingApp>,
    continuity: &mut ClientContinuityState,
    power: &mut ClientPowerRuntime,
    io: &mut ClientIo,
    peer: &mut Peer,
    delivery: (u64, &str, Bytes),
) {
    let (seq, id, payload) = delivery;
    let mut pending_ping = None;
    let mut pending_source = None;
    let mut health = HealthTracker::new(Instant::now());
    let mut mobility = MobilityTracker::new(Instant::now(), false);
    let handle = async {
        let frame = io.recv_frame(1_000).await.unwrap();
        handle_primary_frame(
            config,
            app,
            TransportKind::Wss,
            frame,
            PrimaryFrameState {
                continuity,
                power_runtime: power,
                io,
                pending_ping_sent_at: &mut pending_ping,
                pending_ping_source: &mut pending_source,
                health_tracker: &mut health,
                mobility_tracker: &mut mobility,
            },
        )
        .await
        .unwrap();
    };
    let server = async {
        send_delivery(peer, seq, id, payload).await;
        expect_ack(peer, seq, id).await;
    };
    tokio::join!(handle, server);
}

#[tokio::test]
async fn successful_cutover_refreshes_hello_and_hands_off_ack_once() {
    assert_successful_cutover(Bytes::from_static(b"payload")).await;
}

#[tokio::test]
async fn successful_cutover_hands_off_exact_128k_delivery_after_activation() {
    // Same complete-frame boundary as the old guard test. Business delivery is
    // now forbidden until activation; a DELIVER is never a health receipt.
    let payload = Bytes::from(vec![b'x'; warp_link_core::MAX_FRAME_BYTES - 14]);
    let frame = PushgoWireProfile
        .encode_server_deliver(&DeliverMsg {
            seq: Some(8),
            id: "handoff".into(),
            payload: payload.clone(),
        })
        .unwrap();
    assert_eq!(frame.len(), warp_link_core::MAX_FRAME_BYTES);
    assert_successful_cutover(payload).await;
}

async fn assert_successful_cutover(payload: Bytes) {
    let config = config();
    let app = Arc::new(RecordingApp::new());
    let (mut io, mut old_peer) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let mut continuity = continuity();
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let observer = async {
        let prepared = prepare(&mut peer).await;
        app.hello.lock().unwrap().auth_token = Some("refreshed-auth".into());
        *app.power.lock().unwrap() = Some(ClientPowerHint {
            preferred_tier: Some(ClientPowerTier::High),
            app_state: ClientAppStateHint::Background,
        });
        guard_ok(&mut peer).await;
        freeze_and_fence(&mut old_peer, &[]).await;
        activate(&mut peer, &prepared).await;
    };
    let (result, ()) = tokio::join!(
        commit_candidate_cutover(
            &config,
            app.clone(),
            ActiveTransport {
                continuity: &mut continuity,
                power_runtime: &mut power,
                transport: &mut transport,
                io: &mut io,
            },
            TransportKind::Wss,
            candidate,
            41
        ),
        observer
    );
    let returned = result.unwrap().unwrap();
    assert_eq!(transport, TransportKind::Wss);
    assert_eq!(app.hello_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        continuity.last_acked_seq,
        Some(7),
        "preparation never ACKs business work"
    );
    assert_eq!(continuity.resume_token.as_deref(), Some("old-resume"));
    expect_closed(&mut old_peer).await;
    process_active_delivery(
        &config,
        app.clone(),
        &mut continuity,
        &mut power,
        &mut io,
        &mut peer,
        (8, "handoff", payload.clone()),
    )
    .await;
    assert_eq!(continuity.last_acked_seq, Some(8));
    assert_eq!(*app.persisted.lock().unwrap(), vec![8]);
    assert_eq!(app.count(|event| matches!(event, ClientEvent::Message { msg, .. } if msg.id == "handoff" && msg.payload == payload)), 1);
    let before = Instant::now();
    let old_at = before - Duration::from_secs(50);
    let mut probes = UpgradeProbeRuntime::new(TransportKind::Tcp, old_at);
    probes.probe_failure_streak = 5;
    let mut maintenance = SessionMaintenance {
        idle_timeout_ms: 99_000,
        idle_timeout_streak: 3,
        last_idle_ping_at: old_at,
        inband_hello_snapshot: HelloCtx::default(),
        upgrade_probe_runtime: probes,
    };
    let mut mobility = MobilityTracker::new(before, false);
    maintenance.refresh_after_cutover(
        &config,
        app.as_ref(),
        ActiveTransport {
            continuity: &mut continuity,
            power_runtime: &mut power,
            transport: &mut transport,
            io: &mut io,
        },
        &mut mobility,
        &returned,
    );
    assert_eq!(app.hello_calls.load(Ordering::SeqCst), 2);
    assert_eq!(maintenance.idle_timeout_ms, 5_000);
    assert_eq!(maintenance.idle_timeout_streak, 0);
    assert!(maintenance.last_idle_ping_at >= before);
    assert_eq!(
        maintenance.inband_hello_snapshot.resume_token.as_deref(),
        Some("old-resume")
    );
    assert_eq!(maintenance.inband_hello_snapshot.last_acked_seq, None);
    assert_eq!(
        maintenance.inband_hello_snapshot.auth_token.as_deref(),
        Some("refreshed-auth")
    );
    assert_eq!(
        maintenance.inband_hello_snapshot.perf_tier.as_deref(),
        Some("high")
    );
    assert_eq!(
        maintenance.inband_hello_snapshot.app_state.as_deref(),
        Some("background")
    );
    assert_eq!(continuity.handoff_session.as_deref(), Some("candidate"));
    assert!(continuity.handoff_supported);
    assert_eq!(
        maintenance.upgrade_probe_runtime.transport,
        TransportKind::Wss
    );
    assert_eq!(maintenance.upgrade_probe_runtime.probe_failure_streak, 0);
    assert!(maintenance.upgrade_probe_runtime.connected_at >= before);
    let next = maintenance.upgrade_probe_runtime.next_probe_at.unwrap();
    let base = Duration::from_secs(u64::from(
        config.policy.upgrade_probe_background_interval_secs,
    ));
    assert!(next >= before + base);
    assert!(next <= Instant::now() + base + base / 4);
    maybe_send_inband_hello_update(
        &config,
        app.as_ref(),
        &mut io,
        &mut maintenance.inband_hello_snapshot,
        &mut power,
        &continuity,
    )
    .await
    .unwrap();
    assert_eq!(app.hello_calls.load(Ordering::SeqCst), 3);
    io.send_frame(&PushgoWireProfile.encode_client_ping(), 1_000)
        .await
        .unwrap();
    assert!(matches!(
        recv(&mut peer, &PushgoWireProfile).await,
        DecodedClientFrame::Ping
    ));
    for predicate in [
        (|e: &ClientEvent| {
            matches!(
                e,
                ClientEvent::CandidateStarted {
                    decision_id: 41,
                    ..
                }
            )
        }) as fn(&ClientEvent) -> bool,
        |e| {
            matches!(
                e,
                ClientEvent::CandidateReady {
                    decision_id: 41,
                    ..
                }
            )
        },
        |e| {
            matches!(
                e,
                ClientEvent::CutoverCommitted {
                    decision_id: 41,
                    ..
                }
            )
        },
        |e| matches!(e, ClientEvent::Connected { .. }),
        |e| matches!(e, ClientEvent::Welcome { .. }),
    ] {
        assert_eq!(app.count(predicate), 1);
    }
    assert_eq!(
        app.count(|e| matches!(e, ClientEvent::CutoverRollback { .. })),
        0
    );
    let states: Vec<_> = app
        .events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|event| match event {
            ClientEvent::SchedulerStateChanged { state, .. } => Some(*state),
            _ => None,
        })
        .collect();
    assert_eq!(
        states,
        vec![
            SchedulerState::CandidateConnecting,
            SchedulerState::CutoverReady,
            SchedulerState::DrainingOld,
            SchedulerState::PrimaryActive
        ]
    );
}

#[tokio::test]
async fn failed_handshake_keeps_old_primary_and_continuity() {
    let config = config();
    let app = Arc::new(RecordingApp::new());
    let (mut io, mut old) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let mut continuity = continuity();
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let observer = async {
        receive_hello(&mut peer, "prepare").await;
        send(
            &mut peer,
            PushgoWireProfile
                .encode_server_error("test", "rejected")
                .unwrap(),
        )
        .await;
    };
    let (result, ()) = tokio::join!(
        commit_candidate_cutover(
            &config,
            app.clone(),
            ActiveTransport {
                continuity: &mut continuity,
                power_runtime: &mut power,
                transport: &mut transport,
                io: &mut io
            },
            TransportKind::Wss,
            candidate,
            42
        ),
        observer
    );
    assert!(result.unwrap().is_none());
    assert_eq!(transport, TransportKind::Tcp);
    assert_eq!(continuity.resume_token.as_deref(), Some("old-resume"));
    assert_eq!(continuity.last_acked_seq, Some(7));
    assert_eq!(app.hello_calls.load(Ordering::SeqCst), 1);
    expect_closed(&mut peer).await;
    io.send_frame(&PushgoWireProfile.encode_client_ping(), 1_000)
        .await
        .unwrap();
    assert!(matches!(
        recv(&mut old, &PushgoWireProfile).await,
        DecodedClientFrame::Ping
    ));
    assert_eq!(
        app.count(|e| matches!(e, ClientEvent::CandidateStarted { .. })),
        1
    );
    assert_eq!(
        app.count(|e| matches!(
            e,
            ClientEvent::CandidateReady { .. }
                | ClientEvent::CutoverCommitted { .. }
                | ClientEvent::Welcome { .. }
        )),
        0
    );
}

#[tokio::test]
async fn failed_guard_restores_old_primary_without_success_refresh() {
    let config = config();
    let app = Arc::new(RecordingApp::new());
    let (mut io, mut old) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let mut continuity = continuity();
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let observer = async {
        prepare(&mut peer).await;
        assert!(matches!(
            recv(&mut peer, &PushgoWireProfile).await,
            DecodedClientFrame::Ping
        ));
        send(
            &mut peer,
            PushgoWireProfile
                .encode_server_goaway("guard-rejected")
                .unwrap(),
        )
        .await;
    };
    let (result, ()) = tokio::join!(
        commit_candidate_cutover(
            &config,
            app.clone(),
            ActiveTransport {
                continuity: &mut continuity,
                power_runtime: &mut power,
                transport: &mut transport,
                io: &mut io
            },
            TransportKind::Wss,
            candidate,
            43
        ),
        observer
    );
    assert!(result.unwrap().is_none());
    assert_eq!(transport, TransportKind::Tcp);
    assert_eq!(continuity.last_acked_seq, Some(7));
    assert_eq!(continuity.resume_token.as_deref(), Some("old-resume"));
    expect_closed(&mut peer).await;
    io.send_frame(&PushgoWireProfile.encode_client_ping(), 1_000)
        .await
        .unwrap();
    assert!(matches!(
        recv(&mut old, &PushgoWireProfile).await,
        DecodedClientFrame::Ping
    ));
    assert_eq!(
        app.count(|e| matches!(e, ClientEvent::CandidateStarted { .. })),
        1
    );
    assert_eq!(
        app.count(|e| matches!(
            e,
            ClientEvent::CandidateReady { .. }
                | ClientEvent::CutoverCommitted { .. }
                | ClientEvent::Welcome { .. }
        )),
        0,
        "failed guard never grants application ownership or emits a commit"
    );
}

#[tokio::test]
async fn guard_timeout_rolls_back_to_usable_old_primary() {
    let mut config = config();
    config.policy.cutover_guard_ms = 40;
    let app = Arc::new(RecordingApp::new());
    let (mut io, mut old) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let mut continuity = continuity();
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let observer = async {
        prepare(&mut peer).await;
        assert!(matches!(
            recv(&mut peer, &PushgoWireProfile).await,
            DecodedClientFrame::Ping
        ));
        expect_closed(&mut peer).await;
    };
    let (result, ()) = tokio::join!(
        commit_candidate_cutover(
            &config,
            app.clone(),
            ActiveTransport {
                continuity: &mut continuity,
                power_runtime: &mut power,
                transport: &mut transport,
                io: &mut io
            },
            TransportKind::Wss,
            candidate,
            45
        ),
        observer
    );
    assert!(result.unwrap().is_none());
    assert_eq!(transport, TransportKind::Tcp);
    assert_eq!(continuity.last_acked_seq, Some(7));
    io.send_frame(&PushgoWireProfile.encode_client_ping(), 1_000)
        .await
        .unwrap();
    assert!(matches!(
        recv(&mut old, &PushgoWireProfile).await,
        DecodedClientFrame::Ping
    ));
    assert_eq!(
        app.count(|e| matches!(
            e,
            ClientEvent::CutoverCommitted { .. } | ClientEvent::Welcome { .. }
        )),
        0
    );
}

async fn cancellation_closes_owned_connections(in_guard: bool) {
    let mut config = config();
    config.policy.cutover_guard_ms = 5_000;
    let app = Arc::new(RecordingApp::new());
    let (mut io, mut old) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let (shutdown, mut stopped) = watch::channel(false);
    let owned = app.clone();
    let task = tokio::spawn(async move {
        let mut continuity = continuity();
        let mut power = ClientPowerRuntime::new(Instant::now());
        let mut transport = TransportKind::Tcp;
        tokio::select! { biased;
            _ = stopped.changed() => {},
            result = commit_candidate_cutover(&config, owned, ActiveTransport { continuity: &mut continuity, power_runtime: &mut power,
                transport: &mut transport, io: &mut io }, TransportKind::Wss, candidate, 44) => panic!("held candidate completed: {result:?}"),
        }
    });
    if in_guard {
        prepare(&mut peer).await;
        assert!(matches!(
            recv(&mut peer, &PushgoWireProfile).await,
            DecodedClientFrame::Ping
        ));
    } else {
        receive_hello(&mut peer, "prepare").await;
    }
    shutdown.send(true).unwrap();
    timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    expect_closed(&mut peer).await;
    expect_closed(&mut old).await;
    assert_eq!(
        app.count(|e| matches!(e, ClientEvent::CandidateStarted { .. })),
        1
    );
    assert_eq!(
        app.count(|e| matches!(
            e,
            ClientEvent::CandidateReady { .. }
                | ClientEvent::CutoverCommitted { .. }
                | ClientEvent::Message { .. }
        )),
        0
    );
}

#[tokio::test]
async fn cancellation_before_commit_closes_both_owned_connections() {
    cancellation_closes_owned_connections(false).await;
}
#[tokio::test]
async fn cancellation_during_guard_closes_old_and_new_owned_connections() {
    cancellation_closes_owned_connections(true).await;
}

#[tokio::test]
async fn held_candidate_welcome_does_not_block_primary_persistence_and_ack() {
    assert_preparation_progress(false).await;
}
#[tokio::test]
async fn held_candidate_guard_does_not_block_primary_persistence_and_ack() {
    assert_preparation_progress(true).await;
}

async fn assert_preparation_progress(in_guard: bool) {
    let config = config();
    let app = Arc::new(RecordingApp::new());
    let (mut io, mut old) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let mut continuity = continuity();
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let observer = async {
        let hello = receive_hello(&mut peer, "prepare").await;
        if !in_guard {
            primary_delivery_requires_wire_ack(&mut old, 8).await;
        }
        send(
            &mut peer,
            PushgoWireProfile
                .encode_server_welcome(&receipt(&hello, "prepared", "candidate"))
                .unwrap(),
        )
        .await;
        assert!(matches!(
            recv(&mut peer, &PushgoWireProfile).await,
            DecodedClientFrame::Ping
        ));
        if in_guard {
            primary_delivery_requires_wire_ack(&mut old, 8).await;
        }
        send(&mut peer, PushgoWireProfile.encode_server_pong()).await;
        freeze_and_fence(&mut old, &[]).await;
        activate(&mut peer, &hello).await;
    };
    let (result, ()) = tokio::join!(
        commit_candidate_cutover(
            &config,
            app.clone(),
            ActiveTransport {
                continuity: &mut continuity,
                power_runtime: &mut power,
                transport: &mut transport,
                io: &mut io
            },
            TransportKind::Wss,
            candidate,
            96
        ),
        observer
    );
    assert!(result.unwrap().is_some());
    assert_eq!(*app.persisted.lock().unwrap(), vec![8]);
    assert_eq!(continuity.last_acked_seq, Some(8));
}

#[tokio::test]
async fn simultaneous_ready_unique_deliveries_preserve_primary_before_candidate() {
    let config = config();
    let app = Arc::new(RecordingApp::new());
    let (mut io, mut old) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let mut continuity = continuity();
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let observer = async {
        let hello = prepare(&mut peer).await;
        guard_ok(&mut peer).await;
        freeze_and_fence(&mut old, &[(8, "old-unique-8")]).await;
        let activate = receive_hello(&mut peer, "activate").await;
        assert_eq!(
            activate.metadata.get(handoff::ID_KEY),
            hello.metadata.get(handoff::ID_KEY)
        );
        // Both writes complete before the client is next polled: old8 preceded
        // the drained receipt; active WELCOME and candidate9 are queued together.
        send(
            &mut peer,
            PushgoWireProfile
                .encode_server_welcome(&receipt(&activate, "active", "candidate"))
                .unwrap(),
        )
        .await;
        send_delivery(&mut peer, 9, "new-unique-9", Bytes::from_static(b"later")).await;
    };
    let (result, ()) = tokio::join!(
        commit_candidate_cutover(
            &config,
            app.clone(),
            ActiveTransport {
                continuity: &mut continuity,
                power_runtime: &mut power,
                transport: &mut transport,
                io: &mut io
            },
            TransportKind::Wss,
            candidate,
            95
        ),
        observer
    );
    assert!(result.unwrap().is_some());
    expect_closed(&mut old).await;
    let mut ping = None;
    let mut source = None;
    let mut health = HealthTracker::new(Instant::now());
    let mut mobility = MobilityTracker::new(Instant::now(), false);
    let handle = async {
        let frame = io.recv_frame(1_000).await.unwrap();
        handle_primary_frame(
            &config,
            app.clone(),
            transport,
            frame,
            PrimaryFrameState {
                continuity: &mut continuity,
                power_runtime: &mut power,
                io: &mut io,
                pending_ping_sent_at: &mut ping,
                pending_ping_source: &mut source,
                health_tracker: &mut health,
                mobility_tracker: &mut mobility,
            },
        )
        .await
        .unwrap();
    };
    tokio::join!(handle, expect_ack(&mut peer, 9, "new-unique-9"));
    assert_eq!(*app.persisted.lock().unwrap(), vec![8, 9]);
    assert_eq!(continuity.last_acked_seq, Some(9));
}

#[tokio::test]
async fn application_retry_later_on_old_lower_seq_prevents_candidate_activation() {
    let config = config();
    let app = Arc::new(RecordingApp::new());
    app.decisions
        .lock()
        .unwrap()
        .insert(8, AppDecision::RetryLater);
    let (mut io, mut old) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let mut continuity = continuity();
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let observer = async {
        prepare(&mut peer).await;
        guard_ok(&mut peer).await;
        let freeze = receive_hello(&mut old, "freeze").await;
        send_delivery(&mut old, 8, "not-saved", Bytes::from_static(b"earlier")).await;
        send(
            &mut old,
            PushgoWireProfile
                .encode_server_welcome(&receipt(&freeze, "drained", "old-session"))
                .unwrap(),
        )
        .await;
        expect_closed(&mut peer).await;
    };
    let (result, ()) = tokio::join!(
        commit_candidate_cutover(
            &config,
            app.clone(),
            ActiveTransport {
                continuity: &mut continuity,
                power_runtime: &mut power,
                transport: &mut transport,
                io: &mut io
            },
            TransportKind::Wss,
            candidate,
            97
        ),
        observer
    );
    assert!(matches!(result, Err(WarpLinkError::Reconnect(_))));
    assert!(app.persisted.lock().unwrap().is_empty());
    assert_eq!(continuity.last_acked_seq, Some(7));
    assert_eq!(transport, TransportKind::Tcp);
    assert_eq!(
        app.count(|e| matches!(e, ClientEvent::CutoverCommitted { .. })),
        0
    );
    assert!(
        matches!(old.recv_frame(40).await, Err(WarpLinkError::Timeout(_))),
        "no ACK or fence follows a failed business save"
    );
}

#[tokio::test]
async fn valid_sequence_gaps_and_duplicate_frames_do_not_stall_handoff() {
    let config = config();
    let app = Arc::new(RecordingApp::new());
    let (mut io, mut old) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let mut continuity = continuity();
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let observer = async {
        let hello = prepare(&mut peer).await;
        guard_ok(&mut peer).await;
        freeze_and_fence(&mut old, &[(8, "older"), (11, "gap-is-valid")]).await;
        activate(&mut peer, &hello).await;
    };
    let (result, ()) = tokio::join!(
        commit_candidate_cutover(
            &config,
            app.clone(),
            ActiveTransport {
                continuity: &mut continuity,
                power_runtime: &mut power,
                transport: &mut transport,
                io: &mut io
            },
            TransportKind::Wss,
            candidate,
            98
        ),
        observer
    );
    assert!(result.unwrap().is_some());
    assert_eq!(*app.persisted.lock().unwrap(), vec![8, 11]);
    process_active_delivery(
        &config,
        app.clone(),
        &mut continuity,
        &mut power,
        &mut io,
        &mut peer,
        (11, "gap-is-valid", Bytes::from_static(b"earlier")),
    )
    .await;
    // The callback remains the application's deduplication authority, including
    // a retransmission whose original explicit ACK was lost.
    assert_eq!(
        app.count(|e| matches!(e, ClientEvent::Message { msg, .. } if msg.seq == Some(11))),
        2
    );
    assert_eq!(continuity.last_acked_seq, Some(11));
}

#[tokio::test]
async fn unnegotiated_primary_does_not_send_candidate_hello_or_steal_ownership() {
    let config = config();
    let app = Arc::new(RecordingApp::new());
    let (mut io, mut old) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let mut continuity = continuity();
    continuity.handoff_supported = false;
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let result = commit_candidate_cutover(
        &config,
        app.clone(),
        ActiveTransport {
            continuity: &mut continuity,
            power_runtime: &mut power,
            transport: &mut transport,
            io: &mut io,
        },
        TransportKind::Wss,
        candidate,
        99,
    )
    .await;
    assert!(result.unwrap().is_none());
    expect_closed(&mut peer).await;
    io.send_frame(&PushgoWireProfile.encode_client_ping(), 1_000)
        .await
        .unwrap();
    assert!(matches!(
        recv(&mut old, &PushgoWireProfile).await,
        DecodedClientFrame::Ping
    ));
    assert_eq!(transport, TransportKind::Tcp);
    assert!(app.events.lock().unwrap().is_empty());
    assert_eq!(app.hello_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn never_welcome_times_out_but_primary_can_persist_before_timeout() {
    let mut config = config();
    config.policy.connect_timeout_ms = 100;
    let app = Arc::new(RecordingApp::new());
    let (mut io, mut old) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let mut continuity = continuity();
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let observer = async {
        receive_hello(&mut peer, "prepare").await;
        primary_delivery_requires_wire_ack(&mut old, 8).await;
        expect_closed(&mut peer).await;
    };
    let (result, ()) = tokio::join!(
        commit_candidate_cutover(
            &config,
            app.clone(),
            ActiveTransport {
                continuity: &mut continuity,
                power_runtime: &mut power,
                transport: &mut transport,
                io: &mut io
            },
            TransportKind::Wss,
            candidate,
            100
        ),
        observer
    );
    assert!(result.unwrap().is_none());
    assert_eq!(*app.persisted.lock().unwrap(), vec![8]);
    assert_eq!(transport, TransportKind::Tcp);
}

#[tokio::test]
async fn control_change_while_guard_held_returns_for_rebuild_without_candidate_owner() {
    let mut config = config();
    config.policy.scheduler_v2_enabled = true;
    let app = Arc::new(RecordingApp::new());
    let (mut io, mut old) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let mut continuity = continuity();
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let observer = async {
        prepare(&mut peer).await;
        assert!(matches!(
            recv(&mut peer, &PushgoWireProfile).await,
            DecodedClientFrame::Ping
        ));
        app.control.send_replace(1);
        expect_closed(&mut peer).await;
    };
    let (result, ()) = tokio::join!(
        commit_candidate_cutover(
            &config,
            app.clone(),
            ActiveTransport {
                continuity: &mut continuity,
                power_runtime: &mut power,
                transport: &mut transport,
                io: &mut io
            },
            TransportKind::Wss,
            candidate,
            101
        ),
        observer
    );
    assert!(matches!(result, Err(WarpLinkError::Reconnect(_))));
    assert_eq!(transport, TransportKind::Tcp);
    assert_eq!(
        app.count(|e| matches!(
            e,
            ClientEvent::CutoverCommitted { .. } | ClientEvent::Welcome { .. }
        )),
        0
    );
    io.send_frame(&PushgoWireProfile.encode_client_ping(), 1_000)
        .await
        .unwrap();
    assert!(matches!(
        recv(&mut old, &PushgoWireProfile).await,
        DecodedClientFrame::Ping
    ));
}

#[tokio::test]
async fn premature_candidate_delivery_is_rejected_without_application_or_ack() {
    let config = config();
    let app = Arc::new(RecordingApp::new());
    let (mut io, _old) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let mut continuity = continuity();
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let observer = async {
        prepare(&mut peer).await;
        assert!(matches!(
            recv(&mut peer, &PushgoWireProfile).await,
            DecodedClientFrame::Ping
        ));
        send_delivery(
            &mut peer,
            9,
            "premature",
            Bytes::from_static(b"never-owner"),
        )
        .await;
        expect_closed(&mut peer).await;
    };
    let (result, ()) = tokio::join!(
        commit_candidate_cutover(
            &config,
            app.clone(),
            ActiveTransport {
                continuity: &mut continuity,
                power_runtime: &mut power,
                transport: &mut transport,
                io: &mut io
            },
            TransportKind::Wss,
            candidate,
            102
        ),
        observer
    );
    assert!(result.unwrap().is_none());
    assert_eq!(continuity.last_acked_seq, Some(7));
    assert_eq!(transport, TransportKind::Tcp);
    assert_eq!(
        app.count(|e| matches!(
            e,
            ClientEvent::Message { .. } | ClientEvent::CutoverCommitted { .. }
        )),
        0
    );
}
#[tokio::test]
async fn success_maintenance_clamps_upper_ping_and_clears_disabled_probe() {
    let mut config = config();
    config.policy.upgrade_probe_enabled = false;
    let app = RecordingApp::new();
    let (mut io, _peer) = loopback_pair().await;
    let mut transport = TransportKind::Wss;
    let mut continuity = continuity();
    let before = Instant::now();
    let mut power = ClientPowerRuntime::new(before);
    let mut mobility = MobilityTracker::new(before, false);
    let mut probe = UpgradeProbeRuntime::new(TransportKind::Tcp, before);
    probe.next_probe_at = Some(before + Duration::from_secs(900));
    probe.probe_failure_streak = 5;
    let mut maintenance = SessionMaintenance {
        idle_timeout_ms: 1,
        idle_timeout_streak: 4,
        last_idle_ping_at: before,
        inband_hello_snapshot: HelloCtx::default(),
        upgrade_probe_runtime: probe,
    };
    let mut welcome = welcome();
    welcome.ping_interval_secs = 90;
    maintenance.refresh_after_cutover(
        &config,
        &app,
        ActiveTransport {
            continuity: &mut continuity,
            power_runtime: &mut power,
            transport: &mut transport,
            io: &mut io,
        },
        &mut mobility,
        &welcome,
    );
    assert_eq!(maintenance.idle_timeout_ms, 30_000);
    assert_eq!(maintenance.idle_timeout_streak, 0);
    assert_eq!(
        maintenance.upgrade_probe_runtime.transport,
        TransportKind::Wss
    );
    assert_eq!(maintenance.upgrade_probe_runtime.probe_failure_streak, 0);
    assert!(maintenance.upgrade_probe_runtime.next_probe_at.is_none());
    assert_eq!(
        maintenance.inband_hello_snapshot.resume_token.as_deref(),
        Some("new-resume")
    );
    assert_eq!(maintenance.inband_hello_snapshot.last_acked_seq, None);
    assert_eq!(app.hello_calls.load(Ordering::SeqCst), 1);
    assert!(app.events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn old_lower_persistence_barrier_precedes_activation_and_candidate_ack() {
    let config = config();
    let app = Arc::new(RecordingApp::new());
    let (release, blocked) = std::sync::mpsc::channel();
    *app.block_lower.lock().unwrap() = Some(blocked);
    let mut started = app.callback_started.subscribe();
    let (mut io, mut old) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let mut continuity = continuity();
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let observer = async {
        let prepared = prepare(&mut peer).await;
        guard_ok(&mut peer).await;
        let freeze = receive_hello(&mut old, "freeze").await;
        send_delivery(&mut old, 8, "blocked-save", Bytes::from_static(b"first")).await;
        send(
            &mut old,
            PushgoWireProfile
                .encode_server_welcome(&receipt(&freeze, "drained", "old-session"))
                .unwrap(),
        )
        .await;
        timeout(Duration::from_secs(1), async {
            while !*started.borrow_and_update() {
                started.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert!(app.persisted.lock().unwrap().is_empty());
        assert!(
            matches!(peer.recv_frame(40).await, Err(WarpLinkError::Timeout(_))),
            "candidate must not receive activation while lower application persistence is incomplete"
        );
        assert!(
            matches!(old.recv_frame(40).await, Err(WarpLinkError::Timeout(_))),
            "lower message must not be ACKed before its persistence callback completes"
        );
        release.send(()).unwrap();
        expect_ack(&mut old, 8, "blocked-save").await;
        assert!(matches!(
            recv(&mut old, &PushgoWireProfile).await,
            DecodedClientFrame::Ping
        ));
        send(&mut old, PushgoWireProfile.encode_server_pong()).await;
        activate(&mut peer, &prepared).await;
    };
    let (result, ()) = tokio::join!(
        commit_candidate_cutover(
            &config,
            app.clone(),
            ActiveTransport {
                continuity: &mut continuity,
                power_runtime: &mut power,
                transport: &mut transport,
                io: &mut io,
            },
            TransportKind::Wss,
            candidate,
            103
        ),
        observer
    );
    assert!(result.unwrap().is_some());
    process_active_delivery(
        &config,
        app.clone(),
        &mut continuity,
        &mut power,
        &mut io,
        &mut peer,
        (9, "candidate-ready", Bytes::from_static(b"later")),
    )
    .await;
    assert_eq!(*app.persisted.lock().unwrap(), vec![8, 9]);
}

#[tokio::test]
async fn freeze_timeout_requires_exact_resume_receipt_before_old_owner_reuse() {
    let mut config = config();
    config.policy.drain_timeout_ms = 40;
    let app = Arc::new(RecordingApp::new());
    let (mut io, mut old) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let mut continuity = continuity();
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let observer = async {
        prepare(&mut peer).await;
        guard_ok(&mut peer).await;
        let freeze = receive_hello(&mut old, "freeze").await;
        // No drain receipt: only the client's bounded stage deadline can cause
        // this explicit resume request. A late exact drain receipt is harmless.
        let resume = receive_hello(&mut old, "resume").await;
        assert_eq!(
            resume.metadata.get(handoff::ID_KEY),
            freeze.metadata.get(handoff::ID_KEY)
        );
        send(
            &mut old,
            PushgoWireProfile
                .encode_server_welcome(&receipt(&freeze, "drained", "old-session"))
                .unwrap(),
        )
        .await;
        send(
            &mut old,
            PushgoWireProfile
                .encode_server_welcome(&receipt(&resume, "resumed", "old-session"))
                .unwrap(),
        )
        .await;
        expect_closed(&mut peer).await;
    };
    let (result, ()) = tokio::join!(
        commit_candidate_cutover(
            &config,
            app.clone(),
            ActiveTransport {
                continuity: &mut continuity,
                power_runtime: &mut power,
                transport: &mut transport,
                io: &mut io,
            },
            TransportKind::Wss,
            candidate,
            104
        ),
        observer
    );
    assert!(result.unwrap().is_none());
    assert_eq!(transport, TransportKind::Tcp);
    assert_eq!(continuity.last_acked_seq, Some(7));
    assert_eq!(
        app.count(|event| matches!(event, ClientEvent::CutoverRollback { .. })),
        1
    );
    assert_eq!(
        app.count(|event| matches!(event, ClientEvent::CutoverCommitted { .. })),
        0
    );
    io.send_frame(&PushgoWireProfile.encode_client_ping(), 1_000)
        .await
        .unwrap();
    assert!(matches!(
        recv(&mut old, &PushgoWireProfile).await,
        DecodedClientFrame::Ping
    ));
}

#[tokio::test]
async fn server_aborted_freeze_receipt_keeps_healthy_primary_without_activation() {
    let config = config();
    let app = Arc::new(RecordingApp::new());
    let (mut io, mut old) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let mut continuity = continuity();
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let observer = async {
        prepare(&mut peer).await;
        guard_ok(&mut peer).await;
        let freeze = receive_hello(&mut old, "freeze").await;
        // Gateway can abort an expired/bounded reservation and explicitly prove
        // that this old sender resumed instead of granting candidate ownership.
        send(
            &mut old,
            PushgoWireProfile
                .encode_server_welcome(&receipt(&freeze, "resumed", "old-session"))
                .unwrap(),
        )
        .await;
        expect_closed(&mut peer).await;
    };
    let (result, ()) = tokio::join!(
        commit_candidate_cutover(
            &config,
            app.clone(),
            ActiveTransport {
                continuity: &mut continuity,
                power_runtime: &mut power,
                transport: &mut transport,
                io: &mut io,
            },
            TransportKind::Wss,
            candidate,
            105
        ),
        observer
    );
    assert!(
        matches!(result, Ok(None)),
        "a matching server abort must preserve the healthy old connection: {result:?}"
    );
    assert_eq!(transport, TransportKind::Tcp);
    assert_eq!(continuity.resume_token.as_deref(), Some("old-resume"));
    assert_eq!(continuity.last_acked_seq, Some(7));
    assert_eq!(
        app.count(|e| matches!(e, ClientEvent::CutoverCommitted { .. })),
        0
    );
    assert_eq!(
        app.count(|e| matches!(e, ClientEvent::CutoverRollback { .. })),
        1
    );
    io.send_frame(&PushgoWireProfile.encode_client_ping(), 1_000)
        .await
        .unwrap();
    assert!(matches!(
        recv(&mut old, &PushgoWireProfile).await,
        DecodedClientFrame::Ping
    ));
}

#[tokio::test]
async fn candidate_prepared_under_different_resume_epoch_never_gets_ownership() {
    let config = config();
    let app = Arc::new(RecordingApp::new());
    let (mut io, mut old) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let mut continuity = continuity();
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let observer = async {
        let prepare = receive_hello(&mut peer, "prepare").await;
        let mut wrong_epoch = receipt(&prepare, "prepared", "candidate");
        wrong_epoch.resume_token = Some("unrelated-epoch".into());
        send(
            &mut peer,
            PushgoWireProfile
                .encode_server_welcome(&wrong_epoch)
                .unwrap(),
        )
        .await;
        expect_closed(&mut peer).await;
    };
    let (result, ()) = tokio::join!(
        commit_candidate_cutover(
            &config,
            app.clone(),
            ActiveTransport {
                continuity: &mut continuity,
                power_runtime: &mut power,
                transport: &mut transport,
                io: &mut io,
            },
            TransportKind::Wss,
            candidate,
            106
        ),
        observer
    );
    assert!(matches!(result, Ok(None)));
    assert_eq!(transport, TransportKind::Tcp);
    assert_eq!(continuity.resume_token.as_deref(), Some("old-resume"));
    assert_eq!(
        app.count(|e| matches!(
            e,
            ClientEvent::CandidateReady { .. }
                | ClientEvent::CutoverCommitted { .. }
                | ClientEvent::Message { .. }
        )),
        0
    );
    io.send_frame(&PushgoWireProfile.encode_client_ping(), 1_000)
        .await
        .unwrap();
    assert!(matches!(
        recv(&mut old, &PushgoWireProfile).await,
        DecodedClientFrame::Ping
    ));
}

#[tokio::test]
async fn drain_receipt_from_different_old_session_never_crosses_ack_fence() {
    let config = config();
    let app = Arc::new(RecordingApp::new());
    let (mut io, mut old) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let mut continuity = continuity();
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let observer = async {
        prepare(&mut peer).await;
        guard_ok(&mut peer).await;
        let freeze = receive_hello(&mut old, "freeze").await;
        send(
            &mut old,
            PushgoWireProfile
                .encode_server_welcome(&receipt(&freeze, "drained", "unrelated-old-session"))
                .unwrap(),
        )
        .await;
        expect_closed(&mut peer).await;
    };
    let (result, ()) = tokio::join!(
        commit_candidate_cutover(
            &config,
            app.clone(),
            ActiveTransport {
                continuity: &mut continuity,
                power_runtime: &mut power,
                transport: &mut transport,
                io: &mut io,
            },
            TransportKind::Wss,
            candidate,
            107
        ),
        observer
    );
    assert!(matches!(result, Err(WarpLinkError::Protocol(_))));
    assert_eq!(transport, TransportKind::Tcp);
    assert_eq!(continuity.resume_token.as_deref(), Some("old-resume"));
    assert_eq!(continuity.last_acked_seq, Some(7));
    assert_eq!(
        app.count(|e| matches!(
            e,
            ClientEvent::CutoverCommitted { .. } | ClientEvent::Message { .. }
        )),
        0
    );
    assert!(
        matches!(old.recv_frame(40).await, Err(WarpLinkError::Timeout(_))),
        "an unrelated session receipt must not induce a fence or candidate activation"
    );
}
