//! Real loopback WebSocket IO around the private cutover seam; these do not run
//! the outer client reconnect loop or the four scheduler decision branches.
use super::*;
use bytes::Bytes;
use pushgo_warp_profile::PushgoWireProfile;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_tungstenite::{MaybeTlsStream, accept_async, client_async};
use warp_link_core::{ClientPowerHint, DeliverMsg, WelcomeMsg, WireProfile};

struct RecordingApp {
    events: Mutex<Vec<ClientEvent>>,
    hello: Mutex<HelloCtx>,
    power: Mutex<Option<ClientPowerHint>>,
    policy: Mutex<PolicyInput>,
    hello_calls: AtomicUsize,
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
        self.events.lock().unwrap().push(event);
        AppDecision::AckOk
    }

    fn scheduler_policy(&self) -> PolicyInput {
        self.policy.lock().unwrap().clone()
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
    }
}

#[tokio::test]
async fn successful_cutover_refreshes_hello_and_hands_off_ack_once() {
    assert_successful_cutover(Bytes::from_static(b"payload")).await;
}

#[tokio::test]
async fn successful_cutover_hands_off_exact_128k_guard_delivery() {
    // This envelope has a two-byte header, one-byte seq, eight-byte ID field,
    // and three-byte payload length. It is a codec payload, not business JSON.
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
    let (mut active_io, mut old_peer) = loopback_pair().await;
    let (candidate_io, mut new_peer) = loopback_pair().await;
    let mut continuity = continuity();
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let (hello_seen_tx, hello_seen_rx) = oneshot::channel();
    let (welcome_tx, welcome_rx) = oneshot::channel();
    let profile = Arc::clone(&config.wire_profile);
    let expected_payload = payload.clone();
    let peer = tokio::spawn(async move {
        let DecodedClientFrame::Hello(hello) = recv(&mut new_peer, profile.as_ref()).await else {
            panic!("candidate must send Hello");
        };
        assert_eq!(hello.resume_token.as_deref(), Some("old-resume"));
        assert_eq!(hello.last_acked_seq, Some(7));
        hello_seen_tx.send(()).unwrap();
        welcome_rx.await.unwrap();
        send(
            &mut new_peer,
            profile.encode_server_welcome(&welcome()).unwrap(),
        )
        .await;
        assert!(matches!(
            recv(&mut new_peer, profile.as_ref()).await,
            DecodedClientFrame::Ping
        ));
        send(
            &mut new_peer,
            profile
                .encode_server_deliver(&DeliverMsg {
                    seq: Some(8),
                    id: "handoff".into(),
                    payload,
                })
                .unwrap(),
        )
        .await;
        let DecodedClientFrame::Ack(ack) = recv(&mut new_peer, profile.as_ref()).await else {
            panic!("guard delivery must be ACKed on new connection");
        };
        assert_eq!(ack.seq, Some(8));
        assert_eq!(ack.id, "handoff");
        assert_eq!(ack.status, AckStatus::Ok);
        new_peer
    });
    let previous_policy = app.scheduler_policy();
    let controls = async {
        hello_seen_rx.await.unwrap();
        assert_eq!(app.hello_calls.load(Ordering::SeqCst), 1);
        {
            let mut policy = app.policy.lock().unwrap();
            policy.control_epoch = 1;
            policy.reconnect_epoch = 1;
        }
        // A bounded read sees an idle live socket, not closure, while Welcome is held.
        assert!(matches!(
            old_peer.recv_frame(20).await,
            Err(WarpLinkError::Timeout(_))
        ));
        send(&mut old_peer, config.wire_profile.encode_server_pong()).await;
        app.hello.lock().unwrap().auth_token = Some("refreshed-auth".into());
        *app.power.lock().unwrap() = Some(ClientPowerHint {
            preferred_tier: Some(ClientPowerTier::High),
            app_state: ClientAppStateHint::Background,
        });
        welcome_tx.send(()).unwrap();
    };
    let cutover = commit_candidate_cutover(
        &config,
        app.clone(),
        ActiveTransport {
            continuity: &mut continuity,
            power_runtime: &mut power,
            transport: &mut transport,
            io: &mut active_io,
        },
        TransportKind::Wss,
        candidate_io,
        41,
    );
    let (result, ()) = tokio::join!(cutover, controls);
    let returned = result.unwrap().unwrap();
    assert_eq!(transport, TransportKind::Wss);
    assert_eq!(app.hello_calls.load(Ordering::SeqCst), 1);
    assert_eq!(app.scheduler_policy().control_epoch, 1);
    assert!(matches!(
        evaluate_session_control_action(
            &previous_policy,
            &app.scheduler_policy(),
            transport,
            &continuity
        ),
        SessionControlAction::Rebuild {
            reason_code: "force_reconnect",
            ..
        }
    ));
    assert_eq!(continuity.last_acked_seq, Some(8));
    // Welcome token changes only in the shared successful post-processing.
    assert_eq!(continuity.resume_token.as_deref(), Some("old-resume"));
    let mut new_peer = peer.await.unwrap();
    // The old peer must see closure and no old-connection ACK.
    expect_closed(&mut old_peer).await;
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
            io: &mut active_io,
        },
        &mut mobility,
        &returned,
    );
    assert_eq!(app.hello_calls.load(Ordering::SeqCst), 2);
    assert_eq!(maintenance.idle_timeout_ms, 5_000);
    assert_eq!(maintenance.idle_timeout_streak, 0);
    assert!(maintenance.last_idle_ping_at >= before);
    let hello = &maintenance.inband_hello_snapshot;
    assert_eq!(hello.resume_token.as_deref(), Some("new-resume"));
    assert_eq!(hello.last_acked_seq, Some(8));
    assert_eq!(hello.auth_token.as_deref(), Some("refreshed-auth"));
    assert_eq!(hello.perf_tier.as_deref(), Some("high"));
    assert_eq!(hello.app_state.as_deref(), Some("background"));
    let probes = &maintenance.upgrade_probe_runtime;
    assert_eq!(probes.transport, TransportKind::Wss);
    assert_eq!(probes.probe_failure_streak, 0);
    assert!(probes.connected_at >= before);
    let after = Instant::now();
    let base = Duration::from_secs(u64::from(
        config.policy.upgrade_probe_background_interval_secs,
    ));
    let next = probes.next_probe_at.unwrap();
    assert!(next >= before + base);
    assert!(next <= after + base + base / 4);
    maybe_send_inband_hello_update(
        &config,
        app.as_ref(),
        &mut active_io,
        &mut maintenance.inband_hello_snapshot,
        &mut power,
        &continuity,
    )
    .await
    .unwrap();
    assert_eq!(app.hello_calls.load(Ordering::SeqCst), 3);
    active_io
        .send_frame(&config.wire_profile.encode_client_ping(), 1_000)
        .await
        .unwrap();
    assert!(matches!(
        recv(&mut new_peer, config.wire_profile.as_ref()).await,
        DecodedClientFrame::Ping
    ));
    assert_eq!(
        app.count(|e| matches!(
            e,
            ClientEvent::CandidateStarted {
                decision_id: 41,
                ..
            }
        )),
        1
    );
    assert_eq!(
        app.count(|e| matches!(
            e,
            ClientEvent::CandidateReady {
                decision_id: 41,
                ..
            }
        )),
        1
    );
    assert_eq!(
        app.count(|e| matches!(
            e,
            ClientEvent::CutoverCommitted {
                decision_id: 41,
                ..
            }
        )),
        1
    );
    assert_eq!(app.count(|e| matches!(e, ClientEvent::Connected { .. })), 1);
    assert_eq!(app.count(|e| matches!(e, ClientEvent::Welcome { .. })), 1);
    assert_eq!(app.count(|e| matches!(e, ClientEvent::Message { .. })), 1);
    assert_eq!(
        app.count(|e| matches!(
            e,
            ClientEvent::Message { msg, .. }
                if msg.seq == Some(8) && msg.id == "handoff" && msg.payload == expected_payload
        )),
        1
    );
    assert_eq!(
        app.count(|e| matches!(e, ClientEvent::CutoverRollback { .. })),
        0
    );
    let states: Vec<_> = app
        .events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|event| {
            if let ClientEvent::SchedulerStateChanged { state, .. } = event {
                Some(*state)
            } else {
                None
            }
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
    let (mut io, mut old_peer) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let mut continuity = continuity();
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let responder = async {
        assert!(matches!(
            recv(&mut peer, config.wire_profile.as_ref()).await,
            DecodedClientFrame::Hello(_)
        ));
        send(
            &mut peer,
            config
                .wire_profile
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
        responder
    );
    assert!(result.unwrap().is_none());
    assert_eq!(transport, TransportKind::Tcp);
    assert_eq!(continuity.resume_token.as_deref(), Some("old-resume"));
    assert_eq!(continuity.last_acked_seq, Some(7));
    assert_eq!(app.hello_calls.load(Ordering::SeqCst), 1);
    expect_closed(&mut peer).await;
    io.send_frame(&config.wire_profile.encode_client_ping(), 1_000)
        .await
        .unwrap();
    assert!(matches!(
        recv(&mut old_peer, config.wire_profile.as_ref()).await,
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
    let (mut io, mut old_peer) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let mut continuity = continuity();
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let responder = async {
        assert!(matches!(
            recv(&mut peer, config.wire_profile.as_ref()).await,
            DecodedClientFrame::Hello(_)
        ));
        send(
            &mut peer,
            config
                .wire_profile
                .encode_server_welcome(&welcome())
                .unwrap(),
        )
        .await;
        assert!(matches!(
            recv(&mut peer, config.wire_profile.as_ref()).await,
            DecodedClientFrame::Ping
        ));
        send(
            &mut peer,
            config
                .wire_profile
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
        responder
    );
    assert!(result.unwrap().is_none());
    assert_eq!(transport, TransportKind::Tcp);
    assert_eq!(continuity.resume_token.as_deref(), Some("old-resume"));
    assert_eq!(continuity.last_acked_seq, Some(7));
    assert_eq!(app.hello_calls.load(Ordering::SeqCst), 1);
    expect_closed(&mut peer).await;
    io.send_frame(&config.wire_profile.encode_client_ping(), 1_000)
        .await
        .unwrap();
    assert!(matches!(
        recv(&mut old_peer, config.wire_profile.as_ref()).await,
        DecodedClientFrame::Ping
    ));
    assert_eq!(
        app.count(|e| matches!(e, ClientEvent::CandidateStarted { .. })),
        1
    );
    assert_eq!(
        app.count(|e| matches!(e, ClientEvent::CandidateReady { .. })),
        1
    );
    assert_eq!(
        app.count(|e| matches!(e, ClientEvent::CutoverCommitted { .. })),
        1
    );
    assert_eq!(
        app.count(|e| matches!(
            e,
            ClientEvent::CutoverRollback {
                decision_id: 43,
                ..
            }
        )),
        1
    );
}

#[tokio::test]
async fn cancellation_before_commit_closes_both_owned_connections() {
    let config = config();
    let app = Arc::new(RecordingApp::new());
    let (mut io, mut old_peer) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let owned_app = app.clone();
    let task = tokio::spawn(async move {
        let mut continuity = continuity();
        let mut power = ClientPowerRuntime::new(Instant::now());
        let mut transport = TransportKind::Tcp;
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {},
            result = commit_candidate_cutover(&config, owned_app,
                ActiveTransport { continuity: &mut continuity, power_runtime: &mut power,
                    transport: &mut transport, io: &mut io }, TransportKind::Wss, candidate, 44) => {
                panic!("candidate has no Welcome and cannot finish: {result:?}");
            }
        }
    });
    assert!(matches!(
        recv(&mut peer, &PushgoWireProfile).await,
        DecodedClientFrame::Hello(_)
    ));
    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    expect_closed(&mut peer).await;
    expect_closed(&mut old_peer).await;
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
                | ClientEvent::Message { .. }
        )),
        0
    );
}

#[tokio::test]
async fn guard_timeout_rolls_back_to_usable_old_primary() {
    let mut config = config();
    config.policy.cutover_guard_ms = 40;
    let app = Arc::new(RecordingApp::new());
    let (mut io, mut old_peer) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let mut continuity = continuity();
    let mut power = ClientPowerRuntime::new(Instant::now());
    let mut transport = TransportKind::Tcp;
    let responder = async {
        assert!(matches!(
            recv(&mut peer, config.wire_profile.as_ref()).await,
            DecodedClientFrame::Hello(_)
        ));
        send(
            &mut peer,
            config
                .wire_profile
                .encode_server_welcome(&welcome())
                .unwrap(),
        )
        .await;
        assert!(matches!(
            recv(&mut peer, config.wire_profile.as_ref()).await,
            DecodedClientFrame::Ping
        ));
        // Keep the peer alive without a guard response. EOF proves rollback dropped it.
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
        responder
    );
    assert!(result.unwrap().is_none());
    assert_eq!(transport, TransportKind::Tcp);
    assert_eq!(continuity.resume_token.as_deref(), Some("old-resume"));
    assert_eq!(continuity.last_acked_seq, Some(7));
    io.send_frame(&config.wire_profile.encode_client_ping(), 1_000)
        .await
        .unwrap();
    assert!(matches!(
        recv(&mut old_peer, config.wire_profile.as_ref()).await,
        DecodedClientFrame::Ping
    ));
    assert_eq!(app.count(|e| matches!(e, ClientEvent::CutoverRollback { decision_id: 45, reason, .. } if reason.contains("timeout"))), 1);
    assert_eq!(
        app.count(|e| matches!(e, ClientEvent::CandidateStarted { .. })),
        1
    );
    assert_eq!(
        app.count(|e| matches!(e, ClientEvent::CandidateReady { .. })),
        1
    );
    assert_eq!(
        app.count(|e| matches!(e, ClientEvent::CutoverCommitted { .. })),
        1
    );
    assert_eq!(app.hello_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancellation_during_guard_closes_old_and_new_owned_connections() {
    let mut config = config();
    config.policy.cutover_guard_ms = 5_000;
    let app = Arc::new(RecordingApp::new());
    let (mut io, mut old_peer) = loopback_pair().await;
    let (candidate, mut peer) = loopback_pair().await;
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let owned_app = app.clone();
    let profile = Arc::clone(&config.wire_profile);
    let task = tokio::spawn(async move {
        let mut continuity = continuity();
        let mut power = ClientPowerRuntime::new(Instant::now());
        let mut transport = TransportKind::Tcp;
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {},
            result = commit_candidate_cutover(&config, owned_app,
                ActiveTransport { continuity: &mut continuity, power_runtime: &mut power,
                    transport: &mut transport, io: &mut io }, TransportKind::Wss, candidate, 46) => {
                panic!("candidate has no guard response and cannot finish: {result:?}");
            }
        }
    });
    assert!(matches!(
        recv(&mut peer, profile.as_ref()).await,
        DecodedClientFrame::Hello(_)
    ));
    send(
        &mut peer,
        profile.encode_server_welcome(&welcome()).unwrap(),
    )
    .await;
    assert!(matches!(
        recv(&mut peer, profile.as_ref()).await,
        DecodedClientFrame::Ping
    ));
    shutdown_tx.send(true).unwrap();
    timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    expect_closed(&mut peer).await;
    expect_closed(&mut old_peer).await;
    assert_eq!(
        app.count(|e| matches!(e, ClientEvent::CandidateStarted { .. })),
        1
    );
    assert_eq!(
        app.count(|e| matches!(e, ClientEvent::CandidateReady { .. })),
        1
    );
    assert_eq!(
        app.count(|e| matches!(e, ClientEvent::CutoverCommitted { .. })),
        1
    );
    assert_eq!(
        app.count(|e| matches!(
            e,
            ClientEvent::CutoverRollback { .. } | ClientEvent::Message { .. }
        )),
        0
    );
    assert_eq!(app.hello_calls.load(Ordering::SeqCst), 1);
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
    assert_eq!(maintenance.inband_hello_snapshot.last_acked_seq, Some(7));
    assert_eq!(app.hello_calls.load(Ordering::SeqCst), 1);
    assert!(app.events.lock().unwrap().is_empty());
}
