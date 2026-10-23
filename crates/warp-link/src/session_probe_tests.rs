//! The production handshake/receive/ACK loop with an already-connected loopback
//! WebSocket. Probe candidates use the real TCP connector (no test TLS roots).
use super::*;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt, poll};
use pushgo_warp_profile::PushgoWireProfile;
use std::pin::Pin;
use tokio::{net::TcpStream, sync::mpsc};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::protocol::Role};
use warp_link_core::{DeliverMsg, WelcomeMsg, WireProfile};

struct SessionApp {
    messages: mpsc::UnboundedSender<()>,
}

impl ClientApp for SessionApp {
    fn on_hello(&self) -> HelloCtx {
        HelloCtx {
            identity: "probe-test".into(),
            supported_wire_versions: vec![2],
            supported_payload_versions: vec![1],
            ..Default::default()
        }
    }

    fn scheduler_policy(&self) -> PolicyInput {
        PolicyInput {
            disabled_transports: vec![TransportKind::Quic],
            ..Default::default()
        }
    }

    fn on_event(&self, event: ClientEvent) -> AppDecision {
        if matches!(event, ClientEvent::Message { .. }) {
            self.messages.send(()).unwrap();
        }
        AppDecision::AckOk
    }
}

type Peer = WebSocketStream<TcpStream>;
type Session<'a> = Pin<Box<dyn Future<Output = Result<(), WarpLinkError>> + Send + 'a>>;

async fn pair() -> (ClientIo, Peer) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (client, server) = tokio::join!(TcpStream::connect(address), listener.accept());
    let client = WebSocketStream::from_raw_socket(
        MaybeTlsStream::Plain(client.unwrap()),
        Role::Client,
        None,
    )
    .await;
    let peer = WebSocketStream::from_raw_socket(server.unwrap().0, Role::Server, None).await;
    (
        ClientIo::Wss {
            stream: Box::new(client),
        },
        peer,
    )
}

fn config(tcp_port: u16) -> ClientConfig {
    let mut config = super::tests::sample_client_config();
    config.host = "127.0.0.1".into();
    config.tcp_port = tcp_port;
    config.wire_profile = Arc::new(PushgoWireProfile);
    config.policy.scheduler_v2_enabled = true;
    config.policy.tcp_delay_ms = 0;
    config.policy.upgrade_probe_foreground_interval_secs = 1;
    config.policy.upgrade_probe_background_interval_secs = 1;
    config.policy.upgrade_probe_min_dwell_secs = 1;
    config.policy.upgrade_probe_timeout_ms = 10_000;
    config.policy.mobility_enabled = false;
    config
}

fn session<'a>(
    config: &'a ClientConfig,
    app: Arc<dyn ClientApp>,
    continuity: &'a mut ClientContinuityState,
    io: ClientIo,
) -> Session<'a> {
    let policy = PolicyInput {
        disabled_transports: vec![TransportKind::Quic],
        ..Default::default()
    };
    Box::pin(run_connected_client_session(
        config,
        app,
        continuity,
        policy,
        TransportPlan {
            attempts: vec![(TransportKind::Wss, 0)],
            suppressed_candidates: Vec::new(),
            winner_layer: DecisionWinnerLayer::AdaptiveScheduler,
            reason_code: "test_connected_socket",
        },
        TransportKind::Wss,
        io,
    ))
}

async fn welcome(session: &mut Session<'_>, peer: &mut Peer, with_resume: bool) {
    assert!(poll!(session.as_mut()).is_pending());
    let frame = peer.next().await.unwrap().unwrap();
    assert!(matches!(
        PushgoWireProfile
            .decode_client_frame(&frame.into_data())
            .unwrap(),
        DecodedClientFrame::Hello(_)
    ));
    let welcome = WelcomeMsg {
        session_id: "probe-session".into(),
        identity: "probe-test".into(),
        resume_token: with_resume.then(|| "probe-resume".into()),
        heartbeat_secs: 30,
        ping_interval_secs: 30,
        idle_timeout_secs: 90,
        max_backoff_secs: 60,
        auth_expires_at_unix_secs: None,
        auth_refresh_before_secs: 0,
        max_frame_bytes: TRANSPORT_MAX_FRAME_BYTES,
        negotiated_wire_version: 2,
        negotiated_payload_version: 1,
        metadata: Default::default(),
    };
    peer.send(tokio_tungstenite::tungstenite::Message::Binary(
        PushgoWireProfile.encode_server_welcome(&welcome).unwrap(),
    ))
    .await
    .unwrap();
}

async fn queue_messages(peer: &mut Peer, first: u64, count: u64) {
    for seq in first..first + count {
        let frame = PushgoWireProfile
            .encode_server_deliver(&DeliverMsg {
                seq: Some(seq),
                id: format!("delivery-{seq}"),
                payload: Bytes::from_static(b"ordinary message"),
            })
            .unwrap();
        peer.send(tokio_tungstenite::tungstenite::Message::Binary(frame))
            .await
            .unwrap();
    }
}

// Manually polling prevents automatic advancement of the session's deadline.
// Each poll still executes the real loop and concrete ClientIo, not a scheduler helper.
async fn pump(session: &mut Session<'_>) {
    for _ in 0..64 {
        assert!(poll!(session.as_mut()).is_pending());
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn buffered_delivery_stream_does_not_starve_due_probe() {
    let candidate = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = config(candidate.local_addr().unwrap().port());
    let (messages, mut received) = mpsc::unbounded_channel();
    let app = Arc::new(SessionApp { messages });
    let (io, mut peer) = pair().await;
    let mut continuity = ClientContinuityState::default();
    let mut session = session(&config, app, &mut continuity, io);
    welcome(&mut session, &mut peer, true).await;
    queue_messages(&mut peer, 1, 256).await;
    tokio::select! {
        result = session.as_mut() => panic!("primary must remain active: {result:?}"),
        message = received.recv() => assert_eq!(message, Some(())),
    }
    // The primary has ordinary frames buffered throughout the due deadline.
    tokio::time::advance(Duration::from_secs(2)).await;
    pump(&mut session).await;
    let (socket, _) = timeout(Duration::from_millis(10), candidate.accept())
        .await
        .expect("a busy healthy primary must give the due probe an opportunity")
        .unwrap();
    // One outstanding candidate only, even with more time and primary traffic.
    tokio::time::advance(Duration::from_secs(3)).await;
    pump(&mut session).await;
    assert!(
        timeout(Duration::from_millis(10), candidate.accept())
            .await
            .is_err()
    );
    drop(session);
    drop(socket);
}

#[tokio::test(start_paused = true)]
async fn idle_probe_is_cancelled_with_owned_primary_and_candidate() {
    let candidate = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = config(candidate.local_addr().unwrap().port());
    let (messages, _received) = mpsc::unbounded_channel();
    let (io, mut peer) = pair().await;
    let mut continuity = ClientContinuityState::default();
    let mut session = session(
        &config,
        Arc::new(SessionApp { messages }),
        &mut continuity,
        io,
    );
    welcome(&mut session, &mut peer, true).await;
    pump(&mut session).await;
    tokio::time::advance(Duration::from_secs(2)).await;
    pump(&mut session).await;
    let (mut socket, _) = timeout(Duration::from_millis(10), candidate.accept())
        .await
        .unwrap()
        .unwrap();
    drop(session); // Same future-drop ownership used by client_run_with_shutdown.
    use tokio::io::AsyncReadExt;
    timeout(Duration::from_secs(1), async {
        let mut buf = [0; 4096];
        loop {
            match socket.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await
    .expect("cancelled candidate must close");
    timeout(Duration::from_secs(1), async {
        while let Some(Ok(_)) = peer.next().await {}
    })
    .await
    .expect("cancelled primary closes after any already-buffered HELLO update");
}

#[tokio::test(start_paused = true)]
async fn missing_resume_schedules_skip_without_attempts_or_spin() {
    let candidate = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = config(candidate.local_addr().unwrap().port());
    let (messages, mut received) = mpsc::unbounded_channel();
    let (io, mut peer) = pair().await;
    let mut continuity = ClientContinuityState::default();
    let mut session = session(
        &config,
        Arc::new(SessionApp { messages }),
        &mut continuity,
        io,
    );
    welcome(&mut session, &mut peer, false).await;
    queue_messages(&mut peer, 1, 4).await;
    tokio::select! {
        result = session.as_mut() => panic!("primary must remain active: {result:?}"),
        message = received.recv() => assert_eq!(message, Some(())),
    }
    tokio::time::advance(Duration::from_secs(2)).await;
    pump(&mut session).await;
    assert!(
        timeout(Duration::from_millis(10), candidate.accept())
            .await
            .is_err()
    );
    drop(session);
    assert!(continuity.resume_token.is_none());
    assert!(continuity.last_acked_seq.is_some());
}

#[tokio::test(start_paused = true)]
async fn rejected_probe_releases_candidate_and_backs_off_while_primary_progresses() {
    let candidate = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = config(candidate.local_addr().unwrap().port());
    let (messages, mut received) = mpsc::unbounded_channel();
    let (io, mut peer) = pair().await;
    let mut continuity = ClientContinuityState::default();
    let mut session = session(
        &config,
        Arc::new(SessionApp { messages }),
        &mut continuity,
        io,
    );
    welcome(&mut session, &mut peer, true).await;
    queue_messages(&mut peer, 1, 256).await;
    tokio::select! {
        result = session.as_mut() => panic!("primary must remain active: {result:?}"),
        message = received.recv() => assert_eq!(message, Some(())),
    }
    tokio::time::advance(Duration::from_secs(2)).await;
    pump(&mut session).await;
    let (socket, _) = timeout(Duration::from_millis(10), candidate.accept())
        .await
        .unwrap()
        .unwrap();
    while received.try_recv().is_ok() {}
    drop(socket); // Actual local candidate rejects TLS, not a stubbed result.
    tokio::select! {
        result = session.as_mut() => panic!("probe rejection must retain primary: {result:?}"),
        message = received.recv() => assert_eq!(message, Some(())),
    }
    // Failure uses the existing doubled interval (2s plus at most .25s jitter).
    tokio::time::advance(Duration::from_secs(1)).await;
    pump(&mut session).await;
    assert!(
        timeout(Duration::from_millis(10), candidate.accept())
            .await
            .is_err()
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    pump(&mut session).await;
    let (socket, _) = timeout(Duration::from_millis(10), candidate.accept())
        .await
        .expect("retry becomes eligible after bounded backoff, even under traffic")
        .unwrap();
    drop(session);
    drop(socket);
}

#[tokio::test(start_paused = true)]
async fn slow_failed_probe_backs_off_from_completion_instead_of_catching_up() {
    let candidate = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = config(candidate.local_addr().unwrap().port());
    let (messages, mut received) = mpsc::unbounded_channel();
    let (io, mut peer) = pair().await;
    let mut continuity = ClientContinuityState::default();
    let mut session = session(
        &config,
        Arc::new(SessionApp { messages }),
        &mut continuity,
        io,
    );
    welcome(&mut session, &mut peer, true).await;
    queue_messages(&mut peer, 1, 256).await;
    tokio::select! {
        result = session.as_mut() => panic!("primary must remain active: {result:?}"),
        message = received.recv() => assert_eq!(message, Some(())),
    }
    tokio::time::advance(Duration::from_secs(2)).await;
    pump(&mut session).await;
    let (socket, _) = timeout(Duration::from_millis(10), candidate.accept())
        .await
        .unwrap()
        .unwrap();
    while received.try_recv().is_ok() {}
    // Keep TLS pending longer than the next failure-backoff interval.
    tokio::time::advance(Duration::from_secs(11)).await;
    pump(&mut session).await;
    assert!(
        timeout(Duration::from_millis(10), candidate.accept())
            .await
            .is_err(),
        "timed-out probe must not immediately start a catch-up probe"
    );
    tokio::select! {
        result = session.as_mut() => panic!("timed-out probe must retain primary: {result:?}"),
        message = received.recv() => assert_eq!(message, Some(())),
    }
    drop(session);
    drop(socket);
}

#[tokio::test(start_paused = true)]
async fn idle_retry_deadline_is_measured_after_slow_probe_completion() {
    let candidate = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = config(candidate.local_addr().unwrap().port());
    let (messages, _received) = mpsc::unbounded_channel();
    let (io, mut peer) = pair().await;
    let mut continuity = ClientContinuityState::default();
    let mut session = session(
        &config,
        Arc::new(SessionApp { messages }),
        &mut continuity,
        io,
    );
    welcome(&mut session, &mut peer, true).await;
    pump(&mut session).await;
    tokio::time::advance(Duration::from_secs(2)).await;
    pump(&mut session).await;
    let (socket, _) = timeout(Duration::from_millis(10), candidate.accept())
        .await
        .unwrap()
        .unwrap();
    tokio::time::advance(Duration::from_secs(11)).await;
    pump(&mut session).await;
    tokio::time::advance(Duration::from_secs(3)).await;
    pump(&mut session).await;
    let (retry, _) = timeout(Duration::from_millis(10), candidate.accept())
        .await
        .expect("idle recv must wake at the completion-based next probe deadline")
        .unwrap();
    drop(session);
    drop(socket);
    drop(retry);
}
