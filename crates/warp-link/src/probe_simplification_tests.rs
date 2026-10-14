use super::{first_successful_probe, probe_alternate_transport, probe_higher_priority_transport};
use futures_util::{SinkExt, StreamExt};
use std::{future::pending, sync::Arc, time::Duration};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    task::{JoinHandle, JoinSet},
    time::{Instant, timeout},
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::{Message, protocol::Role},
};
use warp_link_core::{
    ClientConfig, PolicyInput, TransportKind, TransportPreference, WarpLinkError,
};
use warp_link_transport::ClientIo;

const TEST_WAIT: Duration = Duration::from_secs(3);

// Real sockets and ClientIo; this exercises collector ownership, not production TLS trust.
async fn websocket_pair() -> (ClientIo, WebSocketStream<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (client, server) = tokio::join!(TcpStream::connect(address), listener.accept());
    let client = WebSocketStream::from_raw_socket(
        MaybeTlsStream::Plain(client.unwrap()),
        Role::Client,
        None,
    )
    .await;
    let server = WebSocketStream::from_raw_socket(server.unwrap().0, Role::Server, None).await;
    (
        ClientIo::Wss {
            stream: Box::new(client),
        },
        server,
    )
}

async fn assert_websocket_closed(peer: &mut WebSocketStream<TcpStream>) {
    let result = timeout(TEST_WAIT, peer.next())
        .await
        .expect("loser socket must close");
    assert!(result.is_none() || matches!(result, Some(Err(_)) | Some(Ok(Message::Close(_)))));
}

#[tokio::test]
async fn collector_returns_first_success_and_closes_pending_loser() {
    let (winner_io, mut winner_peer) = websocket_pair().await;
    let (loser_io, mut loser_peer) = websocket_pair().await;
    let (started_tx, started_rx) = oneshot::channel();
    let mut attempts = JoinSet::new();
    attempts.spawn(async move {
        let _owned_loser = loser_io;
        started_tx.send(()).unwrap();
        pending::<(TransportKind, Result<ClientIo, WarpLinkError>)>().await
    });
    attempts.spawn(async move {
        started_rx.await.unwrap();
        (TransportKind::Wss, Ok(winner_io))
    });
    let (kind, mut winner) = first_successful_probe(attempts, 1_000).await.unwrap();
    assert_eq!(kind, TransportKind::Wss);
    assert_websocket_closed(&mut loser_peer).await;
    winner.send_frame(b"winner survives", 1_000).await.unwrap();
    let frame = timeout(TEST_WAIT, winner_peer.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(frame.into_data().as_ref(), b"winner survives");
    winner_peer
        .send(Message::Binary(b"reply".to_vec().into()))
        .await
        .unwrap();
    assert_eq!(winner.recv_frame(1_000).await.unwrap(), b"reply");
}

#[tokio::test]
async fn collector_waits_past_failed_attempt_for_a_success() {
    let (io, mut peer) = websocket_pair().await;
    let (failed_tx, failed_rx) = oneshot::channel();
    let mut attempts = JoinSet::new();
    attempts.spawn(async move {
        failed_tx.send(()).unwrap();
        (
            TransportKind::Tcp,
            Err(WarpLinkError::Transport("rejected".into())),
        )
    });
    attempts.spawn(async move {
        failed_rx.await.unwrap();
        (TransportKind::Wss, Ok(io))
    });
    let (_, mut winner) = first_successful_probe(attempts, 1_000).await.unwrap();
    winner.send_frame(b"after failure", 1_000).await.unwrap();
    let frame = timeout(TEST_WAIT, peer.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(frame.into_data().as_ref(), b"after failure");
}

#[tokio::test]
async fn collector_returns_none_for_empty_and_all_failed_attempts() {
    assert!(
        first_successful_probe(JoinSet::new(), 1_000)
            .await
            .is_none()
    );
    let mut attempts = JoinSet::new();
    for transport in [TransportKind::Quic, TransportKind::Tcp, TransportKind::Wss] {
        attempts.spawn(async move {
            (
                transport,
                Err(WarpLinkError::Transport("local refusal".into())),
            )
        });
    }
    assert!(first_successful_probe(attempts, 1_000).await.is_none());
}

#[tokio::test]
async fn collector_deadline_closes_a_pending_candidate() {
    let (io, mut peer) = websocket_pair().await;
    let (started_tx, started_rx) = oneshot::channel();
    let mut attempts = JoinSet::new();
    attempts.spawn(async move {
        let _owned_io = io;
        started_tx.send(()).unwrap();
        pending::<(TransportKind, Result<ClientIo, WarpLinkError>)>().await
    });
    started_rx.await.unwrap();
    assert!(first_successful_probe(attempts, 50).await.is_none());
    assert_websocket_closed(&mut peer).await;
}

#[tokio::test]
async fn dropping_collector_cancels_owned_candidate() {
    let (io, mut peer) = websocket_pair().await;
    let (started_tx, started_rx) = oneshot::channel();
    let mut attempts = JoinSet::new();
    attempts.spawn(async move {
        let _owned_io = io;
        started_tx.send(()).unwrap();
        pending::<(TransportKind, Result<ClientIo, WarpLinkError>)>().await
    });
    let collector = tokio::spawn(first_successful_probe(attempts, 10_000));
    started_rx.await.unwrap();
    collector.abort();
    assert!(matches!(collector.await, Err(error) if error.is_cancelled()));
    assert_websocket_closed(&mut peer).await;
}

struct TcpPeer {
    port: u16,
    accepted: mpsc::UnboundedReceiver<(TcpStream, Instant)>,
    task: JoinHandle<()>,
}

impl TcpPeer {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, accepted) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                if tx.send((socket, Instant::now())).is_err() {
                    break;
                }
            }
        });
        Self {
            port,
            accepted,
            task,
        }
    }

    async fn accept(&mut self) -> (TcpStream, Instant) {
        timeout(TEST_WAIT, self.accepted.recv())
            .await
            .unwrap()
            .unwrap()
    }

    fn assert_no_attempt(&mut self) {
        assert!(matches!(
            self.accepted.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
}

impl Drop for TcpPeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn local_config(tcp_port: u16, wss_port: u16) -> ClientConfig {
    ClientConfig {
        host: "127.0.0.1".into(),
        quic_port: tcp_port,
        tcp_port,
        wss_port,
        wss_path: "/private/ws".into(),
        quic_alpn: "pushgo-quic".into(),
        tcp_alpn: "pushgo-tcp".into(),
        wss_subprotocol: None,
        tls_server_name: Some("localhost".into()),
        bearer_token: None,
        cert_pin_sha256: None,
        quic_cert_pin_sha256: None,
        tcp_cert_pin_sha256: None,
        wss_cert_pin_sha256: None,
        policy: warp_link_core::ClientPolicy {
            connect_timeout_ms: 5_000,
            upgrade_probe_timeout_ms: 150,
            tcp_delay_ms: 0,
            wss_delay_ms: 0,
            ..Default::default()
        },
        wire_profile: Arc::new(pushgo_warp_profile::PushgoWireProfile::new()),
    }
}

fn required(transport: TransportKind) -> PolicyInput {
    PolicyInput {
        required_transport: Some(TransportPreference {
            transport,
            expires_at_unix_ms: None,
        }),
        ..Default::default()
    }
}

async fn assert_tcp_closed(mut peer: TcpStream) {
    timeout(TEST_WAIT, async move {
        let mut data = [0; 4_096];
        loop {
            match peer.read(&mut data).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await
    .expect("cancelled TLS socket must close");
}

#[cfg(feature = "tcp")]
#[tokio::test]
async fn both_wrappers_execute_required_lower_priority_and_timeout_cleanup() {
    for higher in [true, false] {
        let mut tcp = TcpPeer::new().await;
        let mut wss = TcpPeer::new().await;
        let config = local_config(tcp.port, wss.port);
        let policy = required(TransportKind::Tcp);
        let task = tokio::spawn(async move {
            if higher {
                probe_higher_priority_transport(&config, TransportKind::Quic, &policy).await
            } else {
                probe_alternate_transport(&config, TransportKind::Quic, &policy).await
            }
        });
        let (socket, _) = tcp.accept().await;
        assert!(task.await.unwrap().is_none());
        assert_tcp_closed(socket).await;
        tcp.assert_no_attempt();
        wss.assert_no_attempt();
    }
}

#[cfg(feature = "tcp")]
#[tokio::test]
async fn both_wrappers_return_none_after_actual_local_tls_rejection() {
    for higher in [true, false] {
        let mut tcp = TcpPeer::new().await;
        let mut wss = TcpPeer::new().await;
        let config = local_config(tcp.port, wss.port);
        let policy = required(TransportKind::Tcp);
        let task = tokio::spawn(async move {
            if higher {
                probe_higher_priority_transport(&config, TransportKind::Quic, &policy).await
            } else {
                probe_alternate_transport(&config, TransportKind::Quic, &policy).await
            }
        });
        let (socket, _) = tcp.accept().await;
        drop(socket); // Accepted real connection, rejected before TLS completion.
        assert!(timeout(TEST_WAIT, task).await.unwrap().unwrap().is_none());
        tcp.assert_no_attempt();
        wss.assert_no_attempt();
    }
}

#[cfg(feature = "tcp")]
#[tokio::test]
async fn both_wrappers_leave_required_current_and_disabled_candidates_empty() {
    let mut tcp = TcpPeer::new().await;
    let mut wss = TcpPeer::new().await;
    let config = local_config(tcp.port, wss.port);
    for higher in [true, false] {
        let current = required(TransportKind::Tcp);
        let mut disabled = required(TransportKind::Tcp);
        disabled.disabled_transports.push(TransportKind::Tcp);
        for (policy, active) in [
            (current, TransportKind::Tcp),
            (disabled, TransportKind::Quic),
        ] {
            let result = if higher {
                probe_higher_priority_transport(&config, active, &policy).await
            } else {
                probe_alternate_transport(&config, active, &policy).await
            };
            assert!(result.is_none());
        }
    }
    tcp.assert_no_attempt();
    wss.assert_no_attempt();
}

#[cfg(all(feature = "tcp", feature = "wss"))]
#[tokio::test]
async fn wrapper_ranges_keep_higher_priority_exclusion_and_alternate_fallback() {
    let mut tcp = TcpPeer::new().await;
    let mut wss = TcpPeer::new().await;
    let config = local_config(tcp.port, wss.port);
    let policy = PolicyInput {
        disabled_transports: vec![TransportKind::Quic],
        ..Default::default()
    };
    assert!(
        probe_higher_priority_transport(&config, TransportKind::Tcp, &policy)
            .await
            .is_none()
    );
    tcp.assert_no_attempt();
    wss.assert_no_attempt();
    let task = tokio::spawn(async move {
        probe_alternate_transport(&config, TransportKind::Tcp, &policy).await
    });
    let (socket, _) = wss.accept().await;
    assert!(task.await.unwrap().is_none());
    assert_tcp_closed(socket).await;
    tcp.assert_no_attempt();
    wss.assert_no_attempt();
}

#[cfg(all(feature = "tcp", feature = "wss"))]
#[tokio::test]
async fn higher_priority_probe_keeps_only_enabled_upgrade_despite_expired_required() {
    let mut tcp = TcpPeer::new().await;
    let mut wss = TcpPeer::new().await;
    let config = local_config(tcp.port, wss.port);
    let policy = PolicyInput {
        disabled_transports: vec![TransportKind::Quic],
        required_transport: Some(TransportPreference {
            transport: TransportKind::Wss,
            expires_at_unix_ms: Some(1),
        }),
        preferred_transport: Some(TransportPreference {
            transport: TransportKind::Wss,
            expires_at_unix_ms: None,
        }),
        ..Default::default()
    };
    let task = tokio::spawn(async move {
        probe_higher_priority_transport(&config, TransportKind::Wss, &policy).await
    });
    let (socket, _) = tcp.accept().await;
    assert!(task.await.unwrap().is_none());
    assert_tcp_closed(socket).await;
    tcp.assert_no_attempt();
    wss.assert_no_attempt();
}

#[cfg(all(feature = "tcp", feature = "wss"))]
#[tokio::test]
async fn alternate_preference_reorders_and_preserves_transport_delay() {
    let mut tcp = TcpPeer::new().await;
    let mut wss = TcpPeer::new().await;
    let mut config = local_config(tcp.port, wss.port);
    config.policy.tcp_delay_ms = 250;
    config.policy.wss_delay_ms = 2_000; // First candidate must still start immediately.
    config.policy.upgrade_probe_timeout_ms = 800;
    let policy = PolicyInput {
        preferred_transport: Some(TransportPreference {
            transport: TransportKind::Wss,
            expires_at_unix_ms: None,
        }),
        ..Default::default()
    };
    let task = tokio::spawn(async move {
        probe_alternate_transport(&config, TransportKind::Quic, &policy).await
    });
    let (wss_socket, wss_at) = wss.accept().await;
    let (tcp_socket, tcp_at) = tcp.accept().await;
    assert!(tcp_at.saturating_duration_since(wss_at) >= Duration::from_millis(100));
    assert!(task.await.unwrap().is_none());
    assert_tcp_closed(tcp_socket).await;
    assert_tcp_closed(wss_socket).await;
}

#[cfg(feature = "tcp")]
#[tokio::test]
async fn wrapper_cancellation_closes_connection_and_next_call_uses_new_snapshot() {
    let mut tcp = TcpPeer::new().await;
    let mut wss = TcpPeer::new().await;
    let mut config = local_config(tcp.port, wss.port);
    config.policy.upgrade_probe_timeout_ms = 10_000;
    let policy = required(TransportKind::Tcp);
    let probe_config = config.clone();
    let probe_policy = policy.clone();
    let task = tokio::spawn(async move {
        probe_higher_priority_transport(&probe_config, TransportKind::Quic, &probe_policy).await
    });
    let (socket, _) = tcp.accept().await;
    let mut next_policy = policy;
    next_policy.control_epoch = next_policy.control_epoch.saturating_add(1);
    next_policy.disabled_transports.push(TransportKind::Tcp);
    assert!(
        !task.is_finished(),
        "snapshot replacement must not cancel the pending probe"
    );
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    assert_tcp_closed(socket).await;
    assert!(
        probe_higher_priority_transport(&config, TransportKind::Quic, &next_policy)
            .await
            .is_none()
    );
    tcp.assert_no_attempt();
    wss.assert_no_attempt();
}
