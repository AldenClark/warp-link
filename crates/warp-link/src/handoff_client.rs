//! One borrowed application owner throughout a negotiated transport handoff.
use super::*;
use warp_link_core::{WelcomeMsg, handoff};

// An ownership-transfer budget, not a message retention period. The server
// independently expires the corresponding ephemeral reservation after 15s.
const MAX_HANDOFF_STAGE_MS: u64 = 15_000;

struct Primary<'a, 'p> {
    active: ActiveTransport<'a>,
    progress: PrimaryProgress<'p>,
    epoch: u64,
}

impl Primary<'_, '_> {
    async fn handle(
        &mut self,
        config: &ClientConfig,
        app: Arc<dyn ClientApp>,
        frame: Vec<u8>,
    ) -> Result<(), WarpLinkError> {
        handle_primary_frame(
            config,
            app,
            *self.active.transport,
            frame,
            PrimaryFrameState {
                continuity: self.active.continuity,
                power_runtime: self.active.power_runtime,
                io: self.active.io,
                pending_ping_sent_at: self.progress.pending_ping_sent_at,
                pending_ping_source: self.progress.pending_ping_source,
                health_tracker: self.progress.health_tracker,
                mobility_tracker: self.progress.mobility_tracker,
            },
        )
        .await
    }

    fn control_changed(&self, config: &ClientConfig, app: &dyn ClientApp) -> bool {
        config.policy.scheduler_v2_enabled && app.scheduler_policy().control_epoch != self.epoch
    }

    async fn preparing<T>(
        &mut self,
        config: &ClientConfig,
        app: Arc<dyn ClientApp>,
        future: impl Future<Output = T>,
    ) -> Result<T, WarpLinkError> {
        if self.control_changed(config, app.as_ref()) {
            return Err(WarpLinkError::Reconnect(
                "control changed during handoff".into(),
            ));
        }
        tokio::pin!(future);
        loop {
            // Both stream readers retain their partial-frame parser state when
            // the other branch wins. No receive task or callback is detached.
            let frame = tokio::select! {
                biased;
                _ = app.wait_for_control_change(self.epoch), if config.policy.scheduler_v2_enabled => {
                    return Err(WarpLinkError::Reconnect("control changed during handoff".into()));
                }
                result = &mut future => return Ok(result),
                frame = self.active.io.recv_frame(MAX_HANDOFF_STAGE_MS) => frame?,
            };
            self.handle(config, Arc::clone(&app), frame).await?;
        }
    }

    async fn boundary(
        &mut self,
        config: &ClientConfig,
        app: Arc<dyn ClientApp>,
        expected: &HelloCtx,
        phase: &str,
    ) -> Result<WelcomeMsg, WarpLinkError> {
        let deadline = Instant::now()
            + Duration::from_millis(
                config
                    .policy
                    .drain_timeout_ms
                    .clamp(1, MAX_HANDOFF_STAGE_MS),
            );
        loop {
            if self.control_changed(config, app.as_ref()) {
                return Err(WarpLinkError::Reconnect(
                    "control changed during drain".into(),
                ));
            }
            let frame = tokio::select! {
                biased;
                _ = app.wait_for_control_change(self.epoch), if config.policy.scheduler_v2_enabled => {
                    return Err(WarpLinkError::Reconnect("control changed during drain".into()));
                }
                frame = timeout_at(deadline, self.active.io.recv_frame(MAX_HANDOFF_STAGE_MS)) => {
                    frame.map_err(|_| WarpLinkError::Timeout("handoff drain boundary".into()))??
                }
            };
            if let DecodedServerFrame::Welcome(welcome) =
                config.wire_profile.decode_server_frame(&frame)?
            {
                if self.active.continuity.handoff_session.as_deref()
                    != Some(welcome.session_id.as_str())
                {
                    return Err(WarpLinkError::Protocol(
                        "handoff boundary changed primary session".into(),
                    ));
                }
                if matching_receipt(&welcome, expected, phase)
                    || (phase == "drained" && matching_receipt(&welcome, expected, "resumed"))
                {
                    return Ok(welcome);
                }
                // A timed-out freeze may already have written its ordered
                // receipt before a resume request. Consume only that exact
                // reservation's earlier receipt, never an unrelated WELCOME.
                if phase == "resumed" && matching_receipt(&welcome, expected, "drained") {
                    continue;
                }
                return Err(WarpLinkError::Protocol("handoff boundary mismatch".into()));
            }
            self.handle(config, Arc::clone(&app), frame).await?;
        }
    }

    async fn ack_fence(
        &mut self,
        config: &ClientConfig,
        app: Arc<dyn ClientApp>,
    ) -> Result<(), WarpLinkError> {
        // This PONG fences explicit ACK commits *after* the server's freeze
        // boundary. It is not used as a stand-alone cross-stream drain proof.
        self.active
            .io
            .send_frame(
                &config.wire_profile.encode_client_ping(),
                config.policy.write_timeout_ms,
            )
            .await?;
        let deadline = Instant::now()
            + Duration::from_millis(
                config
                    .policy
                    .drain_timeout_ms
                    .clamp(1, MAX_HANDOFF_STAGE_MS),
            );
        loop {
            let frame = tokio::select! {
                biased;
                _ = app.wait_for_control_change(self.epoch), if config.policy.scheduler_v2_enabled => {
                    return Err(WarpLinkError::Reconnect("control changed during ACK fence".into()));
                }
                frame = timeout_at(deadline, self.active.io.recv_frame(MAX_HANDOFF_STAGE_MS)) => {
                    frame.map_err(|_| WarpLinkError::Timeout("handoff ACK fence".into()))??
                }
            };
            match config.wire_profile.decode_server_frame(&frame)? {
                DecodedServerFrame::Pong => return Ok(()),
                DecodedServerFrame::Deliver(_) => {
                    return Err(WarpLinkError::Protocol(
                        "delivery after handoff drain boundary".into(),
                    ));
                }
                _ => self.handle(config, Arc::clone(&app), frame).await?,
            }
        }
    }
}

fn request(base: &HelloCtx, phase: &str, peer: &str, id: &str) -> HelloCtx {
    let mut hello = base.clone();
    hello
        .metadata
        .insert(handoff::VERSION_KEY.into(), handoff::VERSION.into());
    hello
        .metadata
        .insert(handoff::PHASE_KEY.into(), phase.into());
    hello.metadata.insert(handoff::PEER_KEY.into(), peer.into());
    hello.metadata.insert(handoff::ID_KEY.into(), id.into());
    hello
}

fn matching_receipt(welcome: &WelcomeMsg, expected: &HelloCtx, phase: &str) -> bool {
    if welcome.resume_token != expected.resume_token {
        return false;
    }
    welcome
        .metadata
        .get(handoff::VERSION_KEY)
        .map(String::as_str)
        == Some(handoff::VERSION)
        && welcome.metadata.get(handoff::PHASE_KEY).map(String::as_str) == Some(phase)
        && welcome.metadata.get(handoff::PEER_KEY) == expected.metadata.get(handoff::PEER_KEY)
        && welcome.metadata.get(handoff::ID_KEY) == expected.metadata.get(handoff::ID_KEY)
}

async fn exchange(
    config: &ClientConfig,
    io: &mut ClientIo,
    hello: &HelloCtx,
    phase: &str,
) -> Result<WelcomeMsg, WarpLinkError> {
    let deadline = Instant::now()
        + Duration::from_millis(
            config
                .policy
                .connect_timeout_ms
                .clamp(1, MAX_HANDOFF_STAGE_MS),
        );
    timeout_at(deadline, async {
        io.send_frame(
            &config.wire_profile.encode_client_hello(hello)?,
            config.policy.write_timeout_ms,
        )
        .await?;
        let frame = io.recv_frame(MAX_HANDOFF_STAGE_MS).await?;
        let DecodedServerFrame::Welcome(welcome) =
            config.wire_profile.decode_server_frame(&frame)?
        else {
            return Err(WarpLinkError::Protocol("expected handoff WELCOME".into()));
        };
        validate_welcome_negotiation(hello, &welcome)?;
        if !matching_receipt(&welcome, hello, phase) {
            return Err(WarpLinkError::Protocol(
                "unconfirmed handoff capability or reservation".into(),
            ));
        }
        Ok(welcome)
    })
    .await
    .map_err(|_| WarpLinkError::Timeout("handoff WELCOME".into()))?
}

async fn guard(config: &ClientConfig, io: &mut ClientIo) -> Result<(), WarpLinkError> {
    if config.policy.cutover_guard_ms == 0 {
        return Ok(());
    }
    let deadline = Instant::now()
        + Duration::from_millis(
            config
                .policy
                .cutover_guard_ms
                .clamp(1, MAX_HANDOFF_STAGE_MS),
        );
    timeout_at(deadline, async {
        io.send_frame(
            &config.wire_profile.encode_client_ping(),
            config.policy.write_timeout_ms,
        )
        .await?;
        loop {
            let frame = io.recv_frame(MAX_HANDOFF_STAGE_MS).await?;
            match config.wire_profile.decode_server_frame(&frame)? {
                DecodedServerFrame::Pong => return Ok(()),
                DecodedServerFrame::Ping => {
                    io.send_frame(
                        &config.wire_profile.encode_client_pong(),
                        config.policy.write_timeout_ms,
                    )
                    .await?
                }
                DecodedServerFrame::Unknown => {}
                // A prepared candidate has no business ownership. In
                // particular a DELIVER is never used as its health receipt.
                _ => {
                    return Err(WarpLinkError::Protocol(
                        "unexpected prepared candidate frame".into(),
                    ));
                }
            }
        }
    })
    .await
    .map_err(|_| WarpLinkError::Timeout("handoff guard".into()))?
}

pub(super) async fn commit_candidate_cutover(
    config: &ClientConfig,
    app: Arc<dyn ClientApp>,
    active: ActiveTransport<'_>,
    target: TransportKind,
    mut candidate_io: ClientIo,
    decision_id: u64,
    progress: PrimaryProgress<'_>,
) -> Result<Option<WelcomeMsg>, WarpLinkError> {
    let Some(old_session) = active.continuity.handoff_session.clone() else {
        return Ok(None);
    };
    if !active.continuity.handoff_supported {
        return Ok(None);
    }
    let from = *active.transport;
    let epoch = app.scheduler_policy().control_epoch;
    let mut hello = build_effective_hello(config, app.as_ref(), active.power_runtime);
    active.continuity.apply_to_hello(&mut hello);
    let id = format!("{decision_id:016x}{:016x}", rand::random::<u64>());
    let mut primary = Primary {
        active,
        progress,
        epoch,
    };
    emit_scheduler_state(
        app.as_ref(),
        SchedulerState::CandidateConnecting,
        "candidate_connecting",
    );
    let _ = app.on_event(ClientEvent::CandidateStarted {
        from,
        to: target,
        decision_id,
    });
    let prepare = request(&hello, "prepare", &old_session, &id);
    let prepared = match primary
        .preparing(
            config,
            Arc::clone(&app),
            exchange(config, &mut candidate_io, &prepare, "prepared"),
        )
        .await?
    {
        Ok(welcome) => welcome,
        Err(_) => return Ok(None),
    };
    if prepared.session_id.is_empty() || prepared.session_id == old_session {
        return Ok(None);
    }
    match primary
        .preparing(config, Arc::clone(&app), guard(config, &mut candidate_io))
        .await?
    {
        Ok(()) => {}
        Err(_) => return Ok(None),
    }
    emit_scheduler_state(
        app.as_ref(),
        SchedulerState::CutoverReady,
        "candidate_ready",
    );
    let _ = app.on_event(ClientEvent::CandidateReady {
        from,
        to: target,
        decision_id,
    });
    let freeze = request(&hello, "freeze", &prepared.session_id, &id);
    primary
        .active
        .io
        .send_frame(
            &config.wire_profile.encode_client_hello(&freeze)?,
            config.policy.write_timeout_ms,
        )
        .await?;
    emit_scheduler_state(app.as_ref(), SchedulerState::DrainingOld, "draining_old");
    let drained = primary
        .boundary(config, Arc::clone(&app), &freeze, "drained")
        .await;
    if drained.as_ref().is_ok_and(|welcome| {
        welcome.metadata.get(handoff::PHASE_KEY).map(String::as_str) == Some("resumed")
    }) {
        let _ = app.on_event(ClientEvent::CutoverRollback {
            restored: from,
            failed: target,
            decision_id,
            reason: "primary handoff reservation released".into(),
        });
        emit_scheduler_state(
            app.as_ref(),
            SchedulerState::PrimaryActive,
            "handoff_released",
        );
        return Ok(None);
    }
    if let Err(error) = drained {
        if !matches!(error, WarpLinkError::Timeout(_)) {
            return Err(error);
        }
        let resume = request(&hello, "resume", &prepared.session_id, &id);
        primary
            .active
            .io
            .send_frame(
                &config.wire_profile.encode_client_hello(&resume)?,
                config.policy.write_timeout_ms,
            )
            .await?;
        primary
            .boundary(config, Arc::clone(&app), &resume, "resumed")
            .await?;
        let _ = app.on_event(ClientEvent::CutoverRollback {
            restored: from,
            failed: target,
            decision_id,
            reason: error.to_string(),
        });
        return Ok(None);
    }
    primary.ack_fence(config, Arc::clone(&app)).await?;
    let activate = request(&hello, "activate", &old_session, &id);
    // Once activation may have reached the server, failure is ambiguous. Drop
    // both sockets and replay; never resume an old owner that might be retired.
    // The old stream has already emitted its drain boundary and committed
    // preceding explicit ACKs. It has no business ownership now; an ordered
    // retirement GOAWAY may legitimately precede the activation receipt.
    let activated = match await_value_or_control_change(
        config,
        app.as_ref(),
        epoch,
        exchange(config, &mut candidate_io, &activate, "active"),
    )
    .await
    {
        WaitWithControl::Value(result) => result?,
        WaitWithControl::ControlChanged => {
            return Err(WarpLinkError::Reconnect(
                "control changed during activation".into(),
            ));
        }
    };
    if activated.session_id != prepared.session_id {
        return Err(WarpLinkError::Protocol(
            "candidate activation changed session".into(),
        ));
    }
    let old_io = std::mem::replace(primary.active.io, candidate_io);
    *primary.active.transport = target;
    // A ping outstanding on the retired socket has no ownership in the new
    // primary. Preparation itself used the live session's original trackers.
    *primary.progress.pending_ping_sent_at = None;
    *primary.progress.pending_ping_source = None;
    primary
        .progress
        .health_tracker
        .note_frame_progress(Instant::now());
    drop(old_io);
    let _ = app.on_event(ClientEvent::Connected { transport: target });
    let _ = app.on_event(ClientEvent::Welcome {
        welcome: activated.clone(),
    });
    let _ = app.on_event(ClientEvent::CutoverCommitted {
        from,
        to: target,
        decision_id,
    });
    emit_scheduler_state(
        app.as_ref(),
        SchedulerState::PrimaryActive,
        "cutover_completed",
    );
    Ok(Some(activated))
}
