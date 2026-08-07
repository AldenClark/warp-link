use std::cell::Cell;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use flume::TrySendError;
use parking_lot::{Condvar, Mutex};
use pushgo_warp_profile::{PrivatePayloadEnvelope, PushgoWireProfile};
use serde::Deserialize;
use tokio::runtime::Runtime;
use tokio::sync::watch;
use warp_link::{client_run_with_shutdown, warp_link_core};
use warp_link_core::{
    AppDecision, ClientApp, ClientAppStateHint, ClientConfig, ClientEvent, ClientPolicy,
    ClientPowerHint, ClientPowerTier, HelloCtx,
};

const EVENT_QUEUE_CAP: usize = 8192;
const CALLBACK_QUEUE_CAP_PER_WORKER: usize = 1024;
const WIRE_VERSION_V2: u8 = 2;
const PRIVATE_PAYLOAD_VERSION_V1: u8 = 1;
const WL_ABI_VERSION: u32 = 0x0002_0000;
const DEFAULT_STOP_TIMEOUT_MS: u32 = 5_000;
const POLL_OK: i32 = 0;
const POLL_TIMEOUT: i32 = 1;
const POLL_STOPPED: i32 = 2;
const POLL_INVALID_HANDLE: i32 = -1;
const POLL_INVALID_ARGUMENT: i32 = -2;

#[derive(Debug, Deserialize)]
struct StartConfig {
    host: String,
    #[serde(default)]
    quic_port: Option<u16>,
    #[serde(default)]
    wss_port: Option<u16>,
    #[serde(default)]
    tcp_port: Option<u16>,
    #[serde(default)]
    wss_path: Option<String>,
    #[serde(default)]
    quic_alpn: Option<String>,
    #[serde(default)]
    tcp_alpn: Option<String>,
    #[serde(default)]
    wss_subprotocol: Option<String>,
    #[serde(default)]
    tls_server_name: Option<String>,
    #[serde(default)]
    bearer_token: Option<String>,
    #[serde(default)]
    cert_pin_sha256: Option<String>,
    #[serde(default)]
    quic_cert_pin_sha256: Option<String>,
    #[serde(default)]
    tcp_cert_pin_sha256: Option<String>,
    #[serde(default)]
    wss_cert_pin_sha256: Option<String>,
    identity: String,
    #[serde(default, alias = "gateway_token")]
    auth_token: Option<String>,
    #[serde(default)]
    resume_token: Option<String>,
    #[serde(default)]
    last_acked_seq: Option<u64>,
    #[serde(default)]
    perf_tier: Option<String>,
    #[serde(default)]
    app_state: Option<String>,
    #[serde(default)]
    policy: Option<PolicyConfig>,
}

#[derive(Debug, Deserialize)]
struct PolicyConfig {
    #[serde(default)]
    connect_budget_ms: Option<u64>,
    #[serde(default)]
    wss_delay_ms: Option<u64>,
    #[serde(default)]
    tcp_delay_ms: Option<u64>,
    #[serde(default)]
    connect_timeout_ms: Option<u64>,
    #[serde(default)]
    write_timeout_ms: Option<u64>,
    #[serde(default)]
    backoff_min_ms: Option<u64>,
    #[serde(default)]
    backoff_max_ms: Option<u64>,
    #[serde(default)]
    upgrade_probe_enabled: Option<bool>,
    #[serde(default)]
    upgrade_probe_timeout_ms: Option<u64>,
    #[serde(default)]
    upgrade_probe_foreground_interval_secs: Option<u16>,
    #[serde(default)]
    upgrade_probe_background_interval_secs: Option<u16>,
    #[serde(default)]
    upgrade_probe_min_dwell_secs: Option<u16>,
    #[serde(default)]
    scheduler_v2_enabled: Option<bool>,
    #[serde(default)]
    drain_timeout_ms: Option<u64>,
    #[serde(default)]
    cutover_guard_ms: Option<u64>,
}

#[derive(Debug)]
struct SessionStats {
    started_at: Instant,
    events_in_total: AtomicU64,
    events_enqueued_total: AtomicU64,
    events_dropped_total: AtomicU64,
    callbacks_enqueued: AtomicU64,
    callbacks_dropped: AtomicU64,
    callbacks_invoked: AtomicU64,
    poll_returned: AtomicU64,
}

impl SessionStats {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            events_in_total: AtomicU64::new(0),
            events_enqueued_total: AtomicU64::new(0),
            events_dropped_total: AtomicU64::new(0),
            callbacks_enqueued: AtomicU64::new(0),
            callbacks_dropped: AtomicU64::new(0),
            callbacks_invoked: AtomicU64::new(0),
            poll_returned: AtomicU64::new(0),
        }
    }
}

#[derive(Clone)]
struct QueueApp {
    handle: u64,
    hello: Arc<Mutex<HelloCtx>>,
    power_hint: Arc<Mutex<Option<ClientPowerHint>>>,
    event_tx: flume::Sender<String>,
    stats: Arc<SessionStats>,
    lifecycle: Arc<SessionLifecycle>,
}

impl QueueApp {
    fn enqueue_event(&self, payload: String) -> bool {
        self.stats.events_in_total.fetch_add(1, Ordering::Relaxed);
        if self.lifecycle.is_closing() {
            self.stats
                .events_dropped_total
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }
        match self.event_tx.try_send(payload) {
            Ok(()) => {
                self.stats
                    .events_enqueued_total
                    .fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.stats
                    .events_dropped_total
                    .fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    fn enqueue_callback(&self, event: &str) {
        let Some(generation) = self.lifecycle.callback_generation_if_active() else {
            return;
        };

        let task = CallbackTask {
            handle: self.handle,
            event: event.to_string(),
            generation,
        };
        let sender = CALLBACK_DISPATCHER.sender_for(self.handle);
        match sender.try_send(task) {
            Ok(()) => {
                self.stats
                    .callbacks_enqueued
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.stats.callbacks_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl ClientApp for QueueApp {
    fn on_hello(&self) -> HelloCtx {
        self.hello.lock().clone()
    }

    fn on_event(&self, event: ClientEvent) -> AppDecision {
        match event {
            ClientEvent::Message { transport, msg } => {
                let (payload, decode_ok) = decode_payload_map(msg.payload.as_ref());
                let serialized = serde_json::json!({
                    "type": "message",
                    "transport": transport.to_string(),
                    "id": msg.id,
                    "seq": msg.seq,
                    "payload": payload,
                    "payload_len": msg.payload.len(),
                    "decode_ok": decode_ok,
                })
                .to_string();
                let accepted = self.enqueue_event(serialized.clone());
                if accepted {
                    self.enqueue_callback(serialized.as_str());
                }
                if !accepted {
                    AppDecision::RetryLater
                } else if decode_ok {
                    AppDecision::AckOk
                } else {
                    AppDecision::AckInvalidPayload
                }
            }
            other => {
                let serialized = event_to_json(&other);
                if self.enqueue_event(serialized.clone()) {
                    self.enqueue_callback(serialized.as_str());
                }
                AppDecision::Ignore
            }
        }
    }

    fn power_hint(&self) -> Option<ClientPowerHint> {
        *self.power_hint.lock()
    }
}

struct FfiSession {
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    shutdown_tx: watch::Sender<bool>,
    event_tx: Mutex<Option<flume::Sender<String>>>,
    event_rx: Mutex<flume::Receiver<String>>,
    hello: Arc<Mutex<HelloCtx>>,
    power_hint: Arc<Mutex<Option<ClientPowerHint>>>,
    last_error: Arc<Mutex<Option<String>>>,
    stats: Arc<SessionStats>,
    lifecycle: Arc<SessionLifecycle>,
}

#[derive(Debug, Default)]
struct SessionLifecycleState {
    closing: bool,
    task_finished: bool,
    callback: Option<EventCallback>,
    callback_generation: u64,
    callbacks_in_flight: u64,
}

#[derive(Debug, Default)]
struct SessionLifecycle {
    state: Mutex<SessionLifecycleState>,
    changed: Condvar,
}

impl SessionLifecycle {
    fn is_closing(&self) -> bool {
        self.state.lock().closing
    }

    fn callback_generation_if_active(&self) -> Option<u64> {
        let state = self.state.lock();
        (!state.closing && state.callback.is_some()).then_some(state.callback_generation)
    }

    fn begin_callback(
        self: &Arc<Self>,
        generation: u64,
    ) -> Option<(EventCallback, CallbackInvocationGuard)> {
        let mut state = self.state.lock();
        if state.closing || state.callback_generation != generation {
            return None;
        }
        let callback = state.callback?;
        state.callbacks_in_flight = state.callbacks_in_flight.saturating_add(1);
        Some((
            callback,
            CallbackInvocationGuard {
                lifecycle: Arc::clone(self),
            },
        ))
    }

    fn finish_callback(&self) {
        let mut state = self.state.lock();
        state.callbacks_in_flight = state.callbacks_in_flight.saturating_sub(1);
        self.changed.notify_all();
    }

    fn replace_callback(&self, callback: Option<EventCallback>) -> bool {
        let mut state = self.state.lock();
        if state.closing {
            return false;
        }
        state.callback = None;
        state.callback_generation = state.callback_generation.wrapping_add(1);
        while state.callbacks_in_flight != 0 {
            self.changed.wait(&mut state);
        }
        if state.closing {
            return false;
        }
        state.callback = callback;
        true
    }

    fn begin_close(&self) {
        let mut state = self.state.lock();
        state.closing = true;
        state.callback = None;
        state.callback_generation = state.callback_generation.wrapping_add(1);
        self.changed.notify_all();
    }

    fn wait_callbacks_finished(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock();
        while state.callbacks_in_flight != 0 {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            self.changed.wait_for(&mut state, deadline - now);
        }
        true
    }

    fn mark_task_finished(&self) {
        self.state.lock().task_finished = true;
        self.changed.notify_all();
    }

    fn wait_task_finished(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock();
        while !state.task_finished {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            self.changed.wait_for(&mut state, deadline - now);
        }
        true
    }
}

struct CallbackInvocationGuard {
    lifecycle: Arc<SessionLifecycle>,
}

impl Drop for CallbackInvocationGuard {
    fn drop(&mut self) {
        self.lifecycle.finish_callback();
    }
}

struct TaskCompletionGuard {
    lifecycle: Arc<SessionLifecycle>,
}

impl Drop for TaskCompletionGuard {
    fn drop(&mut self) {
        self.lifecycle.mark_task_finished();
    }
}

#[derive(Debug)]
struct CallbackTask {
    handle: u64,
    event: String,
    generation: u64,
}

#[derive(Debug)]
struct CallbackDispatcher {
    shards: Vec<flume::Sender<CallbackTask>>,
}

impl CallbackDispatcher {
    fn new() -> Self {
        let workers = callback_worker_count();
        let mut shards = Vec::with_capacity(workers);
        for index in 0..workers {
            let (tx, rx) = flume::bounded(CALLBACK_QUEUE_CAP_PER_WORKER);
            shards.push(tx);
            if let Err(err) = std::thread::Builder::new()
                .name(format!("warp-link-ffi-callback-{index}"))
                .spawn(move || callback_worker_loop(rx))
            {
                set_last_error(format!("spawn callback worker failed: {err}"));
            }
        }
        Self { shards }
    }

    fn worker_count(&self) -> usize {
        self.shards.len()
    }

    fn shard_index(&self, handle: u64) -> usize {
        (handle as usize) % self.shards.len()
    }

    fn sender_for(&self, handle: u64) -> &flume::Sender<CallbackTask> {
        let index = self.shard_index(handle);
        &self.shards[index]
    }

    fn pending_len_global(&self) -> usize {
        self.shards.iter().map(flume::Sender::len).sum()
    }

    fn pending_len_for_handle(&self, handle: u64) -> usize {
        self.shards[self.shard_index(handle)].len()
    }
}

fn callback_worker_count() -> usize {
    std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(2)
        .clamp(2, 8)
}

fn callback_worker_loop(rx: flume::Receiver<CallbackTask>) {
    while let Ok(task) = rx.recv() {
        let session = {
            let sessions = SESSIONS.lock();
            sessions.get(&task.handle).cloned()
        };
        let Some(session) = session else {
            continue;
        };
        let Some((callback, _guard)) = session.lifecycle.begin_callback(task.generation) else {
            continue;
        };
        let bytes = task.event.into_bytes();
        let _callback_scope = CurrentCallbackScope::enter(task.handle);
        (callback.callback)(callback.user_data, bytes.as_ptr(), bytes.len() as u32);

        session
            .stats
            .callbacks_invoked
            .fetch_add(1, Ordering::Relaxed);
    }
}

thread_local! {
    static CURRENT_CALLBACK_HANDLE: Cell<Option<u64>> = const { Cell::new(None) };
}

struct CurrentCallbackScope {
    previous: Option<u64>,
}

impl CurrentCallbackScope {
    fn enter(handle: u64) -> Self {
        let previous = CURRENT_CALLBACK_HANDLE.replace(Some(handle));
        Self { previous }
    }
}

impl Drop for CurrentCallbackScope {
    fn drop(&mut self) {
        CURRENT_CALLBACK_HANDLE.set(self.previous);
    }
}

fn current_callback_handle() -> Option<u64> {
    CURRENT_CALLBACK_HANDLE.with(Cell::get)
}

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static RUNTIME: LazyLock<Result<Runtime, String>> =
    LazyLock::new(|| Runtime::new().map_err(|e| format!("create runtime failed: {e}")));
static SESSIONS: LazyLock<Mutex<std::collections::HashMap<u64, Arc<FfiSession>>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
static LAST_ERROR: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::new(None));
static CALLBACK_DISPATCHER: LazyLock<CallbackDispatcher> = LazyLock::new(CallbackDispatcher::new);

fn runtime() -> Result<&'static Runtime, String> {
    match &*RUNTIME {
        Ok(runtime) => Ok(runtime),
        Err(err) => Err(err.clone()),
    }
}

fn ffi_guard<T>(function: &'static str, fallback: T, operation: impl FnOnce() -> T) -> T {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(value) => value,
        Err(_) => {
            let _ = catch_unwind(AssertUnwindSafe(|| {
                set_last_error(format!("panic contained at FFI boundary: {function}"));
            }));
            fallback
        }
    }
}

type EventCallbackFn = extern "C" fn(user_data: u64, ptr: *const u8, len: u32);

#[derive(Debug, Clone, Copy)]
struct EventCallback {
    callback: EventCallbackFn,
    user_data: u64,
}

#[repr(C)]
pub struct WlBuffer {
    ptr: *mut u8,
    len: u32,
}

const _: () = {
    let pointer_size = std::mem::size_of::<*mut u8>();
    let alignment = std::mem::align_of::<*mut u8>();
    let unpadded_size = pointer_size + std::mem::size_of::<u32>();
    let expected_size = unpadded_size.div_ceil(alignment) * alignment;
    assert!(std::mem::offset_of!(WlBuffer, ptr) == 0);
    assert!(std::mem::offset_of!(WlBuffer, len) == pointer_size);
    assert!(std::mem::align_of::<WlBuffer>() == alignment);
    assert!(std::mem::size_of::<WlBuffer>() == expected_size);
};

/// Start a warp-link session from a UTF-8 JSON configuration.
///
/// # Safety
///
/// `config_json` must point to a readable, NUL-terminated byte string that remains valid for the
/// duration of this call. The string must contain valid UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wl_session_start(config_json: *const c_char) -> u64 {
    ffi_guard("wl_session_start", 0, || session_start(config_json))
}

fn session_start(config_json: *const c_char) -> u64 {
    // SAFETY: forwarded from wl_session_start's caller contract.
    let Some(raw) = (unsafe { c_str_to_string(config_json) }) else {
        set_last_error("invalid config_json pointer".to_string());
        return 0;
    };
    let parsed: StartConfig = match serde_json::from_str(raw.as_str()) {
        Ok(cfg) => cfg,
        Err(err) => {
            set_last_error(format!("invalid config json: {err}"));
            return 0;
        }
    };

    let mut policy = ClientPolicy::default();
    if let Some(custom) = parsed.policy {
        if let Some(value) = custom.connect_budget_ms {
            policy.connect_budget_ms = value;
        }
        if let Some(value) = custom.wss_delay_ms {
            policy.wss_delay_ms = value;
        }
        if let Some(value) = custom.tcp_delay_ms {
            policy.tcp_delay_ms = value;
        }
        if let Some(value) = custom.connect_timeout_ms {
            policy.connect_timeout_ms = value;
        }
        if let Some(value) = custom.write_timeout_ms {
            policy.write_timeout_ms = value;
        }
        if let Some(value) = custom.backoff_min_ms {
            policy.backoff_min_ms = value;
        }
        if let Some(value) = custom.backoff_max_ms {
            policy.backoff_max_ms = value;
        }
        if let Some(value) = custom.upgrade_probe_enabled {
            policy.upgrade_probe_enabled = value;
        }
        if let Some(value) = custom.upgrade_probe_timeout_ms {
            policy.upgrade_probe_timeout_ms = value;
        }
        if let Some(value) = custom.upgrade_probe_foreground_interval_secs {
            policy.upgrade_probe_foreground_interval_secs = value;
        }
        if let Some(value) = custom.upgrade_probe_background_interval_secs {
            policy.upgrade_probe_background_interval_secs = value;
        }
        if let Some(value) = custom.upgrade_probe_min_dwell_secs {
            policy.upgrade_probe_min_dwell_secs = value;
        }
        if let Some(value) = custom.scheduler_v2_enabled {
            policy.scheduler_v2_enabled = value;
        }
        if let Some(value) = custom.drain_timeout_ms {
            policy.drain_timeout_ms = value;
        }
        if let Some(value) = custom.cutover_guard_ms {
            policy.cutover_guard_ms = value;
        }
    }

    let hello = HelloCtx {
        identity: parsed.identity,
        auth_token: parsed
            .auth_token
            .clone()
            .or_else(|| parsed.bearer_token.clone()),
        resume_token: parsed.resume_token,
        last_acked_seq: parsed.last_acked_seq,
        supported_wire_versions: vec![WIRE_VERSION_V2],
        supported_payload_versions: vec![PRIVATE_PAYLOAD_VERSION_V1],
        perf_tier: None,
        app_state: None,
        metadata: std::collections::BTreeMap::new(),
    };
    let initial_power_hint =
        parse_power_hint(parsed.app_state.as_deref(), parsed.perf_tier.as_deref());

    let config = ClientConfig {
        host: parsed.host,
        quic_port: parsed.quic_port.unwrap_or(443),
        wss_port: parsed.wss_port.or(parsed.quic_port).unwrap_or(443),
        tcp_port: parsed.tcp_port.unwrap_or(5223),
        wss_path: parsed.wss_path.unwrap_or_else(|| "/private/ws".to_string()),
        quic_alpn: parsed
            .quic_alpn
            .unwrap_or_else(|| "pushgo-quic".to_string()),
        tcp_alpn: parsed.tcp_alpn.unwrap_or_else(|| "pushgo-tcp".to_string()),
        wss_subprotocol: parsed
            .wss_subprotocol
            .or_else(|| Some("pushgo-private.v1".to_string())),
        tls_server_name: parsed.tls_server_name,
        bearer_token: parsed.bearer_token,
        cert_pin_sha256: parsed.cert_pin_sha256,
        quic_cert_pin_sha256: parsed.quic_cert_pin_sha256,
        tcp_cert_pin_sha256: parsed.tcp_cert_pin_sha256,
        wss_cert_pin_sha256: parsed.wss_cert_pin_sha256,
        policy,
        wire_profile: std::sync::Arc::new(PushgoWireProfile::new()),
    };

    let (event_tx, event_rx) = flume::bounded(EVENT_QUEUE_CAP);

    let hello = Arc::new(Mutex::new(hello));
    let power_hint = Arc::new(Mutex::new(initial_power_hint));
    let stats = Arc::new(SessionStats::new());
    let lifecycle = Arc::new(SessionLifecycle::default());
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    let app = QueueApp {
        handle,
        hello: Arc::clone(&hello),
        power_hint: Arc::clone(&power_hint),
        event_tx: event_tx.clone(),
        stats: Arc::clone(&stats),
        lifecycle: Arc::clone(&lifecycle),
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let runtime = match runtime() {
        Ok(value) => value,
        Err(err) => {
            set_last_error(err);
            return 0;
        }
    };

    let last_error = Arc::new(Mutex::new(None));
    let task_error = Arc::clone(&last_error);
    let completion = TaskCompletionGuard {
        lifecycle: Arc::clone(&lifecycle),
    };
    let task = runtime.spawn(async move {
        // The guard is created before spawn and captured by the future, so aborting the task before
        // its first poll still marks completion when Tokio drops the unpolled future.
        let _completion = completion;
        if let Err(err) = client_run_with_shutdown(config, app, shutdown_rx).await {
            *task_error.lock() = Some(err.to_string());
            set_last_error(err.to_string());
        }
    });

    SESSIONS.lock().insert(
        handle,
        Arc::new(FfiSession {
            task: Mutex::new(Some(task)),
            shutdown_tx,
            event_tx: Mutex::new(Some(event_tx)),
            event_rx: Mutex::new(event_rx),
            hello,
            power_hint,
            last_error,
            stats,
            lifecycle,
        }),
    );
    clear_last_error();
    handle
}

#[unsafe(no_mangle)]
pub extern "C" fn wl_session_poll_event(handle: u64, timeout_ms: u32) -> WlBuffer {
    ffi_guard("wl_session_poll_event", null_buffer(), || {
        let (_, buffer) = poll_event(handle, timeout_ms);
        buffer
    })
}

fn poll_event(handle: u64, timeout_ms: u32) -> (i32, WlBuffer) {
    let session = {
        let sessions = SESSIONS.lock();
        sessions.get(&handle).cloned()
    };
    let Some(session) = session else {
        set_last_error(format!("invalid session handle={handle}"));
        return (POLL_INVALID_HANDLE, null_buffer());
    };
    if session.lifecycle.is_closing() {
        return (POLL_STOPPED, null_buffer());
    }

    let recv_result = match timeout_ms {
        0 => session
            .event_rx
            .lock()
            .try_recv()
            .map_err(|error| match error {
                flume::TryRecvError::Empty => flume::RecvTimeoutError::Timeout,
                flume::TryRecvError::Disconnected => flume::RecvTimeoutError::Disconnected,
            }),
        u32::MAX => session
            .event_rx
            .lock()
            .recv()
            .map_err(|_| flume::RecvTimeoutError::Disconnected),
        _ => session
            .event_rx
            .lock()
            .recv_timeout(Duration::from_millis(u64::from(timeout_ms))),
    };

    let text = match recv_result {
        Ok(text) => {
            if session.lifecycle.is_closing() {
                return (POLL_STOPPED, null_buffer());
            }
            session.stats.poll_returned.fetch_add(1, Ordering::Relaxed);
            text
        }
        Err(flume::RecvTimeoutError::Timeout) => return (POLL_TIMEOUT, null_buffer()),
        Err(flume::RecvTimeoutError::Disconnected) => return (POLL_STOPPED, null_buffer()),
    };

    (POLL_OK, string_to_buffer(text))
}

/// Poll one event with explicit status reporting.
///
/// `timeout_ms == 0` is non-blocking and `timeout_ms == UINT32_MAX` waits indefinitely.
///
/// # Safety
///
/// `out_buffer` must be non-null, properly aligned, and valid for one `WlBuffer` write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wl_session_poll_event_v2(
    handle: u64,
    timeout_ms: u32,
    out_buffer: *mut WlBuffer,
) -> i32 {
    if out_buffer.is_null() {
        return ffi_guard("wl_session_poll_event_v2", POLL_INVALID_ARGUMENT, || {
            set_last_error("out_buffer must not be null".to_string());
            POLL_INVALID_ARGUMENT
        });
    }
    // Initialize the output before any operation that may panic, so caught panics cannot expose an
    // uninitialized output value to the caller.
    // SAFETY: the caller contract requires out_buffer to be valid for one WlBuffer write.
    unsafe { out_buffer.write(null_buffer()) };
    ffi_guard("wl_session_poll_event_v2", POLL_INVALID_ARGUMENT, || {
        let (status, buffer) = poll_event(handle, timeout_ms);
        // SAFETY: checked non-null above and guaranteed writable by the caller contract.
        unsafe { out_buffer.write(buffer) };
        status
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn wl_session_stop(handle: u64) {
    ffi_guard("wl_session_stop", (), || {
        let _ = stop_session(handle, DEFAULT_STOP_TIMEOUT_MS);
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn wl_session_stop_v2(handle: u64, timeout_ms: u32) -> bool {
    ffi_guard("wl_session_stop_v2", false, || {
        stop_session(handle, timeout_ms.max(1))
    })
}

fn stop_session(handle: u64, timeout_ms: u32) -> bool {
    if let Some(callback_handle) = current_callback_handle() {
        set_last_error(format!(
            "session stop cannot run from callback handle={callback_handle} target={handle}"
        ));
        return false;
    }
    let session = {
        let sessions = SESSIONS.lock();
        sessions.get(&handle).cloned()
    };
    let Some(session) = session else {
        set_last_error(format!("invalid session handle={handle}"));
        return false;
    };
    let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
    session.lifecycle.begin_close();
    let _ = session.shutdown_tx.send(true);
    // Dropping the final canonical sender wakes all finite and infinite pollers immediately.
    session.event_tx.lock().take();

    let callbacks_finished = session
        .lifecycle
        .wait_callbacks_finished(deadline.saturating_duration_since(Instant::now()));
    if !session
        .lifecycle
        .wait_task_finished(deadline.saturating_duration_since(Instant::now()))
        && let Some(task) = session.task.lock().as_ref()
    {
        task.abort();
    }
    let task_finished = session
        .lifecycle
        .wait_task_finished(deadline.saturating_duration_since(Instant::now()));
    if !callbacks_finished || !task_finished {
        set_last_error(format!("session stop timed out handle={handle}"));
        return false;
    }
    session.task.lock().take();
    let removed = SESSIONS
        .lock()
        .remove(&handle)
        .is_some_and(|registered| Arc::ptr_eq(&registered, &session));
    if !removed {
        set_last_error(format!("session changed while stopping handle={handle}"));
        return false;
    }
    clear_last_error();
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn wl_session_set_event_callback(
    handle: u64,
    callback: Option<EventCallbackFn>,
    user_data: u64,
) -> bool {
    ffi_guard("wl_session_set_event_callback", false, || {
        set_event_callback(handle, callback, user_data)
    })
}

fn set_event_callback(handle: u64, callback: Option<EventCallbackFn>, user_data: u64) -> bool {
    if let Some(callback_handle) = current_callback_handle() {
        set_last_error(format!(
            "session callback cannot be replaced from callback handle={callback_handle} target={handle}"
        ));
        return false;
    }
    let callback = callback.map(|value| EventCallback {
        callback: value,
        user_data,
    });
    set_session_callback(handle, callback)
}

/// Replace or clear the bearer token used by a running session.
///
/// # Safety
///
/// `auth_token` may be null. Otherwise it must point to a readable, NUL-terminated byte string
/// that remains valid for the duration of this call and contains valid UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wl_session_replace_auth_token(
    handle: u64,
    auth_token: *const c_char,
) -> bool {
    ffi_guard("wl_session_replace_auth_token", false, || {
        replace_auth_token(handle, auth_token)
    })
}

fn replace_auth_token(handle: u64, auth_token: *const c_char) -> bool {
    let token = if auth_token.is_null() {
        None
    } else {
        // SAFETY: forwarded from wl_session_replace_auth_token's caller contract.
        let Some(raw) = (unsafe { c_str_to_string(auth_token) }) else {
            set_last_error("invalid auth_token pointer".to_string());
            return false;
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    };

    let session = {
        let sessions = SESSIONS.lock();
        sessions.get(&handle).cloned()
    };
    let Some(session) = session else {
        set_last_error(format!("invalid session handle={handle}"));
        return false;
    };
    session.hello.lock().auth_token = token;
    clear_last_error();
    true
}

/// Update the session's application-state and optional power-tier hints.
///
/// # Safety
///
/// Each pointer may be null. Every non-null pointer must reference a readable, NUL-terminated byte
/// string that remains valid for the duration of this call and contains valid UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wl_session_set_power_hint(
    handle: u64,
    app_state: *const c_char,
    power_tier: *const c_char,
) -> bool {
    ffi_guard("wl_session_set_power_hint", false, || {
        set_power_hint(handle, app_state, power_tier)
    })
}

fn set_power_hint(handle: u64, app_state: *const c_char, power_tier: *const c_char) -> bool {
    let hint = if app_state.is_null() {
        None
    } else {
        // SAFETY: forwarded from wl_session_set_power_hint's caller contract.
        let Some(state_raw) = (unsafe { c_str_to_string(app_state) }) else {
            set_last_error("invalid app_state pointer".to_string());
            return false;
        };
        let Some(state) = parse_app_state(Some(state_raw.as_str())) else {
            set_last_error("app_state must be foreground/background".to_string());
            return false;
        };
        let tier = if power_tier.is_null() {
            None
        } else {
            // SAFETY: forwarded from wl_session_set_power_hint's caller contract.
            let Some(tier_raw) = (unsafe { c_str_to_string(power_tier) }) else {
                set_last_error("invalid power_tier pointer".to_string());
                return false;
            };
            let trimmed = tier_raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                match parse_power_tier(Some(trimmed)) {
                    Some(value) => Some(value),
                    None => {
                        set_last_error("power_tier must be high/balanced/low".to_string());
                        return false;
                    }
                }
            }
        };
        Some(ClientPowerHint {
            app_state: state,
            preferred_tier: tier,
        })
    };

    let session = {
        let sessions = SESSIONS.lock();
        sessions.get(&handle).cloned()
    };
    let Some(session) = session else {
        set_last_error(format!("invalid session handle={handle}"));
        return false;
    };
    *session.power_hint.lock() = hint;
    clear_last_error();
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn wl_session_stats_json(handle: u64) -> *mut c_char {
    ffi_guard("wl_session_stats_json", std::ptr::null_mut(), || {
        session_stats_json(handle)
    })
}

fn session_stats_json(handle: u64) -> *mut c_char {
    let session = {
        let sessions = SESSIONS.lock();
        sessions.get(&handle).cloned()
    };
    let Some(session) = session else {
        set_last_error(format!("invalid session handle={handle}"));
        return std::ptr::null_mut();
    };

    let stats = &session.stats;
    let event_queue_len = session
        .event_tx
        .lock()
        .as_ref()
        .map(flume::Sender::len)
        .unwrap_or_default();
    let callback_queue_pending_shard = CALLBACK_DISPATCHER.pending_len_for_handle(handle);
    let callback_queue_pending_global = CALLBACK_DISPATCHER.pending_len_global();
    let data = serde_json::json!({
        "uptime_ms": stats.started_at.elapsed().as_millis(),
        "events_in_total": stats.events_in_total.load(Ordering::Relaxed),
        "events_enqueued_total": stats.events_enqueued_total.load(Ordering::Relaxed),
        "events_dropped_total": stats.events_dropped_total.load(Ordering::Relaxed),
        // Compatibility fields from previous dual-queue model.
        "events_enqueued_critical": stats.events_enqueued_total.load(Ordering::Relaxed),
        "events_enqueued_best_effort": 0,
        "events_dropped_critical": stats.events_dropped_total.load(Ordering::Relaxed),
        "events_dropped_best_effort": 0,
        "callbacks_enqueued": stats.callbacks_enqueued.load(Ordering::Relaxed),
        "callbacks_dropped": stats.callbacks_dropped.load(Ordering::Relaxed),
        "callbacks_invoked": stats.callbacks_invoked.load(Ordering::Relaxed),
        "poll_returned": stats.poll_returned.load(Ordering::Relaxed),
        "event_queue_len": event_queue_len,
        "event_queue_capacity": EVENT_QUEUE_CAP,
        // Compatibility fields from previous dual-queue model.
        "event_queue_critical_len": event_queue_len,
        "event_queue_best_effort_len": 0,
        "callback_workers": CALLBACK_DISPATCHER.worker_count(),
        // Backward-compatible alias, now explicitly scoped to this session's shard.
        "callback_queue_pending": callback_queue_pending_shard,
        "callback_queue_pending_shard": callback_queue_pending_shard,
        "callback_queue_pending_global": callback_queue_pending_global,
    });

    clear_last_error();
    string_to_c(data.to_string().as_str())
}

/// # Safety
///
/// `ptr` and `len` must be the unchanged pair returned by a successful poll from the same loaded
/// warp-link library instance. The allocation must still be live and must be returned exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wl_buffer_free(ptr: *mut u8, len: u32) {
    ffi_guard("wl_buffer_free", (), || {
        // SAFETY: forwarded from wl_buffer_free's caller contract.
        unsafe { buffer_free(ptr, len) };
    });
}

/// # Safety
///
/// Same allocation-provenance, liveness, length, and single-free requirements as
/// [`wl_buffer_free`].
unsafe fn buffer_free(ptr: *mut u8, len: u32) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // SAFETY: ptr/len came from Box<[u8]> in string_to_buffer and are reconstructed once.
    unsafe {
        let slice = std::ptr::slice_from_raw_parts_mut(ptr, len as usize);
        drop(Box::from_raw(slice));
    }
}

#[unsafe(no_mangle)]
pub const extern "C" fn wl_abi_version() -> u32 {
    WL_ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn wl_session_last_error(_handle: u64) -> *mut c_char {
    ffi_guard("wl_session_last_error", std::ptr::null_mut(), || {
        session_last_error(_handle)
    })
}

fn session_last_error(handle: u64) -> *mut c_char {
    if handle != 0 {
        let session = {
            let sessions = SESSIONS.lock();
            sessions.get(&handle).cloned()
        };
        if let Some(session) = session
            && let Some(err) = session.last_error.lock().as_ref()
        {
            return string_to_c(err.as_str());
        }
    }
    let guard = LAST_ERROR.lock();
    match guard.as_deref() {
        Some(value) => string_to_c(value),
        None => std::ptr::null_mut(),
    }
}

/// # Safety
///
/// `ptr` must be a live pointer returned by `wl_session_last_error` or `wl_session_stats_json` from
/// the same loaded warp-link library instance. It must be returned exactly once and must not be
/// accessed after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wl_string_free(ptr: *mut c_char) {
    ffi_guard("wl_string_free", (), || {
        // SAFETY: forwarded from wl_string_free's caller contract.
        unsafe { string_free(ptr) };
    });
}

/// # Safety
///
/// Same allocation-provenance, liveness, and single-free requirements as [`wl_string_free`].
unsafe fn string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: ptr came from CString::into_raw in wl_session_last_error.
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}

/// # Safety
///
/// `value` must be null or point to a readable NUL-terminated string for the duration of this call.
unsafe fn c_str_to_string(value: *const c_char) -> Option<String> {
    if value.is_null() {
        return None;
    }
    // SAFETY: caller must pass a valid NUL-terminated string pointer.
    let cstr = unsafe { CStr::from_ptr(value) };
    cstr.to_str().ok().map(|v| v.to_string())
}

fn null_buffer() -> WlBuffer {
    WlBuffer {
        ptr: std::ptr::null_mut(),
        len: 0,
    }
}

fn set_last_error(err: String) {
    *LAST_ERROR.lock() = Some(err);
}

fn clear_last_error() {
    *LAST_ERROR.lock() = None;
}

fn set_session_callback(handle: u64, callback: Option<EventCallback>) -> bool {
    let session = {
        let sessions = SESSIONS.lock();
        sessions.get(&handle).cloned()
    };
    let Some(session) = session else {
        set_last_error(format!("invalid session handle={handle}"));
        return false;
    };
    if !session.lifecycle.replace_callback(callback) {
        set_last_error(format!("session is stopping handle={handle}"));
        return false;
    }
    clear_last_error();
    true
}

fn string_to_buffer(value: String) -> WlBuffer {
    let bytes = value.into_bytes().into_boxed_slice();
    if bytes.is_empty() || bytes.len() > u32::MAX as usize {
        return null_buffer();
    }
    let len = bytes.len() as u32;
    let ptr = Box::into_raw(bytes).cast::<u8>();
    WlBuffer { ptr, len }
}

fn string_to_c(value: &str) -> *mut c_char {
    CString::new(value)
        .map(|v| v.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn parse_power_hint(app_state: Option<&str>, perf_tier: Option<&str>) -> Option<ClientPowerHint> {
    let app_state = parse_app_state(app_state)?;
    Some(ClientPowerHint {
        app_state,
        preferred_tier: parse_power_tier(perf_tier),
    })
}

fn parse_app_state(value: Option<&str>) -> Option<ClientAppStateHint> {
    let normalized = value?.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "foreground" => Some(ClientAppStateHint::Foreground),
        "background" => Some(ClientAppStateHint::Background),
        _ => None,
    }
}

fn parse_power_tier(value: Option<&str>) -> Option<ClientPowerTier> {
    let normalized = value?.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "high" => Some(ClientPowerTier::High),
        "balanced" => Some(ClientPowerTier::Balanced),
        "low" => Some(ClientPowerTier::Low),
        _ => None,
    }
}

fn event_to_json(event: &ClientEvent) -> String {
    match event {
        ClientEvent::Connected { transport } => serde_json::json!({
            "type": "connected",
            "transport": transport.to_string(),
        })
        .to_string(),
        ClientEvent::Welcome { welcome } => serde_json::json!({
            "type": "welcome",
            "resume_token": welcome.resume_token,
            "heartbeat_secs": welcome.heartbeat_secs,
            "ping_interval_secs": welcome.ping_interval_secs,
            "idle_timeout_secs": welcome.idle_timeout_secs,
            "max_backoff_secs": welcome.max_backoff_secs,
            "auth_expires_at_unix_secs": welcome.auth_expires_at_unix_secs,
            "auth_refresh_before_secs": welcome.auth_refresh_before_secs,
            "wire_version": welcome.negotiated_wire_version,
            "payload_version": welcome.negotiated_payload_version,
        })
        .to_string(),
        ClientEvent::Disconnected { transport, reason } => serde_json::json!({
            "type": "disconnected",
            "transport": transport.to_string(),
            "reason": reason,
        })
        .to_string(),
        ClientEvent::Reconnecting {
            attempt,
            backoff_ms,
        } => serde_json::json!({
            "type": "reconnecting",
            "attempt": attempt,
            "backoff_ms": backoff_ms,
        })
        .to_string(),
        ClientEvent::Fatal { error } => serde_json::json!({
            "type": "fatal",
            "error": error,
        })
        .to_string(),
        ClientEvent::ProbeRtt {
            transport,
            rtt_ms,
            source,
        } => serde_json::json!({
            "type": "probe_rtt",
            "transport": transport.to_string(),
            "rtt_ms": rtt_ms,
            "source": match source {
                warp_link_core::ProbeRttSource::Manual => "manual",
                warp_link_core::ProbeRttSource::IdleKeepalive => "idle_keepalive",
            },
        })
        .to_string(),
        ClientEvent::SchedulerStateChanged { state, reason_code } => serde_json::json!({
            "type": "scheduler_state_changed",
            "state": format!("{state:?}").to_ascii_lowercase(),
            "reason_code": reason_code,
        })
        .to_string(),
        ClientEvent::CandidateStarted {
            from,
            to,
            decision_id,
        } => serde_json::json!({
            "type": "candidate_started",
            "from": from.to_string(),
            "to": to.to_string(),
            "decision_id": decision_id,
        })
        .to_string(),
        ClientEvent::CandidateReady {
            from,
            to,
            decision_id,
        } => serde_json::json!({
            "type": "candidate_ready",
            "from": from.to_string(),
            "to": to.to_string(),
            "decision_id": decision_id,
        })
        .to_string(),
        ClientEvent::CutoverCommitted {
            from,
            to,
            decision_id,
        } => serde_json::json!({
            "type": "cutover_committed",
            "from": from.to_string(),
            "to": to.to_string(),
            "decision_id": decision_id,
        })
        .to_string(),
        ClientEvent::CutoverRollback {
            restored,
            failed,
            decision_id,
            reason,
        } => serde_json::json!({
            "type": "cutover_rollback",
            "restored": restored.to_string(),
            "failed": failed.to_string(),
            "decision_id": decision_id,
            "reason": reason,
        })
        .to_string(),
        ClientEvent::DeadConnectionDetected {
            transport,
            reason_code,
        } => serde_json::json!({
            "type": "dead_connection_detected",
            "transport": transport.to_string(),
            "reason_code": reason_code,
        })
        .to_string(),
        ClientEvent::RecoveryTierEntered { tier, reason_code } => serde_json::json!({
            "type": "recovery_tier_entered",
            "tier": tier,
            "reason_code": reason_code,
        })
        .to_string(),
        ClientEvent::DecisionTrace { trace } => serde_json::json!({
            "type": "decision_trace",
            "decision_id": trace.decision_id,
            "winner_layer": format!("{:?}", trace.winner_layer).to_ascii_lowercase(),
            "reason_code": trace.reason_code,
            "selected_transport": trace.selected_transport.map(|value| value.to_string()),
            "inputs_digest": trace.inputs_digest,
            "suppressed_candidates": trace
                .suppressed_candidates
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        })
        .to_string(),
        ClientEvent::Message { .. } => serde_json::json!({
            "type": "internal_error",
            "error": "message events are serialized in QueueApp::on_event",
        })
        .to_string(),
    }
}

fn decode_payload_map(bytes: &[u8]) -> (serde_json::Value, bool) {
    let decoded: Result<PrivatePayloadEnvelope, _> = postcard::from_bytes(bytes);
    match decoded {
        Ok(envelope) => {
            if envelope.payload_version != 1 {
                return (
                    serde_json::json!({
                        "_payload_version": envelope.payload_version,
                        "_decode": "unsupported_version",
                    }),
                    false,
                );
            }
            match serde_json::to_value(envelope.data) {
                Ok(value) => (value, true),
                Err(_) => (serde_json::json!({}), false),
            }
        }
        Err(_) => (serde_json::json!({}), false),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Barrier, mpsc};

    use super::*;

    #[test]
    fn parse_app_state_accepts_known_values() {
        assert_eq!(
            parse_app_state(Some("foreground")),
            Some(ClientAppStateHint::Foreground)
        );
        assert_eq!(
            parse_app_state(Some(" Background ")),
            Some(ClientAppStateHint::Background)
        );
        assert_eq!(parse_app_state(Some("unknown")), None);
        assert_eq!(parse_app_state(None), None);
    }

    #[test]
    fn parse_power_tier_accepts_known_values() {
        assert_eq!(parse_power_tier(Some("high")), Some(ClientPowerTier::High));
        assert_eq!(
            parse_power_tier(Some("balanced")),
            Some(ClientPowerTier::Balanced)
        );
        assert_eq!(parse_power_tier(Some("low")), Some(ClientPowerTier::Low));
        assert_eq!(parse_power_tier(Some("x")), None);
    }

    #[test]
    fn parse_power_hint_requires_valid_state() {
        let hint = parse_power_hint(Some("foreground"), Some("balanced"))
            .expect("valid state should produce hint");
        assert_eq!(hint.app_state, ClientAppStateHint::Foreground);
        assert_eq!(hint.preferred_tier, Some(ClientPowerTier::Balanced));
        assert!(parse_power_hint(Some("invalid"), Some("high")).is_none());
    }

    #[test]
    fn decode_payload_map_handles_success_and_errors() {
        let mut data = HashMap::new();
        data.insert("channel_id".to_string(), "ch-1".to_string());
        let encoded = postcard::to_allocvec(&PrivatePayloadEnvelope {
            payload_version: PRIVATE_PAYLOAD_VERSION_V1,
            data,
        })
        .expect("envelope should encode");
        let (decoded, ok) = decode_payload_map(&encoded);
        assert!(ok);
        assert_eq!(decoded["channel_id"], "ch-1");

        let unsupported = postcard::to_allocvec(&PrivatePayloadEnvelope {
            payload_version: 9,
            data: HashMap::new(),
        })
        .expect("unsupported envelope should encode");
        let (decoded_unsupported, ok_unsupported) = decode_payload_map(&unsupported);
        assert!(!ok_unsupported);
        assert_eq!(decoded_unsupported["_decode"], "unsupported_version");

        let (decoded_invalid, ok_invalid) = decode_payload_map(b"not-postcard");
        assert!(!ok_invalid);
        assert_eq!(decoded_invalid, serde_json::json!({}));
    }

    extern "C" fn noop_callback(_user_data: u64, _ptr: *const u8, _len: u32) {}

    fn install_test_session() -> u64 {
        let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
        let lifecycle = Arc::new(SessionLifecycle::default());
        let completion = TaskCompletionGuard {
            lifecycle: Arc::clone(&lifecycle),
        };
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let (event_tx, event_rx) = flume::bounded(1);
        let task = runtime()
            .expect("test runtime should initialize")
            .spawn(async move {
                let _completion = completion;
                while !*shutdown_rx.borrow() {
                    if shutdown_rx.changed().await.is_err() {
                        break;
                    }
                }
            });
        let session = Arc::new(FfiSession {
            task: Mutex::new(Some(task)),
            shutdown_tx,
            event_tx: Mutex::new(Some(event_tx)),
            event_rx: Mutex::new(event_rx),
            hello: Arc::new(Mutex::new(HelloCtx::default())),
            power_hint: Arc::new(Mutex::new(None)),
            last_error: Arc::new(Mutex::new(None)),
            stats: Arc::new(SessionStats::new()),
            lifecycle,
        });
        assert!(SESSIONS.lock().insert(handle, session).is_none());
        handle
    }

    #[test]
    fn boxed_slice_buffer_round_trips_when_string_capacity_exceeds_length() {
        let mut value = String::with_capacity(4096);
        value.push_str("event");
        assert!(value.capacity() > value.len());

        let buffer = string_to_buffer(value);
        assert!(!buffer.ptr.is_null());
        assert_eq!(buffer.len, 5);
        // SAFETY: buffer was returned by string_to_buffer and is freed exactly once here.
        unsafe { wl_buffer_free(buffer.ptr, buffer.len) };
    }

    #[test]
    fn dropping_an_unpolled_task_future_marks_completion() {
        let lifecycle = Arc::new(SessionLifecycle::default());
        let completion = TaskCompletionGuard {
            lifecycle: Arc::clone(&lifecycle),
        };
        let unpolled = async move {
            let _completion = completion;
            std::future::pending::<()>().await;
        };

        drop(unpolled);
        assert!(lifecycle.wait_task_finished(Duration::ZERO));
    }

    #[test]
    #[cfg_attr(miri, ignore = "Tokio runtime requires unsupported OS I/O under Miri")]
    fn legacy_zero_timeout_is_nonblocking() {
        let handle = install_test_session();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let buffer = wl_session_poll_event(handle, 0);
            done_tx
                .send((buffer.ptr as usize, buffer.len))
                .expect("poll result receiver should remain");
        });

        let result = done_rx.recv_timeout(Duration::from_secs(1));
        if result.is_err() {
            assert!(wl_session_stop_v2(handle, 1_000));
            worker.join().expect("poll worker should exit after stop");
            panic!("zero-timeout legacy poll blocked");
        }
        assert_eq!(result.expect("checked above"), (0, 0));
        worker.join().expect("poll worker should not panic");
        assert!(wl_session_stop_v2(handle, 1_000));
    }

    #[test]
    #[cfg_attr(miri, ignore = "Tokio runtime requires unsupported OS I/O under Miri")]
    fn stop_wakes_legacy_infinite_poll() {
        let handle = install_test_session();
        let started = Arc::new(Barrier::new(2));
        let worker_started = Arc::clone(&started);
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            worker_started.wait();
            let buffer = wl_session_poll_event(handle, u32::MAX);
            done_tx
                .send((buffer.ptr as usize, buffer.len))
                .expect("poll result receiver should remain");
        });

        started.wait();
        assert!(
            done_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "infinite poll must remain blocked before stop"
        );
        assert!(wl_session_stop_v2(handle, 1_000));
        assert_eq!(
            done_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("stop must wake the blocked poll"),
            (0, 0)
        );
        worker.join().expect("poll worker should not panic");
    }

    #[test]
    #[cfg_attr(miri, ignore = "Tokio runtime requires unsupported OS I/O under Miri")]
    fn timed_stop_is_retriable_after_an_in_flight_callback_exits() {
        let handle = install_test_session();
        let session = SESSIONS
            .lock()
            .get(&handle)
            .cloned()
            .expect("test session should be registered");
        assert!(session.lifecycle.replace_callback(Some(EventCallback {
            callback: noop_callback,
            user_data: 9,
        })));
        let generation = session
            .lifecycle
            .callback_generation_if_active()
            .expect("callback should be active");
        let (_, in_flight) = session
            .lifecycle
            .begin_callback(generation)
            .expect("callback invocation should begin");

        assert!(
            !wl_session_stop_v2(handle, 10),
            "stop must report that callback quiescence missed its deadline"
        );
        assert!(session.lifecycle.is_closing());
        drop(in_flight);
        assert!(
            wl_session_stop_v2(handle, 1_000),
            "stop should be retriable after the callback exits"
        );
    }

    #[test]
    fn callback_replacement_waits_for_in_flight_callback() {
        let lifecycle = Arc::new(SessionLifecycle::default());
        assert!(lifecycle.replace_callback(Some(EventCallback {
            callback: noop_callback,
            user_data: 7,
        })));
        let generation = lifecycle
            .callback_generation_if_active()
            .expect("callback generation should be active");
        let (_, in_flight) = lifecycle
            .begin_callback(generation)
            .expect("callback should begin");
        let replacement_lifecycle = Arc::clone(&lifecycle);
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let replaced = replacement_lifecycle.replace_callback(None);
            done_tx
                .send(replaced)
                .expect("result receiver should remain");
        });

        assert!(
            done_rx.recv_timeout(Duration::from_millis(20)).is_err(),
            "replacement must wait while callback is in flight"
        );
        drop(in_flight);
        assert!(
            done_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("replacement should complete after callback exits")
        );
        worker.join().expect("replacement worker should not panic");
    }

    #[test]
    fn full_event_queue_requests_retry_instead_of_ack() {
        let (event_tx, _event_rx) = flume::bounded(1);
        let lifecycle = Arc::new(SessionLifecycle::default());
        let app = QueueApp {
            handle: u64::MAX,
            hello: Arc::new(Mutex::new(HelloCtx::default())),
            power_hint: Arc::new(Mutex::new(None)),
            event_tx,
            stats: Arc::new(SessionStats::new()),
            lifecycle,
        };
        let payload = postcard::to_allocvec(&PrivatePayloadEnvelope {
            payload_version: PRIVATE_PAYLOAD_VERSION_V1,
            data: HashMap::new(),
        })
        .expect("payload should encode");
        let message = |seq| ClientEvent::Message {
            transport: warp_link_core::TransportKind::Tcp,
            msg: warp_link_core::DeliverMsg {
                seq: Some(seq),
                id: format!("delivery-{seq}"),
                payload: payload.clone().into(),
            },
        };

        assert_eq!(app.on_event(message(1)), AppDecision::AckOk);
        assert_eq!(app.on_event(message(2)), AppDecision::RetryLater);
    }
}
