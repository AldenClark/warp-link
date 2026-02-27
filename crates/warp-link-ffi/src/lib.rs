use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use flume::TrySendError;
use parking_lot::Mutex;
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
}

impl QueueApp {
    fn enqueue_event(&self, payload: String) {
        self.stats.events_in_total.fetch_add(1, Ordering::Relaxed);
        match self.event_tx.try_send(payload) {
            Ok(()) => {
                self.stats
                    .events_enqueued_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.stats
                    .events_dropped_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn enqueue_callback(&self, event: &str) {
        if session_callback(self.handle).is_none() {
            return;
        }

        let task = CallbackTask {
            handle: self.handle,
            event: event.to_string(),
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
                self.enqueue_callback(serialized.as_str());
                self.enqueue_event(serialized);
                if decode_ok {
                    AppDecision::AckOk
                } else {
                    AppDecision::AckInvalidPayload
                }
            }
            other => {
                let serialized = event_to_json(&other);
                self.enqueue_callback(serialized.as_str());
                self.enqueue_event(serialized);
                AppDecision::Ignore
            }
        }
    }

    fn power_hint(&self) -> Option<ClientPowerHint> {
        *self.power_hint.lock()
    }
}

struct FfiSession {
    task: Mutex<tokio::task::JoinHandle<()>>,
    shutdown_tx: watch::Sender<bool>,
    event_tx: flume::Sender<String>,
    event_rx: Mutex<flume::Receiver<String>>,
    hello: Arc<Mutex<HelloCtx>>,
    power_hint: Arc<Mutex<Option<ClientPowerHint>>>,
    callback: Mutex<Option<EventCallback>>,
    last_error: Arc<Mutex<Option<String>>>,
    stats: Arc<SessionStats>,
}

#[derive(Debug)]
struct CallbackTask {
    handle: u64,
    event: String,
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
        let callback = *session.callback.lock();
        let Some(callback) = callback else {
            continue;
        };
        let bytes = task.event.into_bytes();
        (callback.callback)(callback.user_data, bytes.as_ptr(), bytes.len() as u32);

        session
            .stats
            .callbacks_invoked
            .fetch_add(1, Ordering::Relaxed);
    }
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

type EventCallbackFn = extern "C" fn(user_data: u64, ptr: *const u8, len: u32);

#[derive(Clone, Copy)]
struct EventCallback {
    callback: EventCallbackFn,
    user_data: u64,
}

#[repr(C)]
pub struct WlBuffer {
    ptr: *mut u8,
    len: u32,
}

#[unsafe(no_mangle)]
pub extern "C" fn wl_session_start(config_json: *const c_char) -> u64 {
    let Some(raw) = c_str_to_string(config_json) else {
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
    }

    let hello = HelloCtx {
        identity: parsed.identity,
        auth_token: parsed
            .auth_token
            .clone()
            .or_else(|| parsed.bearer_token.clone()),
        resume_token: parsed.resume_token,
        last_acked_seq: parsed.last_acked_seq,
        supported_wire_versions: vec![1],
        supported_payload_versions: vec![1],
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
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    let app = QueueApp {
        handle,
        hello: Arc::clone(&hello),
        power_hint: Arc::clone(&power_hint),
        event_tx: event_tx.clone(),
        stats: Arc::clone(&stats),
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
    let task = runtime.spawn(async move {
        if let Err(err) = client_run_with_shutdown(config, app, shutdown_rx).await {
            *task_error.lock() = Some(err.to_string());
            set_last_error(err.to_string());
        }
    });

    SESSIONS.lock().insert(
        handle,
        Arc::new(FfiSession {
            task: Mutex::new(task),
            shutdown_tx,
            event_tx,
            event_rx: Mutex::new(event_rx),
            hello,
            power_hint,
            callback: Mutex::new(None),
            last_error,
            stats,
        }),
    );
    clear_last_error();
    handle
}

#[unsafe(no_mangle)]
pub extern "C" fn wl_session_poll_event(handle: u64, timeout_ms: u32) -> WlBuffer {
    let session = {
        let sessions = SESSIONS.lock();
        sessions.get(&handle).cloned()
    };
    let Some(session) = session else {
        set_last_error(format!("invalid session handle={handle}"));
        return null_buffer();
    };

    let recv_result = if timeout_ms == 0 {
        session
            .event_rx
            .lock()
            .recv()
            .map_err(|_| flume::RecvTimeoutError::Disconnected)
    } else {
        session
            .event_rx
            .lock()
            .recv_timeout(Duration::from_millis(timeout_ms as u64))
    };

    let event = match recv_result {
        Ok(text) => {
            session.stats.poll_returned.fetch_add(1, Ordering::Relaxed);
            Some(text)
        }
        Err(flume::RecvTimeoutError::Timeout) | Err(flume::RecvTimeoutError::Disconnected) => None,
    };

    let Some(text) = event else {
        return null_buffer();
    };

    let mut bytes = text.into_bytes();
    let len = bytes.len() as u32;
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    WlBuffer { ptr, len }
}

#[unsafe(no_mangle)]
pub extern "C" fn wl_session_stop(handle: u64) {
    let session = {
        let mut sessions = SESSIONS.lock();
        sessions.remove(&handle)
    };
    let Some(session) = session else {
        set_last_error(format!("invalid session handle={handle}"));
        return;
    };
    let _ = session.shutdown_tx.send(true);
    session.task.lock().abort();
}

#[unsafe(no_mangle)]
pub extern "C" fn wl_session_set_event_callback(
    handle: u64,
    callback: Option<EventCallbackFn>,
    user_data: u64,
) -> bool {
    let callback = callback.map(|value| EventCallback {
        callback: value,
        user_data,
    });
    set_session_callback(handle, callback)
}

#[unsafe(no_mangle)]
pub extern "C" fn wl_session_replace_auth_token(handle: u64, auth_token: *const c_char) -> bool {
    let token = if auth_token.is_null() {
        None
    } else {
        let Some(raw) = c_str_to_string(auth_token) else {
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

#[unsafe(no_mangle)]
pub extern "C" fn wl_session_set_power_hint(
    handle: u64,
    app_state: *const c_char,
    power_tier: *const c_char,
) -> bool {
    let hint = if app_state.is_null() {
        None
    } else {
        let Some(state_raw) = c_str_to_string(app_state) else {
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
            let Some(tier_raw) = c_str_to_string(power_tier) else {
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
    let session = {
        let sessions = SESSIONS.lock();
        sessions.get(&handle).cloned()
    };
    let Some(session) = session else {
        set_last_error(format!("invalid session handle={handle}"));
        return std::ptr::null_mut();
    };

    let stats = &session.stats;
    let event_queue_len = session.event_tx.len();
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

#[unsafe(no_mangle)]
/// # Safety
///
/// `ptr`/`len` must come from `wl_session_poll_event` and be freed exactly once.
pub unsafe extern "C" fn wl_buffer_free(ptr: *mut u8, len: u32) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // SAFETY: ptr/len came from wl_session_poll_event and are reconstructed exactly once.
    unsafe {
        let _ = Vec::from_raw_parts(ptr, len as usize, len as usize);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn wl_session_last_error(_handle: u64) -> *mut c_char {
    if _handle != 0 {
        let session = {
            let sessions = SESSIONS.lock();
            sessions.get(&_handle).cloned()
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

#[unsafe(no_mangle)]
/// # Safety
///
/// `ptr` must come from `wl_session_last_error` and be freed exactly once.
pub unsafe extern "C" fn wl_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: ptr came from CString::into_raw in wl_session_last_error.
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}

fn c_str_to_string(value: *const c_char) -> Option<String> {
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

fn session_callback(handle: u64) -> Option<EventCallback> {
    let session = {
        let sessions = SESSIONS.lock();
        sessions.get(&handle).cloned()
    }?;
    *session.callback.lock()
}

fn set_session_callback(handle: u64, callback: Option<EventCallback>) -> bool {
    let sessions = SESSIONS.lock();
    let Some(session) = sessions.get(&handle) else {
        set_last_error(format!("invalid session handle={handle}"));
        return false;
    };
    *session.callback.lock() = callback;
    clear_last_error();
    true
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
    use super::*;

    extern "C" fn noop_callback(_user_data: u64, _ptr: *const u8, _len: u32) {}

    fn make_event_channel(cap: usize) -> (flume::Sender<String>, flume::Receiver<String>) {
        flume::bounded(cap)
    }

    fn insert_test_session(handle: u64) -> Arc<FfiSession> {
        let runtime = runtime().expect("runtime should be available in tests");
        let task = runtime.spawn(async {});
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        let (event_tx, event_rx) = make_event_channel(8);
        let session = Arc::new(FfiSession {
            task: Mutex::new(task),
            shutdown_tx,
            event_tx,
            event_rx: Mutex::new(event_rx),
            hello: Arc::new(Mutex::new(HelloCtx::default())),
            power_hint: Arc::new(Mutex::new(None)),
            callback: Mutex::new(None),
            last_error: Arc::new(Mutex::new(None)),
            stats: Arc::new(SessionStats::new()),
        });
        SESSIONS.lock().insert(handle, Arc::clone(&session));
        session
    }

    fn remove_test_session(handle: u64) {
        if let Some(session) = SESSIONS.lock().remove(&handle) {
            let _ = session.shutdown_tx.send(true);
            session.task.lock().abort();
        }
    }

    #[test]
    fn set_event_callback_is_scoped_to_existing_session() {
        let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
        let _session = insert_test_session(handle);

        assert!(set_session_callback(
            handle,
            Some(EventCallback {
                callback: noop_callback,
                user_data: 7,
            }),
        ));
        let stored = session_callback(handle).expect("callback should be set");
        assert_eq!(stored.user_data, 7);

        remove_test_session(handle);

        assert!(!set_session_callback(
            handle,
            Some(EventCallback {
                callback: noop_callback,
                user_data: 9,
            }),
        ));
        assert!(session_callback(handle).is_none());
    }

    #[test]
    fn session_stats_json_exposes_shard_and_global_callback_pending() {
        let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
        let _session = insert_test_session(handle);

        let ptr = wl_session_stats_json(handle);
        assert!(!ptr.is_null());
        // SAFETY: wl_session_stats_json returns a valid NUL-terminated string or null.
        let json = unsafe { CStr::from_ptr(ptr) }
            .to_str()
            .expect("stats json should be valid utf-8")
            .to_string();
        // SAFETY: ptr came from wl_session_stats_json and must be freed once.
        unsafe { wl_string_free(ptr) };

        let value: serde_json::Value =
            serde_json::from_str(&json).expect("stats json should parse as object");
        assert!(value.get("callback_queue_pending_shard").is_some());
        assert!(value.get("callback_queue_pending_global").is_some());
        assert_eq!(
            value["callback_queue_pending"],
            value["callback_queue_pending_shard"]
        );

        remove_test_session(handle);
    }

    #[test]
    fn poll_event_returns_enqueued_payload() {
        let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
        let session = insert_test_session(handle);
        session
            .event_tx
            .try_send("{\"type\":\"message\",\"id\":\"x\"}".to_string())
            .expect("enqueue should work");

        let out = wl_session_poll_event(handle, 5);
        assert!(!out.ptr.is_null());
        assert!(out.len > 0);
        // SAFETY: out.ptr/out.len are owned buffer returned by wl_session_poll_event.
        let payload = unsafe {
            let bytes = std::slice::from_raw_parts(out.ptr, out.len as usize);
            std::str::from_utf8(bytes)
                .expect("payload should be valid utf-8")
                .to_string()
        };
        assert_eq!(payload, "{\"type\":\"message\",\"id\":\"x\"}");
        // SAFETY: buffer returned by wl_session_poll_event must be freed once.
        unsafe { wl_buffer_free(out.ptr, out.len) };

        remove_test_session(handle);
    }

    #[test]
    fn single_queue_overflow_drops_new_event() {
        let (event_tx, event_rx) = make_event_channel(1);
        let stats = Arc::new(SessionStats::new());
        let app = QueueApp {
            handle: 42,
            hello: Arc::new(Mutex::new(HelloCtx::default())),
            power_hint: Arc::new(Mutex::new(None)),
            event_tx,
            stats: Arc::clone(&stats),
        };

        app.enqueue_event("first".to_string());
        app.enqueue_event("second".to_string());

        assert_eq!(stats.events_in_total.load(Ordering::Relaxed), 2);
        assert_eq!(stats.events_enqueued_total.load(Ordering::Relaxed), 1);
        assert_eq!(stats.events_dropped_total.load(Ordering::Relaxed), 1);
        assert_eq!(event_rx.recv().expect("first event should stay"), "first");
        assert!(event_rx.try_recv().is_err());
    }
}
