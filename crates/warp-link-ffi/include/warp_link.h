#ifndef WARP_LINK_H
#define WARP_LINK_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WL_ABI_VERSION_2_0 0x00020000u
#define WL_POLL_OK 0
#define WL_POLL_TIMEOUT 1
#define WL_POLL_STOPPED 2
#define WL_POLL_INVALID_HANDLE (-1)
#define WL_POLL_INVALID_ARGUMENT (-2)
#define WL_POLL_INFINITE UINT32_MAX

typedef struct WlBuffer {
    uint8_t *ptr;
    uint32_t len;
} WlBuffer;

/* The callback must not throw a C++ exception or otherwise unwind across this C ABI. */
typedef void (*WlEventCallback)(uint64_t user_data, const uint8_t *ptr, uint32_t len);

uint32_t wl_abi_version(void);
uint64_t wl_session_start(const char *config_json);

/* timeout_ms == 0 is non-blocking and WL_POLL_INFINITE waits indefinitely. */
WlBuffer wl_session_poll_event(uint64_t handle, uint32_t timeout_ms);

/*
 * Explicit API: timeout_ms == 0 is non-blocking and WL_POLL_INFINITE waits
 * indefinitely. On every return, out_buffer is initialized; a non-OK result
 * returns {NULL, 0}.
 */
int32_t wl_session_poll_event_v2(
    uint64_t handle,
    uint32_t timeout_ms,
    WlBuffer *out_buffer
);

/* Legacy stop uses a 5-second quiescence budget. */
void wl_session_stop(uint64_t handle);

/*
 * Stop wakes blocked polls and prevents new callbacks immediately. true means
 * the Rust task and all callbacks are quiescent and the handle was removed.
 * false means the deadline expired; the handle remains closing and this call
 * may be retried after the foreign callback returns.
 */
bool wl_session_stop_v2(uint64_t handle, uint32_t timeout_ms);

/*
 * Replacing or clearing a callback is quiescent: after this function returns,
 * the previous callback and user_data are no longer in use. Do not call this
 * function or either stop function from inside any warp-link callback.
 * Callbacks must return promptly so quiescent replacement/stop can complete.
 */
bool wl_session_set_event_callback(
    uint64_t handle,
    WlEventCallback callback,
    uint64_t user_data
);

bool wl_session_replace_auth_token(uint64_t handle, const char *auth_token);
bool wl_session_set_power_hint(
    uint64_t handle,
    const char *app_state,
    const char *power_tier
);

char *wl_session_stats_json(uint64_t handle);
char *wl_session_last_error(uint64_t handle);

/* Rust-owned values must be returned to the matching Rust destructor once. */
void wl_buffer_free(uint8_t *ptr, uint32_t len);
void wl_string_free(char *ptr);

#ifdef __cplusplus
}
#endif

#endif
