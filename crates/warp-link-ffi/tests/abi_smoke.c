#include <stddef.h>

#include "warp_link.h"

#if defined(__cplusplus)
static_assert(offsetof(WlBuffer, ptr) == 0, "WlBuffer.ptr offset drifted");
static_assert(offsetof(WlBuffer, len) == sizeof(void *), "WlBuffer.len offset drifted");
#else
_Static_assert(offsetof(WlBuffer, ptr) == 0, "WlBuffer.ptr offset drifted");
_Static_assert(offsetof(WlBuffer, len) == sizeof(void *), "WlBuffer.len offset drifted");
#endif

static void consume_event(uint64_t user_data, const uint8_t *ptr, uint32_t len) {
    (void)user_data;
    (void)ptr;
    (void)len;
}

int main(void) {
    WlBuffer buffer = {NULL, 0};
    WlEventCallback callback = consume_event;
    (void)callback;
    (void)wl_session_poll_event_v2(0, 0, &buffer);
    return wl_abi_version() == WL_ABI_VERSION_2_0 ? 0 : 1;
}
