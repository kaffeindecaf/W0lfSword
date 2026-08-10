#include "state.h"
#include <stdatomic.h>
#include <unistd.h>

// --- Shared globals ---

_Atomic bool g_exploitDone = false;
_Atomic bool g_patching_in_progress = false;

static bool g_ssv_active = false;
static bool g_ssv_activation_inflight = false;
static uint64_t g_ssv_last_activation_ms = 0;
static pthread_mutex_t g_ssv_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_ui_debug_bypass = false;

// --- Disable toggle ---

bool tweak_is_disabled(void) {
    return (access(TWEAK_DISABLE_FLAG, F_OK) == 0);
}

// --- Exploit lifecycle ---

bool exploit_is_done(void) {
    return atomic_load_explicit(&g_exploitDone, memory_order_acquire);
}

void exploit_set_done(void) {
    atomic_store_explicit(&g_exploitDone, true, memory_order_release);
}

bool exploit_is_patching(void) {
    return atomic_load_explicit(&g_patching_in_progress, memory_order_acquire);
}

void exploit_set_patching(bool v) {
    atomic_store_explicit(&g_patching_in_progress, v, memory_order_release);
}

// --- SSV activation ---

bool ssv_is_active(void) {
    return g_ssv_active;
}

void ssv_set_active(bool v) {
    g_ssv_active = v;
}

// --- SSV inflight tracking ---

bool ssv_activation_inflight(void) {
    return g_ssv_activation_inflight;
}

void ssv_set_activation_inflight(bool v) {
    g_ssv_activation_inflight = v;
}

uint64_t ssv_last_activation_ms(void) {
    return g_ssv_last_activation_ms;
}

void ssv_set_last_activation_ms(uint64_t ms) {
    g_ssv_last_activation_ms = ms;
}

pthread_mutex_t *ssv_mutex(void) {
    return &g_ssv_mutex;
}

// --- UI debug bypass ---

bool ui_debug_bypass_get(void) {
    return g_ui_debug_bypass;
}

void ui_debug_bypass_set(bool v) {
    g_ui_debug_bypass = v;
}
