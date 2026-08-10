#ifndef W0LFSWORD_STATE_H
#define W0LFSWORD_STATE_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

// --- Disable toggle ---
#define TWEAK_DISABLE_FLAG "/var/mobile/Documents/.filza_tweak_disable"
bool tweak_is_disabled(void);

// --- Exploit lifecycle ---
bool exploit_is_done(void);
void exploit_set_done(void);
bool exploit_is_patching(void);
void exploit_set_patching(bool v);

// --- SSV activation ---
bool ssv_is_active(void);
void ssv_set_active(bool v);

// --- SSV inflight tracking (used by ensureSSVActive internally) ---
bool ssv_activation_inflight(void);
void ssv_set_activation_inflight(bool v);
uint64_t ssv_last_activation_ms(void);
void ssv_set_last_activation_ms(uint64_t ms);
pthread_mutex_t *ssv_mutex(void);

// --- UI debug bypass ---
bool ui_debug_bypass_get(void);
void ui_debug_bypass_set(bool v);

#ifdef __cplusplus
}
#endif

#endif /* W0LFSWORD_STATE_H */
