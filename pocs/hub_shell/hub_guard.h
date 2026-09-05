#ifndef W0LFSWORD_HUB_GUARD_H
#define W0LFSWORD_HUB_GUARD_H

// L7.2 — panic guard for the W0lfSword Hub app.
// Pure-C port of the tweak's A3.1 crash-counter + auto-disable logic
// (Tweak.m:1721-1743, TweakExploit.m mark_exploit_success), with app-scoped
// flag files under the app's Library/Application Support directory.

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HUB_GUARD_OK = 0,       // guard cleared: kernel work may proceed
    HUB_GUARD_DISABLED = 1, // guard tripped: no kernel work
} hub_guard_state_t;

// Set the app-scoped base directory and (best-effort) create it. Call once
// before the other functions. Returns 0 on success, -1 on bad input/create.
int hub_guard_init(const char *appSupportDir);

// Run the launch registration: increments the crash counter when no success
// flag exists and the guard is not disabled; writes the disable flag and
// returns HUB_GUARD_DISABLED once the counter reaches 3.
hub_guard_state_t hub_guard_register_launch(void);

// Record a proven exploit success (writes the success flag, removes the crash
// counter). Does not clear the disable flag — remove it manually to re-enable.
void hub_guard_mark_success(void);

// 1 if the disable flag is present (or the guard is uninitialised), else 0.
int hub_guard_is_disabled(void);

// Current stored crash count (0 when the counter file is absent/corrupt).
int hub_guard_crash_count(void);

#ifdef __cplusplus
}
#endif

#endif /* W0LFSWORD_HUB_GUARD_H */
