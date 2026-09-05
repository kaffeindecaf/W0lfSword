// hub_guard.c — L7.2 panic guard for the W0lfSword Hub app.
//
// Ports the tweak's A3.1 crash-counter + auto-disable logic (Tweak.m:1721-1743,
// TweakExploit.m mark_exploit_success) into the standalone Hub app, using plain
// fopen/fprintf/fscanf/unlink like the tweak, but with app-scoped flag files
// stored under the app's own Library/Application Support directory (sandbox).
//
// Semantics (ported verbatim):
//   * On launch, if no success flag exists and the guard is not disabled:
//     read the crash count, increment it, write it back; if it reaches 3,
//     write the disable flag and enter the disabled state (no kernel work).
//   * On proven success: write the success flag and reset/remove the crash count.
//   * The disable flag can be removed to re-enable.
#include "hub_guard.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define HUB_GUARD_SUCCESS_FILE "hub_last_success"
#define HUB_GUARD_CRASH_FILE   "hub_crash_count"
#define HUB_GUARD_DISABLE_FILE "hub_disable"
#define HUB_GUARD_CRASH_LIMIT  3
#define HUB_GUARD_PATH_MAX     1024

// App-scoped base directory (set by hub_guard_init). Empty = uninitialised.
static char g_app_support_dir[HUB_GUARD_PATH_MAX];

// Build a flag-file path under the base directory. Returns 0 on success.
static int hub_guard_path(char *out, size_t outsz, const char *name) {
    if (g_app_support_dir[0] == '\0') return -1;
    int n = snprintf(out, outsz, "%s/%s", g_app_support_dir, name);
    return (n < 0 || (size_t)n >= outsz) ? -1 : 0;
}

int hub_guard_init(const char *appSupportDir) {
    if (!appSupportDir || appSupportDir[0] == '\0') return -1;
    strncpy(g_app_support_dir, appSupportDir, sizeof(g_app_support_dir) - 1);
    g_app_support_dir[sizeof(g_app_support_dir) - 1] = '\0';
    // Best-effort create (parents are created by the caller via NSFileManager).
    if (mkdir(g_app_support_dir, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

int hub_guard_is_disabled(void) {
    char path[HUB_GUARD_PATH_MAX];
    // Uninitialised guard → fail safe (disabled) so no kernel work runs.
    if (hub_guard_path(path, sizeof(path), HUB_GUARD_DISABLE_FILE) != 0) return 1;
    return access(path, F_OK) == 0;
}

int hub_guard_crash_count(void) {
    char path[HUB_GUARD_PATH_MAX];
    if (hub_guard_path(path, sizeof(path), HUB_GUARD_CRASH_FILE) != 0) return 0;
    int count = 0;
    FILE *f = fopen(path, "r");
    if (f) {
        if (fscanf(f, "%d", &count) != 1) count = 0;
        fclose(f);
    }
    return count;
}

hub_guard_state_t hub_guard_register_launch(void) {
    char success[HUB_GUARD_PATH_MAX];
    char crash[HUB_GUARD_PATH_MAX];
    char disable[HUB_GUARD_PATH_MAX];

    if (g_app_support_dir[0] == '\0' ||
        hub_guard_path(success, sizeof(success), HUB_GUARD_SUCCESS_FILE) != 0 ||
        hub_guard_path(crash, sizeof(crash), HUB_GUARD_CRASH_FILE) != 0 ||
        hub_guard_path(disable, sizeof(disable), HUB_GUARD_DISABLE_FILE) != 0) {
        return HUB_GUARD_DISABLED; // cannot run the guard → do no kernel work
    }

    // Match Tweak.m:1724 — increment only when there is no success flag and
    // the guard is not already disabled.
    if (access(success, F_OK) != 0 && !hub_guard_is_disabled()) {
        int count = hub_guard_crash_count() + 1;
        FILE *cf = fopen(crash, "w");
        if (cf) {
            fprintf(cf, "%d", count);
            fclose(cf);
        }
        if (count >= HUB_GUARD_CRASH_LIMIT) {
            FILE *df = fopen(disable, "w");
            if (df) fclose(df);
            return HUB_GUARD_DISABLED;
        }
    }

    if (hub_guard_is_disabled()) {
        return HUB_GUARD_DISABLED;
    }
    return HUB_GUARD_OK;
}

void hub_guard_mark_success(void) {
    char success[HUB_GUARD_PATH_MAX];
    char crash[HUB_GUARD_PATH_MAX];
    if (g_app_support_dir[0] == '\0' ||
        hub_guard_path(success, sizeof(success), HUB_GUARD_SUCCESS_FILE) != 0 ||
        hub_guard_path(crash, sizeof(crash), HUB_GUARD_CRASH_FILE) != 0) {
        return;
    }
    FILE *sf = fopen(success, "w");
    if (sf) {
        fprintf(sf, "%lld", (long long)time(NULL));
        fclose(sf);
    }
    unlink(crash);
}
