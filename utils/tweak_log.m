#include "tweak_log.h"
#include <pthread.h>
#include <string.h>

// Mutex shared across all translation units (not per-TU static in header).
pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

// In-memory ring of the most recent log lines — the on-screen debug HUD
// polls this instead of tailing files (a non-jailbroken sideload has no
// readable /tmp, and os_log isn't visible inside the app).
#define RING_LINES 400
#define RING_LINE_MAX 1024
static char g_ring[RING_LINES][RING_LINE_MAX];
static int g_ring_head = 0;    // next write slot
static int g_ring_count = 0;   // valid lines currently stored
static pthread_mutex_t g_ring_mutex = PTHREAD_MUTEX_INITIALIZER;

void tweak_log_ring_append(const char *line) {
    if (!line) return;
    pthread_mutex_lock(&g_ring_mutex);
    strncpy(g_ring[g_ring_head], line, RING_LINE_MAX - 1);
    g_ring[g_ring_head][RING_LINE_MAX - 1] = '\0';
    g_ring_head = (g_ring_head + 1) % RING_LINES;
    if (g_ring_count < RING_LINES) g_ring_count++;
    pthread_mutex_unlock(&g_ring_mutex);
}

int tweak_log_ring_snapshot(char *out, size_t outsz) {
    if (!out || outsz == 0) return 0;
    pthread_mutex_lock(&g_ring_mutex);
    int start = (g_ring_head - g_ring_count + RING_LINES) % RING_LINES;
    size_t used = 0;
    int count = 0;
    for (int i = 0; i < g_ring_count && used + 2 < outsz; i++) {
        int idx = (start + i) % RING_LINES;
        size_t l = strlen(g_ring[idx]);
        if (used + l + 2 > outsz) break; // truncate at budget
        memcpy(out + used, g_ring[idx], l);
        used += l;
        out[used++] = '\n';
        count++;
    }
    out[used] = '\0';
    pthread_mutex_unlock(&g_ring_mutex);
    return count;
}
