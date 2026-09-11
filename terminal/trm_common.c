// terminal/trm_common.c — context + output sink shared by the 0.11 terminal
// modules. Kept dependency-light (TweakLog only) so the host test can link it.

#include "terminal/trm_common.h"
#include "utils/tweak_log.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static char g_home[PATH_MAX] = {0};
static char g_docs[PATH_MAX] = {0};
static char g_bundle_exec[PATH_MAX] = {0};

void trm_set_context(const char *home, const char *bundle_exec) {
    if (home && home[0]) {
        snprintf(g_home, sizeof(g_home), "%s", home);
        snprintf(g_docs, sizeof(g_docs), "%s/Documents", home);
    }
    if (bundle_exec && bundle_exec[0]) {
        snprintf(g_bundle_exec, sizeof(g_bundle_exec), "%s", bundle_exec);
    }
}

const char *trm_ctx_home(void) {
    return g_home[0] ? g_home : "/var/mobile";
}

const char *trm_ctx_docs(void) {
    return g_docs[0] ? g_docs : "/var/mobile/Documents";
}

const char *trm_ctx_bundle_exec(void) {
    return g_bundle_exec[0] ? g_bundle_exec : NULL;
}

char *trm_ctx_docs_path(char *out, size_t n, const char *name) {
    snprintf(out, n, "%s/%s", trm_ctx_docs(), name ? name : "");
    return out;
}

static trm_out_fn g_out_fn = NULL;
static void *g_out_ctx = NULL;

void trm_set_default_output(trm_out_fn fn, void *ctx) {
    g_out_fn = fn;
    g_out_ctx = ctx;
}

void trm_out(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (g_out_fn) {
        g_out_fn(buf, g_out_ctx);
        return;
    }
    TweakLog("%s", buf);
}
