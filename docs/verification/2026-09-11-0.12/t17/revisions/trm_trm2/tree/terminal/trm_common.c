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

// TRM.2 redirection state. One redirect at a time: the shell is serial (one
// command at a time on its own queue) and nesting would make the file/terminal
// split ambiguous.
static FILE *g_redir = NULL;
static int g_redir_lines = 0;

void trm_set_default_output(trm_out_fn fn, void *ctx) {
    g_out_fn = fn;
    g_out_ctx = ctx;
}

int trm_redirect_open(const char *path, int append) {
    if (g_redir) return -2;
    if (!path || !path[0]) return -1;
    FILE *f = fopen(path, append ? "a" : "w");
    if (!f) return -1;
    g_redir = f;
    g_redir_lines = 0;
    return 0;
}

int trm_redirect_active(void) {
    return g_redir_lines;
}

void trm_redirect_close(void) {
    if (!g_redir) return;
    fflush(g_redir);
    fclose(g_redir);
    g_redir = NULL;
}

static void trm_emit(int bypass, const char *buf) {
    if (!bypass && g_redir) {
        fprintf(g_redir, "%s\n", buf);
        g_redir_lines++;
        return;
    }
    if (g_out_fn) {
        g_out_fn(buf, g_out_ctx);
        return;
    }
    TweakLog("%s", buf);
}

void trm_out(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    trm_emit(0, buf);
}

void trm_out_always(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    trm_emit(1, buf);
}
