#ifndef TRM_COMMON_H
#define TRM_COMMON_H

// Shared context for the 0.11 terminal-research modules (trm_probe + trm_shell).
//
// Pure C on purpose: these translation units compile as plain C (no
// Foundation), so the shell core can be built and exercised by a host test
// (tests/trm_shell_host_test.c) on Linux — no iOS SDK, no device. ObjC-only
// facts (NSHomeDirectory, NSBundle executable path) are pushed in ONCE from
// TweakInit via trm_set_context().

#include <stddef.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

// Called once from TweakInit. home = app container (NSHomeDirectory()),
// bundle_exec = NSBundle.mainBundle.executablePath (NULL when unknown).
void trm_set_context(const char *home, const char *bundle_exec);
const char *trm_ctx_home(void);          // app container, never NULL
const char *trm_ctx_docs(void);          // <container>/Documents, never NULL
const char *trm_ctx_bundle_exec(void);   // may be NULL
// Build <container>/Documents/<name> into out; returns out.
char *trm_ctx_docs_path(char *out, size_t n, const char *name);

// Output sink for terminal/probe lines. Default (NULL fn) = TweakLog, which
// fans out to /tmp + Documents/FilzaTweak.log + os_log + the on-screen HUD
// ring, so terminal output is visible in the app AND pullable over USB.
typedef void (*trm_out_fn)(const char *line, void *ctx);
void trm_set_default_output(trm_out_fn fn, void *ctx);
void trm_out(const char *fmt, ...);
// Emits to the default sink even while a redirect is active: errors and notices
// must stay visible in the terminal (TRM.2).
void trm_out_always(const char *fmt, ...);

// --- output redirection (TRM.2) -------------------------------------------
// `cmd > file` truncates, `cmd >> file` appends. While a redirect is open every
// trm_out line goes to the file instead of the sink; nested redirects are
// refused (-2). trm_redirect_active() returns the number of lines written so the
// caller can report "N line(s) written to ..." after closing.
int trm_redirect_open(const char *path, int append);   // 0 ok, -1 open failed, -2 nested
int trm_redirect_active(void);                         // lines written so far
void trm_redirect_close(void);

#ifdef __cplusplus
}
#endif

#endif /* TRM_COMMON_H */
