#ifndef TRM_PROBE_H
#define TRM_PROBE_H

// TRM.1 (exec surface) / TRM.2 (bundled-binary exec) / TRM.4 (pty) probes for
// the 0.11 "terminal with full kernel R/W" research round.
//
// Everything here is measurement, not machinery: each probe logs what the
// DEVICE actually answers (sandbox verdicts, errno, spawn exit status) so the
// A/B/C route decision in ROADMAP 0.11 stops being desk research. Pure C.

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Full report for one phase ("post-escape", "manual", "shell"). Safe to call
// repeatedly; read-only apart from the two spawn tests, which run a shell
// command with its output redirected into the app container.
void trm_probe_run_all(const char *phase);

// Single datapoint: raw sandbox_check(pid, op, ...) return for this process.
// 0 = ALLOWED, !=0 = DENIED, -1 = the call itself failed (errno set).
int trm_probe_sandbox_op(const char *op, const char *path);
// "ALLOWED" / "DENIED" / "ERR" for a raw sandbox_check value.
const char *trm_probe_sbx_word(int v);

// Inventory one directory: exec bit, Mach-O magic, and the sandbox verdict for
// "process-exec" on every entry. max_lines caps the per-entry log lines.
// Returns entries seen, or -1 when the directory can't be opened.
int trm_probe_exec_surface(const char *dir, int max_lines);

// TRM.1: fork() (process-fork rule) — pty shells need it, route A does not.
// Returns 0 when the child was created and reaped.
int trm_probe_fork_test(void);

// TRM.1/TRM.2: submit one spawn and report rc / errno / exit status plus the
// captured output. argv must be NULL-terminated and argv[0] set. outfile ==
// NULL means "<container>/Documents/trm_spawn_out.txt". Returns the
// posix_spawn return value (0 = spawned; then *exit_status_out is valid),
// or -1 when the wait timed out.
int trm_probe_spawn(const char *path, char *const argv[], int timeout_ms,
                    const char *outfile, int *exit_status_out);

// TRM.2: copy /bin/sh into the app container and exec the COPY — the closest
// available stand-in for "exec a binary shipped inside our own bundle" (a real
// bundle helper needs a signed sidecar binary; see ROADMAP 0.11 TRM.2).
int trm_probe_container_copy_exec(void);

// TRM.4: posix_openpt + grantpt + unlockpt + ptsname + slave open + a
// master->slave and slave->master round trip. Returns 0 on a working pty,
// negative errno of the first failing step otherwise.
int trm_probe_pty(char *slave_out, size_t n);

// TRM.5: can this process read (yes, sealed volume is readable) and write (no,
// until the SSV/extension patch applies) SystemVersion.plist? Logs both.
void trm_probe_sealed_volume(void);

// One-line summary of the last run_all — greppable field list for the log.
const char *trm_probe_verdict(void);

// The sandbox_check operand matrix on its own (also a shell builtin, so the
// profile can be re-measured after a route-B relaxation without a relaunch).
void trm_probe_sbx_matrix(void);

#ifdef __cplusplus
}
#endif

#endif /* TRM_PROBE_H */
