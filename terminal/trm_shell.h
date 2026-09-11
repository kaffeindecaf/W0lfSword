#ifndef TRM_SHELL_H
#define TRM_SHELL_H

// TRM.3 — route A of the 0.11 terminal research: an IN-PROCESS shell.
//
// No posix_spawn, no pty, no dependency on the sandbox profile allowing
// process-exec or /dev/ptmx. Commands run inside the Filza process (which the
// kernel exploit has already escaped + given kernel R/W), so this route works
// the moment the escape is live — and it is the route every App Store terminal
// on iOS uses (a-Shell/ios_system; iSH dodges it with an x86 emulator, because
// "creating pages of executable code" does not survive review — see ROADMAP
// 0.11 findings).
//
// Pure C, no Foundation: the core is exercised on the host by
// tests/trm_shell_host_test.c, so parsing/execution bugs are caught before a
// device round trip.

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Runs one command line. Returns 0 on success, 1 on usage/unknown-command
// errors, 2 when a command needs `unsafe 1` first, -1 on an internal failure.
int trm_shell_exec_line(const char *line);

// "w0lf> " / "w0lf(unsafe)> " — for a future prompt label in the UI.
const char *trm_shell_prompt(void);

// Kernel writes (kwrite*, ssvw, rm -r) are refused until this is enabled.
// Read-only introspection (kread, sbxinfo, ps, ls everywhere, cat everywhere)
// needs no flag.
int trm_shell_unsafe(void);
void trm_shell_set_unsafe(int v);

// Scripted smoke test: runs a fixed list of read-only commands and logs one
// [TRM][SELFTEST] line per step. Gives a device verdict without any UI.
void trm_shell_selftest(void);

// Number of registered commands (host test asserts the table is intact).
int trm_shell_command_count(void);

// --- packages -------------------------------------------------------------
// Command packs that are not part of the core shell. The host app's Settings
// screen (W0lfTerm) toggles them; the `pkg` command does the same from inside
// the Filza HUD terminal, which has no settings UI. State is in-memory: the
// app persists it (NSUserDefaults) and pushes it back at launch.
//
// Why packs at all: everything here runs IN-PROCESS (no exec, no pty - route A
// of ROADMAP 0.11), so a "package" is a group of builtin commands, not a
// downloaded binary. Real .deb/tarball installs need exec (route B/C).
int trm_shell_package_count(void);
const char *trm_shell_package_name(int i);
const char *trm_shell_package_desc(int i);
int trm_shell_package_enabled(int i);
void trm_shell_set_package_enabled(int i, int on);
// Returns the package index for a name, or -1.
int trm_shell_package_index(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* TRM_SHELL_H */
