// tests/trm_shell_host_test.c — host-side test for the route-A in-process shell
// (terminal/trm_shell.c). Compiles on Linux with the kernel/mach dependencies
// stubbed, so parsing, the POSIX commands and the unsafe gating are verified
// before a device round trip. It is NOT part of the tweak build.
//
//   bash scripts/run_trm_host_test.sh
//
// Kernel-side commands are covered by stubs that return recognisable values
// (fake proc_self, fake kread) so the test asserts the shell ROUTES them
// correctly without a kernel.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "terminal/trm_common.h"
#include "terminal/trm_shell.h"
#include "terminal/trm_probe.h"
#include "utils/tweak_log.h"   // tweak_log_hook_fn (stubbed below)

// --- output capture -------------------------------------------------------
static char g_last[256][1024];
static int g_count = 0;

static void test_out(const char *line, void *ctx) {
    (void)ctx;
    if (g_count < 256) snprintf(g_last[g_count], sizeof(g_last[0]), "%s", line);
    g_count++;
}

static int g_failures = 0;
static int g_checks = 0;

static int saw(const char *needle) {
    for (int i = 0; i < g_count && i < 256; i++) {
        if (strstr(g_last[i], needle)) return 1;
    }
    return 0;
}

static void check(int cond, const char *what) {
    g_checks++;
    if (cond) {
        printf("  ok   %s\n", what);
    } else {
        printf("  FAIL %s\n", what);
        g_failures++;
    }
}

static void run(const char *line, const char *label) {
    g_count = 0;
    int rc = trm_shell_exec_line(line);
    printf("  rc=%d  %-38s | %s\n", rc, label ? label : line, g_count > 0 ? g_last[0] : "(no output)");
}

// Run a command built from the container path.
static int run_fmt(const char *fmt, const char *arg, const char *label) {
    char line[PATH_MAX + 64];
    snprintf(line, sizeof(line), fmt, arg);
    run(line, label);
    return g_count;
}

// --- kernel / probe stubs -------------------------------------------------
pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
void tweak_log_ring_append(const char *line) { (void)line; }
int tweak_log_ring_snapshot(char *out, size_t outsz) { (void)out; (void)outsz; return 0; }
void tweak_log_set_hook(tweak_log_hook_fn fn) { (void)fn; }
void tweak_log_hook_emit(const char *line) { (void)line; }

int wolf_test_mode = 3;
bool exploit_is_done(void) { return true; }
uint64_t proc_self(void) { return 0xfffffff00aabbcc8ULL; }
uint64_t proc_find_by_name(const char *name) { return (name && !strcmp(name, "SpringBoard")) ? 0xfffffff00ddeeff0ULL : 0; }
uint64_t proc_get_cred_label(uint64_t proc) { return proc ? 0xfffffff00c0ffee0ULL : 0; }
uint64_t label_get_sandbox(uint64_t label) { return label ? 0xfffffff00badd00dULL : 0; }
int sandbox_escape_read_posix_creds(uint64_t proc, uint32_t *uid, uint32_t *gid, uint32_t *g0) {
    (void)proc;
    if (uid) *uid = 0;
    if (gid) *gid = 0;
    if (g0) *g0 = 0;
    return 0;
}
bool ssv_write(const char *path, const void *data, size_t len) { (void)path; (void)data; (void)len; return true; }

bool is_kaddr_valid(uint64_t addr) { return addr >= 0xfffffff000000000ULL; }
void kreadbuf(uint64_t addr, void *buf, uint64_t len) {
    // Zero-filled: a name read should produce an empty string in the host test
    // (garbage bytes would make the shell's log lines non-text).
    (void)addr;
    memset(buf, 0, (size_t)len);
}
uint16_t kread16(uint64_t a) { (void)a; return 0x1111; }
uint32_t kread32(uint64_t a) { return (uint32_t)(a & 0xffffffff); }
uint64_t kread64(uint64_t a) { return a ^ 0xffffffffffffff00ULL; }
void kwrite8(uint64_t a, uint8_t v) { printf("  [stub] kwrite8(0x%llx, %u)\n", (unsigned long long)a, v); }
void kwrite16(uint64_t a, uint16_t v) { printf("  [stub] kwrite16(0x%llx, %u)\n", (unsigned long long)a, v); }
void kwrite32(uint64_t a, uint32_t v) { printf("  [stub] kwrite32(0x%llx, %u)\n", (unsigned long long)a, v); }
void kwrite64(uint64_t a, uint64_t v) { printf("  [stub] kwrite64(0x%llx, %llu)\n", (unsigned long long)a, (unsigned long long)v); }
uint32_t off_proc_p_pid = 0x10, off_proc_p_name = 0x338;

// probe layer: recorded, not executed (no device in a host test)
static int g_probe_runs = 0;
static int g_sbx_runs = 0;
static int g_execsurf_runs = 0;
void trm_probe_run_all(const char *phase) { g_probe_runs++; trm_out("  [stub] trm_probe_run_all(%s)", phase ? phase : "(null)"); }
void trm_probe_sbx_matrix(void) { g_sbx_runs++; trm_out("  [stub] trm_probe_sbx_matrix"); }
int trm_probe_exec_surface(const char *dir, int max_lines) { g_execsurf_runs++; trm_out("  [stub] exec_surface(%s, %d)", dir, max_lines); return 0; }
int trm_probe_spawn(const char *path, char *const argv[], int timeout_ms, const char *outfile, int *exit_status_out) {
    (void)argv; (void)timeout_ms; (void)outfile;
    printf("  [stub] trm_probe_spawn(%s)\n", path);
    if (exit_status_out) *exit_status_out = -1;
    return 1;   // simulate a sandbox denial
}
int trm_probe_pty(char *slave_out, size_t n) { if (slave_out && n) slave_out[0] = '\0'; printf("  [stub] trm_probe_pty\n"); return -1; }
const char *trm_probe_verdict(void) { return "exec_profile=DENIED(1) pty_rc=-1 :: host-test stub verdict"; }
int trm_probe_fork_test(void) { return 0; }
int trm_probe_container_copy_exec(void) { return 1; }
void trm_probe_sealed_volume(void) {}

// --- test body ------------------------------------------------------------

int main(void) {
    char tmpdir[] = "/tmp/trm_shell_test_XXXXXX";
    if (!mkdtemp(tmpdir)) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        return 2;
    }
    trm_set_context(tmpdir, NULL);
    trm_set_default_output(test_out, NULL);
    // The shell starts in the process cwd; pin it to the container so the
    // relative-path tests below mean what they say (and so the test never
    // writes into the repo working tree).
    if (chdir(tmpdir) != 0) {
        fprintf(stderr, "chdir(%s) failed: %s\n", tmpdir, strerror(errno));
        return 2;
    }

    printf("trm_shell host test — container=%s\n", tmpdir);

    printf("\n[1] parser + dispatch\n");
    check(trm_shell_command_count() > 30, "command table populated (>30 commands)");
    run("echo hello  world", "echo collapses whitespace");
    check(saw("hello world"), "echo output correct");
    run("echo \"quoted text here\"", "quoted argument");
    check(saw("quoted text here"), "quotes group into one argv");
    run("# just a comment", "comment line");
    check(g_count == 0, "comment produces no output");
    run("", "empty line");
    check(g_count == 0, "empty line produces no output");
    run("   ", "whitespace line");
    check(g_count == 0, "whitespace-only line produces no output");
    run("nosuchcommand", "unknown command");
    check(saw("command not found"), "unknown command reported");
    run("echo a b c d e", "many args");
    check(saw("a b c d e"), "all args passed through");

    printf("\n[2] filesystem commands (real POSIX, temp dir)\n");
    run("pwd", "pwd");
    check(saw(tmpdir), "pwd is the container");
    run("mkdir sub", "mkdir");
    check(saw("created"), "mkdir reported");
    run("touch sub/file.txt", "touch");
    check(saw("touched"), "touch reported");
    run("ls -l .", "ls -l");
    check(saw("sub"), "ls lists the new dir");
    run("ls sub", "ls sub");
    check(saw("file.txt"), "ls lists the file");
    run("stat sub/file.txt", "stat");
    check(saw("type=file"), "stat identifies a file");
    run("cp sub/file.txt sub/copy.txt", "cp");
    check(saw("copied"), "cp reported");

    // Give cat real content (the shell has no redirection by design).
    char note[PATH_MAX];
    snprintf(note, sizeof(note), "%s/sub/note.txt", tmpdir);
    FILE *nf = fopen(note, "w");
    if (nf) { fprintf(nf, "trm-host-test-line\n"); fclose(nf); }
    run("cat sub/note.txt", "cat with content");
    check(saw("trm-host-test-line"), "cat prints file content");
    run("head -n 1 sub/note.txt", "head -n 1");
    check(saw("trm-host-test-line"), "head prints the first line");

    run("mv sub/copy.txt sub/moved.txt", "mv");
    check(saw("moved"), "mv reported");
    run("ls sub", "ls after mv");
    check(saw("moved.txt") && !saw("copy.txt"), "mv visible in ls");
    run("rm sub/moved.txt", "rm");
    run("ls sub", "ls after rm");
    check(!saw("moved.txt"), "rm removed the file");
    run("rm sub", "rm a non-empty dir without -r");
    check(saw("errno") || saw("!"), "rm refuses a non-empty dir");
    run("rmdir sub", "rmdir on a non-empty dir");
    check(saw("errno") || saw("!"), "rmdir refuses a non-empty dir");

    printf("\n[3] cd / path resolution\n");
    run("cd sub", "cd sub");
    run("pwd", "pwd after cd");
    check(saw("/sub"), "cwd is inside sub");
    run("cd ~", "cd ~ (container)");
    run("pwd", "pwd after cd ~");
    check(saw(tmpdir), "cd ~ lands in the container");
    run("cd /", "cd /");
    run("pwd", "pwd at /");
    check(saw("\n") || saw("/"), "cd / works");
    run("cd /definitely-not-here", "cd to a missing path");
    check(saw("errno") || saw("!"), "cd failure reports errno");
    run_fmt("cd %s", tmpdir, "cd back to the container");
    run("pwd", "pwd back in the container");
    check(saw(tmpdir), "cwd restored to the container");

    printf("\n[4] gating (unsafe)\n");
    run("unsafe 0", "unsafe 0");
    check(trm_shell_unsafe() == 0, "unsafe off");
    run("rm -r sub", "rm -r while gated");
    check(saw("gated"), "rm -r refused without unsafe");
    run("kwrite32 0xfffffff007004000 1", "kwrite32 while gated");
    check(saw("gated"), "kernel write refused without unsafe");
    run("chmod 777 sub", "chmod while gated");
    check(saw("gated"), "chmod refused without unsafe");
    run("ssvw /etc/hostname /tmp/x", "ssvw while gated");
    check(saw("gated"), "SSV write refused without unsafe");
    run("unsafe 1", "unsafe 1");
    check(trm_shell_unsafe() == 1, "unsafe on");
    check(strstr(trm_shell_prompt(), "unsafe") != NULL, "prompt shows unsafe state");
    run("kwrite32 0xfffffff007004000 1", "kwrite32 while allowed");
    check(saw("wrote"), "kernel write routed to kwrite32");
    run("kwrite64 0xfffffff007004000 0x4141", "kwrite64 while allowed");
    check(saw("wrote"), "kernel write routed to kwrite64");
    run("kwrite16 0xfffffff007004000 7", "kwrite16 while allowed");
    check(saw("wrote"), "kernel write routed to kwrite16");
    run("kwrite32 0x1000 1", "kwrite32 to a bad address");
    check(saw("not a kernel address"), "non-kernel address refused");
    run("chmod 644 sub/file.txt", "chmod while allowed");
    check(saw("chmod"), "chmod works when allowed");
    run("rm -r sub", "rm -r while allowed");
    check(!saw("gated"), "rm -r no longer gated");
    run("ls .", "ls after rm -r");
    check(!saw("sub"), "rm -r removed the tree");
    run("unsafe 0", "unsafe 0 (back to read-only)");
    check(trm_shell_unsafe() == 0, "unsafe off again");
    run("rm -r sub", "rm -r after re-gating");
    check(saw("gated"), "gating is not sticky");

    printf("\n[5] kernel + probe commands\n");
    run("krw", "krw status");
    check(saw("LIVE") && saw("proc_self"), "krw reports the live primitive");
    run("kread 0xfffffff007004000 32", "kread");
    check(saw("fffffff007004000"), "kread hexdump starts at the address");
    check(saw("|"), "kread prints an ascii column");
    run("kread 0x10 32", "kread bad address");
    check(saw("not in the kernel VA range"), "kread refuses non-kernel addresses");
    run("kread zz 32", "kread bad number");
    check(saw("bad address"), "kread rejects non-numeric input");
    run("id", "id");
    check(saw("uid=") && saw("kernel creds"), "id shows posix + kernel creds");
    run("proc SpringBoard", "proc lookup");
    check(saw("kaddr=0xfffffff00ddeeff0"), "proc reports the kernel proc address");
    run("proc nosuchproc", "proc miss");
    check(saw("not found"), "proc reports a miss");
    run("sbxinfo", "sbxinfo");
    check(saw("route B"), "sbxinfo names the route-B target");
    run("sbxtest", "sbxtest");
    check(g_sbx_runs == 1, "sbxtest routed to the probe layer");
    run("probe hosttest", "probe");
    check(g_probe_runs == 1, "probe reached trm_probe_run_all");
    run("verdict", "verdict");
    check(saw("stub verdict"), "verdict prints the probe layer's line");
    run("spawn /bin/sh", "spawn (stubbed denial)");
    check(saw("rc=1"), "spawn reports the denial rc");
    run("ptytest", "ptytest (stubbed denial)");
    check(saw("pty rc=-1"), "pty probe reports the denial");
    run("execsurf /bin", "execsurf");
    check(g_execsurf_runs == 1, "execsurf routed to the probe layer");
    run("sleep 0.05", "sleep (short)");
    run("uname", "uname");
    check(saw("Linux") || saw("Darwin"), "uname reports the host kernel");
    run("date", "date");
    check(saw("-"), "date formatted");
    run("df", "df");
    check(saw("total="), "df reports space");
    run("env", "env");
    run("help", "help");
    check(saw("in-process shell"), "help header present");
    run("help kread", "help kread");
    check(saw("hexdump kernel memory"), "help for one command");
    run("help nosuchcmd", "help unknown");
    check(saw("no such command"), "help reports an unknown command");

    printf("\n[6] packages (in-process command packs)\n");
    check(trm_shell_package_count() == 3, "three packages registered");
    check(trm_shell_package_index("sysinfo") == 0 && trm_shell_package_index("net") == 1 &&
          trm_shell_package_index("hex") == 2, "package index lookup");
    check(trm_shell_package_index("nope") == -1, "unknown package -> -1");
    check(trm_shell_package_name(0) && trm_shell_package_desc(0), "package name + description");
    run("pkg", "pkg list");
    check(saw("packages") && saw("sysinfo"), "pkg lists the packages");
    run("fetch", "fetch before install (gated)");
    check(saw("part of the 'sysinfo' package"), "package command refuses until installed");
    check(trm_shell_package_enabled(0) == 0, "sysinfo starts disabled");
    run("pkg install sysinfo", "pkg install");
    check(saw("installed") && trm_shell_package_enabled(0) == 1, "install enables the package");
    run("fetch", "fetch after install");
    check(saw("w0lfterm") && saw("route A shell"), "fetch renders the system card");
    run("loadavg", "loadavg");
    check(!saw("command not found"), "loadavg available");
    run("cpu", "cpu");
    check(saw("model"), "cpu reports the model");
    run("pkg install net", "pkg install net");
    run("net", "net");
    check(saw("iface") && saw("family"), "net lists interfaces");
    run("pkg install hex", "pkg install hex");
    char binfile[PATH_MAX];
    snprintf(binfile, sizeof(binfile), "%s/bin.dat", tmpdir);
    FILE *bf = fopen(binfile, "wb");
    if (bf) {
        const char *payload = "TRM-HOST-STRING\x01\x02\x03\xff\xfeTRM-SECOND";
        fwrite(payload, 1, strlen(payload), bf);
        fclose(bf);
    }
    run_fmt("strings %s", binfile, "strings on a binary");
    check(saw("TRM-HOST-STRING") && saw("TRM-SECOND"), "strings finds both runs");
    run_fmt("hexdump %s 0 32", binfile, "hexdump on a binary");
    check(saw("offset 0, 32 bytes") || saw("offset 0, 30 bytes"), "hexdump reports offset + length");
    run("pkg install nosuchpkg", "pkg install unknown");
    check(saw("no package named"), "unknown package reported");
    run("pkg remove sysinfo", "pkg remove");
    check(trm_shell_package_enabled(0) == 0, "remove disables the package");
    run("fetch", "fetch after remove");
    check(saw("part of the 'sysinfo' package"), "gating is re-applied after remove");
    run("pkg remove net", "cleanup: remove net");
    run("pkg remove hex", "cleanup: remove hex");

    printf("\n[7] selftest path (the device smoke test, stubbed deps)\n");
    trm_shell_selftest();
    check(1, "trm_shell_selftest() ran without crashing");

    char cmd[PATH_MAX + 32];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
    if (system(cmd) != 0) printf("  (cleanup of %s failed)\n", tmpdir);

    printf("\nchecks=%d failures=%d\n%s\n", g_checks, g_failures,
           g_failures == 0 ? "TRM_SHELL_HOST_TEST PASS" : "TRM_SHELL_HOST_TEST FAIL");
    return g_failures == 0 ? 0 : 1;
}
