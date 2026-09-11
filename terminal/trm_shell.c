// terminal/trm_shell.c — TRM.3, route A of the 0.11 terminal research:
// an in-process shell. No exec, no pty, no sandbox rule to relax.
//
// Why this is the shipped route (ROADMAP 0.11 findings, 2026-09-11):
//   * a jailed /bin ships almost nothing to run, so a working spawn buys less
//     than it looks like;
//   * posix_spawn + /dev/ptmx are governed by sandbox PROFILE rules
//     (process-exec, file-* on /dev/ptmx), and our escape rewrites extension
//     paths + the class — it does not add rules, so both are expected to fail
//     until the sandbox label itself is relaxed (route B) or a daemon is made
//     to spawn for us (route C);
//   * every App Store terminal does it this way (a-Shell/ios_system; iSH
//     sidesteps exec with an emulator).
// This shell therefore implements commands in-process over POSIX + kernel R/W,
// and only reaches for exec/pty through explicit probe commands.
//
// Pure C on purpose — tests/trm_shell_host_test.c compiles this file on the
// host (with mach/kernel deps stubbed) so parsing and the POSIX commands are
// verified before any device round trip.

#include "terminal/trm_shell.h"
#include "terminal/trm_common.h"
#include "terminal/trm_probe.h"

#include "kexploit/krw.h"        // kread*/kwrite*/is_kaddr_valid
#include "kexploit/kutils.h"     // proc_self, proc_find_by_name, label helpers
#include "kexploit/offsets.h"    // off_proc_p_pid / off_proc_p_name
#include "utils/state.h"         // exploit_is_done
#include "utils/tweak_log.h"     // TweakLog (selftest)
#include "sandbox_escape.h"      // sandbox_escape_read_posix_creds

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#endif
#include <sys/utsname.h>
#include <sys/wait.h>

// SSV/SSVUtils.h pulls in Foundation (ObjC only), so the one symbol the shell
// needs is declared here; the definition lives in SSV/SSVUtils.m.
bool ssv_write(const char *path, const void *data, size_t len);
// kexploit/kexploit_opa334.h likewise imports Foundation/UIKit.
extern int wolf_test_mode;

extern char **environ;

#define TRM_MAX_ARGS      24
#define TRM_MAX_ARG_LEN   512
#define TRM_READ_MAX      4096     // bytes per kread
#define TRM_CAT_LINE_MAX  512
#define TRM_CAT_LINES_MAX 400
#define TRM_LS_MAX        200
#define TRM_LS_NAME_MAX   200

static int g_unsafe = 0;
static char g_prompt[32] = "w0lf> ";
static char g_ls_names[TRM_LS_MAX][TRM_LS_NAME_MAX];

// --- output ---------------------------------------------------------------

static void sh_out(const char *fmt, ...) {
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    trm_out("[sh] %s", msg);
}

static void sh_err(const char *fmt, ...) {
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    trm_out("[sh] ! %s", msg);
}

static void sh_hexdump(uint64_t base, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i += 16) {
        char hex[64] = {0};
        char asc[17];
        int hl = 0;
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                // Bounded: the hex column of a full row is 49 chars, so a guard
                // keeps a long snprintf return from underflowing the size arg.
                if (hl < (int)sizeof(hex) - 4) {
                    hl += snprintf(hex + hl, sizeof(hex) - (size_t)hl, "%02x ", b[i + j]);
                }
                asc[j] = (b[i + j] >= 0x20 && b[i + j] <= 0x7e) ? (char)b[i + j] : '.';
            } else {
                asc[j] = ' ';
            }
            if (j == 7 && hl < (int)sizeof(hex) - 2) hex[hl++] = ' ';
        }
        asc[16] = '\0';
        sh_out("%016llx  %-50s |%s|", (unsigned long long)(base + i), hex, asc);
    }
}

// --- parsing --------------------------------------------------------------

// Whitespace split with "..." / '...' grouping. No globbing, no variables, no
// redirection (deliberately small surface: a shell with kernel R/W should not
// have a rich interpreter).
static int sh_parse(const char *line, int *argc_out, char argv[TRM_MAX_ARGS][TRM_MAX_ARG_LEN]) {
    int argc = 0;
    const char *p = line;
    while (*p && argc < TRM_MAX_ARGS) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        if (*p == '#') break;                       // comment
        char quote = 0;
        if (*p == '"' || *p == '\'') quote = *p++;
        int n = 0;
        while (*p) {
            if (quote) {
                if (*p == quote) { p++; break; }
            } else if (*p == ' ' || *p == '\t') {
                break;
            }
            if (n < TRM_MAX_ARG_LEN - 1) argv[argc][n++] = *p;
            p++;
        }
        argv[argc][n] = '\0';
        argc++;
    }
    *argc_out = argc;
    return argc;
}

static int sh_parse_u64(const char *s, uint64_t *out) {
    if (!s || !*s) return -1;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 0);
    if (errno != 0 || end == s || *end != '\0') return -1;
    *out = (uint64_t)v;
    return 0;
}

static const char *sh_resolve(const char *p, char *buf, size_t n) {
    if (p && p[0] == '~') {
        snprintf(buf, n, "%s%s", trm_ctx_home(), p + 1);
        return buf;
    }
    return p;
}

static void sh_join(char *out, size_t n, const char *dir, const char *name) {
    if (!strcmp(dir, "/")) snprintf(out, n, "/%s", name);
    else snprintf(out, n, "%s/%s", dir, name);
}

static int sh_qsort_names(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

// --- commands: core -------------------------------------------------------

typedef struct trm_cmd trm_cmd;
struct trm_cmd {
    const char *name;
    const char *usage;
    const char *help;
    int needs_unsafe;
    int pkg;            // TRM_PKG_NONE for core commands
    int (*fn)(int argc, char **argv);
};

// --- packages: in-process command packs ----------------------------------
// A "package" here is a group of builtin commands, not a downloaded binary:
// this shell has no exec (route A, ROADMAP 0.11), so nothing from a tarball
// could run anyway. The `pkg` command and the app's Settings screen toggle the
// same table; state lives in memory and the app persists it.
enum { TRM_PKG_NONE = -1, TRM_PKG_SYSINFO = 0, TRM_PKG_NET, TRM_PKG_HEX, TRM_PKG_COUNT };

static const char *kPkgNames[TRM_PKG_COUNT] = { "sysinfo", "net", "hex" };
static const char *kPkgDescs[TRM_PKG_COUNT] = {
    "fetch, mem, cpu, loadavg - a fastfetch-style system card",
    "net, myip, dns - interfaces, addresses, resolver",
    "hexdump, strings - inspect any file byte by byte",
};
static int g_pkgEnabled[TRM_PKG_COUNT] = { 0, 0, 0 };

int trm_shell_package_count(void) { return TRM_PKG_COUNT; }

const char *trm_shell_package_name(int i) {
    return (i >= 0 && i < TRM_PKG_COUNT) ? kPkgNames[i] : NULL;
}

const char *trm_shell_package_desc(int i) {
    return (i >= 0 && i < TRM_PKG_COUNT) ? kPkgDescs[i] : NULL;
}

int trm_shell_package_enabled(int i) {
    return (i >= 0 && i < TRM_PKG_COUNT) ? g_pkgEnabled[i] : 0;
}

void trm_shell_set_package_enabled(int i, int on) {
    if (i >= 0 && i < TRM_PKG_COUNT) g_pkgEnabled[i] = on ? 1 : 0;
}

int trm_shell_package_index(const char *name) {
    if (!name) return -1;
    for (int i = 0; i < TRM_PKG_COUNT; i++) {
        if (!strcmp(kPkgNames[i], name)) return i;
    }
    return -1;
}

static int g_pkgInstalledCount(void) {
    int n = 0;
    for (int i = 0; i < TRM_PKG_COUNT; i++) {
        if (g_pkgEnabled[i]) n++;
    }
    return n;
}

static int cmd_help(int argc, char **argv);

static int cmd_echo(int argc, char **argv) {
    char out[1024] = {0};
    size_t used = 0;
    for (int i = 1; i < argc; i++) {
        used += (size_t)snprintf(out + used, sizeof(out) - used, "%s%s", i > 1 ? " " : "", argv[i]);
        if (used >= sizeof(out)) break;
    }
    sh_out("%s", out);
    return 0;
}

static int cmd_pwd(int argc, char **argv) {
    (void)argc; (void)argv;
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
        sh_err("getcwd failed errno=%d (%s)", errno, strerror(errno));
        return 1;
    }
    sh_out("%s", cwd);
    return 0;
}

static int cmd_cd(int argc, char **argv) {
    char buf[PATH_MAX];
    const char *target = (argc < 2) ? trm_ctx_home() : sh_resolve(argv[1], buf, sizeof(buf));
    if (chdir(target) != 0) {
        sh_err("cd %s: errno=%d (%s)", target, errno, strerror(errno));
        return 1;
    }
    char cwd[PATH_MAX];
    sh_out("%s", getcwd(cwd, sizeof(cwd)) ? cwd : target);
    return 0;
}

static int cmd_ls(int argc, char **argv) {
    int lflag = 0, aflag = 0;
    const char *paths[8];
    int npaths = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-l")) { lflag = 1; continue; }
        if (!strcmp(argv[i], "-a")) { aflag = 1; continue; }
        if (!strcmp(argv[i], "-la") || !strcmp(argv[i], "-al")) { lflag = 1; aflag = 1; continue; }
        if (argv[i][0] == '-' && argv[i][1]) { sh_err("ls: unknown flag %s", argv[i]); return 1; }
        if (npaths < 8) paths[npaths++] = argv[i];
    }
    if (npaths == 0) paths[npaths++] = ".";

    int rc = 0;
    for (int pi = 0; pi < npaths; pi++) {
        char rbuf[PATH_MAX];
        const char *path = sh_resolve(paths[pi], rbuf, sizeof(rbuf));
        struct stat st;
        DIR *d = opendir(path);
        if (!d && lstat(path, &st) == 0 && !S_ISDIR(st.st_mode)) {
            // A file argument lists as a single entry, like ls(1).
            sh_out("%c %04o %9lld  %s", S_ISLNK(st.st_mode) ? 'l' : '-', (unsigned)(st.st_mode & 07777),
                   (long long)st.st_size, path);
            continue;
        }
        if (!d) {
            sh_err("ls %s: errno=%d (%s)", path, errno, strerror(errno));
            rc = 1;
            continue;
        }
        int n = 0, extra = 0;
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (!aflag && e->d_name[0] == '.') continue;
            if (n < TRM_LS_MAX) {
                // Copy with an explicit cap: dirent names can be 255 bytes and
                // a plain snprintf into the fixed row triggers
                // -Wformat-truncation on the SDK's clang (truncation is
                // intended, so the copy says so).
                size_t nl = strlen(e->d_name);
                if (nl >= TRM_LS_NAME_MAX) nl = TRM_LS_NAME_MAX - 1;
                memcpy(g_ls_names[n], e->d_name, nl);
                g_ls_names[n][nl] = '\0';
                n++;
            } else {
                extra = 1;
            }
        }
        closedir(d);
        qsort(g_ls_names, (size_t)n, TRM_LS_NAME_MAX, sh_qsort_names);
        if (npaths > 1) sh_out("%s:", path);
        char line[1024];
        int hl = 0;
        for (int i = 0; i < n; i++) {
            if (lflag) {
                char full[PATH_MAX];
                sh_join(full, sizeof(full), path, g_ls_names[i]);
                struct stat st;
                char kind = '?';
                long long size = -1;
                unsigned mode = 0;
                if (lstat(full, &st) == 0) {
                    kind = S_ISDIR(st.st_mode) ? 'd' : S_ISLNK(st.st_mode) ? 'l' : S_ISREG(st.st_mode) ? '-' : '?';
                    size = (long long)st.st_size;
                    mode = (unsigned)(st.st_mode & 07777);
                }
                sh_out("%c %04o %9lld  %s", kind, mode, size, g_ls_names[i]);
            } else {
                hl += snprintf(line + hl, sizeof(line) - (size_t)hl, "%-22s", g_ls_names[i]);
                if (hl > 900 || i + 1 == n) {
                    sh_out("%s", line);
                    hl = 0;
                    line[0] = '\0';
                }
            }
        }
        if (n == 0) sh_out("(empty)");
        if (extra) sh_out("... more entries not listed (cap %d)", TRM_LS_MAX);
    }
    return rc;
}

static int cmd_cat(int argc, char **argv) {
    if (argc < 2) { sh_err("cat: usage: cat <file>..."); return 1; }
    int rc = 0;
    for (int i = 1; i < argc; i++) {
        char rbuf[PATH_MAX];
        const char *path = sh_resolve(argv[i], rbuf, sizeof(rbuf));
        FILE *f = fopen(path, "r");
        if (!f) {
            sh_err("cat %s: errno=%d (%s)", path, errno, strerror(errno));
            rc = 1;
            continue;
        }
        char line[TRM_CAT_LINE_MAX];
        int n = 0;
        int binary_hint = 0;
        while (fgets(line, sizeof(line), f)) {
            size_t l = strlen(line);
            for (size_t k = 0; k < l; k++) {
                if ((unsigned char)line[k] < 0x09) binary_hint = 1;
            }
            if (n < TRM_CAT_LINES_MAX) {
                while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = '\0';
                sh_out("%s", line);
                n++;
            }
        }
        if (n >= TRM_CAT_LINES_MAX) sh_out("... truncated at %d lines", TRM_CAT_LINES_MAX);
        if (n == 0 && binary_hint) sh_err("cat %s: no text lines (binary file — use kread for kernel memory)", path);
        fclose(f);
    }
    return rc;
}

static int cmd_head(int argc, char **argv) {
    int want = 20;
    int first = 1;
    if (argc > 3 && !strcmp(argv[1], "-n")) {
        want = atoi(argv[2]);
        first = 3;
    }
    if (argc <= first) { sh_err("head: usage: head [-n N] <file>"); return 1; }
    if (want < 0) want = 0;
    char rbuf[PATH_MAX];
    const char *path = sh_resolve(argv[first], rbuf, sizeof(rbuf));
    FILE *f = fopen(path, "r");
    if (!f) { sh_err("head %s: errno=%d (%s)", path, errno, strerror(errno)); return 1; }
    char line[TRM_CAT_LINE_MAX];
    int n = 0;
    while (n < want && fgets(line, sizeof(line), f)) {
        size_t l = strlen(line);
        while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = '\0';
        sh_out("%s", line);
        n++;
    }
    fclose(f);
    return 0;
}

static int cmd_stat(int argc, char **argv) {
    if (argc < 2) { sh_err("stat: usage: stat <path>"); return 1; }
    char rbuf[PATH_MAX];
    const char *path = sh_resolve(argv[1], rbuf, sizeof(rbuf));
    struct stat st;
    if (lstat(path, &st) != 0) {
        sh_err("stat %s: errno=%d (%s)", path, errno, strerror(errno));
        return 1;
    }
    sh_out("%s", path);
    sh_out("  mode=%07o type=%s size=%lld uid=%d gid=%d links=%d",
           st.st_mode, S_ISDIR(st.st_mode) ? "dir" : S_ISLNK(st.st_mode) ? "link" : S_ISREG(st.st_mode) ? "file" : "other",
           (long long)st.st_size, (int)st.st_uid, (int)st.st_gid, (int)st.st_nlink);
    sh_out("  readable=%d writable=%d executable=%d", access(path, R_OK) == 0, access(path, W_OK) == 0, access(path, X_OK) == 0);
    return 0;
}

static int cmd_mkdir(int argc, char **argv) {
    if (argc < 2) { sh_err("mkdir: usage: mkdir <dir>"); return 1; }
    char rbuf[PATH_MAX];
    const char *path = sh_resolve(argv[1], rbuf, sizeof(rbuf));
    if (mkdir(path, 0755) != 0) { sh_err("mkdir %s: errno=%d (%s)", path, errno, strerror(errno)); return 1; }
    sh_out("created %s", path);
    return 0;
}

static int cmd_rmdir(int argc, char **argv) {
    if (argc < 2) { sh_err("rmdir: usage: rmdir <dir>"); return 1; }
    char rbuf[PATH_MAX];
    const char *path = sh_resolve(argv[1], rbuf, sizeof(rbuf));
    if (rmdir(path) != 0) { sh_err("rmdir %s: errno=%d (%s)", path, errno, strerror(errno)); return 1; }
    sh_out("removed %s", path);
    return 0;
}

static int rm_recursive(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (!d) return -1;
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            char child[PATH_MAX];
            sh_join(child, sizeof(child), path, e->d_name);
            if (rm_recursive(child) != 0) {
                closedir(d);
                return -1;
            }
        }
        closedir(d);
        return rmdir(path);
    }
    return unlink(path);
}

static int cmd_rm(int argc, char **argv) {
    int recursive = 0;
    int start = 1;
    if (argc > 1 && !strcmp(argv[1], "-r")) { recursive = 1; start = 2; }
    if (argc <= start) { sh_err("rm: usage: rm [-r] <path>..."); return 1; }
    if (recursive && !g_unsafe) {
        sh_err("rm -r is gated: run `unsafe 1` first (a recursive delete with a full-FS sandbox escape has no undo)");
        return 2;
    }
    int rc = 0;
    for (int i = start; i < argc; i++) {
        char rbuf[PATH_MAX];
        const char *path = sh_resolve(argv[i], rbuf, sizeof(rbuf));
        if (recursive) {
            // Refuse the two paths whose deletion is unrecoverable on-device.
            if (!strcmp(path, "/") || !strcmp(path, "/System") || !strcmp(path, "/var")) {
                sh_err("rm -r %s: refused (system root)", path);
                rc = 1;
                continue;
            }
            if (rm_recursive(path) != 0) { sh_err("rm -r %s: errno=%d (%s)", path, errno, strerror(errno)); rc = 1; }
            else sh_out("removed %s (recursive)", path);
        } else {
            if (unlink(path) != 0) { sh_err("rm %s: errno=%d (%s)", path, errno, strerror(errno)); rc = 1; }
        }
    }
    return rc;
}

static int cmd_mv(int argc, char **argv) {
    if (argc < 3) { sh_err("mv: usage: mv <src> <dst>"); return 1; }
    char rb1[PATH_MAX], rb2[PATH_MAX];
    const char *src = sh_resolve(argv[1], rb1, sizeof(rb1));
    const char *dst = sh_resolve(argv[2], rb2, sizeof(rb2));
    if (rename(src, dst) != 0) { sh_err("mv %s -> %s: errno=%d (%s)", src, dst, errno, strerror(errno)); return 1; }
    sh_out("moved %s -> %s", src, dst);
    return 0;
}

static int cmd_cp(int argc, char **argv) {
    if (argc < 3) { sh_err("cp: usage: cp <src> <dst> (files only)"); return 1; }
    char rb1[PATH_MAX], rb2[PATH_MAX];
    const char *src = sh_resolve(argv[1], rb1, sizeof(rb1));
    const char *dst = sh_resolve(argv[2], rb2, sizeof(rb2));
    int in = open(src, O_RDONLY);
    if (in < 0) { sh_err("cp %s: errno=%d (%s)", src, errno, strerror(errno)); return 1; }
    struct stat st;
    mode_t mode = 0644;
    if (fstat(in, &st) == 0) {
        if (S_ISDIR(st.st_mode)) { close(in); sh_err("cp: %s is a directory (recursive copy not implemented)", src); return 1; }
        mode = st.st_mode & 07777;
    }
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (out < 0) { int e = errno; close(in); sh_err("cp %s: errno=%d (%s)", dst, e, strerror(e)); return 1; }
    char buf[65536];
    ssize_t r;
    long long total = 0;
    int rc = 0;
    while ((r = read(in, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < r) {
            ssize_t w = write(out, buf + off, (size_t)(r - off));
            if (w <= 0) { rc = 1; break; }
            off += w;
        }
        total += r;
        if (rc) break;
    }
    if (r < 0) rc = 1;
    close(in);
    close(out);
    if (rc) { sh_err("cp: write failed errno=%d (%s)", errno, strerror(errno)); return 1; }
    sh_out("copied %s -> %s (%lld bytes)", src, dst, total);
    return 0;
}

static int cmd_touch(int argc, char **argv) {
    if (argc < 2) { sh_err("touch: usage: touch <file>"); return 1; }
    char rbuf[PATH_MAX];
    const char *path = sh_resolve(argv[1], rbuf, sizeof(rbuf));
    int fd = open(path, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) { sh_err("touch %s: errno=%d (%s)", path, errno, strerror(errno)); return 1; }
    close(fd);
    sh_out("touched %s", path);
    return 0;
}

static int cmd_chmod(int argc, char **argv) {
    if (argc < 3) { sh_err("chmod: usage: chmod <octal> <path>"); return 1; }
    if (!g_unsafe) { sh_err("chmod is gated: run `unsafe 1` first (mode changes on system files are not undoable)"); return 2; }
    char *end = NULL;
    long mode = strtol(argv[1], &end, 8);
    if (end == argv[1] || *end != '\0' || mode < 0 || mode > 07777) { sh_err("chmod: bad mode %s", argv[1]); return 1; }
    char rbuf[PATH_MAX];
    const char *path = sh_resolve(argv[2], rbuf, sizeof(rbuf));
    if (chmod(path, (mode_t)mode) != 0) { sh_err("chmod %s: errno=%d (%s)", path, errno, strerror(errno)); return 1; }
    sh_out("chmod %04lo %s", mode, path);
    return 0;
}

// --- commands: process / system info --------------------------------------

static int cmd_id(int argc, char **argv) {
    (void)argc; (void)argv;
    sh_out("uid=%d euid=%d gid=%d egid=%d pid=%d ppid=%d", (int)getuid(), (int)geteuid(),
           (int)getgid(), (int)getegid(), (int)getpid(), (int)getppid());
    if (!exploit_is_done()) {
        sh_out("kernel side: not readable yet (escape not live)");
        return 0;
    }
    uint32_t kuid = 0, kgid = 0, kgroups0 = 0;
    uint64_t self = proc_self();
    if (self && sandbox_escape_read_posix_creds(self, &kuid, &kgid, &kgroups0) == 0) {
        sh_out("kernel creds: proc=0x%llx uid=%u gid=%u groups[0]=%u", (unsigned long long)self, kuid, kgid, kgroups0);
    } else {
        sh_err("kernel creds: unreadable (proc=0x%llx)", (unsigned long long)self);
    }
    return 0;
}

static int cmd_uname(int argc, char **argv) {
    (void)argc; (void)argv;
    struct utsname un;
    if (uname(&un) != 0) { sh_err("uname failed errno=%d (%s)", errno, strerror(errno)); return 1; }
    sh_out("%s %s %s %s", un.sysname, un.release, un.version, un.machine);
    return 0;
}

static int cmd_date(int argc, char **argv) {
    (void)argc; (void)argv;
    time_t now = time(NULL);
    struct tm t;
    localtime_r(&now, &t);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S %z", &t);
    sh_out("%s", buf);
    return 0;
}

static int cmd_uptime(int argc, char **argv) {
    (void)argc; (void)argv;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) { sh_err("clock_gettime failed errno=%d (%s)", errno, strerror(errno)); return 1; }
    long long s = (long long)ts.tv_sec;
    sh_out("up %lldd %02lld:%02lld:%02lld (monotonic, excludes deep sleep)", s / 86400, (s % 86400) / 3600, (s % 3600) / 60, s % 60);
    return 0;
}

static int cmd_df(int argc, char **argv) {
    const char *paths[4];
    int n = 0;
    if (argc > 1) {
        for (int i = 1; i < argc && n < 4; i++) paths[n++] = argv[i];
    } else {
        paths[n++] = "/";
        paths[n++] = trm_ctx_home();
    }
    for (int i = 0; i < n; i++) {
        struct statvfs vfs;
        if (statvfs(paths[i], &vfs) != 0) {
            sh_err("df %s: errno=%d (%s)", paths[i], errno, strerror(errno));
            continue;
        }
        unsigned long long bsize = vfs.f_frsize ? vfs.f_frsize : vfs.f_bsize;
        sh_out("%-32s total=%lluMB free=%lluMB avail=%lluMB",
               paths[i],
               (unsigned long long)vfs.f_blocks * bsize / (1024ULL * 1024ULL),
               (unsigned long long)vfs.f_bfree * bsize / (1024ULL * 1024ULL),
               (unsigned long long)vfs.f_bavail * bsize / (1024ULL * 1024ULL));
    }
    return 0;
}

static int cmd_env(int argc, char **argv) {
    (void)argc; (void)argv;
    if (!environ) { sh_out("(no environment)"); return 0; }
    for (char **e = environ; *e; e++) sh_out("%s", *e);
    return 0;
}

static int cmd_sleep(int argc, char **argv) {
    if (argc < 2) { sh_err("sleep: usage: sleep <seconds>"); return 1; }
    double secs = atof(argv[1]);
    if (secs < 0) secs = 0;
    if (secs > 30) { sh_err("sleep: capped at 30s (the shell runs on a background queue)"); secs = 30; }
    struct timespec ts;
    ts.tv_sec = (time_t)secs;
    ts.tv_nsec = (long)((secs - (double)ts.tv_sec) * 1e9);
    nanosleep(&ts, NULL);
    return 0;
}

static int cmd_ps(int argc, char **argv) {
    (void)argc; (void)argv;
#ifndef __APPLE__
    // sysctl(KERN_PROC) is Darwin-only. The host test covers the rest of the
    // shell; on device this path is real (and its errno is a datapoint: iOS
    // may restrict KERN_PROC_ALL for a sideloaded app).
    sh_err("ps: sysctl(KERN_PROC_ALL) is Darwin-only (host test build) — on device use `proc <name>` as well");
    return 1;
#else
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t len = 0;
    if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) {
        sh_err("ps: sysctl(KERN_PROC_ALL) failed errno=%d (%s) — profile may restrict it; use `proc <name>` (kernel walk) instead",
               errno, strerror(errno));
        return 1;
    }
    struct kinfo_proc *kp = malloc(len ? len : 1);
    if (!kp) { sh_err("ps: out of memory (%zu bytes)", len); return 1; }
    if (sysctl(mib, 4, kp, &len, NULL, 0) != 0) {
        sh_err("ps: sysctl read failed errno=%d (%s)", errno, strerror(errno));
        free(kp);
        return 1;
    }
    int n = (int)(len / sizeof(struct kinfo_proc));
    sh_out("pid    ppid   uid  stat  command");
    int shown = 0;
    for (int i = 0; i < n && shown < 120; i++) {
        const struct kinfo_proc *p = &kp[i];
        if (p->kp_proc.p_pid == 0) continue;
        sh_out("%-6d %-6d %-4d %-5d %s", p->kp_proc.p_pid, p->kp_eproc.e_ppid,
               p->kp_eproc.e_ucred.cr_uid, p->kp_proc.p_stat, p->kp_proc.p_comm);
        shown++;
    }
    if (n > shown) sh_out("... %d more processes not shown", n - shown);
    free(kp);
    return 0;
#endif /* __APPLE__ */
}

// --- commands: kernel -----------------------------------------------------

static int cmd_proc(int argc, char **argv) {
    if (argc < 2) { sh_err("proc: usage: proc <name>"); return 1; }
    if (!exploit_is_done()) { sh_err("proc: kernel not initialized (escape not live)"); return 1; }
    uint64_t p = proc_find_by_name(argv[1]);
    if (!p) { sh_err("proc: '%s' not found in the kernel proc list", argv[1]); return 1; }
    char name[64] = {0};
    kreadbuf(p + off_proc_p_name, name, sizeof(name) - 1);
    uint32_t pid = kread32(p + off_proc_p_pid);
    uint64_t label = proc_get_cred_label(p);
    uint64_t sbx = label ? label_get_sandbox(label) : 0;
    sh_out("proc '%s' pid=%u kaddr=0x%llx label=0x%llx sandbox=0x%llx",
           name, pid, (unsigned long long)p, (unsigned long long)label, (unsigned long long)sbx);
    return 0;
}

static int cmd_krw(int argc, char **argv) {
    (void)argc; (void)argv;
    sh_out("escape=%s test_mode=%d", exploit_is_done() ? "LIVE" : "not live", wolf_test_mode);
    uint64_t self = proc_self();
    if (!self) { sh_err("proc_self()=0 — kernel helpers unavailable"); return 1; }
    uint64_t first = kread64(self);
    sh_out("proc_self=0x%llx valid=%d kread64(self)=0x%llx", (unsigned long long)self,
           is_kaddr_valid(self), (unsigned long long)first);
    if (!is_kaddr_valid(self)) { sh_err("proc_self is not a valid kernel address — read primitive is not usable"); return 1; }
    return 0;
}

static int cmd_kread(int argc, char **argv) {
    if (argc < 2) { sh_err("kread: usage: kread <addr> [len<=4096]"); return 1; }
    if (!exploit_is_done()) { sh_err("kread: kernel R/W not live yet"); return 1; }
    uint64_t addr = 0;
    if (sh_parse_u64(argv[1], &addr) != 0) { sh_err("kread: bad address '%s' (use 0x...)", argv[1]); return 1; }
    size_t len = 64;
    if (argc > 2) {
        uint64_t l = 0;
        if (sh_parse_u64(argv[2], &l) != 0 || l == 0) { sh_err("kread: bad length '%s'", argv[2]); return 1; }
        len = (size_t)(l > TRM_READ_MAX ? TRM_READ_MAX : l);
    }
    if (!is_kaddr_valid(addr)) {
        sh_err("kread: 0x%llx is not in the kernel VA range (kernel-VA masks come from t1sz_boot)", (unsigned long long)addr);
        return 1;
    }
    uint8_t buf[TRM_READ_MAX];
    memset(buf, 0, sizeof(buf));
    kreadbuf(addr, buf, len);
    sh_hexdump(addr, buf, len);
    return 0;
}

// kwrite8/16/32/64 — one handler; the width comes from the command name
// ("kwrite" + atoi), so the table stays a plain function-pointer table.
static int cmd_kwrite(int argc, char **argv) {
    if (argc < 3) { sh_err("%s: usage: %s <addr> <value>", argv[0], argv[0]); return 1; }
    if (!g_unsafe) {
        sh_err("%s is a kernel write — run `unsafe 1` first (an accidental write panics the device)", argv[0]);
        return 2;
    }
    if (!exploit_is_done()) { sh_err("%s: kernel R/W not live yet", argv[0]); return 1; }
    int width = atoi(argv[0] + 6);   // "kwrite" is 6 chars
    uint64_t addr = 0, val = 0;
    if (sh_parse_u64(argv[1], &addr) != 0 || sh_parse_u64(argv[2], &val) != 0) {
        sh_err("%s: bad numbers (addr='%s' value='%s')", argv[0], argv[1], argv[2]);
        return 1;
    }
    if (!is_kaddr_valid(addr)) { sh_err("%s: 0x%llx is not a kernel address", argv[0], (unsigned long long)addr); return 1; }
    switch (width) {
        case 8:  kwrite8(addr, (uint8_t)val);   break;
        case 16: kwrite16(addr, (uint16_t)val); break;
        case 32: kwrite32(addr, (uint32_t)val); break;
        case 64: kwrite64(addr, val);           break;
        default: sh_err("%s: unknown width", argv[0]); return 1;
    }
    sh_out("%s wrote %s at 0x%llx", argv[0], argv[2], (unsigned long long)addr);
    uint64_t back = kread64(addr & ~0x7ULL);
    sh_out("read-back 0x%llx = 0x%llx", (unsigned long long)(addr & ~0x7ULL), (unsigned long long)back);
    return 0;
}

static int cmd_sbxinfo(int argc, char **argv) {
    (void)argc; (void)argv;
    sh_out("posix: uid=%d euid=%d gid=%d egid=%d", (int)getuid(), (int)geteuid(), (int)getgid(), (int)getegid());
    if (!exploit_is_done()) { sh_out("kernel side: escape not live yet"); return 0; }
    uint64_t self = proc_self();
    uint64_t label = proc_get_cred_label(self);
    uint64_t sbx = label ? label_get_sandbox(label) : 0;
    uint32_t kuid = 0, kgid = 0, g0 = 0;
    int creds = sandbox_escape_read_posix_creds(self, &kuid, &kgid, &g0);
    sh_out("proc=0x%llx label=0x%llx sandbox=0x%llx creds(rc=%d) uid=%u gid=%u groups[0]=%u",
           (unsigned long long)self, (unsigned long long)label, (unsigned long long)sbx,
           creds, kuid, kgid, g0);
    sh_out("route B would neutralise the sandbox object at 0x%llx (that is the object that owns the profile rules for process-exec/ptmx)",
           (unsigned long long)sbx);
    return 0;
}

static int cmd_sbxtest(int argc, char **argv) {
    (void)argc; (void)argv;
    trm_probe_sbx_matrix();
    return 0;
}

// --- commands: terminal-research probes -----------------------------------

static int cmd_probe(int argc, char **argv) {
    trm_probe_run_all(argc > 1 ? argv[1] : "shell");
    return 0;
}

static int cmd_verdict(int argc, char **argv) {
    (void)argc; (void)argv;
    sh_out("%s", trm_probe_verdict());
    return 0;
}

static int cmd_execsurf(int argc, char **argv) {
    if (argc > 1) {
        for (int i = 1; i < argc; i++) trm_probe_exec_surface(argv[i], 12);
        return 0;
    }
    static const char *dirs[] = { "/bin", "/usr/bin", "/usr/sbin", "/usr/libexec" };
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) trm_probe_exec_surface(dirs[i], 12);
    return 0;
}

static int cmd_spawn(int argc, char **argv) {
    if (argc < 2) { sh_err("spawn: usage: spawn <path> [args...] — exec a platform binary (needs process-exec in the profile)"); return 1; }
    char *cargv[TRM_MAX_ARGS + 1];
    int n = 0;
    for (int i = 1; i < argc && n < TRM_MAX_ARGS; i++) cargv[n++] = argv[i];
    cargv[n] = NULL;
    int status = -1;
    int rc = trm_probe_spawn(argv[1], cargv, 5000, NULL, &status);
    sh_out("spawn rc=%d exit=%d %s", rc, status, rc == 0 ? "(exec permitted)" : "(exec refused — see the [TRM][SPAWN] lines above)");
    return rc == 0 ? 0 : 1;
}

static int cmd_ptytest(int argc, char **argv) {
    (void)argc; (void)argv;
    char slave[128];
    int rc = trm_probe_pty(slave, sizeof(slave));
    sh_out("pty rc=%d slave=%s", rc, slave[0] ? slave : "(none)");
    return rc == 0 ? 0 : 1;
}

static int cmd_ssvw(int argc, char **argv) {
    if (argc < 3) { sh_err("ssvw: usage: ssvw <local-file> <dest-path> — write over an SSV-protected file"); return 1; }
    if (!g_unsafe) { sh_err("ssvw is an SSV write — run `unsafe 1` first (it can brick a bootable system file)"); return 2; }
    struct stat st;
    if (stat(argv[1], &st) != 0) { sh_err("ssvw: %s unreadable errno=%d (%s)", argv[1], errno, strerror(errno)); return 1; }
    if (st.st_size <= 0 || st.st_size > (8 << 20)) { sh_err("ssvw: refusing size %lld (1B..8MB)", (long long)st.st_size); return 1; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { sh_err("ssvw: open %s failed errno=%d (%s)", argv[1], errno, strerror(errno)); return 1; }
    size_t len = (size_t)st.st_size;
    uint8_t *buf = malloc(len);
    if (!buf) { fclose(f); sh_err("ssvw: out of memory"); return 1; }
    size_t got = fread(buf, 1, len, f);
    fclose(f);
    bool ok = ssv_write(argv[2], buf, got);
    free(buf);
    sh_out("ssvw %s -> %s (%zu bytes): %s", argv[1], argv[2], got, ok ? "written" : "FAILED");
    return ok ? 0 : 1;
}

static int cmd_unsafe(int argc, char **argv) {
    if (argc < 2) { sh_out("unsafe=%d (%s)", g_unsafe, g_unsafe ? "kernel writes + rm -r + chmod + ssvw allowed" : "read-only"); return 0; }
    g_unsafe = (atoi(argv[1]) != 0);
    snprintf(g_prompt, sizeof(g_prompt), "%s", g_unsafe ? "w0lf(unsafe)> " : "w0lf> ");
    sh_out("unsafe=%d — %s", g_unsafe,
           g_unsafe ? "kernel writes, rm -r, chmod and ssvw are now allowed" : "back to read-only");
    return 0;
}

// --- commands: package packs (sysinfo / net / hex) ------------------------
// Everything here is in-process: sysctl/uname/statvfs/getifaddrs plus the
// shell's own file readers. No exec, so no downloaded binary could be run
// anyway (ROADMAP 0.11 route A).

static int sh_sysctl_u64(const char *name, uint64_t *out) {
#ifdef __APPLE__
    uint64_t v = 0;
    size_t len = sizeof(v);
    if (sysctlbyname(name, &v, &len, NULL, 0) != 0) return -1;
    *out = v;
    return 0;
#else
    (void)name;
    (void)out;
    errno = ENOTSUP;
    return -1;   // host test: Darwin-only sysctls are simply unavailable
#endif
}

static int sh_sysctl_str(const char *name, char *out, size_t n) {
#ifdef __APPLE__
    size_t len = n;
    if (sysctlbyname(name, out, &len, NULL, 0) != 0) return -1;
    out[n - 1] = '\0';
    return 0;
#else
    (void)name;
    (void)out;
    (void)n;
    return -1;
#endif
}

static void sh_uptime_str(char *out, size_t n) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        snprintf(out, n, "?");
        return;
    }
    long long s = (long long)ts.tv_sec;
    snprintf(out, n, "%lldd %02lld:%02lld:%02lld", s / 86400, (s % 86400) / 3600, (s % 3600) / 60, s % 60);
}

// fastfetch-style card: a 4-line ASCII mark next to live system facts.
static int cmd_fetch(int argc, char **argv) {
    (void)argc; (void)argv;
    static const char *logo[4] = {
        "  __      __  ___  _    ___ ",
        "  \\ \\    / / / _ \\| |  | __|",
        "   \\ \\/\\/ / | (_) | |__| _| ",
        "    \\_/\\_/   \\___/|____|_|  ",
    };
    static const char *colors[3] = { "\033[38;5;117m", "\033[38;5;152m", "\033[38;5;110m" };
    char machine[128] = "unknown", release[128] = "", iosver[32] = "", build[32] = "";
    struct utsname un;
    if (uname(&un) == 0) {
        snprintf(machine, sizeof(machine), "%s", un.machine);
        snprintf(release, sizeof(release), "%s", un.release);
    }
    if (sh_sysctl_str("kern.osproductversion", iosver, sizeof(iosver)) != 0) snprintf(iosver, sizeof(iosver), "?");
    if (sh_sysctl_str("kern.osversion", build, sizeof(build)) != 0) snprintf(build, sizeof(build), "?");

    uint64_t ncpu = 0, memtotal = 0, pagesize = 0, pagefree = 0;
    sh_sysctl_u64("hw.ncpu", &ncpu);
    sh_sysctl_u64("hw.memsize", &memtotal);
    sh_sysctl_u64("hw.pagesize", &pagesize);
    sh_sysctl_u64("vm.page_free_count", &pagefree);

    char up[48];
    sh_uptime_str(up, sizeof(up));
    double load[3] = { 0, 0, 0 };
    getloadavg(load, 3);

    unsigned long long diskFree = 0, diskTotal = 0;
    struct statvfs vfs;
    if (statvfs("/", &vfs) == 0) {
        unsigned long long bs = vfs.f_frsize ? vfs.f_frsize : vfs.f_bsize;
        diskFree = (unsigned long long)vfs.f_bavail * bs / (1024ULL * 1024ULL);
        diskTotal = (unsigned long long)vfs.f_blocks * bs / (1024ULL * 1024ULL);
    }

    char rows[12][160];
    int nr = 0;
    snprintf(rows[nr++], 160, "w0lfterm  route A shell (%d cmds)", trm_shell_command_count());
    snprintf(rows[nr++], 160, "host      %s", machine);
    snprintf(rows[nr++], 160, "ios       %s (%s)", iosver, build);
    snprintf(rows[nr++], 160, "kernel    %s", release);
    snprintf(rows[nr++], 160, "uptime    %s", up);
    if (ncpu) snprintf(rows[nr++], 160, "cpu       %llu cores, page %llu KB",
                       (unsigned long long)ncpu, (unsigned long long)(pagesize / 1024));
    if (memtotal) {
        unsigned long long freeMB = (pagesize && pagefree) ? (pagefree * pagesize) / (1024ULL * 1024ULL) : 0;
        snprintf(rows[nr++], 160, "memory    %llu MB (free %llu MB)",
                 (unsigned long long)(memtotal / (1024ULL * 1024ULL)), freeMB);
    }
    if (diskTotal) snprintf(rows[nr++], 160, "disk      %llu MB free of %llu MB", diskFree, diskTotal);
    snprintf(rows[nr++], 160, "load      %.2f %.2f %.2f", load[0], load[1], load[2]);
    snprintf(rows[nr++], 160, "escape    %s", exploit_is_done() ? "live (sandbox escaped)" : "not live");
    snprintf(rows[nr++], 160, "kernel rw %s", (exploit_is_done() && is_kaddr_valid(proc_self())) ? "readable" : "unavailable");

    int i;
    for (i = 0; i < nr; i++) {
        const char *art = (i < 4) ? logo[i] : "                              ";
        if (i < 4) {
            sh_out("%s%s%s  %s", colors[i % 3], art, "\033[0m", rows[i]);
        } else {
            sh_out("%s  %s\033[0m", art, rows[i]);
        }
    }
    return 0;
}

static int cmd_mem(int argc, char **argv) {
    (void)argc; (void)argv;
    uint64_t memtotal = 0, pagesize = 0, pagefree = 0, pagecount = 0;
    if (sh_sysctl_u64("hw.memsize", &memtotal) != 0) {
        sh_err("mem: hw.memsize unavailable (host build, or a restricted profile)");
        return 1;
    }
    sh_sysctl_u64("hw.pagesize", &pagesize);
    sh_sysctl_u64("vm.page_free_count", &pagefree);
    sh_sysctl_u64("vm.page_count", &pagecount);
    unsigned long long totalMB = (unsigned long long)(memtotal / (1024ULL * 1024ULL));
    unsigned long long freeMB = (pagesize && pagefree) ? (pagefree * pagesize) / (1024ULL * 1024ULL) : 0;
    unsigned long long pagesMB = (pagesize && pagecount) ? (pagecount * pagesize) / (1024ULL * 1024ULL) : 0;
    sh_out("physical   %llu MB", totalMB);
    if (pagesMB) sh_out("managed    %llu MB (%llu MB free, %d%% used)", pagesMB, freeMB,
                        (int)(pagesMB ? (100 - (freeMB * 100 / pagesMB)) : 0));
    if (pagesize) sh_out("page size  %llu bytes", (unsigned long long)pagesize);
    return 0;
}

static int cmd_cpu(int argc, char **argv) {
    (void)argc; (void)argv;
    char machine[128] = "unknown";
    struct utsname un;
    if (uname(&un) == 0) snprintf(machine, sizeof(machine), "%s", un.machine);
    uint64_t ncpu = 0, cputype = 0, cpusubtype = 0, physcpu = 0;
    sh_sysctl_u64("hw.ncpu", &ncpu);
    sh_sysctl_u64("hw.cputype", &cputype);
    sh_sysctl_u64("hw.cpusubtype", &cpusubtype);
    sh_sysctl_u64("hw.physicalcpu", &physcpu);
    sh_out("model      %s", machine);
    if (ncpu) sh_out("logical    %llu", (unsigned long long)ncpu);
    if (physcpu) sh_out("physical   %llu", (unsigned long long)physcpu);
    if (cputype) sh_out("cputype    %llu subtype %llu", (unsigned long long)cputype, (unsigned long long)cpusubtype);
    return 0;
}

static int cmd_loadavg(int argc, char **argv) {
    (void)argc; (void)argv;
    double load[3] = { 0, 0, 0 };
    if (getloadavg(load, 3) != 3) {
        sh_err("loadavg: unavailable errno=%d (%s)", errno, strerror(errno));
        return 1;
    }
    sh_out("load  %.2f %.2f %.2f  (1m 5m 15m)", load[0], load[1], load[2]);
    return 0;
}

static int cmd_net(int argc, char **argv) {
    (void)argc; (void)argv;
    struct ifaddrs *ifa = NULL;
    if (getifaddrs(&ifa) != 0) {
        sh_err("net: getifaddrs failed errno=%d (%s)", errno, strerror(errno));
        return 1;
    }
    sh_out("iface      family  address");
    int n = 0;
    char host[NI_MAXHOST];
    for (struct ifaddrs *p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr) continue;
        int fam = p->ifa_addr->sa_family;
        if (fam != AF_INET && fam != AF_INET6) continue;
        host[0] = '\0';
        if (getnameinfo(p->ifa_addr, (socklen_t)(fam == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)),
                        host, sizeof(host), NULL, 0, NI_NUMERICHOST) != 0) continue;
        sh_out("%-10s %-7s %s", p->ifa_name, fam == AF_INET ? "inet" : "inet6", host);
        n++;
    }
    freeifaddrs(ifa);
    if (!n) sh_out("(no IPv4/IPv6 interface addresses - the sandbox may hide them)");
    return 0;
}

static int cmd_myip(int argc, char **argv) {
    (void)argc; (void)argv;
    struct ifaddrs *ifa = NULL;
    if (getifaddrs(&ifa) != 0) {
        sh_err("myip: getifaddrs failed errno=%d (%s)", errno, strerror(errno));
        return 1;
    }
    char found[NI_MAXHOST] = "";
    for (struct ifaddrs *p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
        if (p->ifa_flags & IFF_LOOPBACK) continue;
        if (getnameinfo(p->ifa_addr, sizeof(struct sockaddr_in), found, sizeof(found), NULL, 0, NI_NUMERICHOST) == 0) break;
        found[0] = '\0';
    }
    freeifaddrs(ifa);
    if (!found[0]) {
        sh_err("myip: no non-loopback IPv4 address visible");
        return 1;
    }
    sh_out("%s", found);
    return 0;
}

static int cmd_dns(int argc, char **argv) {
    (void)argc; (void)argv;
    FILE *f = fopen("/etc/resolv.conf", "r");
    if (!f) {
        sh_out("dns        resolv.conf not readable errno=%d (%s)", errno, strerror(errno));
        sh_out("           iOS resolves through mDNSResponder; enumerating its servers needs");
        sh_out("           a query or exec (route B/C) - `net` shows the interface addresses.");
        return 0;
    }
    char line[256];
    int n = 0;
    while (fgets(line, sizeof(line), f) && n < 20) {
        size_t l = strlen(line);
        while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = '\0';
        if (line[0]) {
            sh_out("%s", line);
            n++;
        }
    }
    fclose(f);
    if (!n) sh_out("dns        resolv.conf is empty");
    return 0;
}

static int cmd_hexdump(int argc, char **argv) {
    if (argc < 2) { sh_err("hexdump: usage: hexdump <file> [offset] [len<=4096]"); return 1; }
    char rbuf[PATH_MAX];
    const char *path = sh_resolve(argv[1], rbuf, sizeof(rbuf));
    uint64_t off = 0, len = 256;
    if (argc > 2 && sh_parse_u64(argv[2], &off) != 0) { sh_err("hexdump: bad offset '%s'", argv[2]); return 1; }
    if (argc > 3) {
        if (sh_parse_u64(argv[3], &len) != 0 || len == 0) { sh_err("hexdump: bad length '%s'", argv[3]); return 1; }
        if (len > TRM_READ_MAX) len = TRM_READ_MAX;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) { sh_err("hexdump %s: errno=%d (%s)", path, errno, strerror(errno)); return 1; }
    if (off && lseek(fd, (off_t)off, SEEK_SET) == (off_t)-1) {
        sh_err("hexdump %s: seek to %llu failed errno=%d (%s)", path, (unsigned long long)off, errno, strerror(errno));
        close(fd);
        return 1;
    }
    uint8_t buf[TRM_READ_MAX];
    ssize_t n = read(fd, buf, (size_t)len);
    close(fd);
    if (n < 0) { sh_err("hexdump %s: read failed errno=%d (%s)", path, errno, strerror(errno)); return 1; }
    if (n == 0) { sh_out("(end of file at offset %llu)", (unsigned long long)off); return 0; }
    sh_out("%s  offset %llu, %zd bytes", path, (unsigned long long)off, n);
    sh_hexdump(off, buf, (size_t)n);
    return 0;
}

static int cmd_strings(int argc, char **argv) {
    if (argc < 2) { sh_err("strings: usage: strings <file> [minlen=4]"); return 1; }
    char rbuf[PATH_MAX];
    const char *path = sh_resolve(argv[1], rbuf, sizeof(rbuf));
    int minlen = 4;
    if (argc > 2) {
        minlen = atoi(argv[2]);
        if (minlen < 2) minlen = 2;
        if (minlen > 64) minlen = 64;
    }
    FILE *f = fopen(path, "rb");
    if (!f) { sh_err("strings %s: errno=%d (%s)", path, errno, strerror(errno)); return 1; }
    // Stream the file in chunks; runs longer than the buffer are split, which
    // is fine for a debug tool (documented in the command help).
    char run[512];
    int rl = 0;
    int shown = 0;
    int c;
    while ((c = fgetc(f)) != EOF) {
        int printable = (c >= 0x20 && c < 0x7f);
        if (printable) {
            if (rl < (int)sizeof(run) - 1) run[rl++] = (char)c;
            continue;
        }
        if (rl >= minlen) {
            run[rl] = '\0';
            sh_out("%s", run);
            if (++shown >= 300) {
                sh_out("... truncated at 300 strings");
                break;
            }
        }
        rl = 0;
    }
    if (shown < 300 && rl >= minlen) {
        run[rl] = '\0';
        sh_out("%s", run);
        shown++;
    }
    fclose(f);
    if (!shown) sh_out("(no printable runs >= %d chars)", minlen);
    return 0;
}

static int cmd_pkg(int argc, char **argv) {
    if (argc == 1) {
        sh_out("packages - in-process command packs (this shell cannot exec, so a");
        sh_out("package adds builtins instead of downloading a binary):");
        for (int i = 0; i < TRM_PKG_COUNT; i++) {
            sh_out("  %-9s %-12s %s", kPkgNames[i], g_pkgEnabled[i] ? "[installed]" : "[available]", kPkgDescs[i]);
        }
        sh_out("  pkg install <name> | pkg remove <name>");
        return 0;
    }
    int action_install = !strcmp(argv[1], "install");
    int action_remove = !strcmp(argv[1], "remove");
    if ((!action_install && !action_remove) || argc < 3) {
        sh_err("pkg: usage: pkg | pkg install <name> | pkg remove <name>");
        return 1;
    }
    int idx = trm_shell_package_index(argv[2]);
    if (idx < 0) {
        sh_err("pkg: no package named '%s'", argv[2]);
        return 1;
    }
    trm_shell_set_package_enabled(idx, action_install);
    sh_out("%s %s", action_install ? "installed" : "removed", kPkgNames[idx]);
    if (action_install) sh_out("  new commands: %s", kPkgDescs[idx]);
    return 0;
}

// --- command table --------------------------------------------------------

static const trm_cmd kCmds[] = {
    { "help",      "help [cmd]",              "list commands or explain one",                0, TRM_PKG_NONE, cmd_help },
    { "echo",      "echo <text>",             "print argument text",                         0, TRM_PKG_NONE, cmd_echo },
    { "pwd",       "pwd",                     "print working directory",                     0, TRM_PKG_NONE, cmd_pwd },
    { "cd",        "cd [path]",               "change directory (~ = app container)",         0, TRM_PKG_NONE, cmd_cd },
    { "ls",        "ls [-l] [-a] [path]",     "list a directory",                            0, TRM_PKG_NONE, cmd_ls },
    { "cat",       "cat <file>...",           "print text files",                            0, TRM_PKG_NONE, cmd_cat },
    { "head",      "head [-n N] <file>",      "first N lines of a file",                     0, TRM_PKG_NONE, cmd_head },
    { "stat",      "stat <path>",             "file metadata + access bits",                  0, TRM_PKG_NONE, cmd_stat },
    { "mkdir",     "mkdir <dir>",             "create a directory",                          0, TRM_PKG_NONE, cmd_mkdir },
    { "rmdir",     "rmdir <dir>",             "remove an empty directory",                   0, TRM_PKG_NONE, cmd_rmdir },
    { "rm",        "rm [-r] <path>",          "remove files (-r needs unsafe)",              0, TRM_PKG_NONE, cmd_rm },
    { "mv",        "mv <src> <dst>",          "rename/move",                                 0, TRM_PKG_NONE, cmd_mv },
    { "cp",        "cp <src> <dst>",          "copy a file",                                 0, TRM_PKG_NONE, cmd_cp },
    { "touch",     "touch <file>",            "create/update a file",                        0, TRM_PKG_NONE, cmd_touch },
    { "chmod",     "chmod <octal> <path>",    "change mode (needs unsafe)",                  1, TRM_PKG_NONE, cmd_chmod },
    { "id",        "id",                      "posix + kernel-side credentials",             0, TRM_PKG_NONE, cmd_id },
    { "uname",     "uname",                   "system identity (utsname)",                   0, TRM_PKG_NONE, cmd_uname },
    { "date",      "date",                    "current date/time",                           0, TRM_PKG_NONE, cmd_date },
    { "uptime",    "uptime",                  "monotonic uptime",                            0, TRM_PKG_NONE, cmd_uptime },
    { "df",        "df [path]",               "filesystem space",                            0, TRM_PKG_NONE, cmd_df },
    { "env",       "env",                     "environment variables",                       0, TRM_PKG_NONE, cmd_env },
    { "sleep",     "sleep <sec>",             "sleep (capped at 30s)",                       0, TRM_PKG_NONE, cmd_sleep },
    { "ps",        "ps",                      "process list via sysctl",                     0, TRM_PKG_NONE, cmd_ps },
    { "proc",      "proc <name>",             "kernel-side proc lookup + label addrs",       0, TRM_PKG_NONE, cmd_proc },
    { "krw",       "krw",                     "kernel R/W status + sanity read",             0, TRM_PKG_NONE, cmd_krw },
    { "kread",     "kread <addr> [len]",      "hexdump kernel memory",                       0, TRM_PKG_NONE, cmd_kread },
    { "kwrite8",   "kwrite8 <addr> <val>",    "8-bit kernel write (needs unsafe)",           1, TRM_PKG_NONE, cmd_kwrite },
    { "kwrite16",  "kwrite16 <addr> <val>",   "16-bit kernel write (needs unsafe)",          1, TRM_PKG_NONE, cmd_kwrite },
    { "kwrite32",  "kwrite32 <addr> <val>",   "32-bit kernel write (needs unsafe)",          1, TRM_PKG_NONE, cmd_kwrite },
    { "kwrite64",  "kwrite64 <addr> <val>",   "64-bit kernel write (needs unsafe)",          1, TRM_PKG_NONE, cmd_kwrite },
    { "sbxinfo",   "sbxinfo",                 "sandbox label/object addrs (route B target)", 0, TRM_PKG_NONE, cmd_sbxinfo },
    { "sbxtest",   "sbxtest",                 "sandbox_check matrix (profile verdicts)",     0, TRM_PKG_NONE, cmd_sbxtest },
    { "probe",     "probe [phase]",           "run the full TRM.1/2/4/5 device probe",       0, TRM_PKG_NONE, cmd_probe },
    { "verdict",   "verdict",                 "last probe verdict line",                     0, TRM_PKG_NONE, cmd_verdict },
    { "execsurf",  "execsurf [dir]",          "exec surface inventory",                      0, TRM_PKG_NONE, cmd_execsurf },
    { "spawn",     "spawn <path> [args]",     "posix_spawn a platform binary",               0, TRM_PKG_NONE, cmd_spawn },
    { "ptytest",   "ptytest",                 "posix_openpt + round-trip test",              0, TRM_PKG_NONE, cmd_ptytest },
    { "ssvw",      "ssvw <local> <dest>",     "SSV write over a system file (needs unsafe)", 1, TRM_PKG_NONE, cmd_ssvw },
    { "pkg",       "pkg [install|remove <n>]", "list/install/remove command packs",          0, TRM_PKG_NONE, cmd_pkg },
    { "unsafe",    "unsafe <0|1>",            "enable/disable gated commands",               0, TRM_PKG_NONE, cmd_unsafe },
    // package: sysinfo (fastfetch-style system card)
    { "fetch",     "fetch",                   "system info card (w0lf logo + live facts)",    0, TRM_PKG_SYSINFO, cmd_fetch },
    { "mem",       "mem",                     "memory totals + free pages",                   0, TRM_PKG_SYSINFO, cmd_mem },
    { "cpu",       "cpu",                     "cpu model/cores/cputype",                      0, TRM_PKG_SYSINFO, cmd_cpu },
    { "loadavg",   "loadavg",                 "1/5/15 minute load average",                   0, TRM_PKG_SYSINFO, cmd_loadavg },
    // package: net
    { "net",       "net",                     "interfaces + addresses (getifaddrs)",          0, TRM_PKG_NET, cmd_net },
    { "myip",      "myip",                    "first non-loopback IPv4 address",              0, TRM_PKG_NET, cmd_myip },
    { "dns",       "dns",                     "resolver configuration",                       0, TRM_PKG_NET, cmd_dns },
    // package: hex
    { "hexdump",   "hexdump <file> [off] [n]", "hex + ascii of any file",                     0, TRM_PKG_HEX, cmd_hexdump },
    { "strings",   "strings <file> [minlen]", "printable runs in a file",                     0, TRM_PKG_HEX, cmd_strings },
};

static const int kCmdCount = (int)(sizeof(kCmds) / sizeof(kCmds[0]));

int trm_shell_command_count(void) { return kCmdCount; }

static const trm_cmd *sh_lookup(const char *name) {
    for (int i = 0; i < kCmdCount; i++) {
        if (!strcmp(kCmds[i].name, name)) return &kCmds[i];
    }
    return NULL;
}

static int cmd_help(int argc, char **argv) {
    if (argc > 1) {
        const trm_cmd *c = sh_lookup(argv[1]);
        if (!c) { sh_err("help: no such command '%s'", argv[1]); return 1; }
        sh_out("%-28s %s", c->usage, c->help);
        if (c->needs_unsafe) sh_out("  (gated: run `unsafe 1` first)");
        return 0;
    }
    sh_out("route A in-process shell - no exec, no pty, full kernel R/W via the escape");
    {
        char cwd[PATH_MAX];
        sh_out("unsafe=%d  cwd=%s  packages=%d/%d installed", g_unsafe,
               getcwd(cwd, sizeof(cwd)) ? cwd : "?", g_pkgInstalledCount(), TRM_PKG_COUNT);
    }
    for (int i = 0; i < kCmdCount; i++) {
        const trm_cmd *c = &kCmds[i];
        char tag[40] = "";
        if (c->pkg != TRM_PKG_NONE) {
            snprintf(tag, sizeof(tag), " [%s%s]", kPkgNames[c->pkg], g_pkgEnabled[c->pkg] ? ":on" : " - pkg install");
        }
        sh_out("  %-28s %s%s%s", c->usage, c->help, c->needs_unsafe ? " [unsafe]" : "", tag);
    }
    return 0;
}

int trm_shell_exec_line(const char *line) {
    if (!line) return -1;
    while (*line == ' ' || *line == '\t') line++;
    if (!*line || *line == '#') return 0;

    static char argv[TRM_MAX_ARGS][TRM_MAX_ARG_LEN];
    int argc = 0;
    sh_parse(line, &argc, argv);
    if (argc == 0) return 0;

    const trm_cmd *c = sh_lookup(argv[0]);
    if (!c) {
        sh_err("%s: command not found (this shell implements commands in-process; `spawn %s` runs a platform binary if the profile allows it)", argv[0], argv[0]);
        return 1;
    }
    if (c->needs_unsafe && !g_unsafe) {
        sh_err("%s is gated - run `unsafe 1` first", c->name);
        return 2;
    }
    if (c->pkg != TRM_PKG_NONE && !g_pkgEnabled[c->pkg]) {
        sh_err("%s is part of the '%s' package - install it: `pkg install %s` (or Settings > Packages)",
               c->name, kPkgNames[c->pkg], kPkgNames[c->pkg]);
        return 2;
    }
    char *cargv[TRM_MAX_ARGS];
    for (int i = 0; i < argc; i++) cargv[i] = argv[i];
    return c->fn(argc, cargv);
}

const char *trm_shell_prompt(void) { return g_prompt; }

int trm_shell_unsafe(void) { return g_unsafe; }

void trm_shell_set_unsafe(int v) {
    g_unsafe = v ? 1 : 0;
    snprintf(g_prompt, sizeof(g_prompt), "%s", g_unsafe ? "w0lf(unsafe)> " : "w0lf> ");
}

// --- device smoke test ----------------------------------------------------

void trm_shell_selftest(void) {
    // Read-only commands only: this must be safe to run on the daily driver
    // with no unsafe flag, no kernel writes, and no exec side effects.
    static const char *lines[] = {
        "help",
        "id",
        "uname",
        "pwd",
        "ls -l /",
        "ls /System/Library/CoreServices",
        "cat /System/Library/CoreServices/SystemVersion.plist",
        "cd /",
        "pwd",
        "stat /",
        "df",
        "echo selftest-echo",
        "krw",
        "sbxinfo",
        "proc SpringBoard",
        "sbxtest",
        "verdict",
        "nosuchcommand",
        "kread 0x0 16",
        // packages: gated commands refuse until installed, then work in-process
        "pkg",
        "fetch",
        "pkg install sysinfo",
        "fetch",
        "loadavg",
        "cpu",
        "mem",
        "pkg install net",
        "net",
        "myip",
        "dns",
        "pkg install hex",
        "strings /etc/hosts",
        "hexdump /etc/hosts 0 64",
        "pkg remove sysinfo",
        "pkg remove net",
        "pkg remove hex",
        "pkg",
        "unsafe 0",
    };
    int total = (int)(sizeof(lines) / sizeof(lines[0]));
    int ok = 0, err = 0;
    TweakLog("[TRM][SELFTEST] running %d read-only shell commands", total);
    for (int i = 0; i < total; i++) {
        int rc = trm_shell_exec_line(lines[i]);
        if (rc == 0) ok++;
        else err++;
        TweakLog("[TRM][SELFTEST] %2d/%d '%s' -> rc=%d", i + 1, total, lines[i], rc);
    }
    // cwd was changed by the script; go back to the container.
    if (chdir(trm_ctx_home()) != 0) { /* best effort */ }
    TweakLog("[TRM][SELFTEST] done: ok=%d err=%d (rc=1/2 is expected for the deliberate failures: nosuchcommand, kread 0x0, and the gated `fetch` before its package is installed)", ok, err);
}
