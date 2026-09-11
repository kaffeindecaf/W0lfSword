// terminal/trm_probe.c — TRM.1 / TRM.2 / TRM.4 on-device probes.
//
// The 0.11 round (ROADMAP: "Terminal with full kernel R/W") was first written
// up from desk research because no device was attached. This file turns each
// open question into a datapoint the 26.0.1 daily driver answers on the next
// launch:
//
//   TRM.1  does the sandbox profile allow process-exec after our escape?
//          (sandbox_check per path + a real posix_spawn of /bin/sh)
//   TRM.2  can a binary that is NOT on the system volume be exec'd?
//          (copy of /bin/sh into the container, then exec the copy)
//   TRM.4  do posix_openpt/grantpt/unlockpt + slave open work, and does data
//          actually round-trip through the pty?
//   TRM.5  read yes / write no on the sealed system volume
//
// Nothing here relaxes anything. It measures, logs, and stops — the A/B/C
// route decision follows from the numbers (trm_probe_verdict()).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <poll.h>
#include <spawn.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <termios.h>
#include <limits.h>
#include <mach/mach.h>

#include "terminal/trm_common.h"
#include "terminal/trm_probe.h"
#include "kexploit/sandbox.h"   // sandbox_check + filter-type constants
#include "utils/tweak_log.h"

extern char **environ;

// --- probe datapoints (read by trm_probe_verdict) -------------------------
static int g_proc_exec_sbx = -2;   // sandbox_check("process-exec","/bin/sh")
static int g_spawn_rc = -1;        // posix_spawn return for /bin/sh
static int g_spawn_errno = -1;     // errno at the failing step
static int g_fork_rc = -1;
static int g_copy_exec_rc = -1;
static int g_pty_rc = -1;
static int g_sealed_read = -1;
static int g_sealed_write = -1;
static char g_verdict[768] = {0};

const char *trm_probe_sbx_word(int v) {
    if (v == 0) return "ALLOWED";
    if (v < 0) return "ERR";
    return "DENIED";
}

int trm_probe_sandbox_op(const char *op, const char *path) {
    if (!op) return -1;
    errno = 0;
    if (path && path[0]) {
        return sandbox_check(getpid(), op,
                             (enum sandbox_filter_type)(SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT),
                             path);
    }
    return sandbox_check(getpid(), op,
                         (enum sandbox_filter_type)(SANDBOX_FILTER_NONE | SANDBOX_CHECK_NO_REPORT));
}

// --- helpers --------------------------------------------------------------

// Echo the first `max_lines` lines of a capture file into the log. The spawn
// tests redirect stdout+stderr there, so this is where a successful
// posix_spawn's evidence shows up (non-jailbroken sideloads cannot read the
// child's stdout any other way).
static void dump_capture(const char *path, int max_lines) {
    if (!path) return;
    FILE *f = fopen(path, "r");
    if (!f) {
        TweakLog("[TRM]   (no capture file %s: errno=%d %s)", path, errno, strerror(errno));
        return;
    }
    char line[512];
    int n = 0;
    int truncated = 0;
    while (fgets(line, sizeof(line), f)) {
        size_t l = strlen(line);
        while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = '\0';
        if (n < max_lines) {
            TweakLog("[TRM]   | %s", line);
            n++;
        } else {
            truncated = 1;
        }
    }
    if (truncated) TweakLog("[TRM]   | ... (further output truncated)");
    if (n == 0) TweakLog("[TRM]   | (capture empty — child produced no output)");
    fclose(f);
    if (n == 0) unlink(path);
}

static int copy_file(const char *src, const char *dst, mode_t mode) {
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    unlink(dst);
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (out < 0) {
        int e = errno;
        close(in);
        errno = e;
        return -1;
    }
    char buf[65536];
    ssize_t r;
    int rc = 0;
    while ((r = read(in, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < r) {
            ssize_t w = write(out, buf + off, (size_t)(r - off));
            if (w <= 0) {
                rc = -1;
                break;
            }
            off += w;
        }
        if (rc < 0) break;
    }
    if (r < 0) rc = -1;
    close(in);
    close(out);
    if (rc == 0) chmod(dst, mode);
    return rc;
}

// --- TRM.1: exec surface -------------------------------------------------

typedef struct {
    const char *op;
    const char *path;   // NULL = no path filter
} trm_sbx_op;

// Operands that decide the terminal's route. Kept to ops that take zero or one
// path operand (a vararg mismatch on a path op would feed the checker garbage).
static const trm_sbx_op kSbxOps[] = {
    { "process-exec",                        "/bin/sh" },
    { "process-exec",                        "/usr/bin/true" },
    { "process-exec-interpreter",            "/bin/sh" },
    { "process-fork",                        NULL },
    { "file-read-data",                      "/bin/sh" },
    { "file-read-metadata",                  "/" },
    { "file-write-data",                     "/private/var/mobile" },
    { "file-read-data",                      "/private/var" },
    { "file-write-data",                     "/private/var" },
    { "file-read-data",                      "/dev/ptmx" },
    { "file-write-data",                     "/dev/ptmx" },
    { "file-ioctl",                          "/dev/ptmx" },
    { "file-write-data",                     "/System/Library/CoreServices/SystemVersion.plist" },
    { "sysctl-read",                         NULL },
    { "network-outbound",                    NULL },
    { "ipc-posix-shm",                       NULL },
};

void trm_probe_sbx_matrix(void) {
    TweakLog("[TRM][EXEC] sandbox_check matrix pid=%d (0=ALLOWED, 1=DENIED, -1=call failed):", (int)getpid());
    for (size_t i = 0; i < sizeof(kSbxOps) / sizeof(kSbxOps[0]); i++) {
        const trm_sbx_op *o = &kSbxOps[i];
        int v = trm_probe_sandbox_op(o->op, o->path);
        TweakLog("[TRM][EXEC]   %-28s %-52s -> %s(%d)",
                 o->op, o->path ? o->path : "(no path)", trm_probe_sbx_word(v), v);
    }
    g_proc_exec_sbx = trm_probe_sandbox_op("process-exec", "/bin/sh");
}

int trm_probe_exec_surface(const char *dir, int max_lines) {
    if (!dir) return -1;
    DIR *d = opendir(dir);
    if (!d) {
        TweakLog("[TRM][EXEC] opendir %s FAILED errno=%d (%s)", dir, errno, strerror(errno));
        return -1;
    }
    int entries = 0, regular = 0, execbit = 0, macho = 0, sbxok = 0, shown = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '\0') continue;
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(full, &st) != 0) continue;
        entries++;
        if (!S_ISREG(st.st_mode)) continue;
        regular++;

        int x = (access(full, X_OK) == 0);
        if (x) execbit++;

        int is_macho = 0, is_fat = 0;
        int fd = open(full, O_RDONLY);
        if (fd >= 0) {
            uint32_t magic = 0;
            if (read(fd, &magic, sizeof(magic)) == (ssize_t)sizeof(magic)) {
                if (magic == 0xfeedfacf || magic == 0xfeedface) is_macho = 1;
                else if (magic == 0xcafebabe || magic == 0xbebafeca) is_fat = 1;
            }
            close(fd);
        }
        if (is_macho || is_fat) macho++;

        int sx = trm_probe_sandbox_op("process-exec", full);
        if (sx == 0) sbxok++;

        if (shown < max_lines) {
            TweakLog("[TRM][EXEC]   %-40s x=%d macho=%d fat=%d size=%-9lld sbx_exec=%s(%d)",
                     full, x, is_macho, is_fat, (long long)st.st_size,
                     trm_probe_sbx_word(sx), sx);
            shown++;
        }
    }
    closedir(d);
    TweakLog("[TRM][EXEC] %s: entries=%d regular=%d exec_bit=%d macho=%d sbx_allows_exec=%d",
             dir, entries, regular, execbit, macho, sbxok);
    if (entries - shown > 0) {
        TweakLog("[TRM][EXEC] %s: ... %d more entries not shown", dir, entries - shown);
    }
    return entries;
}

// --- TRM.1: fork ---------------------------------------------------------

int trm_probe_fork_test(void) {
    errno = 0;
    pid_t pid = fork();
    if (pid < 0) {
        int e = errno;
        TweakLog("[TRM][FORK] fork FAILED errno=%d (%s)", e, strerror(e));
        g_fork_rc = -e;
        return -e;
    }
    if (pid == 0) {
        _exit(0);   // child: no logging, no ObjC, no atexit handlers
    }
    int st = 0;
    int waited_ms = 0;
    while (waited_ms < 2000) {
        pid_t w = waitpid(pid, &st, WNOHANG);
        if (w == pid) break;
        if (w < 0) break;
        usleep(20000);
        waited_ms += 20;
    }
    if (waited_ms >= 2000) {
        kill(pid, SIGKILL);
        TweakLog("[TRM][FORK] fork OK (child pid=%d) but reap timed out", (int)pid);
        g_fork_rc = -1;
        return -1;
    }
    TweakLog("[TRM][FORK] fork OK child=%d exited status=%d", (int)pid, WEXITSTATUS(st));
    g_fork_rc = 0;
    return 0;
}

// --- TRM.1/TRM.2: spawn --------------------------------------------------

int trm_probe_spawn(const char *path, char *const argv[], int timeout_ms,
                    const char *outfile, int *exit_status_out) {
    if (!path || !argv) return -1;
    if (exit_status_out) *exit_status_out = -1;

    char default_out[PATH_MAX];
    if (!outfile) outfile = trm_ctx_docs_path(default_out, sizeof(default_out), "trm_spawn_out.txt");

    // Redirect stdout+stderr before exec: on a non-jailbroken sideload there is
    // no pipe to a host, so the child's output can only be recovered through a
    // file in our own container.
    posix_spawn_file_actions_t fa;
    int have_fa = (posix_spawn_file_actions_init(&fa) == 0);
    if (have_fa) {
        unlink(outfile);
        posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    }

    const char *envp[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/var/mobile", NULL };
    pid_t pid = 0;
    errno = 0;
    // posix_spawn returns the error DIRECTLY (not -1/errno), so the return
    // value itself is the errno to report.
    int ret = posix_spawn(&pid, path, have_fa ? &fa : NULL, NULL, argv, (char *const *)envp);
    if (have_fa) posix_spawn_file_actions_destroy(&fa);

    if (ret != 0) {
        int sx = trm_probe_sandbox_op("process-exec", path);
        TweakLog("[TRM][SPAWN] posix_spawn(\"%s\") FAILED rc=%d errno=%d (%s) uid=%d euid=%d",
                 path, ret, ret, strerror(ret), (int)getuid(), (int)geteuid());
        TweakLog("[TRM][SPAWN]   argv=%s %s %s", argv[0] ? argv[0] : "(null)",
                 argv[1] ? argv[1] : "", argv[2] ? argv[2] : "");
        TweakLog("[TRM][SPAWN]   sandbox_check(process-exec, %s)=%s(%d) — a profile denial here is a rule, not code signing",
                 path, trm_probe_sbx_word(sx), sx);
        // Nothing ran, so no capture file exists — dump_capture says so.
        dump_capture(outfile, 15);
        return ret;
    }

    int st = 0;
    int waited_ms = 0;
    int timed_out = 0;
    while (1) {
        pid_t w = waitpid(pid, &st, WNOHANG);
        if (w == pid) break;
        if (w < 0) break;   // ECHILD / already reaped
        if (waited_ms >= timeout_ms) {
            kill(pid, SIGKILL);
            waitpid(pid, &st, 0);
            timed_out = 1;
            break;
        }
        usleep(20000);
        waited_ms += 20;
    }

    int exited = WIFEXITED(st);
    int signaled = WIFSIGNALED(st);
    TweakLog("[TRM][SPAWN] \"%s\" spawned pid=%d -> %s exit=%d sig=%d",
             path, (int)pid,
             timed_out ? "TIMEOUT(killed)" : exited ? "exited" : signaled ? "signaled" : "unknown",
             exited ? WEXITSTATUS(st) : -1,
             signaled ? WTERMSIG(st) : 0);
    dump_capture(outfile, 20);
    if (exit_status_out) *exit_status_out = exited ? WEXITSTATUS(st) : -1;
    return timed_out ? -1 : 0;
}

int trm_probe_container_copy_exec(void) {
    char dst[PATH_MAX];
    trm_ctx_docs_path(dst, sizeof(dst), "trm_sh_copy");

    // A bundle-resident helper (TRM.2's real target) needs a signed sidecar
    // binary at build time. The container copy exercises the same kernel
    // question — "can a Mach-O that does not live on the SSV be exec'd?" —
    // with zero build-side work: /bin/sh's bytes are copied verbatim, so the
    // Apple signature travels along and only the location changes.
    if (copy_file("/bin/sh", dst, 0755) != 0) {
        TweakLog("[TRM][EXEC2] copy /bin/sh -> %s FAILED errno=%d (%s) — needs file-read on /bin",
                 dst, errno, strerror(errno));
        g_copy_exec_rc = -errno;
        return -errno;
    }
    struct stat st;
    if (stat(dst, &st) == 0) {
        TweakLog("[TRM][EXEC2] copied /bin/sh -> %s (%lld bytes, mode=%o)",
                 dst, (long long)st.st_size, st.st_mode & 07777);
    }
    char *argv[] = { (char *)dst, (char *)"-c", (char *)"echo TRM2-CONTAINER-EXEC-OK", NULL };
    int status = -1;
    int rc = trm_probe_spawn(dst, argv, 4000, NULL, &status);
    TweakLog("[TRM][EXEC2] container-resident Mach-O exec: rc=%d status=%d (0 + status 0 = exec works off the SSV)",
             rc, status);
    g_copy_exec_rc = rc;
    return rc;
}

// --- TRM.4: pty ----------------------------------------------------------

int trm_probe_pty(char *slave_out, size_t n) {
    if (slave_out && n) slave_out[0] = '\0';

    int mr = trm_probe_sandbox_op("file-read-data", "/dev/ptmx");
    int mw = trm_probe_sandbox_op("file-write-data", "/dev/ptmx");
    TweakLog("[TRM][PTY] sandbox /dev/ptmx: read=%s(%d) write=%s(%d)",
             trm_probe_sbx_word(mr), mr, trm_probe_sbx_word(mw), mw);

    errno = 0;
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    int e_openpt = errno;
    if (master < 0) {
        TweakLog("[TRM][PTY] posix_openpt FAILED errno=%d (%s)", e_openpt, strerror(e_openpt));
        errno = 0;
        int fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        int e_dev = errno;
        TweakLog("[TRM][PTY] direct open(/dev/ptmx) -> %d errno=%d (%s)", fd, e_dev, strerror(e_dev));
        if (fd >= 0) close(fd);
        g_pty_rc = -e_openpt;
        return -e_openpt;
    }

    errno = 0;
    int gp = grantpt(master);
    int e_gp = (gp != 0) ? errno : 0;
    errno = 0;
    int up = unlockpt(master);
    int e_up = (up != 0) ? errno : 0;
    errno = 0;
    char *name = ptsname(master);
    int e_name = errno;
    TweakLog("[TRM][PTY] master=%d grantpt=%d(errno=%d) unlockpt=%d(errno=%d) ptsname=%s(errno=%d)",
             master, gp, e_gp, up, e_up, name ? name : "(null)", e_name);
    if (name && slave_out) snprintf(slave_out, n, "%s", name);

    int slave = -1;
    int e_slave = 0;
    if (name) {
        errno = 0;
        slave = open(name, O_RDWR | O_NOCTTY);
        e_slave = errno;
    }
    TweakLog("[TRM][PTY] slave=%d errno=%d (%s)", slave, e_slave, strerror(e_slave));
    if (slave < 0) {
        close(master);
        g_pty_rc = -e_slave;
        return -e_slave;
    }

    struct termios t;
    int e_tc = 0;
    errno = 0;
    int tc = tcgetattr(master, &t);
    if (tc != 0) e_tc = errno;

    // master -> slave
    const char *m2s = "trm-pty-master\n";
    ssize_t w1 = write(master, m2s, strlen(m2s));
    int e_w1 = (w1 < 0) ? errno : 0;
    int got_m2s = 0;
    char rbuf[256];
    struct pollfd pfd = { .fd = slave, .events = POLLIN, .revents = 0 };
    if (poll(&pfd, 1, 400) > 0) {
        ssize_t r = read(slave, rbuf, sizeof(rbuf) - 1);
        if (r > 0) {
            rbuf[r] = '\0';
            got_m2s = (int)r;
        }
    }

    // slave -> master
    const char *s2m = "trm-pty-slave\n";
    ssize_t w2 = write(slave, s2m, strlen(s2m));
    int e_w2 = (w2 < 0) ? errno : 0;
    int got_s2m = 0;
    struct pollfd pfd2 = { .fd = master, .events = POLLIN, .revents = 0 };
    if (poll(&pfd2, 1, 400) > 0) {
        ssize_t r = read(master, rbuf, sizeof(rbuf) - 1);
        got_s2m = (r > 0) ? (int)r : 0;
    }

    TweakLog("[TRM][PTY] tcgetattr=%d(errno=%d) write_master=%zd(errno=%d) master->slave=%d bytes, "
             "write_slave=%zd(errno=%d) slave->master=%d bytes",
             tc, e_tc, w1, e_w1, got_m2s, w2, e_w2, got_s2m);

    close(slave);
    close(master);

    if (got_m2s > 0 || got_s2m > 0) {
        TweakLog("[TRM][PTY] PTY WORKS — posix_openpt + slave + round trip all succeeded");
        g_pty_rc = 0;
        return 0;
    }
    TweakLog("[TRM][PTY] pty opened but NO data round trip (master->slave=%d, slave->master=%d)",
             got_m2s, got_s2m);
    g_pty_rc = -1;
    return -1;
}

// --- TRM.5: sealed volume ------------------------------------------------

void trm_probe_sealed_volume(void) {
    const char *p = "/System/Library/CoreServices/SystemVersion.plist";
    errno = 0;
    int fd = open(p, O_RDONLY);
    int e_r = errno;
    char first[64] = {0};
    if (fd >= 0) {
        read(fd, first, sizeof(first) - 1);
        close(fd);
    }
    TweakLog("[TRM][SSV] read %s -> fd=%d errno=%d (%s) head=\"%.24s\"", p, fd, e_r, strerror(e_r), first);
    g_sealed_read = (fd >= 0) ? 0 : -e_r;

    errno = 0;
    int wfd = open(p, O_WRONLY);
    int e_w = errno;
    TweakLog("[TRM][SSV] write-open %s -> fd=%d errno=%d (%s) %s", p, wfd, e_w, strerror(e_w),
             wfd >= 0 ? "(WRITABLE — SSV/extension patch is live)" : "(sealed, expected pre-patch)");
    if (wfd >= 0) close(wfd);
    g_sealed_write = (wfd >= 0) ? 0 : -e_w;
}

// --- report --------------------------------------------------------------

const char *trm_probe_verdict(void) {
    return g_verdict[0] ? g_verdict : "(no probe run yet)";
}

void trm_probe_run_all(const char *phase) {
    const char *ph = phase ? phase : "manual";
    TweakLog("[TRM] ===== terminal/exec probe: phase=%s =====", ph);
    TweakLog("[TRM][ID] pid=%d ppid=%d uid=%d euid=%d gid=%d egid=%d",
             (int)getpid(), (int)getppid(), (int)getuid(), (int)geteuid(),
             (int)getgid(), (int)getegid());
    struct utsname un;
    if (uname(&un) == 0) {
        TweakLog("[TRM][ID] sysname=%s release=%s machine=%s", un.sysname, un.release, un.machine);
    }

    // 1. profile verdicts (TRM.1)
    trm_probe_sbx_matrix();

    // 2. what is actually present and exec-capable (TRM.1 desk-research check:
    //    "/bin ships essentially sh/df/ps" — verify on this device)
    static const char *dirs[] = { "/bin", "/usr/bin", "/usr/sbin", "/sbin", "/usr/libexec" };
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        trm_probe_exec_surface(dirs[i], 12);
    }

    // 3. fork (needed by a pty shell, not by the in-process shell)
    trm_probe_fork_test();

    // 4. the real thing: run a platform shell (TRM.1)
    char docs_out[PATH_MAX];
    trm_ctx_docs_path(docs_out, sizeof(docs_out), "trm_sh_out.txt");
    char *argv[] = { (char *)"/bin/sh", (char *)"-c",
                     (char *)"id; uname -a; echo TRM1-SPAWN-OK; ls /System/Library/CoreServices | head -3", NULL };
    int status = -1;
    errno = 0;
    g_spawn_rc = trm_probe_spawn("/bin/sh", argv, 5000, docs_out, &status);
    g_spawn_errno = (g_spawn_rc != 0) ? g_spawn_rc : 0;

    // 5. off-SSV exec (TRM.2 analogue)
    trm_probe_container_copy_exec();

    // 6. pty (TRM.4)
    char slave[128];
    trm_probe_pty(slave, sizeof(slave));

    // 7. sealed volume read/write (TRM.5)
    trm_probe_sealed_volume();

    // Verdict: the route decision the roadmap asks for, stated as measurements.
    const char *exec_word = trm_probe_sbx_word(g_proc_exec_sbx);
    int exec_denied = (g_proc_exec_sbx != 0);
    const char *route;
    if (!exec_denied && g_spawn_rc == 0) {
        route = "exec works post-escape -> terminal can drive Apple binaries directly (pty shell is viable)";
    } else if (exec_denied && g_pty_rc == 0) {
        route = "pty works, exec denied by profile -> route A (in-process shell) + pty UI; route B needed only to run Apple binaries";
    } else {
        route = "exec + pty both denied -> route A (in-process shell, no exec, no pty) is the only route without kernel-side sandbox work";
    }
    snprintf(g_verdict, sizeof(g_verdict),
             "exec_profile=%s(%d) spawn_rc=%d fork_rc=%d copy_exec_rc=%d pty_rc=%d sealed_r=%d sealed_w=%d :: %s",
             exec_word, g_proc_exec_sbx, g_spawn_rc, g_fork_rc, g_copy_exec_rc, g_pty_rc,
             g_sealed_read, g_sealed_write, route);
    TweakLog("[TRM][VERDICT] %s", g_verdict);
    TweakLog("[TRM] ===== probe done (phase=%s) =====", ph);
}
