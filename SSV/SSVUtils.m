#import "SSVUtils.h"
#import <stdbool.h>
#import <unistd.h>
#import <fcntl.h>
#import <time.h>
#import <stdarg.h>
#import <limits.h>
#import <dispatch/dispatch.h>
#import "kexploit/krw.h"
#import "kexploit/vnode.h"
#import "kexploit/kutils.h"
#import "kexploit/sandbox.h"
#import "kexploit/file.h"
#import "kexploit/vnode_research.h"
#import "utils/permission_utils.h"
#import "utils/tweak_log.h"
#import "utils/state.h"

__attribute__((constructor))
static void SSVUtils_init(void) {
    TweakLog("SSVUtils loaded successfully");
}

bool ssv_write(const char *path, const void *data, size_t len) {
    TweakLog("ssv_write called with path: %s", path);
    if (!data || len == 0) return false;

    // Kernel operations below need a live exploit. Check FIRST, before any
    // work, so we never touch kernel memory with a cold krw primitive.
    if (!exploit_is_done()) {
        TweakLog("[SSV] Exploit not done — refusing ssv_write");
        return false;
    }

    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "/tmp/ssv_%d", getpid());
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;
    write(fd, data, len);
    close(fd);

    TweakLog("Calling patch_sandbox_ext()...");
    int sandboxRet = patch_sandbox_ext();
    TweakLog("patch_sandbox_ext returned %d", sandboxRet);
    if (sandboxRet != 0) {
        // SSV write path is not active — the vnode swap below would corrupt
        // the wrong file. Abort before any kernel write.
        TweakLog("[SSV] patch_sandbox_ext failed (%d) — aborting before kernel vnode writes", sandboxRet);
        unlink(tmp);
        return false;
    }

    bool isSSV = is_ssv_protected_path(path);
    TweakLog("Path %s is SSV-protected: %s", path, isSSV ? "YES" : "NO");

    int ret = -1;
    if (isSSV) {
        TweakLog("Using overwrite_system_file for SSV path");
        ret = overwrite_system_file((char*)path, tmp);
        if (ret == 0) {
            TweakLog("SSV write successful, applying root:wheel");
            force_chown_root_wheel(path);
        }
    } else {
        TweakLog("Using standard copy for non-SSV path");
        if (rename(tmp, path) == 0) {
            ret = 0;
            TweakLog("Non-SSV write successful, applying parent permissions");
            apply_parent_permissions(path);
        } else {
            TweakLog("rename failed: %s", strerror(errno));
            int fd_in = open(tmp, O_RDONLY);
            int fd_out = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd_in >= 0 && fd_out >= 0) {
                char buf[4096];
                ssize_t n;
                while ((n = read(fd_in, buf, sizeof(buf))) > 0) {
                    write(fd_out, buf, n);
                }
                ret = 0;
                apply_parent_permissions(path);
            }
            if (fd_in >= 0) close(fd_in);
            if (fd_out >= 0) close(fd_out);
        }
    }

    TweakLog("Final result: %d", ret);
    unlink(tmp);
    return ret == 0;
}

bool ssv_chown_root(const char *path) {
    TweakLog("ssv_chown_root called for: %s", path);
    if (!exploit_is_done()) {
        TweakLog("[SSV] Exploit not done — refusing ssv_chown_root (kernel fsnode write)");
        return false;
    }
    return force_chown_root_wheel(path);
}

void ssv_dump_fsnode(const char *path) {
    if (!exploit_is_done()) {
        TweakLog("[SSV] Exploit not done — refusing ssv_dump_fsnode (kernel vnode read)");
        return;
    }
    research_vnode_apfs_fsnode(path);
}
