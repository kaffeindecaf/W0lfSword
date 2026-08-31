#import "permission_utils.h"
#import "../kexploit/vnode.h"
#import "../kexploit/krw.h"
#import "../kexploit/offsets.h"
#import "../kexploit/xpaci.h"
#import "tweak_log.h"
#import "state.h"
#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <unistd.h>
#import <fcntl.h>
#import <errno.h>
#import <string.h>
#import <libgen.h>

bool is_ssv_protected_path(const char *path) {
    if (!path) return false;
    
    // SSV-protected paths: /System, /bin, /sbin, /usr/libexec
    if (strncmp(path, "/System", 7) == 0) return true;
    if (strncmp(path, "/bin", 4) == 0) return true;
    if (strncmp(path, "/sbin", 5) == 0) return true;
    if (strncmp(path, "/usr/libexec", 12) == 0) return true;
    
    return false;
}

bool get_parent_dir_info(const char *path, uid_t *uid, gid_t *gid, mode_t *mode) {
    if (!path || !uid || !gid || !mode) return false;
    
    char *pathCopy = strdup(path);
    char *parentDir = dirname(pathCopy);
    
    TweakLog("get_parent_dir_info: path=%s parent=%s", path, parentDir);
    
    // Try user-level stat first
    struct stat st;
    if (stat(parentDir, &st) == 0) {
        *uid = st.st_uid;
        *gid = st.st_gid;
        *mode = st.st_mode;
        TweakLog("User stat succeeded: uid=%d gid=%d mode=%o", *uid, *gid, *mode);
        free(pathCopy);
        return true;
    }
    
    TweakLog("User stat failed, trying kernel-level read for %s", parentDir);
    
    // Fallback: kernel-level vnode read
    uint64_t vnode = get_vnode_for_path_by_chdir(parentDir);
    if (vnode == -1) {
        TweakLog("Cannot get vnode for parent dir %s", parentDir);
        free(pathCopy);
        return false;
    }
    
    uint64_t v_data = xpaci(kread64(vnode + off_vnode_v_data));
    if (!v_data) {
        TweakLog("Cannot get v_data for parent dir %s", parentDir);
        free(pathCopy);
        return false;
    }
    
    *uid = kread32(v_data + off_apfs_fsnode_uid);
    *gid = kread32(v_data + off_apfs_fsnode_gid);
    *mode = kread16(v_data + off_apfs_fsnode_mode);
    
    TweakLog("Kernel read succeeded: uid=%d gid=%d mode=%o", *uid, *gid, *mode);
    free(pathCopy);
    return true;
}

static int apply_permissions_kernel(const char *path, uid_t uid, gid_t gid, mode_t mode) {
    TweakLog("apply_permissions_kernel: %s uid=%d gid=%d mode=%o", path, uid, gid, mode);
    
    if (!exploit_is_done()) {
        TweakLog("apply_permissions_kernel: exploit not done — refusing kernel fsnode write for %s", path);
        return -1;
    }
    
    uint64_t vnode = get_vnode_for_path_by_open(path);
    if (vnode == -1) {
        TweakLog("Cannot get vnode for %s", path);
        return -1;
    }
    
    uint64_t v_data = xpaci(kread64(vnode + off_vnode_v_data));
    if (!v_data) {
        TweakLog("Cannot get v_data for %s", path);
        return -1;
    }

    // Sanity check: read the current mode to verify fsnode offset is valid (BB-012).
    // APFS modes carry S_IFMT type bits (dirs read 040777, files 0100644), so the
    // old `currentMode > 0777` guard compared type bits against a permission mask:
    // it ALWAYS aborted on real paths (kernel chmod/chown dead on every device)
    // while still passing any small garbage value if the offset were wrong — the
    // worst possible guard. Validate the type bits and cross-check uid/gid so a
    // wrong offset must fail BOTH plausibility tests before any write happens.
    uint16_t currentMode = kread16(v_data + off_apfs_fsnode_mode);
    uint32_t curUid = kread32(v_data + off_apfs_fsnode_uid);
    uint32_t curGid = kread32(v_data + off_apfs_fsnode_gid);
    uint32_t typeBits = currentMode & 0170000;
    bool typeOk = typeBits == 0 || typeBits == 0010000 || typeBits == 0020000 ||
                  typeBits == 0040000 || typeBits == 0060000 || typeBits == 0100000 ||
                  typeBits == 0120000 || typeBits == 0140000;
    if (!typeOk || curUid > 65535 || curGid > 65535) {
        TweakLog("APFS fsnode offset mismatch: mode=0%o type=0%o uid=%u gid=%u — aborting write to avoid corruption", currentMode, typeBits, curUid, curGid);
        return -1;
    }

    // Sanity: validate uid/gid are within reasonable bounds (0-65535)
    if (uid > 65535 || gid > 65535) {
        TweakLog("APFS fsnode sanity fail: uid=%u gid=%u out of range — aborting", uid, gid);
        return -1;
    }

    kwrite32(v_data + off_apfs_fsnode_uid, uid);
    kwrite32(v_data + off_apfs_fsnode_gid, gid);
    kwrite16(v_data + off_apfs_fsnode_mode, mode & 0777);
    
    // Refresh vnode counters to trigger kernel revalidation
    uint32_t usec = kread32(vnode + off_vnode_v_usecount);
    uint32_t ioc = kread32(vnode + off_vnode_v_iocount);
    kwrite32(vnode + off_vnode_v_usecount, usec + 1);
    kwrite32(vnode + off_vnode_v_iocount, ioc + 1);
    kwrite32(vnode + off_vnode_v_usecount, usec);
    kwrite32(vnode + off_vnode_v_iocount, ioc);
    
    TweakLog("Kernel permissions applied successfully");
    return 0;
}

int apply_parent_permissions(const char *path) {
    if (!path) return -1;
    
    TweakLog("apply_parent_permissions: %s", path);
    
    uid_t uid;
    gid_t gid;
    mode_t mode;
    
    if (!get_parent_dir_info(path, &uid, &gid, &mode)) {
        TweakLog("Failed to get parent dir info for %s", path);
        return -1;
    }
    
    // Try user-level chown first
    if (chown(path, uid, gid) == 0) {
        chmod(path, mode & 0777);
        TweakLog("User-level chown/chmod succeeded");
        return 0;
    }
    
    TweakLog("User-level chown failed, using kernel: %s", strerror(errno));
    
    // Fallback to kernel-level
    return apply_permissions_kernel(path, uid, gid, mode);
}

bool force_chown_root_wheel(const char *path) {
    if (!path) return false;
    
    TweakLog("force_chown_root_wheel: %s", path);
    
    // For SSV paths, always use kernel-level
    return apply_permissions_kernel(path, 0, 0, 0644) == 0;
}

void apply_permissions_after_operation(const char *path, const char *operation) {
    if (!path || !operation) return;
    
    TweakLog("apply_permissions_after_operation: %s (%s)", path, operation);
    
    if (is_ssv_protected_path(path)) {
        TweakLog("SSV-protected path detected, forcing root:wheel");
        force_chown_root_wheel(path);
    } else {
        TweakLog("Non-SSV path, applying parent permissions");
        apply_parent_permissions(path);
    }
}
