// container_access.m — userspace container access layer
// Techniques ported from 0xjohnnydev/FilzaSlop (MCMBridge + MCMFilzaIntegration).
#import "container_access.h"
#import "mcm_bridge.h"

#import <stdlib.h>
#import <string.h>
#import <stdio.h>
#import <fcntl.h>
#import <unistd.h>
#import <dirent.h>
#import <sys/stat.h>
#import <Foundation/Foundation.h>
#import <xpc/xpc.h>
#import "../utils/tweak_log.h"

// Flags from FilzaSlop: metadata-only enumeration and read-write part flags.
#define MCM_ENUMERATE_FLAGS     0x100000000ULL
#define MCM_READWRITE_PART_FLAGS 0x8100000000ULL

// Older iOS SDK headers don't export this; it lives in libxpc.
extern xpc_object_t xpc_string_create(const char *string);

static bool identifier_char(uint8_t c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
}

char *mcm_activate_container(uint64_t container_class, const char *identifier,
                             bool group, uint64_t part, const char *part_domain,
                             uint64_t flags) {
    if (!mcm_bridge_available() || !identifier || !identifier[0]) return NULL;
    const struct mcm_api *api = mcm_api();

    void *query = api->query_create();
    if (!query) return NULL;
    api->query_set_class(query, container_class);
    xpc_object_t value = xpc_string_create(identifier);
    if (group) api->query_set_group_identifiers(query, value);
    else       api->query_set_identifiers(query, value);
#if !OS_OBJECT_USE_OBJC
    xpc_release(value);
#endif
    api->query_set_flags(query, flags);
    if (part != 0 && api->query_set_part) api->query_set_part(query, part);
    if (part_domain && api->query_set_part_domain) api->query_set_part_domain(query, part_domain);

    void *object = api->query_get_single_result(query);
    if (!object) {
        void *qerr = api->query_get_last_error(query);
        int posix = qerr && api->error_get_posix_errno ? api->error_get_posix_errno(qerr) : 0;
        TweakLog("[MCM] lookup denied class=%llu id=%s posix=%d",
                 (unsigned long long)container_class, identifier, posix);
        api->query_free(query);
        return NULL;
    }

    const char *rawPath = api->object_get_path(object);
    if (!rawPath || !rawPath[0] || rawPath[0] != '/') {
        api->query_free(query);
        return NULL;
    }
    char *root = strdup(rawPath);
    if (root && strncmp(root, "/var/", 5) == 0) {
        char *fixed = NULL;
        if (asprintf(&fixed, "/private%s", root) > 0) { free(root); root = fixed; }
    }

    void *activation = api->object_copy(object);
    char *token = activation ? api->object_copy_sandbox_token(activation) : NULL;
    bool activated = false;
    if (token && token[0] != '\0' && activation) {
        activated = api->object_sandbox_extension_activate(activation, false);
    }
    if (!activated) {
        TweakLog("[MCM] activation failed class=%llu id=%s (token=%s)",
                 (unsigned long long)container_class, identifier,
                 (token && token[0]) ? "yes" : "no");
        free(root); root = NULL;
    } else {
        TweakLog("[MCM] activated class=%llu id=%s path=%s",
                 (unsigned long long)container_class, identifier, root ? root : "(null)");
    }
    if (token) free(token);
    if (activation) api->object_free(activation);
    api->query_free(query);
    return root;
}

static int mcm_count_identifiers(uint64_t container_class, int limit) {
    if (!mcm_bridge_available()) return -1;
    const struct mcm_api *api = mcm_api();
    if (!api->query_iterate_results_sync || !api->object_get_identifier) return -1;

    void *query = api->query_create();
    if (!query) return -1;
    api->query_set_class(query, container_class);
    api->query_set_flags(query, MCM_ENUMERATE_FLAGS);
    if (api->query_set_part) api->query_set_part(query, 0);

    __block int count = 0;
    bool ok = api->query_iterate_results_sync(query, ^bool(void *object) {
        if (object && api->object_get_identifier(object)) count++;
        return count < limit;
    });
    if (!ok) {
        void *qerr = api->query_get_last_error(query);
        int posix = qerr && api->error_get_posix_errno ? api->error_get_posix_errno(qerr) : 0;
        TweakLog("[MCM] enumerate class=%llu denied posix=%d",
                 (unsigned long long)container_class, posix);
    }
    api->query_free(query);
    return ok ? count : -1;
}

bool userspace_container_probe(void) {
    static dispatch_once_t onceToken;
    static bool probeResult = false;
    dispatch_once(&onceToken, ^{
        if (!mcm_bridge_available()) {
            TweakLog("[MCM] bridge unavailable — no userspace container access");
            probeResult = false;
            return;
        }
        int successes = 0;

        // Probe: our own app container (class 2) is the least privileged ask.
        const char *selfId = [[NSBundle mainBundle].bundleIdentifier UTF8String];
        if (selfId && selfId[0]) {
            char *own = mcm_activate_container(MCM_CLASS_APP_DATA, selfId,
                                               false, 0, NULL, MCM_ENUMERATE_FLAGS);
            if (own) { successes++; free(own); }
        }

        // Probe: com.apple.lsd service container (iOS 26 app discovery gate).
        char *lsd = mcm_activate_container(MCM_CLASS_SERVICE_DATA, "com.apple.lsd",
                                           false, 0, NULL, MCM_ENUMERATE_FLAGS);
        if (lsd) { successes++; free(lsd); }

        int appCount = mcm_count_identifiers(MCM_CLASS_APP_DATA, 256);
        TweakLog("[MCM] app container enumeration: %s", appCount > 0 ? "YES" : "no/denied");

        if (successes > 0 || appCount > 0) {
            TweakLog("[MCM] *** CONTAINER ACCESS ACTIVE (userspace) — %d leases, %d apps ***",
                     successes, appCount > 0 ? appCount : 0);
            probeResult = true;
        } else {
            TweakLog("[MCM] userspace container access DENIED — identity not trusted "
                     "(kernel escape needed, or re-sign as com.apple.mobile.MobileHouseArrest)");
            probeResult = false;
        }
    });
    return probeResult;
}

char **mcm_lsd_discover_apps(int limit) {
    if (limit <= 0) return NULL;
    char *lsdPath = mcm_activate_container(MCM_CLASS_SERVICE_DATA, "com.apple.lsd",
                                           false, 0, NULL, MCM_READWRITE_PART_FLAGS);
    if (!lsdPath) {
        TweakLog("[MCM] lsd service container unavailable — cannot scan LaunchServices store");
        return NULL;
    }

    char **out = calloc((size_t)limit + 1, sizeof(char *));
    int found = 0;
    DIR *dir = opendir(lsdPath);
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) && found < limit) {
            const char *name = entry->d_name;
            if (strncmp(name, "com.apple.LaunchServices-", 25) != 0) continue;
            char full[PATH_MAX];
            snprintf(full, sizeof(full), "%s/%s", lsdPath, name);
            int fd = open(full, O_RDONLY);
            if (fd < 0) continue;
            // Byte-scan the store file for bundle-identifier-shaped runs.
            uint8_t buf[8192];
            ssize_t n;
            char run[256]; int runLen = 0;
            while ((n = read(fd, buf, sizeof(buf))) > 0 && found < limit) {
                for (ssize_t i = 0; i < n; i++) {
                    if (identifier_char(buf[i])) {
                        if (runLen < (int)sizeof(run) - 1) run[runLen++] = (char)buf[i];
                    } else {
                        run[runLen] = '\0';
                        if (runLen >= 5 && strchr(run, '.')) {
                            bool dup = false;
                            for (int j = 0; j < found; j++)
                                if (strcmp(out[j], run) == 0) { dup = true; break; }
                            if (!dup) { out[found++] = strdup(run); }
                        }
                        runLen = 0;
                    }
                }
            }
            close(fd);
        }
        closedir(dir);
    }
    free(lsdPath);
    TweakLog("[MCM] lsd store scan: %d bundle candidates", found);
    out[found] = NULL;
    return out;
}
