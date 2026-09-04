//
//  mobilegestalt.m
//  W0lfSword - MobileGestalt editing module (Chain F kernel-route impl)
//
//  See mobilegestalt.h for the host protocol. Objective-C is used for plist
//  + JSON handling only; every filesystem op is raw POSIX (open/write/fsync/
//  rename) so the module is immune to the SSV NSFileManager swizzles in
//  Tweak.m and to Filza's own file layer. MRC (the project builds without
//  -fobjc-arc): no code below stores autoreleased objects in statics.
//
//  Build note: substrate-free (plain Foundation), included in BOTH the MHA
//  and jailbroken tweak builds via the Makefile.
//

#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/types.h>
#import <sys/proc.h>
#import <signal.h>
#import <dirent.h>
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>
#import <string.h>
#import <strings.h>
#import <stdatomic.h>
#import <stdio.h>

#include "mobilegestalt.h"
#include "../utils/tweak_log.h"

// iOS 18.x-era container name (pre-26 fallback) and the 26.x container that
// bl_sbx/SparseBoxPlus/Erosion all target. The module globs for whichever
// exists on the device.
#define MG_CONTAINER_26   "systemgroup.com.apple.mobilegestaltcache"
#define MG_CONTAINER_18   "systemgroup.com.apple.mobilegestalt"
#define MG_REL_PATH       "Library/Caches/com.apple.MobileGestalt.plist"
#define MG_CMD_PREFIX     "mg-cmd-"
#define MG_RESULT_PREFIX  "mg-result-"
#define MG_STATE_PREFIX   "mg-state-"

// ---------------------------------------------------------------------------
// Known-key catalog (name -> base64 gestalt key + value type + description).
// Keys are the canonical MobileGestalt CacheExtra identifiers (PoomSmart
// dump lineage, cross-checked against Erosion MGKey.swift and SparseBoxPlus
// GestaltTweaksView.swift). Type: 'i' int, 's' string, 'b' bool, 'd' data.
// ---------------------------------------------------------------------------

typedef struct {
    const char *name;
    const char *key;
    char type;
    const char *desc;
} mg_catalog_entry;

static const mg_catalog_entry mg_catalog[] = {
    { "dynamic-island",    "YlEtTtHlNesRBMal1CqRaA", 'i', "DeviceSupportsDynamicIsland" },
    { "always-on-time",    "j8/Omm6s1lsmTDFsXjsBfA", 'i', "DeviceSupportsAlwaysOnTime" },
    { "always-on-display", "2OOJf1VhaM7NxfRok3HbWQ", 'i', "DeviceSupportsAlwaysOnDisplay" },
    { "aod-vibrancy",      "ykpu7qyhqFweVMKtxNylWA", 'i', "DeviceSupportsAODVibrancy" },
    { "charge-limit-80",   "37NVydb//GP/GrhuTN+exg", 'i', "DeviceSupports80ChargeLimit" },
    { "boot-chime",        "QHxt+hGLaBPbQJbXiUJX3w", 'i', "DeviceSupportsBootChime" },
    { "apple-pencil",      "yhHcB0iH0d1XzPO/CFd3ow", 'i', "DeviceSupportsApplePencil" },
    { "tap-to-wake",       "yZf3GTRMGTuwSV/lD7Cagw", 'i', "DeviceSupportsTapToWake" },
    { "camera-button",     "CwvKxM2cEogD3p+HYgaW0Q", 'i', "CameraButtonCapability" },
    { "action-button",     "cT44WE1EohiwRzhsZ8xEsw", 'i', "RingerButtonCapability" },
    { "collision-sos",     "HCzWusHQwZDea6nNhaKndw", 'i', "DeviceSupportsCollisionSOS" },
    { "pulse-width-max",   "6IejgN+1Fmu5/QrZFOIeNw", 'i', "DeviceSupportsPulseWidthMaximization" },
    { "internal-build",    "LBJfwOEzExRxzlAnSuI7eg", 'i', "InternalBuild (storage info in Settings)" },
    { "internal-install",  "EqrsVvjcYDdxHBiQmGhAWw", 'i', "apple-internal-install (Metal HUD etc)" },
    { "generative-models", "A62OafQ85EJAiiqKn4agtg", 'i', "DeviceSupportsGenerativeModelSystems (AI gating)" },
    { "research-fuse",     "XYlJKKkj2hztRP1NWWnhlw", 'i', "ResearchFuse" },
    { "region-code",       "h63QSdBCiT/z0WU6rdQv6Q", 's', "RegionCode (e.g. LL)" },
    { "product-type",      "h9jDsbgj7xIVeIQ8S3/X3Q", 's', "ProductType (e.g. iPhone15,3 - device spoof)" },
    { "device-class",      "+3Uf0Pm5F8Xy7Onyvko0vA", 's', "DeviceClass (iPhone/iPad)" },
    { "thinning-product",  "0+nc/Udy4WNG8S+Q7a/s1A", 's', "ThinningProductType" },
    // lara cross-check additions (2026-09-02, GestaltView.swift catalog)
    { "liquid-glass-lpm",  "SAGvsp6O6kAQ4fEfDJpC4Q", 'i', "Liquid Glass low-power-mode UI" },
    { "region-info",       "zHeENZu+wbg7PUprwNwBWg", 's', "RegionInfo (e.g. LL/A)" },
    { "has-internal-bundle", "Oji6HRoPi7rH7HPdWVakuw", 'i', "HasInternalSettingsBundle" },
    { "stage-manager",     "qeaj75wk3HF4DwQ8qbIi7g", 'i', "DeviceSupportsEnhancedMultitasking (Stage Manager)" },
    { "medusa-floating",   "mG0AnH/Vy1veoqoLRAIgTA", 'i', "MedusaFloatingLiveAppCapability (iPadOS)" },
    { "medusa-overlay",    "UCG5MkVahJxG1YULbbd5Bg", 'i', "MedusaOverlayAppCapability (iPadOS)" },
    { "medusa-pinned",     "ZYqko/XM5zD3XBfN5RmaXA", 'i', "MedusaPinnedAppCapability (iPadOS)" },
    { "medusa-pip",        "nVh/gwNpy7Jv1NOk00CMrw", 'i', "MedusaPIPCapability (iPadOS)" },
    { "ipad-uikit",        "uKc7FPnEO++lVhHWHFlGbQ", 'i', "iPad UI idiom (TrollPad family)" },
    // artwork-subtype is special: nested under the ArtworkTraits dict
    { "artwork-subtype",   "oPeik/9e8lQWMszEjbPzng", 'i', "ArtworkTraits.ArtworkDeviceSubType (nested)" },
    { NULL, NULL, 0, NULL }
};

static const char *mg_catalog_lookup_key(const char *name_or_key) {
    if (!name_or_key) return NULL;
    for (const mg_catalog_entry *e = mg_catalog; e->name; e++) {
        if (strcasecmp(e->name, name_or_key) == 0) return e->key;
        if (strcmp(e->key, name_or_key) == 0) return e->key;
    }
    // Not in the catalog: accept the raw base64 gestalt key as-is (full
    // editing support). Reject only obvious junk (control chars / spaces).
    for (const unsigned char *p = (const unsigned char *)name_or_key; *p; p++) {
        if (*p < 0x21 || *p > 0x7e) return NULL;
    }
    return name_or_key;
}

static char mg_catalog_type_for(const char *name_or_key) {
    if (!name_or_key) return 0;
    for (const mg_catalog_entry *e = mg_catalog; e->name; e++) {
        if (strcasecmp(e->name, name_or_key) == 0) return e->type;
        if (strcmp(e->key, name_or_key) == 0) return e->type;
    }
    return 0;
}

static BOOL mg_catalog_is_artwork(const char *name_or_key) {
    return name_or_key &&
        (strcasecmp(name_or_key, "artwork-subtype") == 0 ||
         strcmp(name_or_key, "oPeik/9e8lQWMszEjbPzng") == 0);
}

// ---------------------------------------------------------------------------
// Path discovery
// ---------------------------------------------------------------------------

static char g_mg_path[PATH_MAX] = {0};

// The systemgroup container UUID is stable per device, but glob anyway so a
// future container rename doesn't break the module.
static const char *mg_find_plist_path(void) {
    if (g_mg_path[0]) return g_mg_path;

    NSString *sg = @"/var/containers/Shared/SystemGroup";
    NSArray *entries = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:sg error:NULL];
    // Prefer the 26.x container name (bl_sbx/SparseBoxPlus/Erosion target),
    // fall back to any *mobilegestalt* container (18.x-era name).
    NSArray *wanted = @[ @MG_CONTAINER_26, @"__any__" ];
    for (NSString *w in wanted) {
        for (NSString *dir in entries) {
            BOOL isDir = NO;
            if (![[NSFileManager defaultManager] fileExistsAtPath:
                  [sg stringByAppendingPathComponent:dir] isDirectory:&isDir] || !isDir) continue;
            if ([w isEqualToString:@"__any__"]) {
                if (![dir containsString:@"mobilegestalt"]) continue;
            } else if (![dir isEqualToString:w]) {
                continue;
            }
            NSString *cand = [[sg stringByAppendingPathComponent:dir]
                              stringByAppendingPathComponent:@MG_REL_PATH];
            if ([[NSFileManager defaultManager] fileExistsAtPath:cand]) {
                snprintf(g_mg_path, sizeof(g_mg_path), "%s", [cand UTF8String]);
                TweakLog("[MG] gestalt cache: %s", g_mg_path);
                return g_mg_path;
            }
        }
    }
    // One-time log: mg_poll_commands runs on the 0.5s HUD tick, so logging
    // per miss flooded the log + os_log + HUD ring 2x/sec on stock devices
    // (seen 2026-09-04: "gestalt cache NOT FOUND" every tick, repeating
    // output on the HUD panel).
    static int s_notFoundLogged = 0;
    if (!s_notFoundLogged) {
        s_notFoundLogged = 1;
        TweakLog("[MG] gestalt cache NOT FOUND under %s", [sg UTF8String]);
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// plist read/write (raw POSIX, atomic)
// ---------------------------------------------------------------------------

static NSMutableDictionary *mg_read_dict(const char *path, char *errbuf, size_t errlen) {
    NSData *data = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:path]];
    if (!data) {
        snprintf(errbuf, errlen, "read failed errno=%d (%s)", errno, strerror(errno));
        return nil;
    }
    NSError *err = nil;
    id obj = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListMutableContainersAndLeaves format:NULL error:&err];
    if (!obj) {
        snprintf(errbuf, errlen, "plist parse failed: %s",
                 err ? [[err localizedDescription] UTF8String] : "unknown");
        return nil;
    }
    if (![obj isKindOfClass:[NSDictionary class]]) {
        snprintf(errbuf, errlen, "plist root is not a dictionary");
        return nil;
    }
    return (NSMutableDictionary *)obj;
}

// Write path atomically: temp in same dir, fsync, preserve owner/mode of the
// original (mobile:mobile 0644 on iOS - the cache is mobile-owned and
// mobilegestaltd re-reads it as mobile), rename over, fsync the directory.
// Raw POSIX throughout: the NSFileManager SSV hooks in Tweak.m must never
// see this write.
static int mg_write_dict(const char *path, NSDictionary *dict, char *errbuf, size_t errlen) {
    BOOL binary = YES;
    NSData *raw = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:path]];
    if (raw && raw.length >= 8 && memcmp(raw.bytes, "bplist00", 8) != 0) binary = NO;

    NSPropertyListFormat fmt = binary ? NSPropertyListBinaryFormat_v1_0 : NSPropertyListXMLFormat_v1_0;
    NSError *err = nil;
    NSData *out = [NSPropertyListSerialization dataWithPropertyList:dict format:fmt options:0 error:&err];
    if (!out) {
        snprintf(errbuf, errlen, "serialize failed: %s",
                 err ? [[err localizedDescription] UTF8String] : "unknown");
        return -1;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        snprintf(errbuf, errlen, "stat failed errno=%d (%s)", errno, strerror(errno));
        return -1;
    }

    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        snprintf(errbuf, errlen, "open tmp failed errno=%d (%s)", errno, strerror(errno));
        return -1;
    }

    const uint8_t *bytes = out.bytes;
    size_t left = out.length;
    while (left > 0) {
        ssize_t n = write(fd, bytes + (out.length - left), left);
        if (n < 0) {
            if (errno == EINTR) continue;
            snprintf(errbuf, errlen, "write failed errno=%d (%s)", errno, strerror(errno));
            close(fd);
            unlink(tmp);
            return -1;
        }
        left -= (size_t)n;
    }
    if (fsync(fd) != 0) {
        snprintf(errbuf, errlen, "fsync failed errno=%d (%s)", errno, strerror(errno));
        close(fd);
        unlink(tmp);
        return -1;
    }
    close(fd);

    // Preserve ownership + mode of the original (usually mobile:mobile 0644).
    if (st.st_uid != 0 || st.st_gid != 0) {
        if (chown(tmp, st.st_uid, st.st_gid) != 0) {
            snprintf(errbuf, errlen, "chown %d:%d failed errno=%d (%s)",
                     (int)st.st_uid, (int)st.st_gid, errno, strerror(errno));
            unlink(tmp);
            return -1;
        }
    }
    if (chmod(tmp, st.st_mode & 07777) != 0) {
        snprintf(errbuf, errlen, "chmod failed errno=%d (%s)", errno, strerror(errno));
        unlink(tmp);
        return -1;
    }

    if (rename(tmp, path) != 0) {
        snprintf(errbuf, errlen, "rename failed errno=%d (%s)", errno, strerror(errno));
        unlink(tmp);
        return -1;
    }

    // fsync the containing directory so the rename is durable.
    char dirbuf[PATH_MAX];
    snprintf(dirbuf, sizeof(dirbuf), "%s", path);
    char *slash = strrchr(dirbuf, '/');
    if (slash) {
        *slash = '\0';
        int d2 = open(dirbuf, O_RDONLY | O_CLOEXEC);
        if (d2 >= 0) { fsync(d2); close(d2); }
    }

    // read-back verify
    NSData *verify = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:path]];
    if (!verify || ![verify isEqualToData:out]) {
        snprintf(errbuf, errlen, "read-back verify FAILED");
        return -1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Respring (backboardd kill). Only meaningful with root creds.
// ---------------------------------------------------------------------------

static int mg_kill_process_by_name(const char *name, int sig) {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t len = 0;
    if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0) return -1;
    struct kinfo_proc *procs = malloc(len);
    if (!procs) return -1;
    if (sysctl(mib, 4, procs, &len, NULL, 0) != 0) { free(procs); return -1; }
    size_t count = len / sizeof(struct kinfo_proc);
    int killed = 0;
    for (size_t i = 0; i < count; i++) {
        if (procs[i].kp_proc.p_comm[0] == '\0') continue;
        if (strncmp(procs[i].kp_proc.p_comm, name, MAXCOMLEN) == 0) {
            kill(procs[i].kp_proc.p_pid, sig);
            killed++;
        }
    }
    free(procs);
    return killed;
}

static int mg_respring(char *errbuf, size_t errlen) {
    int n = mg_kill_process_by_name("backboardd", SIGKILL);
    if (n <= 0) {
        snprintf(errbuf, errlen, "backboardd not found (killed=%d) - respring skipped", n);
        return -1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// JSON <-> plist value conversion
// ---------------------------------------------------------------------------

// CacheExtra entries can be Data (e.g. some region/device blobs). JSON
// cannot carry NSData, so export it as {"$b64": "..."} and accept the same
// shape back in.
static id mg_jsonify(id obj) {
    if (!obj) return [NSNull null];
    if ([obj isKindOfClass:[NSData class]]) {
        NSString *b64 = [(NSData *)obj base64EncodedStringWithOptions:0];
        return @{ @"$b64": b64 };
    }
    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *out = [NSMutableDictionary dictionary];
        for (id k in [(NSDictionary *)obj allKeys]) {
            out[k] = mg_jsonify([(NSDictionary *)obj objectForKey:k]);
        }
        return out;
    }
    if ([obj isKindOfClass:[NSArray class]]) {
        NSMutableArray *out = [NSMutableArray array];
        for (id item in (NSArray *)obj) [out addObject:mg_jsonify(item)];
        return out;
    }
    return obj;  // NSString / NSNumber / NSNull
}

static id mg_value_from_json(id val, const char *type_hint) {
    if (!val || [val isKindOfClass:[NSNull class]]) return nil;
    if ([val isKindOfClass:[NSDictionary class]] && val[@"$b64"]) {
        NSData *d = [[NSData alloc] initWithBase64EncodedString:val[@"$b64"] options:0];
        return [d autorelease];  // MRC: balanced against the alloc
    }
    if (type_hint && strcmp(type_hint, "int") == 0) {
        return [NSNumber numberWithLongLong:[val longLongValue]];
    }
    if (type_hint && strcmp(type_hint, "bool") == 0) {
        return [NSNumber numberWithBool:[val boolValue]];
    }
    // JSON numbers -> NSNumber already; leave strings as-is
    return val;
}

// ---------------------------------------------------------------------------
// Command execution
// ---------------------------------------------------------------------------

static NSString *mg_docs(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
}

static int mg_op_set(NSMutableDictionary *extra, NSDictionary *cmd, char *errbuf, size_t errlen) {
    NSString *nameOrKey = cmd[@"name"] ?: cmd[@"key"];
    if (![nameOrKey isKindOfClass:[NSString class]] || nameOrKey.length == 0) {
        snprintf(errbuf, errlen, "set needs name or key");
        return -1;
    }
    const char *nk = [nameOrKey UTF8String];
    const char *key = mg_catalog_lookup_key(nk);
    if (!key) {
        snprintf(errbuf, errlen, "invalid gestalt key '%s'", nk);
        return -1;
    }
    if (!mg_catalog_type_for(nk)) {
        TweakLog("[MG] raw key not in catalog: %s", nk);
    }

    id val = cmd[@"value"];
    if (!val || [val isKindOfClass:[NSNull class]]) {
        snprintf(errbuf, errlen, "set needs a value");
        return -1;
    }
    // Resolve type: explicit --type wins, else catalog hint, else leave JSON type.
    const char *type = NULL;
    if ([cmd[@"type"] isKindOfClass:[NSString class]]) {
        type = [cmd[@"type"] UTF8String];
    }
    char catalog_type = mg_catalog_type_for(nk);
    if (!type && catalog_type) {
        static char tbuf[2];
        tbuf[0] = catalog_type;
        tbuf[1] = '\0';
        type = tbuf;
    }
    id obj = mg_value_from_json(val, type);
    if (!obj) {
        snprintf(errbuf, errlen, "unusable value for %s", nk);
        return -1;
    }

    if (mg_catalog_is_artwork(nk)) {
        // Nested: CacheExtra["oPeik/9e8lQWMszEjbPzng"]["ArtworkDeviceSubType"]
        NSMutableDictionary *art = [extra objectForKey:@(key)];
        if (![art isKindOfClass:[NSMutableDictionary class]]) {
            art = [NSMutableDictionary dictionary];
            [extra setObject:art forKey:@(key)];
        }
        [art setObject:obj forKey:@"ArtworkDeviceSubType"];
    } else {
        [extra setObject:obj forKey:@(key)];
    }
    return 0;
}

static int mg_op_unset(NSMutableDictionary *extra, NSDictionary *cmd, char *errbuf, size_t errlen) {
    NSString *nameOrKey = cmd[@"name"] ?: cmd[@"key"];
    if (![nameOrKey isKindOfClass:[NSString class]] || nameOrKey.length == 0) {
        snprintf(errbuf, errlen, "unset needs name or key");
        return -1;
    }
    const char *nk = [nameOrKey UTF8String];
    const char *key = mg_catalog_lookup_key(nk);
    if (!key) {
        snprintf(errbuf, errlen, "invalid gestalt key '%s'", nk);
        return -1;
    }
    if (mg_catalog_is_artwork(nk)) {
        NSMutableDictionary *art = [extra objectForKey:@(key)];
        if ([art isKindOfClass:[NSMutableDictionary class]]) {
            [art removeObjectForKey:@"ArtworkDeviceSubType"];
            if (art.count == 0) [extra removeObjectForKey:@(key)];
        }
    } else {
        [extra removeObjectForKey:@(key)];
    }
    return 0;
}

// Runs one command dict against the live plist; result dict is JSON-safe.
static NSMutableDictionary *mg_execute(NSDictionary *cmd, const char *path) {
    NSMutableDictionary *res = [NSMutableDictionary dictionary];
    NSString *op = cmd[@"op"];
    res[@"op"] = op ?: @"?";

    if ([op isEqualToString:@"respring"]) {
        char ebuf[256];
        int rc = mg_respring(ebuf, sizeof(ebuf));
        res[@"ok"] = @(rc == 0);
        res[@"detail"] = rc == 0 ? @"backboardd killed - respringing"
                                 : [NSString stringWithUTF8String:ebuf];
        return res;
    }

    if ([op isEqualToString:@"status"]) {
        res[@"ok"] = @YES;
        res[@"detail"] = @"ready";
        res[@"path"] = @(path);
        res[@"euid"] = @((int)geteuid());
        res[@"root"] = @(geteuid() == 0 || access(path, W_OK) == 0);
        return res;
    }

    // All remaining ops mutate/read the plist.
    char ebuf[512];
    NSMutableDictionary *dict = mg_read_dict(path, ebuf, sizeof(ebuf));
    if (!dict) {
        res[@"ok"] = @NO;
        res[@"detail"] = @(ebuf);
        return res;
    }
    NSMutableDictionary *extra = [dict objectForKey:@"CacheExtra"];
    if (![extra isKindOfClass:[NSMutableDictionary class]]) {
        extra = [NSMutableDictionary dictionary];
        dict[@"CacheExtra"] = extra;
    }

    if ([op isEqualToString:@"get"]) {
        NSString *nameOrKey = cmd[@"name"] ?: cmd[@"key"];
        const char *nk = nameOrKey ? [nameOrKey UTF8String] : NULL;
        const char *key = nk ? mg_catalog_lookup_key(nk) : NULL;
        id val = key ? [extra objectForKey:@(key)] : nil;
        if (nk && mg_catalog_is_artwork(nk)) {
            val = [[extra objectForKey:@(key)] objectForKey:@"ArtworkDeviceSubType"];
        }
        res[@"ok"] = @YES;
        res[@"found"] = @(val != nil);
        if (val) res[@"value"] = mg_jsonify(val);
        return res;
    }

    if ([op isEqualToString:@"unset"]) {
        int rc = mg_op_unset(extra, cmd, ebuf, sizeof(ebuf));
        res[@"ok"] = @(rc == 0);
        res[@"detail"] = rc == 0 ? @"removed" : @(ebuf);
    } else if ([op isEqualToString:@"set"]) {
        int rc = mg_op_set(extra, cmd, ebuf, sizeof(ebuf));
        res[@"ok"] = @(rc == 0);
        res[@"detail"] = rc == 0 ? @"applied" : @(ebuf);
    } else if ([op isEqualToString:@"batch"]) {
        id ops = cmd[@"ops"];
        int done = 0, failed = 0;
        if ([ops isKindOfClass:[NSArray class]]) {
            for (id item in (NSArray *)ops) {
                if (![item isKindOfClass:[NSDictionary class]]) { failed++; continue; }
                NSString *sub = item[@"op"];
                int rc;
                if ([sub isEqualToString:@"set"]) rc = mg_op_set(extra, item, ebuf, sizeof(ebuf));
                else if ([sub isEqualToString:@"unset"]) rc = mg_op_unset(extra, item, ebuf, sizeof(ebuf));
                else { failed++; continue; }
                if (rc == 0) done++; else failed++;
            }
        }
        res[@"ok"] = @(failed == 0 && done > 0);
        res[@"detail"] = [NSString stringWithFormat:@"%d applied, %d failed", done, failed];
    } else if ([op isEqualToString:@"dump"] || [op isEqualToString:@"export"]) {
        res[@"ok"] = @YES;
        res[@"cacheExtra"] = mg_jsonify(extra);
        res[@"cacheVersion"] = mg_jsonify(dict[@"CacheVersion"]);
    } else {
        res[@"ok"] = @NO;
        res[@"detail"] = [NSString stringWithFormat:@"unknown op %@", op];
        return res;
    }

    // Persist on success (dump/export don't mutate - skip the write).
    if ([res[@"ok"] boolValue] && ![op isEqualToString:@"dump"] && ![op isEqualToString:@"export"]) {
        if (mg_write_dict(path, dict, ebuf, sizeof(ebuf)) != 0) {
            res[@"ok"] = @NO;
            res[@"detail"] = [NSString stringWithFormat:@"write failed: %s", ebuf];
            return res;
        }
        // Keep a rolling backup next to the cache so reset/restore has an anchor.
        NSString *bakDir = [mg_docs() stringByAppendingPathComponent:@"gestalt-backups"];
        [[NSFileManager defaultManager] createDirectoryAtPath:bakDir withIntermediateDirectories:YES attributes:nil error:NULL];
        NSString *bak = [bakDir stringByAppendingPathComponent:@"com.apple.MobileGestalt.plist"];
        [dict writeToFile:bak atomically:YES];
    }

    if ([op isEqualToString:@"set"] || [op isEqualToString:@"unset"] || [op isEqualToString:@"batch"]) {
        // read-back echo of the touched key(s)
        if ([op isEqualToString:@"batch"]) {
            res[@"detail"] = [NSString stringWithFormat:@"%@ - see mg-state dump", res[@"detail"]];
        } else {
            NSString *nameOrKey = cmd[@"name"] ?: cmd[@"key"];
            const char *nk = nameOrKey ? [nameOrKey UTF8String] : NULL;
            const char *key = nk ? mg_catalog_lookup_key(nk) : NULL;
            id val = nil;
            if (key) {
                if (nk && mg_catalog_is_artwork(nk)) {
                    val = [[extra objectForKey:@(key)] objectForKey:@"ArtworkDeviceSubType"];
                } else {
                    val = [extra objectForKey:@(key)];
                }
            }
            if (val) res[@"value"] = mg_jsonify(val);
        }
    }

    return res;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

int mg_apply_command_json(const char *json_cmd, char *result_buf, size_t result_len) {
    if (result_buf && result_len > 0) result_buf[0] = '\0';
    if (!json_cmd) return -1;

    NSError *err = nil;
    id cmd = [NSJSONSerialization JSONObjectWithData:
              [NSData dataWithBytes:json_cmd length:strlen(json_cmd)]
              options:NSJSONReadingMutableContainers error:&err];
    if (![cmd isKindOfClass:[NSDictionary class]]) {
        if (result_buf && result_len > 0) {
            snprintf(result_buf, result_len, "{\"ok\":false,\"detail\":\"cmd json parse failed\"}");
        }
        return -1;
    }

    const char *path = mg_find_plist_path();
    if (!path) {
        if (result_buf && result_len > 0) {
            snprintf(result_buf, result_len,
                     "{\"ok\":false,\"detail\":\"gestalt cache not found on this device\"}");
        }
        return -1;
    }

    NSMutableDictionary *res = mg_execute((NSDictionary *)cmd, path);

    if ([res[@"op"] isEqualToString:@"respring"]) {
        // Nothing more to write - the device is going away.
        TweakLog("[MG] respring issued");
    }

    NSData *out = [NSJSONSerialization dataWithJSONObject:res options:0 error:&err];
    NSString *outStr = out ? [[NSString alloc] initWithData:out encoding:NSUTF8StringEncoding] : nil;
    if (!outStr) {
        if (result_buf && result_len > 0) {
            snprintf(result_buf, result_len, "{\"ok\":false,\"detail\":\"result serialize failed\"}");
        }
        return -1;
    }
    TweakLog("[MG] op %s -> %s", [[res[@"op"] description] UTF8String],
             [res[@"ok"] boolValue] ? "OK" : "FAILED");
    if (result_buf && result_len > 0) {
        if (outStr.length >= result_len) {
            // Never hand the host a truncated JSON blob - say so instead.
            snprintf(result_buf, result_len,
                     "{\"ok\":false,\"detail\":\"result too large for buffer (%lu bytes)\"}",
                     (unsigned long)outStr.length);
        } else {
            snprintf(result_buf, result_len, "%s", [outStr UTF8String]);
        }
    }
    return [res[@"ok"] boolValue] ? 0 : -1;
}

static int mg_file_write_json(const char *path, id obj) {
    NSError *err = nil;
    NSData *out = [NSJSONSerialization dataWithJSONObject:obj options:0 error:&err];
    if (!out) return -1;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return -1;
    size_t left = out.length;
    const uint8_t *bytes = out.bytes;
    while (left > 0) {
        ssize_t n = write(fd, bytes + (out.length - left), left);
        if (n < 0) { if (errno == EINTR) continue; close(fd); return -1; }
        left -= (size_t)n;
    }
    fsync(fd);
    close(fd);
    return 0;
}

int mg_poll_commands(void) {
    // Only meaningful after the kernel escape (root creds). Cheap probe:
    // the cache must be writable, otherwise leave any pending command for a
    // later tick (the host keeps polling).
    const char *path = mg_find_plist_path();
    if (!path) return 0;
    if (access(path, R_OK | W_OK) != 0) return -1;  // not escaped yet

    static _Atomic int busy = 0;
    if (atomic_exchange(&busy, 1)) return 0;  // previous tick still processing
    int rc = 0;

    NSString *docs = mg_docs();
    NSArray *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:docs error:NULL];
    NSString *cmdFile = nil;
    for (NSString *f in files) {
        if ([f hasPrefix:@MG_CMD_PREFIX] && [f hasSuffix:@".json"]) {
            cmdFile = f;
            break;
        }
    }
    if (!cmdFile) {
        atomic_store(&busy, 0);
        return 0;
    }

    NSString *cmdPath = [docs stringByAppendingPathComponent:cmdFile];
    NSData *cmdData = [NSData dataWithContentsOfFile:cmdPath];
    if (!cmdData) {
        // Unreadable/zero-length cmd: consume it to avoid a retry storm.
        [[NSFileManager defaultManager] removeItemAtPath:cmdPath error:NULL];
        atomic_store(&busy, 0);
        return 0;
    }

    TweakLog("[MG] processing %s", [cmdFile UTF8String]);

    // Token = everything between "mg-cmd-" and ".json"
    NSRange range = NSMakeRange([@MG_CMD_PREFIX length],
                                cmdFile.length - [@MG_CMD_PREFIX length] - [@".json" length]);
    NSString *token = [cmdFile substringWithRange:range];

    char cmdBuf[65536];
    NSUInteger n = MIN(cmdData.length, sizeof(cmdBuf) - 1);
    memcpy(cmdBuf, cmdData.bytes, n);
    cmdBuf[n] = '\0';

    // 4MB heap result buffer: dump/export return the full CacheExtra JSON.
    char *resultBuf = malloc(4 * 1024 * 1024);
    if (!resultBuf) {
        atomic_store(&busy, 0);
        return -1;
    }
    int exec_rc = mg_apply_command_json(cmdBuf, resultBuf, 4 * 1024 * 1024);

    NSString *resultName = [NSString stringWithFormat:@MG_RESULT_PREFIX"%@.json", token];
    NSString *stateName = [NSString stringWithFormat:@MG_STATE_PREFIX"%@.json", token];
    NSString *resultPath = [docs stringByAppendingPathComponent:resultName];
    NSString *statePath = [docs stringByAppendingPathComponent:stateName];

    id resultObj = nil;
    if (resultBuf[0]) {
        NSError *jerr = nil;
        resultObj = [NSJSONSerialization JSONObjectWithData:
                     [NSData dataWithBytes:resultBuf length:strlen(resultBuf)]
                     options:0 error:&jerr];
    }
    if (!resultObj) resultObj = @{ @"ok": @NO, @"detail": @"no result payload" };

    // Sidecar state dump for set/unset/batch so the host can show the whole
    // CacheExtra after an apply.
    if (exec_rc == 0) {
        const char *path2 = mg_find_plist_path();
        char ebuf[256];
        NSMutableDictionary *dict = path2 ? mg_read_dict(path2, ebuf, sizeof(ebuf)) : nil;
        if (dict) {
            NSMutableDictionary *extra = dict[@"CacheExtra"];
            if ([extra isKindOfClass:[NSMutableDictionary class]]) {
                NSMutableDictionary *state = [NSMutableDictionary dictionary];
                state[@"cacheExtra"] = mg_jsonify(extra);
                mg_file_write_json([statePath UTF8String], state);
            }
        }
    }

    mg_file_write_json([resultPath UTF8String], resultObj);
    [[NSFileManager defaultManager] removeItemAtPath:cmdPath error:NULL];
    free(resultBuf);
    rc = 1;

    atomic_store(&busy, 0);
    return rc;
}
