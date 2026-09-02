//
//  sbtweak.m
//  W0lfSword - SpringBoard live tweaks via the in-tree TaskRop RemoteCall
//
//  Remote ObjC layer on top of the flat kexploit/RemoteCall API:
//    do_remote_call_stable(timeout, "symbol", x0..x7) resolves the symbol
//    with dlsym in OUR process and executes it at that address inside the
//    target process - valid because dyld shared-cache images slide together,
//    so objc_msgSend / sel_registerName / objc_getClass live at the same
//    address in SpringBoard. Strings are written to the remote scratch page
//    (remote_call_scratch) first.
//
//  Dock column count: SBIconController (sharedInstance) -> iconManager ->
//  dockListView -> model: setGridSize:(cols in the low 16 bits), and dock ->
//  layout -> layoutConfiguration: setNumberOfPortraitColumns:. Standard
//  SpringBoard runtime API (public tweak knowledge); verified to exist on
//  iOS 17-18.x and 26.0.x by lara's feature set.
//
//  MRC (project builds without -fobjc-arc): no autoreleased objects are
//  stored anywhere; JSON in/out via NSJSONSerialization on the runloop.

#import <Foundation/Foundation.h>
#import <stdatomic.h>
#import <stdio.h>
#import <string.h>
#import <errno.h>
#import <unistd.h>

#include "sbtweak.h"
#include "../kexploit/RemoteCall.h"
#include "../TweakExploit.h"
#include "../utils/tweak_log.h"

#define SBT_CMD_PREFIX    "sb-cmd-"
#define SBT_RESULT_PREFIX "sb-result-"

// ---------------------------------------------------------------------------
// Remote ObjC layer (fresh implementation over the RemoteCall API)
// ---------------------------------------------------------------------------

// RemoteCall session state. init parks two of SpringBoard's threads for a
// few hundred ms - run it off the main thread, once.
static _Atomic int g_sbt_state = 0;   // 0 idle, 1 initing, 2 ready, -1 failed
static _Atomic int g_sbt_retries = 0;
#define SBT_MAX_INIT_RETRIES 2

static uint64_t sbt_rc_str(const char *s) {
    if (!s) return 0;
    uint64_t scratch = remote_call_scratch();
    if (!scratch) return 0;
    // remote_writeStr from the current position so multiple strings can be
    // staged before the call (callers use one string per call - fine).
    size_t len = strlen(s) + 1;
    if (len > 4096) len = 4096;
    if (!remote_writeStr(scratch, s)) return 0;
    (void)len;
    return scratch;
}

static uint64_t sbt_rc_sel(const char *name) {
    uint64_t str = sbt_rc_str(name);
    if (!str) return 0;
    return do_remote_call_stable(5, "sel_registerName", str, 0, 0, 0, 0, 0, 0, 0);
}

static uint64_t sbt_rc_cls(const char *name) {
    uint64_t str = sbt_rc_str(name);
    if (!str) return 0;
    return do_remote_call_stable(5, "objc_getClass", str, 0, 0, 0, 0, 0, 0, 0);
}

static uint64_t sbt_rc_msg(uint64_t obj, uint64_t sel, uint64_t a0, uint64_t a1, uint64_t a2) {
    if (!obj || !sel) return 0;
    return do_remote_call_stable(5, "objc_msgSend", obj, sel, a0, a1, a2, 0, 0, 0);
}

// ---------------------------------------------------------------------------
// Feature implementations
// ---------------------------------------------------------------------------

// Returns the previous column count, or -1 on failure.
static int sbt_dock_set_columns(int columns) {
    if (columns < 1) columns = 1;
    if (columns > 12) columns = 12;

    uint64_t selShared   = sbt_rc_sel("sharedInstance");
    uint64_t selIconMgr  = sbt_rc_sel("iconManager");
    uint64_t selDockView = sbt_rc_sel("dockListView");
    uint64_t selModel    = sbt_rc_sel("model");
    uint64_t selModel2   = sbt_rc_sel("iconListModel");
    uint64_t selGridGet  = sbt_rc_sel("gridSize");
    uint64_t selGridSet  = sbt_rc_sel("setGridSize:");
    uint64_t selLayout   = sbt_rc_sel("layout");
    uint64_t selLayoutCfg = sbt_rc_sel("layoutConfiguration");
    uint64_t selSetCols  = sbt_rc_sel("setNumberOfPortraitColumns:");
    uint64_t selPerfMain = sbt_rc_sel("performSelectorOnMainThread:withObject:waitUntilDone:");
    uint64_t selSetNL    = sbt_rc_sel("setNeedsLayout");
    if (!selShared || !selIconMgr || !selDockView || !selGridGet || !selGridSet) {
        TweakLog("[SBT] dock: selector resolution failed");
        return -1;
    }

    uint64_t cls = sbt_rc_cls("SBIconController");
    if (!cls) { TweakLog("[SBT] dock: SBIconController not found"); return -1; }

    uint64_t ctrl = sbt_rc_msg(cls, selShared, 0, 0, 0);
    if (!ctrl) { TweakLog("[SBT] dock: sharedInstance failed"); return -1; }

    uint64_t mgr = sbt_rc_msg(ctrl, selIconMgr, 0, 0, 0);
    uint64_t dock = 0;
    if (mgr) dock = sbt_rc_msg(mgr, selDockView, 0, 0, 0);
    if (!dock) dock = sbt_rc_msg(ctrl, selDockView, 0, 0, 0);
    if (!dock) { TweakLog("[SBT] dock: dockListView not found"); return -1; }

    int oldColumns = -1;
    uint64_t model = sbt_rc_msg(dock, selModel, 0, 0, 0);
    if (!model) model = sbt_rc_msg(dock, selModel2, 0, 0, 0);
    if (model) {
        uint64_t oldGrid = sbt_rc_msg(model, selGridGet, 0, 0, 0) & 0xFFFFFFFFULL;
        oldColumns = (int)(oldGrid & 0xFFFFULL);
        uint64_t newGrid = (oldGrid & 0xFFFF0000ULL) | ((uint64_t)columns & 0xFFFFULL);
        sbt_rc_msg(model, selGridSet, newGrid, 0, 0);
        TweakLog("[SBT] dock gridSize columns %d -> %d", oldColumns, columns);
    }

    uint64_t layout = sbt_rc_msg(dock, selLayout, 0, 0, 0);
    if (layout) {
        uint64_t cfg = sbt_rc_msg(layout, selLayoutCfg, 0, 0, 0);
        if (cfg && selSetCols) {
            sbt_rc_msg(cfg, selSetCols, (uint64_t)columns, 0, 0);
        }
    }

    if (selPerfMain && selSetNL) {
        // ask SpringBoard to re-layout the dock on its own main thread
        sbt_rc_msg(dock, selPerfMain, selSetNL, 0 /*nil*/, 0 /*NO*/);
    }
    return oldColumns >= 0 ? oldColumns : columns;
}

// ---------------------------------------------------------------------------
// Command dispatch
// ---------------------------------------------------------------------------

static NSString *sbt_docs(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
}

static NSMutableDictionary *sbt_execute(NSDictionary *cmd) {
    NSMutableDictionary *res = [NSMutableDictionary dictionary];
    NSString *op = cmd[@"op"] ?: @"?";
    res[@"op"] = op;

    if ([op isEqualToString:@"status"]) {
        int st = atomic_load(&g_sbt_state);
        res[@"ok"] = @YES;
        res[@"state"] = @(st);  // 0 idle, 1 initing, 2 ready, -1 failed
        res[@"detail"] = [NSString stringWithFormat:@"RemoteCall state %d (2=ready; init parks SpringBoard threads briefly)", st];
        return res;
    }

    if ([op isEqualToString:@"dock"] || [op isEqualToString:@"reset"]) {
        int columns = 5;
        if ([op isEqualToString:@"reset"]) columns = 4;
        id c = cmd[@"columns"];
        if ([c respondsToSelector:@selector(intValue)]) columns = [c intValue];
        int rc = sbt_dock_set_columns(columns);
        res[@"ok"] = @(rc >= 0);
        res[@"detail"] = rc >= 0
            ? [NSString stringWithFormat:@"dock columns -> %d (old %d)", columns, rc]
            : @"dock update failed (see tweak log for the stage)";
        return res;
    }

    res[@"ok"] = @NO;
    res[@"detail"] = [NSString stringWithFormat:@"unknown op %@", op];
    return res;
}

// Runs on the background queue. Returns 0 on success.
static int sbt_execute_json(const char *json_cmd, char *result_buf, size_t result_len) {
    if (result_buf && result_len > 0) result_buf[0] = '\0';
    if (!json_cmd) return -1;

    NSError *err = nil;
    id cmd = [NSJSONSerialization JSONObjectWithData:
              [NSData dataWithBytes:json_cmd length:strlen(json_cmd)]
              options:0 error:&err];
    if (![cmd isKindOfClass:[NSDictionary class]]) {
        if (result_buf && result_len > 0)
            snprintf(result_buf, result_len, "{\"ok\":false,\"detail\":\"cmd json parse failed\"}");
        return -1;
    }

    // Make sure the RemoteCall session exists before running the op.
    int st = atomic_load(&g_sbt_state);
    NSString *op = cmd[@"op"];
    if (![op isEqualToString:@"status"]) {
        if (st != 2) {
            if (result_buf && result_len > 0)
                snprintf(result_buf, result_len,
                         "{\"ok\":false,\"detail\":\"RemoteCall not ready (state %d) - run 'status' first, check log\"}", st);
            return -1;
        }
    }

    NSMutableDictionary *res = sbt_execute((NSDictionary *)cmd);
    NSData *out = [NSJSONSerialization dataWithJSONObject:res options:0 error:&err];
    NSString *outStr = out ? [[NSString alloc] initWithData:out encoding:NSUTF8StringEncoding] : nil;
    if (!outStr) {
        if (result_buf && result_len > 0)
            snprintf(result_buf, result_len, "{\"ok\":false,\"detail\":\"result serialize failed\"}");
        return -1;
    }
    TweakLog("[SBT] op %s -> %s", [op UTF8String], [res[@"ok"] boolValue] ? "OK" : "FAILED");
    if (result_buf && result_len > 0) {
        if (outStr.length >= result_len) {
            snprintf(result_buf, result_len, "{\"ok\":false,\"detail\":\"result too large\"}");
        } else {
            snprintf(result_buf, result_len, "%s", [outStr UTF8String]);
        }
    }
    return [res[@"ok"] boolValue] ? 0 : -1;
}

int sbt_run_command_json(const char *json_cmd, char *result_buf, size_t result_len) {
    // Public synchronous entry (tests). Requires the escape to be live.
    if (tweak_exploit_status() != 2) {
        if (result_buf && result_len > 0)
            snprintf(result_buf, result_len, "{\"ok\":false,\"detail\":\"kernel escape not live (status %d)\"}", tweak_exploit_status());
        return -1;
    }
    return sbt_execute_json(json_cmd, result_buf, result_len);
}

// ---------------------------------------------------------------------------
// Background worker
// ---------------------------------------------------------------------------

static void sbt_ensure_ready(void) {
    int st = atomic_load(&g_sbt_state);
    if (st == 2 || st == 1) return;
    if (st == -1 && atomic_load(&g_sbt_retries) >= SBT_MAX_INIT_RETRIES) return;

    if (atomic_compare_exchange_strong(&g_sbt_state, &(int){0}, 1)) {
        TweakLog("[SBT] init_remote_call(SpringBoard) start");
        int rc = init_remote_call("SpringBoard", false);
        if (rc == 0) {
            atomic_store(&g_sbt_state, 2);
            TweakLog("[SBT] init_remote_call(SpringBoard) ready");
        } else {
            atomic_store(&g_sbt_state, -1);
            atomic_fetch_add(&g_sbt_retries, 1);
            TweakLog("[SBT] init_remote_call(SpringBoard) failed rc=%d", rc);
        }
    }
}

static int sbt_file_write(const char *path, id obj) {
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

int sbt_poll_commands(void) {
    // RemoteCall needs the kernel escape (krw + offsets).
    if (tweak_exploit_status() != 2) return -1;

    static _Atomic int busy = 0;
    if (atomic_exchange(&busy, 1)) return 0;

    static dispatch_queue_t sbt_q = NULL;
    static dispatch_once_t once = 0;
    dispatch_once(&once, ^{
        sbt_q = dispatch_queue_create("com.kaffeindecaf.w0lfsword.sbtweak", DISPATCH_QUEUE_SERIAL);
    });

    NSString *docs = sbt_docs();
    NSArray *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:docs error:NULL];
    NSString *cmdFile = nil;
    for (NSString *f in files) {
        if ([f hasPrefix:@SBT_CMD_PREFIX] && [f hasSuffix:@".json"]) {
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
        [[NSFileManager defaultManager] removeItemAtPath:cmdPath error:NULL];
        atomic_store(&busy, 0);
        return 0;
    }

    NSRange range = NSMakeRange([@SBT_CMD_PREFIX length],
                                cmdFile.length - [@SBT_CMD_PREFIX length] - [@".json" length]);
    NSString *token = [cmdFile substringWithRange:range];

    char *cmdBuf = malloc(65536);
    if (!cmdBuf) { atomic_store(&busy, 0); return -1; }
    NSUInteger n = MIN(cmdData.length, 65535);
    memcpy(cmdBuf, cmdData.bytes, n);
    cmdBuf[n] = '\0';

    TweakLog("[SBT] processing %s", [cmdFile UTF8String]);
    // Hand off to the serial queue; the result file lands there too.
    dispatch_async(sbt_q, ^{
        sbt_ensure_ready();
        char resultBuf[8192];
        int rc = sbt_execute_json(cmdBuf, resultBuf, sizeof(resultBuf));

        id resultObj = nil;
        if (resultBuf[0]) {
            NSError *jerr = nil;
            resultObj = [NSJSONSerialization JSONObjectWithData:
                         [NSData dataWithBytes:resultBuf length:strlen(resultBuf)]
                         options:0 error:&jerr];
        }
        if (!resultObj) resultObj = @{ @"ok": @NO, @"detail": @"no result payload" };

        NSString *resultName = [NSString stringWithFormat:@SBT_RESULT_PREFIX"%@.json", token];
        sbt_file_write([[docs stringByAppendingPathComponent:resultName] UTF8String], resultObj);
        [[NSFileManager defaultManager] removeItemAtPath:cmdPath error:NULL];
        free(cmdBuf);
    });

    atomic_store(&busy, 0);
    return 1;
}
