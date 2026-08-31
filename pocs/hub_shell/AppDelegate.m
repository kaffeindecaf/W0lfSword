#import "AppDelegate.h"

// L5.1/L5.2 — post-escape verification probes (engine-backed).
// The probes are READ-ONLY and gated on exploit_is_done(): when the exploit
// has not run, they report "not acquired" instead of touching kernel memory.
#import "kexploit/kexploit_opa334.h"
#import "kexploit/krw.h"
#import "kexploit/kutils.h"
#import "kexploit/offsets.h"
#import "utils/state.h"
#import "sandbox_escape.h"
#import <unistd.h>

@implementation AppDelegate

// L3.1 boot path: pick the highest offsets.json threshold <= running iOS and
// report the effective table. Bundled at build time by
// scripts/gen_offsets_json.py (make offsets-json).
- (NSString *)resolveOffsetsInfo {
    NSString *path = [[NSBundle mainBundle] pathForResource:@"offsets" ofType:@"json"];
    if (!path) return @"offsets.json missing";
    NSData *data = [NSData dataWithContentsOfFile:path];
    NSDictionary *root = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    NSArray *versions = root[@"versions"];
    if (!versions) return @"offsets.json parse error";

    NSOperatingSystemVersion v = [[NSProcessInfo processInfo] operatingSystemVersion];
    double running = v.majorVersion + v.minorVersion / 100.0;
    NSDictionary *chosen = nil;
    for (NSDictionary *entry in versions) {
        NSArray *parts = [entry[@"threshold"] componentsSeparatedByString:@"."];
        if (parts.count < 2) continue;
        double t = [parts[0] doubleValue] + [parts[1] doubleValue] / 100.0;
        if (t <= running + 0.0001) chosen = entry;
    }
    if (!chosen) return [NSString stringWithFormat:@"unsupported iOS %.1f", running];

    NSDictionary *offs = chosen[@"offsets"];
    NSNumber *itk = offs[@"off_task_itk_space"];
    return [NSString stringWithFormat:@"%@ -> %lu offsets, itk_space=0x%lX",
            chosen[@"threshold"], (unsigned long)offs.count,
            (unsigned long)[itk unsignedLongValue]];
}

// L5.2: kread64 smoke test on a known-safe address (own proc pid field).
// Only runs when the exploit has completed; otherwise reports "not acquired".
static NSString *kernelRWStatus(void) {
    if (!exploit_is_done()) return @"not acquired (exploit not run)";
    uint64_t self_proc = proc_self();
    if (!self_proc) return @"smoke failed (proc_self NULL)";
    uint64_t pid = kread64(self_proc + off_proc_p_pid);
    if (pid == (uint64_t)getpid()) return @"live";
    return @"smoke mismatch";
}

// L5.1: read back the kernel-side posix creds after the escape.
static NSString *rootCredsStatus(void) {
    if (!exploit_is_done()) return @"not acquired (exploit not run)";
    uint64_t self_proc = proc_self();
    if (!self_proc) return @"read-back failed (proc_self NULL)";
    uint32_t uid = 0, gid = 0, groups0 = 0;
    if (sandbox_escape_read_posix_creds(self_proc, &uid, &gid, &groups0) != 0)
        return @"read-back failed";
    if (uid == 0 && gid == 0 && groups0 == 0) return @"root:wheel active";
    return [NSString stringWithFormat:@"user creds (uid=%u gid=%u)", uid, gid];
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = [UIColor blackColor];

    UILabel *label = [[UILabel alloc] init];
    label.text = [NSString stringWithFormat:@"W0lfSword Hub shell\nbuild path OK (L2.1)\nengine: libw0lfengine.a (L2.2)\noffsets: %@\n\nverification (L5.1/L5.2)\nrunning probes…",
                  [self resolveOffsetsInfo]];
    label.textColor = [UIColor colorWithRed:0.60 green:0.85 blue:1.0 alpha:1.0];
    label.numberOfLines = 0;
    label.textAlignment = NSTextAlignmentCenter;
    label.frame = vc.view.bounds;
    label.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [vc.view addSubview:label];

    // Probes are read-only and gated; run them off the main thread, then
    // publish the results back on main.
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *krw = kernelRWStatus();
        NSString *creds = rootCredsStatus();
        dispatch_async(dispatch_get_main_queue(), ^{
            label.text = [NSString stringWithFormat:@"W0lfSword Hub shell\nbuild path OK (L2.1)\nengine: libw0lfengine.a (L2.2)\noffsets: %@\n\nverification (L5.1/L5.2)\nkernel r/w: %@\ncredentials: %@",
                          [self resolveOffsetsInfo], krw, creds];
        });
    });

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    return YES;
}

@end
