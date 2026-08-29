#import "AppDelegate.h"

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

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = [UIColor blackColor];

    UILabel *label = [[UILabel alloc] init];
    label.text = [NSString stringWithFormat:@"W0lfSword Hub shell\nbuild path OK (L2.1)\nengine: libw0lfengine.a (L2.2)\noffsets: %@",
                  [self resolveOffsetsInfo]];
    label.textColor = [UIColor colorWithRed:0.60 green:0.85 blue:1.0 alpha:1.0];
    label.numberOfLines = 0;
    label.textAlignment = NSTextAlignmentCenter;
    label.frame = vc.view.bounds;
    label.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [vc.view addSubview:label];

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    return YES;
}

@end
