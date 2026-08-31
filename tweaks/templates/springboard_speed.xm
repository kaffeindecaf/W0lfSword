// springboard_speed.xm — W0lfSword tweak template
// Speeds up SpringBoard animations (jailbreak-required).
//
// NOTE: skeleton template. Global animation duration lives in
// SBIconAnimationSettings / SBAnimationSettings (0.3-0.5s defaults);
// hook the duration getters and return 0.8x. Requires kernel R/W
// (darksword) to patch SpringBoard in memory. Verify on device.

#import <UIKit/UIKit.h>

@interface SBIconAnimationSettings : NSObject
@end

%hook SBIconAnimationSettings
- (double)maxIconScrollDuration {
    double orig = %orig;
    return orig * 0.8;
}
%end

%ctor {
    NSLog(@"[W0lfSword] springboard_speed loaded — animations at 0.8x");
}
