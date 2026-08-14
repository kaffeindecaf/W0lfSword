// hide_home_bar.xm — W0lfSword tweak template (K3.2 seed entry)
// Hides the home indicator (home bar) in SpringBoard.
//
// NOTE: skeleton template. Hooking UIViewController covers SpringBoard's own
// controllers; narrow to SBHomeScreenViewController etc. per iOS if needed.
// Verify on device before shipping.

#import <UIKit/UIKit.h>

%hook UIViewController
- (BOOL)prefersHomeIndicatorAutoHidden {
    return YES;
}
%end

%ctor {
    NSLog(@"[W0lfSword] hide_home_bar loaded — home indicator auto-hidden");
}
