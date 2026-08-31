// battery_percent.xm — W0lfSword tweak template
// Forces the battery percentage into the status bar.
//
// NOTE: skeleton template. Modern iOS hides the percentage unless the
// user enables it in Settings; the knob is in _UIStatusBarBatteryItem /
// _UIStatusBarBatteryView (SpringBoard) or the battery module. Hook the
// visibility query and return YES. Verify on device before shipping.

#import <UIKit/UIKit.h>

%hook _UIStatusBarBatteryItem
- (BOOL)showsPercentage {
    return YES;
}
%end

%ctor {
    NSLog(@"[W0lfSword] battery_percent loaded — percentage forced on");
}
