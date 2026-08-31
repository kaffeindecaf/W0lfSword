// status_bar_date.xm — W0lfSword tweak template
// Shows the date next to the status bar clock on iOS 16-26.
//
// NOTE: skeleton template. The status bar layout moved from UIKit
// (UIStatusBarServer) to the _UIStatusBar* items in SpringBoard on 16+.
// Hook _UIStatusBarTimeItem or the container view to inject the date
// label; exact class names vary per iOS. Verify on device before
// shipping.

#import <UIKit/UIKit.h>

%hook _UIStatusBarTimeItem
- (void)_create_timeLabel {
    %orig;
}
%end

%ctor {
    NSLog(@"[W0lfSword] status_bar_date loaded — date label injection point");
}
