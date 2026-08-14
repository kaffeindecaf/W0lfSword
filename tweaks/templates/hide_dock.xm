// hide_dock.xm — W0lfSword tweak template (K3.2 seed entry)
// Removes the dock background on iOS 16-26 SpringBoard.
//
// NOTE: skeleton template. Dock backdrop view class names changed across iOS
// (SBDockBackdropView → material views on 16+). The layoutSubviews sweep
// catches them by name. Verify on device before shipping.

#import <UIKit/UIKit.h>

@interface SBRootFolderView : UIView
@end

%hook SBRootFolderView
- (void)layoutSubviews {
    %orig;
    for (UIView *subview in [self subviews]) {
        NSString *cn = NSStringFromClass([subview class]);
        if ([cn containsString:@"DockBackground"] || [cn containsString:@"DockBackdrop"]) {
            subview.hidden = YES;
            subview.alpha = 0.0;
        }
    }
}
%end

%ctor {
    NSLog(@"[W0lfSword] hide_dock loaded — dock background hidden");
}
