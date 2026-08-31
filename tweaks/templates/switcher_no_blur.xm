// switcher_no_blur.xm — W0lfSword tweak template
// Removes the blur from app switcher cards.
//
// NOTE: skeleton template. Switcher cards are SBIconListGridClippedView /
// SBIconListView inside SBMainSwitcherViewController; the blur is a
// UIVisualEffectView (SBCardBackgroundBlurView / SBLiveCardBlurView).
// Sweep the card's subviews and kill UIVisualEffectView instances.
// Verify on device before shipping.

#import <UIKit/UIKit.h>

@interface SBIconListGridClippedView : UIView
@end

%hook SBIconListGridClippedView
- (void)layoutSubviews {
    %orig;
    for (UIView *sub in [self subviews]) {
        if ([sub isKindOfClass:NSClassFromString(@"UIVisualEffectView")]) {
            sub.hidden = YES;
            sub.alpha = 0.0;
        }
    }
}
%end

%ctor {
    NSLog(@"[W0lfSword] switcher_no_blur loaded — switcher blur removed");
}
