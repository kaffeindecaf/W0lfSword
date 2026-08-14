// five_icon_dock.xm — W0lfSword tweak template (K3.2 seed entry)
// Allows 5 icons per dock row on iOS 17-26 SpringBoard.
//
// NOTE: skeleton template. `maxIconCountForDock` lives on SBRootFolderView
// in SpringBoardHome.framework on iOS 13+. If a future iOS moves the dock
// layout logic (e.g. SBIconListModel), add that hook here. Verify on device
// before shipping.

#import <UIKit/UIKit.h>

@interface SBRootFolderView : UIView
@end

%hook SBRootFolderView
- (unsigned long long)maxIconCountForDock {
    return 5;
}
%end

%ctor {
    NSLog(@"[W0lfSword] five_icon_dock loaded — dock allows 5 icons");
}
