// transparent_folders.xm — W0lfSword tweak template
// Removes the folder background blur/darkening (jailbreak-required).
//
// NOTE: skeleton template. Folder backdrop is SBFolderBackgroundView /
// SBFolderIconBackgroundView; on 15+ it is a material view. Requires
// kernel R/W (darksword) because SpringBoardHome is modified in memory.
// Verify on device before shipping.

#import <UIKit/UIKit.h>

@interface SBFolderBackgroundView : UIView
@end

%hook SBFolderBackgroundView
- (void)layoutSubviews {
    %orig;
    self.backgroundColor = [UIColor clearColor];
    self.alpha = 0.0;
}
%end

%ctor {
    NSLog(@"[W0lfSword] transparent_folders loaded — folder background cleared");
}
