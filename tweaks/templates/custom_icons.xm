// custom_icons.xm - W0lfSword tweak template (catalog id: custom_icons, K3.7)
// Themes app icons from PNGs at /var/mobile/Documents/Icons/<bundleid>.png
// (Mugunghwa parity - see tweaks/parity.md, row "icon theming (user apps)").
//
// Owner differs on purpose: Mugunghwa rewrites Assets.car renditions through a
// root helper; this template only hooks the reader, so no asset file, no
// SSV/vnode write path and no backup file are involved. The Assets.car
// rendition route is parity.md's follow-up, not this row.
//
// NOTE: skeleton template. Hook point is SpringBoardHome's SBIconView: after
// -setIcon: runs, a themed PNG - if one exists for that bundle id - is pushed
// into the icon's own image views. Both accessors used here (SBIconView
// -setIcon:, SBIcon -applicationBundleIdentifier) are runtime-guarded, so a
// renamed accessor disables the lookup instead of crashing SpringBoard. If a
// build renders icons through another path (candidate: SBIconImageView
// -updateImageAnimated:), add that hook here. Verify on device before
// shipping.
//
// Safe revert: this tweak writes nothing to the device. It only READS
// /var/mobile/Documents/Icons/<bundleid>.png, so deleting that directory and
// respringing (or `./W0lfSword tweaks remove custom_icons`) brings the stock
// icons back - there is no changed asset to restore.

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

static NSString *const kW0lfIconThemeDir = @"/var/mobile/Documents/Icons";

@interface SBIcon : NSObject
- (NSString *)applicationBundleIdentifier;
@end

@interface SBIconView : UIView
- (void)setIcon:(SBIcon *)icon;
@end

// <bundleid>.png from the theme dir, or nil when this icon is not themed.
static UIImage *W0lfThemedIconForIcon(SBIcon *icon) {
    if (!icon || ![icon respondsToSelector:@selector(applicationBundleIdentifier)]) return nil;
    NSString *bundleID = [icon applicationBundleIdentifier];
    if (bundleID.length == 0) return nil;
    NSString *path = [kW0lfIconThemeDir stringByAppendingPathComponent:
                      [bundleID stringByAppendingPathExtension:@"png"]];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) return nil;
    return [UIImage imageWithContentsOfFile:path];
}

%hook SBIconView
- (void)setIcon:(SBIcon *)icon {
    %orig;
    UIImage *themed = W0lfThemedIconForIcon(icon);
    if (!themed) return;
    for (UIView *sub in [self subviews]) {
        if ([sub isKindOfClass:[UIImageView class]]) {
            [(UIImageView *)sub setImage:themed];
        }
    }
}
%end

%ctor {
    NSLog(@"[W0lfSword] custom_icons loaded - themed icons from %@", kW0lfIconThemeDir);
}
