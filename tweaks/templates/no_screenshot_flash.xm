// no_screenshot_flash.xm — W0lfSword tweak template
// Disables the white flash animation on screenshots.
//
// NOTE: skeleton template. Screenshot flash is driven by
// SBScreenshotManager / SBCaptureApplication in SpringBoard. Hook the
// flash-triggering method (name changed across iOS versions: flashScreenshot
// → playScreenshotSoundAndFlash etc.) and no-op it. Verify on device.

#import <UIKit/UIKit.h>

@interface SBScreenshotManager : NSObject
@end

%hook SBScreenshotManager
- (void)flashScreenshot {
    // no-op: skip the white flash
}
%end

%ctor {
    NSLog(@"[W0lfSword] no_screenshot_flash loaded — flash suppressed");
}
