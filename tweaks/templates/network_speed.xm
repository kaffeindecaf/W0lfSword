// network_speed.xm — W0lfSword tweak template
// Live upload/download speed indicator in the status bar.
//
// NOTE: skeleton template. This is the most involved of the userspace
// tweaks: it needs a background monitor (NWPathMonitor or sysctl
// netstat-style deltas on interface counters) plus a view injected into
// the status bar. The template below hooks the status bar container to
// prove the injection point; the traffic monitor itself is left as an
// exercise (see research/ for network counter reads). Verify on device.

#import <UIKit/UIKit.h>
#import <Network/Network.h>

@interface _UIStatusBar : UIView
@end

%hook _UIStatusBar
- (void)layoutSubviews {
    %orig;
    static UILabel *speedLabel = nil;
    if (!speedLabel) {
        speedLabel = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, 60, 20)];
        speedLabel.font = [UIFont systemFontOfSize:10];
        speedLabel.text = @"0 B/s";
        speedLabel.textColor = [UIColor whiteColor];
        speedLabel.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin;
        [self addSubview:speedLabel];
    }
    // TODO: update speedLabel.text from interface counter deltas.
}
%end

%ctor {
    NSLog(@"[W0lfSword] network_speed loaded — status bar speed label attached");
}
