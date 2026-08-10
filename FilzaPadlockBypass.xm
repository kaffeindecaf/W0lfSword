//
//  FilzaPadlockBypass.xm
//  W0lfSword
//
//  Bypasses Filza's UI padlock and permission checks on real TG/TIGI classes.
//  The old NZ* hooks were dead code — those classes never existed in Filza 4.0.x.
//

#import "FilzaPadlockBypass.h"
#import "utils/permission_utils.h"
#import "utils/tweak_log.h"
#import "utils/state.h"
#import "kexploit/krw.h"
#import "kexploit/vnode.h"
#import "kexploit/offsets.h"
#import <substrate.h>

static BOOL g_hooks_disabled = NO;

static const char *safe_utf8(NSString *s) {
    return s ? [s UTF8String] : "(nil)";
}

#pragma mark - Class existence verification

static void verify_padlock_classes(void) {
    static const char *classNames[] = {
        "TIGIBrowserView",
        "TGPageViewController",
        "TGFileSystemListViewController",
        NULL
    };

    int found = 0, missing = 0;
    for (int i = 0; classNames[i]; i++) {
        Class cls = NSClassFromString([NSString stringWithUTF8String:classNames[i]]);
        if (cls) {
            found++;
        } else {
            TweakLog("[Padlock] WARNING: class '%s' not found", classNames[i]);
            missing++;
        }
    }

    if (found == 0) {
        TweakLog("[Padlock] ALL target classes missing — disabling padlock hooks");
        g_hooks_disabled = YES;
    } else {
        TweakLog("[Padlock] Class check: %d found, %d missing (hooks %s)",
                 found, missing, missing > 0 ? "partially active" : "fully active");
    }
}

#pragma mark - Helper Functions

BOOL filza_canEditPath(NSString *path) {
    return YES;
}

BOOL filza_canWritePath(NSString *path) {
    return YES;
}

BOOL filza_canDeletePath(NSString *path) {
    return YES;
}

BOOL filza_canCreatePath(NSString *path) {
    return YES;
}

#pragma mark - TIGIBrowserView (internal browser — force readOnly:NO + allow all edits)

%hook TIGIBrowserView

- (id)initWithStyle:(int)style reuseIdentifier:(id)rid delegate:(id)del readOnly:(BOOL)ro {
    if (g_hooks_disabled) return %orig;
    return %orig(style, rid, del, NO);
}

- (BOOL)tableView:(id)tv canEditRowAtIndexPath:(id)ip {
    if (g_hooks_disabled) return %orig;
    return YES;
}

%end

#pragma mark - TGPageViewController (main file list — allow delete + skip confirm)

%hook TGPageViewController

- (BOOL)browserView:(id)bv canDeleteItemAtIndexPath:(id)ip {
    if (g_hooks_disabled) return %orig;
    return YES;
}

- (void)askDeleteItems:(id)items {
    if (g_hooks_disabled) return %orig;
    ((void(*)(id,SEL))objc_msgSend)(self, NSSelectorFromString(@"deleteSelectedItems"));
}

%end

#pragma mark - TGFileSystemListViewController (file browser — same pattern)

%hook TGFileSystemListViewController

- (BOOL)browserView:(id)bv canDeleteItemAtIndexPath:(id)ip {
    if (g_hooks_disabled) return %orig;
    return YES;
}

- (void)askDeleteItems:(id)items {
    if (g_hooks_disabled) return %orig;
    ((void(*)(id,SEL))objc_msgSend)(self, NSSelectorFromString(@"deleteSelectedItems"));
}

%end

#pragma mark - Initialization

void initFilzaPadlockBypass(void) {
    verify_padlock_classes();
    TweakLog("[Padlock] initFilzaPadlockBypass — TG/TIGI hooks active (disabled=%d)", g_hooks_disabled);
}
