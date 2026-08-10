//
//  FilzaPadlockBypass.m
//  FilzaJailedDS-SSV-Bypass
//
//  Bypasses Filza's UI padlock and permission checks
//  Allows editing/creating/deleting files in ALL locations including /System
//

#import "FilzaPadlockBypass.h"
#import "utils/permission_utils.h"
#import "utils/tweak_log.h"
#import "kexploit/krw.h"
#import "kexploit/vnode.h"
#import "kexploit/offsets.h"
#import <substrate.h>

static BOOL g_hooks_disabled = NO;

#pragma mark - Class existence verification

static void verify_padlock_classes(void) {
    static const char *classNames[] = {
        "NZFileBrowserController",
        "NZDirectoryController",
        "NZFileItem",
        "NZFileManager",
        "NZTextEditor",
        "NZFileViewer",
        NULL
    };

    int found = 0, missing = 0;
    for (int i = 0; classNames[i]; i++) {
        Class cls = NSClassFromString([NSString stringWithUTF8String:classNames[i]]);
        if (cls) {
            found++;
        } else {
            TweakLog("[Padlock] WARNING: class '%s' not found — hooks targeting it are dead code",
                     classNames[i]);
            missing++;
        }
    }

    if (found == 0) {
        TweakLog("[Padlock] ALL target classes missing — disabling padlock hooks (likely wrong Filza version)");
        g_hooks_disabled = YES;
    } else {
        TweakLog("[Padlock] Class check: %d found, %d missing (hooks %s)",
                 found, missing, missing > 0 ? "partially active" : "fully active");
    }
}

#pragma mark - Helper Functions

BOOL filza_canEditPath(NSString *path) {
    TweakLog("[Padlock] filza_canEditPath: %s - returning YES", [path UTF8String]);
    return YES;
}

BOOL filza_canWritePath(NSString *path) {
    TweakLog("[Padlock] filza_canWritePath: %s - returning YES", [path UTF8String]);
    return YES;
}

BOOL filza_canDeletePath(NSString *path) {
    TweakLog("[Padlock] filza_canDeletePath: %s - returning YES", [path UTF8String]);
    return YES;
}

BOOL filza_canCreatePath(NSString *path) {
    TweakLog("[Padlock] filza_canCreatePath: %s - returning YES", [path UTF8String]);
    return YES;
}

#pragma mark - NZFileBrowserController Hooks

%hook NZFileBrowserController

- (BOOL)canEditItemAtURL:(NSURL *)url {
    if (g_hooks_disabled) return %orig;
    %log;
    NSString *path = [url path];
    TweakLog("NZFileBrowserController::canEditItemAtURL: %s - BYPASSING", [path UTF8String]);
    return YES;
}

- (BOOL)isLocked {
    if (g_hooks_disabled) return %orig;
    %log;
    TweakLog("NZFileBrowserController::isLocked - BYPASSING (returning NO)");
    return NO;
}

- (BOOL)readOnlyMode {
    if (g_hooks_disabled) return %orig;
    %log;
    TweakLog("NZFileBrowserController::readOnlyMode - BYPASSING (returning NO)");
    return NO;
}

- (BOOL)canCreateFiles {
    if (g_hooks_disabled) return %orig;
    %log;
    TweakLog("NZFileBrowserController::canCreateFiles - BYPASSING (returning YES)");
    return YES;
}

- (BOOL)canDeleteItems {
    if (g_hooks_disabled) return %orig;
    %log;
    TweakLog("NZFileBrowserController::canDeleteItems - BYPASSING (returning YES)");
    return YES;
}

%end

#pragma mark - NZDirectoryController Hooks

%hook NZDirectoryController

- (BOOL)canCreateFiles {
    if (g_hooks_disabled) return %orig;
    %log;
    TweakLog("NZDirectoryController::canCreateFiles - BYPASSING (returning YES)");
    return YES;
}

- (BOOL)canDeleteItems {
    if (g_hooks_disabled) return %orig;
    %log;
    TweakLog("NZDirectoryController::canDeleteItems - BYPASSING (returning YES)");
    return YES;
}

- (BOOL)isLocked {
    if (g_hooks_disabled) return %orig;
    %log;
    TweakLog("NZDirectoryController::isLocked - BYPASSING (returning NO)");
    return NO;
}

%end

#pragma mark - NZFileItem Hooks

%hook NZFileItem

- (BOOL)isLocked {
    if (g_hooks_disabled) return %orig;
    %log;
    TweakLog("NZFileItem::isLocked - BYPASSING (returning NO)");
    return NO;
}

- (BOOL)canWrite {
    if (g_hooks_disabled) return %orig;
    %log;
    TweakLog("NZFileItem::canWrite - BYPASSING (returning YES)");
    return YES;
}

- (BOOL)canDelete {
    if (g_hooks_disabled) return %orig;
    %log;
    TweakLog("NZFileItem::canDelete - BYPASSING (returning YES)");
    return YES;
}

- (BOOL)canEdit {
    if (g_hooks_disabled) return %orig;
    %log;
    TweakLog("NZFileItem::canEdit - BYPASSING (returning YES)");
    return YES;
}

%end

#pragma mark - NZFileManager Hooks (with permission application)

%hook NZFileManager

- (BOOL)createFileAtPath:(NSString *)path contents:(NSData *)data attributes:(NSDictionary *)attr {
    if (g_hooks_disabled) return %orig;
    %log;
    TweakLog("NZFileManager::createFileAtPath: %s - applying permissions after", [path UTF8String]);
    
    BOOL result = %orig;
    
    if (result) {
        apply_permissions_after_operation([path UTF8String], "create");
    }
    
    return result;
}

- (BOOL)copyItemAtPath:(NSString *)src toPath:(NSString *)dst error:(NSError **)err {
    if (g_hooks_disabled) return %orig;
    %log;
    TweakLog("NZFileManager::copyItemAtPath: %s -> %s - applying permissions after", [src UTF8String], [dst UTF8String]);
    
    BOOL result = %orig;
    
    if (result) {
        apply_permissions_after_operation([dst UTF8String], "copy");
    }
    
    return result;
}

- (BOOL)moveItemAtPath:(NSString *)src toPath:(NSString *)dst error:(NSError **)err {
    if (g_hooks_disabled) return %orig;
    %log;
    TweakLog("NZFileManager::moveItemAtPath: %s -> %s - applying permissions after", [src UTF8String], [dst UTF8String]);
    
    BOOL result = %orig;
    
    if (result) {
        apply_permissions_after_operation([dst UTF8String], "move");
    }
    
    return result;
}

- (BOOL)removeItemAtPath:(NSString *)path error:(NSError **)err {
    if (g_hooks_disabled) return %orig;
    %log;
    TweakLog("NZFileManager::removeItemAtPath: %s - allowing deletion", [path UTF8String]);
    
    // For SSV paths, we need to clear the immutable flag before deletion
    if (is_ssv_protected_path([path UTF8String])) {
        TweakLog("SSV path detected, attempting to clear immutable flag");
        uint64_t vnode = get_vnode_for_path_by_open([path UTF8String]);
        if (vnode != -1) {
            uint64_t v_data = kread64(vnode + off_vnode_v_data);
            if (v_data) {
                // Clear UF_IMMUTABLE flag (0x8000)
                uint32_t flags = kread32(v_data + off_apfs_fsnode_flags);
                kwrite32(v_data + off_apfs_fsnode_flags, flags & ~0x8000);
                TweakLog("Cleared immutable flag for %s", [path UTF8String]);
            }
        }
    }
    
    return %orig;
}

- (BOOL)replaceItemAtPath:(NSString *)path withItemAtPath:(NSString *)withItem error:(NSError **)err {
    if (g_hooks_disabled) return %orig;
    %log;
    TweakLog("NZFileManager::replaceItemAtPath: %s - applying permissions after", [path UTF8String]);
    
    BOOL result = %orig;
    
    if (result) {
        apply_permissions_after_operation([path UTF8String], "replace");
    }
    
    return result;
}

%end

#pragma mark - NZTextEditor Hooks (file modifications)

%hook NZTextEditor

- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    if (g_hooks_disabled) return %orig;
    %log;
    TweakLog("NZTextEditor::writeToFile: %s - applying permissions after", [path UTF8String]);
    
    BOOL result = %orig;
    
    if (result) {
        apply_permissions_after_operation([path UTF8String], "modify");
    }
    
    return result;
}

%end

#pragma mark - NZFileViewer Hooks

%hook NZFileViewer

- (BOOL)canEdit {
    if (g_hooks_disabled) return %orig;
    %log;
    TweakLog("NZFileViewer::canEdit - BYPASSING (returning YES)");
    return YES;
}

- (BOOL)canSave {
    if (g_hooks_disabled) return %orig;
    %log;
    TweakLog("NZFileViewer::canSave - BYPASSING (returning YES)");
    return YES;
}

%end

#pragma mark - Initialization

void initFilzaPadlockBypass(void) {
    verify_padlock_classes();
    TweakLog("initFilzaPadlockBypass called - hooks are active (disabled=%d)", g_hooks_disabled);
}
