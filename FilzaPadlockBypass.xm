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
    %log;
    NSString *path = [url path];
    TweakLog("NZFileBrowserController::canEditItemAtURL: %s - BYPASSING", [path UTF8String]);
    return YES;
}

- (BOOL)isLocked {
    %log;
    TweakLog("NZFileBrowserController::isLocked - BYPASSING (returning NO)");
    return NO;  // Hide the padlock
}

- (BOOL)readOnlyMode {
    %log;
    TweakLog("NZFileBrowserController::readOnlyMode - BYPASSING (returning NO)");
    return NO;  // Disable read-only mode
}

- (BOOL)canCreateFiles {
    %log;
    TweakLog("NZFileBrowserController::canCreateFiles - BYPASSING (returning YES)");
    return YES;
}

- (BOOL)canDeleteItems {
    %log;
    TweakLog("NZFileBrowserController::canDeleteItems - BYPASSING (returning YES)");
    return YES;
}

%end

#pragma mark - NZDirectoryController Hooks

%hook NZDirectoryController

- (BOOL)canCreateFiles {
    %log;
    TweakLog("NZDirectoryController::canCreateFiles - BYPASSING (returning YES)");
    return YES;
}

- (BOOL)canDeleteItems {
    %log;
    TweakLog("NZDirectoryController::canDeleteItems - BYPASSING (returning YES)");
    return YES;
}

- (BOOL)isLocked {
    %log;
    TweakLog("NZDirectoryController::isLocked - BYPASSING (returning NO)");
    return NO;
}

%end

#pragma mark - NZFileItem Hooks

%hook NZFileItem

- (BOOL)isLocked {
    %log;
    TweakLog("NZFileItem::isLocked - BYPASSING (returning NO)");
    return NO;
}

- (BOOL)canWrite {
    %log;
    TweakLog("NZFileItem::canWrite - BYPASSING (returning YES)");
    return YES;
}

- (BOOL)canDelete {
    %log;
    TweakLog("NZFileItem::canDelete - BYPASSING (returning YES)");
    return YES;
}

- (BOOL)canEdit {
    %log;
    TweakLog("NZFileItem::canEdit - BYPASSING (returning YES)");
    return YES;
}

%end

#pragma mark - NZFileManager Hooks (with permission application)

%hook NZFileManager

- (BOOL)createFileAtPath:(NSString *)path contents:(NSData *)data attributes:(NSDictionary *)attr {
    %log;
    TweakLog("NZFileManager::createFileAtPath: %s - applying permissions after", [path UTF8String]);
    
    BOOL result = %orig;
    
    if (result) {
        apply_permissions_after_operation([path UTF8String], "create");
    }
    
    return result;
}

- (BOOL)copyItemAtPath:(NSString *)src toPath:(NSString *)dst error:(NSError **)err {
    %log;
    TweakLog("NZFileManager::copyItemAtPath: %s -> %s - applying permissions after", [src UTF8String], [dst UTF8String]);
    
    BOOL result = %orig;
    
    if (result) {
        apply_permissions_after_operation([dst UTF8String], "copy");
    }
    
    return result;
}

- (BOOL)moveItemAtPath:(NSString *)src toPath:(NSString *)dst error:(NSError **)err {
    %log;
    TweakLog("NZFileManager::moveItemAtPath: %s -> %s - applying permissions after", [src UTF8String], [dst UTF8String]);
    
    BOOL result = %orig;
    
    if (result) {
        apply_permissions_after_operation([dst UTF8String], "move");
    }
    
    return result;
}

- (BOOL)removeItemAtPath:(NSString *)path error:(NSError **)err {
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
    %log;
    TweakLog("NZFileViewer::canEdit - BYPASSING (returning YES)");
    return YES;
}

- (BOOL)canSave {
    %log;
    TweakLog("NZFileViewer::canSave - BYPASSING (returning YES)");
    return YES;
}

%end

#pragma mark - Initialization

void initFilzaPadlockBypass(void) {
    TweakLog("initFilzaPadlockBypass called - hooks are active");
}
