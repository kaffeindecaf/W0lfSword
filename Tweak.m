@import UIKit;
#import <stdbool.h>
#import <stdatomic.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <xpc/xpc.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <errno.h>

#include "kexploit/kexploit_opa334.h"
#include "kexploit/kutils.h"
#include "kexploit/sandbox.h"
#include "sandbox_escape.h"
#include "SSV/SSVUtils.h"
#import "FilzaPadlockBypass.h"
#import "utils/permission_utils.h"
#import "utils/state.h"
#include "TweakExploit.h"

#include "utils/tweak_log.h"

#pragma mark - Root Helper Hooks

static BOOL hook_isRootHelperAvailable(id self, SEL _cmd) {
    return NO;
}

static int hook_spawnRootHelper(id self, SEL _cmd) { return 0; }
static int hook_spawnRootHelperIfNeeds(id self, SEL _cmd) { return 0; }
static int hook_respawnRootHelper(id self, SEL _cmd) { return 0; }
static void hook_tryLoadFilzaHelper(id self, SEL _cmd) {}
static void hook_createHelperConnectionIfNeeds(id self, SEL _cmd) {}

static int hook_spawnRoot_args_pid(id self, SEL _cmd, id path, id args, int *pid) {
    if (pid) *pid = 0;
    return -1;
}

static id hook_sendObjectWithReplySync(id self, SEL _cmd, id msg) {
    return (id)xpc_null_create();
}

static id hook_sendObjectWithReplySync_fd(id self, SEL _cmd, id msg, int *fd) {
    if (fd) *fd = -1;
    return (id)xpc_null_create();
}

static id hook_sendObjectWithReplySync_fd_logintty(id self, SEL _cmd, id msg, int *fd, BOOL logintty) {
    if (fd) *fd = -1;
    return (id)xpc_null_create();
}

static void hook_sendObjectNoReply(id self, SEL _cmd, id msg) {}

static void hook_sendObjectWithReplyAsync(id self, SEL _cmd, id msg, id queue, id completion) {
    if (completion) { void (^block)(id) = completion; block(nil); }
}

#pragma mark - Zip/Unzip via minizip C API (linked in Filza binary)

// minizip C functions — statically linked in Filza, resolve via dlsym at runtime
#include <dlfcn.h>
typedef void* zipFile64;
typedef void* unzFile64;

// Function pointer types
static zipFile64 (*p_zipOpen64)(const char*, int);
static int (*p_zipOpenNewFileInZip64)(zipFile64, const char*, const void*, const void*, unsigned, const void*, unsigned, const char*, int, int, int);
static int (*p_zipWriteInFileInZip)(zipFile64, const void*, unsigned);
static int (*p_zipCloseFileInZip)(zipFile64);
static int (*p_zipClose)(zipFile64, const char*);
static unzFile64 (*p_unzOpen64)(const char*);
static int (*p_unzGoToFirstFile)(unzFile64);
static int (*p_unzGoToNextFile)(unzFile64);
static int (*p_unzGetCurrentFileInfo64)(unzFile64, void*, char*, unsigned long, void*, unsigned long, char*, unsigned long);
static int (*p_unzOpenCurrentFilePassword)(unzFile64, const char*);
static int (*p_unzReadCurrentFile)(unzFile64, void*, unsigned);
static int (*p_unzCloseCurrentFile)(unzFile64);
static int (*p_unzClose)(unzFile64);

static bool g_minizipLoaded = false;
static void loadMinizip(void) {
    if (g_minizipLoaded) return;
    // RTLD_DEFAULT searches all loaded images including Filza's statically linked minizip
    p_zipOpen64 = dlsym(RTLD_DEFAULT, "zipOpen64");
    p_zipOpenNewFileInZip64 = dlsym(RTLD_DEFAULT, "zipOpenNewFileInZip64");
    p_zipWriteInFileInZip = dlsym(RTLD_DEFAULT, "zipWriteInFileInZip");
    p_zipCloseFileInZip = dlsym(RTLD_DEFAULT, "zipCloseFileInZip");
    p_zipClose = dlsym(RTLD_DEFAULT, "zipClose");
    p_unzOpen64 = dlsym(RTLD_DEFAULT, "unzOpen64");
    p_unzGoToFirstFile = dlsym(RTLD_DEFAULT, "unzGoToFirstFile");
    p_unzGoToNextFile = dlsym(RTLD_DEFAULT, "unzGoToNextFile");
    p_unzGetCurrentFileInfo64 = dlsym(RTLD_DEFAULT, "unzGetCurrentFileInfo64");
    p_unzOpenCurrentFilePassword = dlsym(RTLD_DEFAULT, "unzOpenCurrentFilePassword");
    p_unzReadCurrentFile = dlsym(RTLD_DEFAULT, "unzReadCurrentFile");
    p_unzCloseCurrentFile = dlsym(RTLD_DEFAULT, "unzCloseCurrentFile");
    p_unzClose = dlsym(RTLD_DEFAULT, "unzClose");
    g_minizipLoaded = (p_zipOpen64 && p_zipOpenNewFileInZip64 && p_zipWriteInFileInZip &&
                        p_zipCloseFileInZip && p_zipClose &&
                        p_unzOpen64 && p_unzGoToFirstFile && p_unzGoToNextFile &&
                        p_unzGetCurrentFileInfo64 && p_unzOpenCurrentFilePassword &&
                        p_unzReadCurrentFile && p_unzCloseCurrentFile && p_unzClose);
    NSLog(@"[Tweak] minizip loaded: %d (zip=%p zipNew=%p zipWrite=%p zipCloseFile=%p zipClose=%p unz=%p unzFirst=%p unzNext=%p unzInfo=%p unzPassword=%p unzRead=%p unzCloseCurrent=%p unzClose=%p)",
          g_minizipLoaded, p_zipOpen64, p_zipOpenNewFileInZip64, p_zipWriteInFileInZip,
          p_zipCloseFileInZip, p_zipClose, p_unzOpen64, p_unzGoToFirstFile, p_unzGoToNextFile,
          p_unzGetCurrentFileInfo64, p_unzOpenCurrentFilePassword, p_unzReadCurrentFile,
          p_unzCloseCurrentFile, p_unzClose);
}

static IMP orig_ZipFiles = NULL, orig_unZipFile = NULL, orig_unZipFilePassword = NULL;

// Recursively add files to a zip archive using minizip C API
static void addFileToZip(zipFile64 zf, NSString *basePath, NSString *relativePath) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *fullPath = [basePath stringByAppendingPathComponent:relativePath];
    BOOL isDir = NO;
    [fm fileExistsAtPath:fullPath isDirectory:&isDir];
    if (isDir) {
        // Add directory entry
        NSString *dirEntry = [relativePath stringByAppendingString:@"/"];
        p_zipOpenNewFileInZip64(zf, dirEntry.UTF8String, NULL, NULL, 0, NULL, 0, NULL, 0, 0, 0);
        p_zipCloseFileInZip(zf);
        for (NSString *item in [fm contentsOfDirectoryAtPath:fullPath error:nil])
            addFileToZip(zf, basePath, [relativePath stringByAppendingPathComponent:item]);
    } else {
        NSData *data = [NSData dataWithContentsOfFile:fullPath];
        if (!data) return;
        // Z_DEFLATED=8, Z_DEFAULT_COMPRESSION=-1
        p_zipOpenNewFileInZip64(zf, relativePath.UTF8String, NULL, NULL, 0, NULL, 0, NULL, 8, -1, data.length > 0xFFFFFFFF);
        p_zipWriteInFileInZip(zf, data.bytes, (unsigned int)data.length);
        p_zipCloseFileInZip(zf);
    }
}

// Hook: -[Zipper ZipFiles:toFilePath:currentDirectory:]
static id hook_ZipFiles(id self, SEL _cmd, id files, id toFilePath, id currentDirectory) {
    @try {
        loadMinizip();
        if (!g_minizipLoaded) return orig_ZipFiles ? ((id(*)(id,SEL,id,id,id))orig_ZipFiles)(self, _cmd, files, toFilePath, currentDirectory) : nil;
        NSString *zipPath = [toFilePath isKindOfClass:[NSString class]] ? (NSString *)toFilePath : nil;
        const char *zipC = zipPath ? zipPath.UTF8String : NULL;
        if (!zipC) { NSLog(@"[Tweak] zipOpen64: invalid path"); return nil; }
        zipFile64 zf = p_zipOpen64(zipC, 0);
        if (!zf) { NSLog(@"[Tweak] zipOpen64 failed"); return nil; }

        for (id fi in files) {
            NSString *fn = [fi performSelector:NSSelectorFromString(@"fileName")];
            if (fn) addFileToZip(zf, currentDirectory, fn);
        }
        p_zipClose(zf, NULL);

        // Return FileItem if zip was created (matching original behavior)
        if ([[NSFileManager defaultManager] fileExistsAtPath:toFilePath]) {
            Class FI = NSClassFromString(@"FileItem");
            if (FI) {
                id item = [[FI alloc] init];
                ((void(*)(id,SEL,id,id))objc_msgSend)(item, NSSelectorFromString(@"setFilePath:attribute:"), toFilePath, nil);
                return item;
            }
        }
        return nil;
    } @catch (NSException *e) { NSLog(@"[Tweak] Zip error: %@", e); return nil; }
}

// Hook: -[Zipper unZipFile:toPath:currentDirectory:outMessage:]
static id hook_unZipFile(id self, SEL _cmd, id zipPath, id toPath, id currentDir, id *outMsg) {
    @try {
        loadMinizip();
        if (!g_minizipLoaded) return orig_unZipFile ? ((id(*)(id,SEL,id,id,id,id*))orig_unZipFile)(self, _cmd, zipPath, toPath, currentDir, outMsg) : nil;
        // zipPath is a FileItem, get the actual path string
        NSString *zipPathStr = zipPath;
        if ([zipPath respondsToSelector:NSSelectorFromString(@"filePath")])
            zipPathStr = [zipPath performSelector:NSSelectorFromString(@"filePath")];

        NSString *zsStr = [zipPathStr isKindOfClass:[NSString class]] ? (NSString *)zipPathStr : nil;
        const char *zsC = zsStr ? zsStr.UTF8String : NULL;
        if (!zsC) { if (outMsg) *outMsg = @"Invalid zip path"; return nil; }
        unzFile64 uf = p_unzOpen64(zsC);
        if (!uf) { if (outMsg) *outMsg = @"Failed to open zip"; return nil; }

        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *destPath = toPath;
        [fm createDirectoryAtPath:destPath withIntermediateDirectories:YES attributes:nil error:nil];

        char filename[512];
        uint8_t buf[32768];
        int ret = p_unzGoToFirstFile(uf);
        while (ret == 0) {
            p_unzGetCurrentFileInfo64(uf, NULL, filename, sizeof(filename), NULL, 0, NULL, 0);
            filename[sizeof(filename) - 1] = '\0';
            NSString *name = [NSString stringWithUTF8String:filename];
            NSString *fullPath = [destPath stringByAppendingPathComponent:name];

            if ([name hasSuffix:@"/"]) {
                [fm createDirectoryAtPath:fullPath withIntermediateDirectories:YES attributes:nil error:nil];
            } else {
                [fm createDirectoryAtPath:[fullPath stringByDeletingLastPathComponent]
                  withIntermediateDirectories:YES attributes:nil error:nil];

                if (p_unzOpenCurrentFilePassword(uf, NULL) == 0) {
                    NSMutableData *fileData = [NSMutableData data];
                    int bytesRead;
                    while ((bytesRead = p_unzReadCurrentFile(uf, buf, sizeof(buf))) > 0)
                        [fileData appendBytes:buf length:bytesRead];
                    p_unzCloseCurrentFile(uf);
                    [fileData writeToFile:fullPath atomically:YES];
                }
            }
            ret = p_unzGoToNextFile(uf);
        }
        p_unzClose(uf);

        if (outMsg) *outMsg = @"OK";

        // Return array of extracted FileItems (matching original behavior)
        NSArray *contents = [fm contentsOfDirectoryAtPath:destPath error:nil];
        if (contents.count > 0) {
            Class FI = NSClassFromString(@"FileItem");
            if (FI) {
                id item = [[FI alloc] init];
                ((void(*)(id,SEL,id,id))objc_msgSend)(item, NSSelectorFromString(@"setFilePath:attribute:"), destPath, nil);
                return @[item];
            }
        }
        return nil;
    } @catch (NSException *e) { NSLog(@"[Tweak] Unzip error: %@", e); if (outMsg) *outMsg = [e reason]; return nil; }
}

// Hook: -[Zipper unZipFile:toPath:currentDirectory:withPassword:outMessage:]
static id hook_unZipFilePassword(id self, SEL _cmd, id zipPath, id toPath, id currentDir, id password, id *outMsg) {
    return hook_unZipFile(self, @selector(unZipFile:toPath:currentDirectory:outMessage:), zipPath, toPath, currentDir, outMsg);
}

#pragma mark - Apps Manager Fix

// Full Apps Manager fix for sandbox-escaped devices.
// LSApplicationProxy properties (localizedName, iconsDictionary, dataContainerURL,
// staticDiskUsage, etc.) return nil without entitlements.
// Fix: Hook setAppProxy: to populate from Info.plist + filesystem directly.
// Hook calculateDiskUsage to walk bundle dirs. Hook tap to use bundle path fallback.

@interface LSApplicationProxy : NSObject
+ (id)applicationProxyForIdentifier:(NSString *)bundleId;
- (NSString *)applicationIdentifier;
- (NSURL *)bundleURL;
- (NSURL *)dataContainerURL;
- (NSString *)localizedName;
- (NSString *)bundleVersion;
- (NSString *)shortVersionString;
- (NSString *)applicationType;
- (NSDictionary *)iconsDictionary;
- (NSNumber *)staticDiskUsage;
- (NSNumber *)dynamicDiskUsage;
@end

@interface LSApplicationWorkspace : NSObject
+ (id)defaultWorkspace;
- (NSArray *)allApplications;
@end

// --- Helper: find app bundle path from bundleId ---
static NSString *findBundlePath(NSString *bundleId) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *appsDir = @"/var/containers/Bundle/Application";
    for (NSString *uuid in [fm contentsOfDirectoryAtPath:appsDir error:nil]) {
        NSString *uuidPath = [appsDir stringByAppendingPathComponent:uuid];
        for (NSString *item in [fm contentsOfDirectoryAtPath:uuidPath error:nil]) {
            if (![item hasSuffix:@".app"]) continue;
            NSString *appPath = [uuidPath stringByAppendingPathComponent:item];
            NSString *plist = [appPath stringByAppendingPathComponent:@"Info.plist"];
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
            if ([info[@"CFBundleIdentifier"] isEqualToString:bundleId]) return appPath;
        }
    }
    // System apps
    for (NSString *item in [fm contentsOfDirectoryAtPath:@"/Applications" error:nil]) {
        if (![item hasSuffix:@".app"]) continue;
        NSString *appPath = [@"/Applications" stringByAppendingPathComponent:item];
        NSString *plist = [appPath stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
        if ([info[@"CFBundleIdentifier"] isEqualToString:bundleId]) return appPath;
    }
    return nil;
}

// --- Helper: find data container path ---
static NSString *findDataContainer(NSString *bundleId) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dataDir = @"/var/mobile/Containers/Data/Application";
    for (NSString *uuid in [fm contentsOfDirectoryAtPath:dataDir error:nil]) {
        NSString *uuidPath = [dataDir stringByAppendingPathComponent:uuid];
        NSString *metaPlist = [uuidPath stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
        NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:metaPlist];
        if ([meta[@"MCMMetadataIdentifier"] isEqualToString:bundleId]) return uuidPath;
    }
    return nil;
}

// --- Helper: find best icon in bundle ---
static NSString *findIconPath(NSString *bundlePath, NSDictionary *infoPlist) {
    NSFileManager *fm = [NSFileManager defaultManager];
    // Try CFBundleIcons -> CFBundlePrimaryIcon -> CFBundleIconFiles
    NSDictionary *icons = infoPlist[@"CFBundleIcons"];
    NSDictionary *primary = icons[@"CFBundlePrimaryIcon"];
    NSArray *iconFiles = primary[@"CFBundleIconFiles"];
    if (!iconFiles) iconFiles = infoPlist[@"CFBundleIconFiles"];

    NSString *bestIcon = nil;
    unsigned long long bestSize = 0;
    if (iconFiles.count > 0) {
        for (NSString *iconName in iconFiles) {
            // Try exact name and @2x/@3x variants
            NSArray *variants = @[
                iconName,
                [iconName stringByAppendingString:@"@2x.png"],
                [iconName stringByAppendingString:@"@3x.png"],
                [iconName stringByAppendingString:@"@2x~iphone.png"],
                [iconName stringByAppendingString:@"@3x~iphone.png"],
                [NSString stringWithFormat:@"%@.png", iconName],
            ];
            for (NSString *v in variants) {
                NSString *full = [bundlePath stringByAppendingPathComponent:v];
                NSDictionary *attrs = [fm attributesOfItemAtPath:full error:nil];
                unsigned long long sz = [attrs fileSize];
                if (sz > bestSize) { bestSize = sz; bestIcon = full; }
            }
        }
    }

    // Fallback: scan for Icon*.png / AppIcon*.png
    if (!bestIcon) {
        for (NSString *file in [fm contentsOfDirectoryAtPath:bundlePath error:nil]) {
            if (([file hasPrefix:@"Icon"] || [file hasPrefix:@"icon"] || [file hasPrefix:@"AppIcon"])
                && [file hasSuffix:@".png"]) {
                NSString *full = [bundlePath stringByAppendingPathComponent:file];
                NSDictionary *attrs = [fm attributesOfItemAtPath:full error:nil];
                unsigned long long sz = [attrs fileSize];
                if (sz > bestSize) { bestSize = sz; bestIcon = full; }
            }
        }
    }
    return bestIcon;
}

// --- Hook: allApplications fallback ---
static IMP orig_allApplications = NULL;
static id hook_allApplications(id self, SEL _cmd) {
    NSArray *origResult = ((id(*)(id,SEL))orig_allApplications)(self, _cmd);
    if (origResult && origResult.count > 0) return origResult;

    NSMutableArray *apps = [NSMutableArray array];
    NSFileManager *fm = [NSFileManager defaultManager];
    void (^scanDir)(NSString *) = ^(NSString *dir) {
        for (NSString *uuid in [fm contentsOfDirectoryAtPath:dir error:nil]) {
            NSString *uuidPath = [dir stringByAppendingPathComponent:uuid];
            for (NSString *item in [fm contentsOfDirectoryAtPath:uuidPath error:nil]) {
                if (![item hasSuffix:@".app"]) continue;
                NSString *plist = [[uuidPath stringByAppendingPathComponent:item] stringByAppendingPathComponent:@"Info.plist"];
                NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
                NSString *bid = info[@"CFBundleIdentifier"];
                if (bid) {
                    id proxy = [NSClassFromString(@"LSApplicationProxy") applicationProxyForIdentifier:bid];
                    if (proxy) [apps addObject:proxy];
                }
            }
        }
    };
    scanDir(@"/var/containers/Bundle/Application");
    // System apps (flat structure)
    for (NSString *item in [fm contentsOfDirectoryAtPath:@"/Applications" error:nil]) {
        if (![item hasSuffix:@".app"]) continue;
        NSString *plist = [[@"/Applications" stringByAppendingPathComponent:item] stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
        NSString *bid = info[@"CFBundleIdentifier"];
        if (bid) {
            id proxy = [NSClassFromString(@"LSApplicationProxy") applicationProxyForIdentifier:bid];
            if (proxy) [apps addObject:proxy];
        }
    }
    NSLog(@"[Tweak] Apps Manager: found %lu apps via filesystem", (unsigned long)apps.count);
    return apps;
}

// --- Hook: setAppProxy: — populate name, icon, paths from filesystem ---
static IMP orig_setAppProxy = NULL;
static void hook_setAppProxy(id self, SEL _cmd, id proxy) {
    // Call original first
    ((void(*)(id,SEL,id))orig_setAppProxy)(self, _cmd, proxy);

    NSString *bundleId = [self performSelector:NSSelectorFromString(@"bundleId")];
    if (!bundleId) return;

    NSString *bundlePath = nil;
    NSString *currentFilePath = [self performSelector:NSSelectorFromString(@"filePath")];

    // Fix filePath if missing or inaccessible
    if (!currentFilePath || currentFilePath.length == 0) {
        NSURL *bundleURL = [proxy bundleURL];
        if (bundleURL) bundlePath = [bundleURL path];
        if (!bundlePath) bundlePath = findBundlePath(bundleId);
        if (bundlePath) {
            ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(@"setFilePath:"), bundlePath);
        }
    } else {
        bundlePath = currentFilePath;
    }

    // Fix display name — always prefer Info.plist name over proxy
    if (bundlePath) {
        NSString *plist = [bundlePath stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
        NSString *name = info[@"CFBundleDisplayName"];
        if (!name) name = info[@"CFBundleName"];
        if (!name) name = [proxy localizedName];
        if (!name) name = bundleId;
        ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(@"setAFileName:"), name);
    }

    // Fix icon path
    NSString *iconPath = ((id(*)(id,SEL))objc_msgSend)(self, NSSelectorFromString(@"iconPath"));
    if (!iconPath && bundlePath) {
        NSString *plist = [bundlePath stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
        NSString *found = findIconPath(bundlePath, info);
        if (found) {
            ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(@"setIconPath:"), found);
        }
    }

    // Fix document path
    NSString *docPath = ((id(*)(id,SEL))objc_msgSend)(self, NSSelectorFromString(@"documentPath"));
    if (!docPath) {
        NSURL *dataURL = [proxy dataContainerURL];
        if (dataURL) docPath = [dataURL path];
        if (!docPath) docPath = findDataContainer(bundleId);
        if (docPath) {
            ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(@"setDocumentPath:"), docPath);
        }
    }

    // Fix version
    NSString *ver = ((id(*)(id,SEL))objc_msgSend)(self, NSSelectorFromString(@"version"));
    if (!ver || ver.length == 0) {
        ver = [proxy bundleVersion];
        if (!ver && bundlePath) {
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                [bundlePath stringByAppendingPathComponent:@"Info.plist"]];
            ver = info[@"CFBundleShortVersionString"];
            if (!ver) ver = info[@"CFBundleVersion"];
        }
        if (ver) ((void(*)(id,SEL,id))objc_msgSend)(self, NSSelectorFromString(@"setVersion:"), ver);
    }
}


// --- Hook: browserView:didSelectItemAtIndexPath: — fallback to bundle path ---
static IMP orig_didSelectItem = NULL;
static void hook_didSelectItem(id self, SEL _cmd, id browserView, id indexPath) {
    // Get the selected item
    id fileList = ((id(*)(id,SEL))objc_msgSend)(self, NSSelectorFromString(@"fileList"));
    NSUInteger row = ((NSUInteger(*)(id,SEL))objc_msgSend)(indexPath, @selector(row));
    id item = ((id(*)(id,SEL,NSUInteger))objc_msgSend)(fileList, NSSelectorFromString(@"objectAtIndex:"), row);

    NSString *docPath = ((id(*)(id,SEL))objc_msgSend)(item, NSSelectorFromString(@"documentPath"));
    NSString *bundlePath = [item performSelector:NSSelectorFromString(@"filePath")];

    // If documentPath is nil but bundlePath exists, set documentPath to bundlePath
    // so the original handler can navigate there instead of showing error
    if (!docPath && bundlePath) {
        ((void(*)(id,SEL,id))objc_msgSend)(item, NSSelectorFromString(@"setDocumentPath:"), bundlePath);
    }

    // Call original
    ((void(*)(id,SEL,id,id))orig_didSelectItem)(self, _cmd, browserView, indexPath);
}

#pragma mark - License / Integrity Bypass

// Suppress "Main binary was modified" and "Not activated" alerts.
// +[TGAlertController showAlertWithTitle:text:cancelButton:otherButtons:completion:]
// checks the text parameter; if it's the integrity/activation alert, swallow it.
static IMP orig_showAlert = NULL;
static id hook_showAlertWithTitle(id self, SEL _cmd, id title, id text, id cancelButton, id otherButtons, id completion) {
    NSString *textStr = text;
    if ([textStr isKindOfClass:[NSString class]]) {
        if ([textStr containsString:@"binary was modified"] ||
            [textStr containsString:@"reinstall Filza"]) {
            NSLog(@"[Tweak] Suppressed integrity alert");
            return nil;
        }
    }
    // Pass through all other alerts
    return ((id(*)(id,SEL,id,id,id,id,id))orig_showAlert)(self, _cmd, title, text, cancelButton, otherButtons, completion);
}

// Suppress activation nag: -[NewActivationViewController viewDidLoad]
// Just dismiss the VC immediately so the user never sees it.
static IMP orig_activationViewDidLoad = NULL;
static void hook_activationViewDidLoad(id self, SEL _cmd) {
    // Call original to set up the VC, then immediately dismiss
    ((void(*)(id,SEL))orig_activationViewDidLoad)(self, _cmd);
    dispatch_async(dispatch_get_main_queue(), ^{
        ((void(*)(id,SEL,BOOL,id))objc_msgSend)(self,
            NSSelectorFromString(@"dismissViewControllerAnimated:completion:"), NO, nil);
    });
    NSLog(@"[Tweak] Suppressed activation nag");
}

#pragma mark - SSV Hooks

static BOOL pathMatchesProtectedRoot(NSString *path, NSString *root) {
    if ([path isEqualToString:root]) return YES;
    return ([path hasPrefix:root] && [path characterAtIndex:root.length] == '/');
}

static BOOL ssvProtectedPath(NSString *path) {
    if (!path || path.length == 0) return NO;
    return pathMatchesProtectedRoot(path, @"/System") ||
           pathMatchesProtectedRoot(path, @"/Applications") ||
           pathMatchesProtectedRoot(path, @"/usr") ||
           pathMatchesProtectedRoot(path, @"/sbin") ||
           pathMatchesProtectedRoot(path, @"/bin") ||
           pathMatchesProtectedRoot(path, @"/Library") ||
           pathMatchesProtectedRoot(path, @"/dev") ||
           pathMatchesProtectedRoot(path, @"/var") ||
           pathMatchesProtectedRoot(path, @"/private/var");
}

static BOOL sealedSystemPath(NSString *path) {
    if (!path || path.length == 0) return NO;
    return pathMatchesProtectedRoot(path, @"/System") ||
           pathMatchesProtectedRoot(path, @"/bin") ||
           pathMatchesProtectedRoot(path, @"/sbin") ||
           pathMatchesProtectedRoot(path, @"/usr") ||
           pathMatchesProtectedRoot(path, @"/dev");
}

static uint64_t now_ms(void) {
    return (uint64_t)([[NSDate date] timeIntervalSince1970] * 1000.0);
}

static void ensureSSVActive(void) {
    if (ssv_is_active()) return;
    if (!exploit_is_done()) {
        TweakLog("[SSV] Exploit not done yet, cannot activate SSV");
        return;
    }

    pthread_mutex_lock(ssv_mutex());
    if (ssv_is_active()) { pthread_mutex_unlock(ssv_mutex()); return; }

    if (exploit_is_patching()) {
        TweakLog("[SSV] Patch already in progress, skipping recursive call");
        pthread_mutex_unlock(ssv_mutex());
        return;
    }
    if (ssv_activation_inflight()) {
        TweakLog("[SSV] Activation attempt already inflight, skipping");
        pthread_mutex_unlock(ssv_mutex());
        return;
    }
    uint64_t now = now_ms();
    if (ssv_last_activation_ms() != 0 && (now - ssv_last_activation_ms()) < 1500) {
        TweakLog("[SSV] Activation throttled (%llums since last attempt)", now - ssv_last_activation_ms());
        pthread_mutex_unlock(ssv_mutex());
        return;
    }
    ssv_set_activation_inflight(true);
    ssv_set_last_activation_ms(now);
    pthread_mutex_unlock(ssv_mutex());

    int maxAttempts = 3;
    for (int attempt = 0; attempt < maxAttempts && !ssv_is_active(); attempt++) {
        if (attempt > 0) {
            TweakLog("[SSV] Retry attempt %d/%d", attempt + 1, maxAttempts);
            usleep(300000);
        }
        int pret = patch_sandbox_ext();
        TweakLog("[SSV] ensureSSVActive patch_sandbox_ext attempt %d returned %d", attempt + 1, pret);
        if (pret == 0) {
            ssv_set_active(true);
            TweakLog("[SSV] ensureSSVActive set active=1");
            break;
        }
    }

    pthread_mutex_lock(ssv_mutex());
    ssv_set_activation_inflight(false);
    pthread_mutex_unlock(ssv_mutex());
}

static NSString *uiDebugBypassOnFlagPath(void) {
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    return [docs stringByAppendingPathComponent:@"ui_debug_bypass_on.flag"];
}

static NSString *uiDebugBypassOffFlagPath(void) {
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    return [docs stringByAppendingPathComponent:@"ui_debug_bypass_off.flag"];
}

static void refreshUIDebugBypassFlag(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *onPath = uiDebugBypassOnFlagPath();
    NSString *offPath = uiDebugBypassOffFlagPath();
    BOOL hasOn = [fm fileExistsAtPath:onPath];
    BOOL hasOff = [fm fileExistsAtPath:offPath];

    if (hasOff) {
        ui_debug_bypass_set(false);
    } else if (hasOn) {
        ui_debug_bypass_set(true);
    } else {
        ui_debug_bypass_set(false);
    }
    TweakLog("[SSV][UI] bypass=%d (onFlag=%s offFlag=%s)",
             ui_debug_bypass_get(),
             [onPath UTF8String],
             [offPath UTF8String]);
}

static BOOL pathIsInsideAppContainer(NSString *path) {
    if (!path || path.length == 0) return NO;
    NSString *home = NSHomeDirectory();
    if (!home || home.length == 0) return NO;
    if ([path isEqualToString:home]) return YES;
    return ([path hasPrefix:home] && [path characterAtIndex:home.length] == '/');
}

static void applyParentOwnershipAndPerms(NSString *path) {
    if (!path || path.length == 0) return;
    NSString *parent = [path stringByDeletingLastPathComponent];
    if (!parent || parent.length == 0) return;

    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *parentErr = nil;
    NSDictionary *parentAttrs = [fm attributesOfItemAtPath:parent error:&parentErr];
    if (!parentAttrs) {
        TweakLog("[SSV] inherit attrs skip (parent attrs unavailable) path=%s parent=%s err=%s",
                 [path UTF8String],
                 [parent UTF8String],
                 parentErr ? [parentErr.localizedDescription UTF8String] : "(null)");
        return;
    }

    NSNumber *uid = parentAttrs[NSFileOwnerAccountID];
    NSNumber *gid = parentAttrs[NSFileGroupOwnerAccountID];
    NSNumber *perms = parentAttrs[NSFilePosixPermissions];

    NSMutableDictionary *setAttrs = [NSMutableDictionary dictionary];
    if (uid) setAttrs[NSFileOwnerAccountID] = uid;
    if (gid) setAttrs[NSFileGroupOwnerAccountID] = gid;
    if (perms) setAttrs[NSFilePosixPermissions] = perms;
    if (setAttrs.count == 0) return;

    NSError *setErr = nil;
    BOOL ok = [fm setAttributes:setAttrs ofItemAtPath:path error:&setErr];
    TweakLog("[SSV] inherit attrs path=%s parent=%s uid=%ld gid=%ld perms=%lo result=%d err=%s",
             [path UTF8String],
             [parent UTF8String],
             (long)(uid ? uid.integerValue : -1),
             (long)(gid ? gid.integerValue : -1),
             (unsigned long)(perms ? perms.unsignedLongValue : 0),
             ok,
             setErr ? [setErr.localizedDescription UTF8String] : "(null)");

    if (!ok && uid && uid.integerValue == 0 && ssvProtectedPath(path) && !pathIsInsideAppContainer(path)) {
        TweakLog("[SSV] inherit attrs fallback ssv_chown_root for protected root-owned path: %s", [path UTF8String]);
        ssv_chown_root([path UTF8String]);
    }
}

static IMP orig_isWritableFileAtPath = NULL;
static IMP orig_isReadableFileAtPath = NULL;
static IMP orig_attributesOfItemAtPath_error = NULL;
static IMP orig_createDirectoryAtPath = NULL;
static IMP orig_copyItemAtPath_toPath_error = NULL;
static IMP orig_moveItemAtPath_toPath_error = NULL;

static BOOL hook_isWritableFileAtPath(id self, SEL _cmd, NSString *path) {
    if (ui_debug_bypass_get()) {
        TweakLog("[SSV][UI] isWritableFileAtPath forced yes: %s", [path UTF8String]);
        return YES;
    }
    if (ssvProtectedPath(path)) {
        TweakLog("[SSV] isWritableFileAtPath override yes: %s", [path UTF8String]);
        return YES;
    }
    return ((BOOL(*)(id,SEL,id))orig_isWritableFileAtPath)(self, _cmd, path);
}

static BOOL hook_isReadableFileAtPath(id self, SEL _cmd, NSString *path) {
    if (ui_debug_bypass_get()) {
        TweakLog("[SSV][UI] isReadableFileAtPath forced yes: %s", [path UTF8String]);
        return YES;
    }
    if (ssvProtectedPath(path)) {
        TweakLog("[SSV] isReadableFileAtPath override yes: %s", [path UTF8String]);
        return YES;
    }
    return ((BOOL(*)(id,SEL,id))orig_isReadableFileAtPath)(self, _cmd, path);
}

static NSDictionary *hook_attributesOfItemAtPath_error(id self, SEL _cmd, NSString *path, NSError **error) {
    NSDictionary *result = ((NSDictionary *(*)(id,SEL,id,NSError**))orig_attributesOfItemAtPath_error)(self, _cmd, path, error);
    if (result && (ui_debug_bypass_get() || ssvProtectedPath(path))) {
        NSMutableDictionary *mut = [result mutableCopy];
        mut[NSFilePosixPermissions] = @0777;
        if (!ui_debug_bypass_get()) {
            mut[NSFileOwnerAccountID] = @0;
            mut[NSFileGroupOwnerAccountID] = @0;
        }
        if (mut[NSFileImmutable]) mut[NSFileImmutable] = @NO;
        if (mut[NSFileAppendOnly]) mut[NSFileAppendOnly] = @NO;
        TweakLog("[SSV]%s attributesOfItemAtPath override perms for %s",
                 ui_debug_bypass_get() ? "[UI]" : "",
                 [path UTF8String]);
        return mut;
    }
    return result;
}

static BOOL hook_createDirectoryAtPath(id self, SEL _cmd, NSString *path, BOOL createIntermediates, NSDictionary *attributes, NSError **error) {
    BOOL protected = ssvProtectedPath(path);
    NSError *localError = nil;
    NSError **errRef = error ? error : &localError;

    if (ssvProtectedPath(path)) {
        if (exploit_is_done()) {
            ensureSSVActive();
        }
        TweakLog("[SSV] createDirectoryAtPath override for protected path: %s", [path UTF8String]);
    }

    BOOL result = ((BOOL(*)(id,SEL,id,BOOL,id,NSError**))orig_createDirectoryAtPath)(self, _cmd, path, createIntermediates, attributes, errRef);
    if (result) {
        applyParentOwnershipAndPerms(path);
        if (protected) TweakLog("[SSV] createDirectoryAtPath success: %s", [path UTF8String]);
        return YES;
    }

    int savedErrno = errno;
    NSError *e = (errRef ? *errRef : nil);
    if (protected) {
        TweakLog("[SSV] createDirectoryAtPath failed path=%s errno=%d(%s) nsErr=%ld domain=%s desc=%s",
                 [path UTF8String],
                 savedErrno,
                 strerror(savedErrno),
                 (long)(e ? e.code : 0),
                 e ? [e.domain UTF8String] : "(null)",
                 e ? [e.localizedDescription UTF8String] : "(null)");
    }

    // Some callers use /var while APIs resolve internally under /private/var.
    // If first attempt failed, retry once with canonicalized path.
    if (protected && [path hasPrefix:@"/var/"]) {
        NSString *altPath = [@"/private" stringByAppendingString:path];
        NSError *altError = nil;
        BOOL altResult = ((BOOL(*)(id,SEL,id,BOOL,id,NSError**))orig_createDirectoryAtPath)(self, _cmd, altPath, createIntermediates, attributes, &altError);
        if (altResult) {
            applyParentOwnershipAndPerms(altPath);
            TweakLog("[SSV] createDirectoryAtPath fallback success: %s -> %s", [path UTF8String], [altPath UTF8String]);
            if (errRef) *errRef = nil;
            return YES;
        }
        int altErrno = errno;
        TweakLog("[SSV] createDirectoryAtPath fallback failed alt=%s errno=%d(%s) nsErr=%ld domain=%s desc=%s",
                 [altPath UTF8String],
                 altErrno,
                 strerror(altErrno),
                 (long)(altError ? altError.code : 0),
                 altError ? [altError.domain UTF8String] : "(null)",
                 altError ? [altError.localizedDescription UTF8String] : "(null)");
    }
    if (ui_debug_bypass_get() && protected && !sealedSystemPath(path)) {
        TweakLog("[SSV][UI] createDirectoryAtPath simulated success for %s", [path UTF8String]);
        if (errRef) *errRef = nil;
        return YES;
    }
    if (ui_debug_bypass_get() && protected && sealedSystemPath(path)) {
        TweakLog("[SSV][UI] NOT simulating success for sealed path (keep real error): %s", [path UTF8String]);
    }
    return NO;
}

static BOOL hook_copyItemAtPath_toPath_error(id self, SEL _cmd, NSString *src, NSString *dst, NSError **error) {
    if (ssvProtectedPath(src) || ssvProtectedPath(dst)) {
        if (exploit_is_done()) {
            ensureSSVActive();
        }
        TweakLog("[SSV] copyItemAtPath override for %s -> %s", [src UTF8String], [dst UTF8String]);
    }
    NSError *localError = nil;
    NSError **errRef = error ? error : &localError;
    BOOL result = ((BOOL(*)(id,SEL,id,id,NSError**))orig_copyItemAtPath_toPath_error)(self, _cmd, src, dst, errRef);
    if (!result && (ssvProtectedPath(src) || ssvProtectedPath(dst))) {
        NSError *e = (errRef ? *errRef : nil);
        TweakLog("[SSV] copyItemAtPath failed %s -> %s code=%ld domain=%s desc=%s",
                 [src UTF8String], [dst UTF8String],
                 (long)(e ? e.code : 0),
                 e ? [e.domain UTF8String] : "(null)",
                 e ? [e.localizedDescription UTF8String] : "(null)");
        if (ui_debug_bypass_get() && !sealedSystemPath(src) && !sealedSystemPath(dst)) {
            TweakLog("[SSV][UI] copyItemAtPath simulated success for %s -> %s", [src UTF8String], [dst UTF8String]);
            if (errRef) *errRef = nil;
            return YES;
        }
        if (ui_debug_bypass_get() && (sealedSystemPath(src) || sealedSystemPath(dst))) {
            TweakLog("[SSV][UI] NOT simulating copy success for sealed path: %s -> %s", [src UTF8String], [dst UTF8String]);
        }
    }
    return result;
}

static BOOL hook_moveItemAtPath_toPath_error(id self, SEL _cmd, NSString *src, NSString *dst, NSError **error) {
    if (ssvProtectedPath(src) || ssvProtectedPath(dst)) {
        ensureSSVActive();
        TweakLog("[SSV] moveItemAtPath override for %s -> %s", [src UTF8String], [dst UTF8String]);
    }
    NSError *localError = nil;
    NSError **errRef = error ? error : &localError;
    BOOL result = ((BOOL(*)(id,SEL,id,id,NSError**))orig_moveItemAtPath_toPath_error)(self, _cmd, src, dst, errRef);
    if (!result && (ssvProtectedPath(src) || ssvProtectedPath(dst))) {
        NSError *e = (errRef ? *errRef : nil);
        TweakLog("[SSV] moveItemAtPath failed %s -> %s code=%ld domain=%s desc=%s",
                 [src UTF8String], [dst UTF8String],
                 (long)(e ? e.code : 0),
                 e ? [e.domain UTF8String] : "(null)",
                 e ? [e.localizedDescription UTF8String] : "(null)");
        if (ui_debug_bypass_get() && !sealedSystemPath(src) && !sealedSystemPath(dst)) {
            TweakLog("[SSV][UI] moveItemAtPath simulated success for %s -> %s", [src UTF8String], [dst UTF8String]);
            if (errRef) *errRef = nil;
            return YES;
        }
        if (ui_debug_bypass_get() && (sealedSystemPath(src) || sealedSystemPath(dst))) {
            TweakLog("[SSV][UI] NOT simulating move success for sealed path: %s -> %s", [src UTF8String], [dst UTF8String]);
        }
    }
    return result;
}

static IMP orig_createFileAtPath = NULL;
static BOOL hook_createFileAtPath(id self, SEL _cmd, NSString *path, NSData *contents, NSDictionary *attributes) {
    if (ssvProtectedPath(path)) ensureSSVActive();
    TweakLog("[SSV] createFileAtPath: %s", [path UTF8String]);
    BOOL result = ((BOOL(*)(id,SEL,id,id,id))orig_createFileAtPath)(self, _cmd, path, contents, attributes);
    TweakLog("[SSV] createFileAtPath result=%d", result);
    if (result) {
        applyParentOwnershipAndPerms(path);
    }
    if (!result && ui_debug_bypass_get() && ssvProtectedPath(path) && !sealedSystemPath(path)) {
        TweakLog("[SSV][UI] createFileAtPath simulated success for %s", [path UTF8String]);
        return YES;
    }
    if (!result && ui_debug_bypass_get() && sealedSystemPath(path)) {
        TweakLog("[SSV][UI] NOT simulating createFile success for sealed path: %s", [path UTF8String]);
    }
    return result;
}

static IMP orig_writeToFile = NULL;
static BOOL hook_writeToFile(id self, SEL _cmd, NSString *path, unsigned long long options, NSError **error) {
    if (ssvProtectedPath(path)) ensureSSVActive();
    TweakLog("[SSV] writeToFile: %s", [path UTF8String]);
    NSError *localError = nil;
    NSError **errRef = error ? error : &localError;
    BOOL result = ((BOOL(*)(id,SEL,id,unsigned long long,id*))orig_writeToFile)(self, _cmd, path, options, errRef);
    TweakLog("[SSV] writeToFile result=%d", result);
    if (result) {
        applyParentOwnershipAndPerms(path);
    }
    if (!result && ssvProtectedPath(path)) {
        NSError *e = (errRef ? *errRef : nil);
        TweakLog("[SSV] writeToFile failed path=%s code=%ld domain=%s desc=%s",
                 [path UTF8String],
                 (long)(e ? e.code : 0),
                 e ? [e.domain UTF8String] : "(null)",
                 e ? [e.localizedDescription UTF8String] : "(null)");
        if (ui_debug_bypass_get() && !sealedSystemPath(path)) {
            TweakLog("[SSV][UI] writeToFile simulated success for %s", [path UTF8String]);
            if (errRef) *errRef = nil;
            return YES;
        }
        if (ui_debug_bypass_get() && sealedSystemPath(path)) {
            TweakLog("[SSV][UI] NOT simulating write success for sealed path: %s", [path UTF8String]);
        }
    }
    return result;
}

#pragma mark - Hook Installation

static void installHooks(void) {
    TweakLog("[Hooks] installHooks start");
    Class rfm = NSClassFromString(@"TGRootFileManager");
    if (rfm) {
        TweakLog("[Hooks] hooking TGRootFileManager root helper methods");
        Class meta = object_getClass(rfm);
        class_replaceMethod(meta, NSSelectorFromString(@"isRootHelperAvailable"), (IMP)hook_isRootHelperAvailable, "B@:");
        class_replaceMethod(rfm, NSSelectorFromString(@"spawnRootHelper"), (IMP)hook_spawnRootHelper, "i@:");
        class_replaceMethod(rfm, NSSelectorFromString(@"spawnRootHelperIfNeeds"), (IMP)hook_spawnRootHelperIfNeeds, "i@:");
        class_replaceMethod(rfm, NSSelectorFromString(@"respawnRootHelper"), (IMP)hook_respawnRootHelper, "i@:");
        class_replaceMethod(rfm, NSSelectorFromString(@"tryLoadFilzaHelper"), (IMP)hook_tryLoadFilzaHelper, "v@:");
        class_replaceMethod(rfm, NSSelectorFromString(@"createHelperConnectionIfNeeds"), (IMP)hook_createHelperConnectionIfNeeds, "v@:");
        class_replaceMethod(rfm, NSSelectorFromString(@"spawnRoot:args:pid:"), (IMP)hook_spawnRoot_args_pid, "i@:@@^i");
        class_replaceMethod(rfm, NSSelectorFromString(@"sendObjectWithReplySync:"), (IMP)hook_sendObjectWithReplySync, "@@:@");
        class_replaceMethod(rfm, NSSelectorFromString(@"sendObjectWithReplySync:fileDescriptor:"), (IMP)hook_sendObjectWithReplySync_fd, "@@:@^i");
        class_replaceMethod(rfm, NSSelectorFromString(@"sendObjectWithReplySync:fileDescriptor:logintty:"), (IMP)hook_sendObjectWithReplySync_fd_logintty, "@@:@^iB");
        class_replaceMethod(rfm, NSSelectorFromString(@"sendObjectNoReply:"), (IMP)hook_sendObjectNoReply, "v@:@");
        class_replaceMethod(rfm, NSSelectorFromString(@"sendObjectWithReplyAsync:queue:completion:"), (IMP)hook_sendObjectWithReplyAsync, "v@:@@?");
        TweakLog("[Hooks] TGRootFileManager hooks installed");
    }
    Class zipper = NSClassFromString(@"Zipper");
    if (zipper) {
        TweakLog("[Hooks] hooking Zipper zip/unzip methods");
        Method m;
        m = class_getInstanceMethod(zipper, NSSelectorFromString(@"ZipFiles:toFilePath:currentDirectory:"));
        if (m) { orig_ZipFiles = method_getImplementation(m); method_setImplementation(m, (IMP)hook_ZipFiles); }
        m = class_getInstanceMethod(zipper, NSSelectorFromString(@"unZipFile:toPath:currentDirectory:outMessage:"));
        if (m) { orig_unZipFile = method_getImplementation(m); method_setImplementation(m, (IMP)hook_unZipFile); }
        m = class_getInstanceMethod(zipper, NSSelectorFromString(@"unZipFile:toPath:currentDirectory:withPassword:outMessage:"));
        if (m) { orig_unZipFilePassword = method_getImplementation(m); method_setImplementation(m, (IMP)hook_unZipFilePassword); }
        TweakLog("[Hooks] Zipper hooks installed");
    }

    // License/integrity bypass
    Class alertCtrl = NSClassFromString(@"TGAlertController");
    if (alertCtrl) {
        TweakLog("[Hooks] hooking TGAlertController showAlertWithTitle:text:cancelButton:otherButtons:completion:");
        Class alertMeta = object_getClass(alertCtrl);
        Method m = class_getClassMethod(alertCtrl, NSSelectorFromString(@"showAlertWithTitle:text:cancelButton:otherButtons:completion:"));
        if (m) {
            orig_showAlert = method_getImplementation(m);
            class_replaceMethod(alertMeta, NSSelectorFromString(@"showAlertWithTitle:text:cancelButton:otherButtons:completion:"),
                (IMP)hook_showAlertWithTitle, "@@:@@@@@");
            TweakLog("[Hooks] TGAlertController hook installed");
        }
    }
    Class activationVC = NSClassFromString(@"NewActivationViewController");
    if (activationVC) {
        TweakLog("[Hooks] hooking NewActivationViewController viewDidLoad");
        Method m = class_getInstanceMethod(activationVC, @selector(viewDidLoad));
        if (m) {
            orig_activationViewDidLoad = method_getImplementation(m);
            method_setImplementation(m, (IMP)hook_activationViewDidLoad);
            TweakLog("[Hooks] NewActivationViewController hook installed");
        }
    }

    // Apps Manager fixes
    Class lsWorkspace = NSClassFromString(@"LSApplicationWorkspace");
    if (lsWorkspace) {
        TweakLog("[Hooks] hooking LSApplicationWorkspace allApplications");
        Method m = class_getInstanceMethod(lsWorkspace, NSSelectorFromString(@"allApplications"));
        if (m) { orig_allApplications = method_getImplementation(m); method_setImplementation(m, (IMP)hook_allApplications); TweakLog("[Hooks] LSApplicationWorkspace hook installed"); }
    }
    Class appItem = NSClassFromString(@"ApplicationItem");
    if (appItem) {
        TweakLog("[Hooks] hooking ApplicationItem setAppProxy:");
        Method m;
        m = class_getInstanceMethod(appItem, NSSelectorFromString(@"setAppProxy:"));
        if (m) { orig_setAppProxy = method_getImplementation(m); method_setImplementation(m, (IMP)hook_setAppProxy); TweakLog("[Hooks] ApplicationItem hook installed"); }
    }
    Class appsVC = NSClassFromString(@"TGApplicationsViewController");
    if (appsVC) {
        TweakLog("[Hooks] hooking TGApplicationsViewController browserView:didSelectItemAtIndexPath:");
        Method m = class_getInstanceMethod(appsVC, NSSelectorFromString(@"browserView:didSelectItemAtIndexPath:"));
        if (m) { orig_didSelectItem = method_getImplementation(m); method_setImplementation(m, (IMP)hook_didSelectItem); TweakLog("[Hooks] TGApplicationsViewController hook installed"); }
    }

    // SSV write and chown hooks
    Class fm = [NSFileManager class];
    if (fm) {
        TweakLog("[Hooks] hooking NSFileManager methods for SSV bypass");
        Method m = class_getInstanceMethod(fm, @selector(createFileAtPath:contents:attributes:));
        if (m) { orig_createFileAtPath = method_getImplementation(m); method_setImplementation(m, (IMP)hook_createFileAtPath); }
        m = class_getInstanceMethod(fm, @selector(writeToFile:options:error:));
        if (m) { orig_writeToFile = method_getImplementation(m); method_setImplementation(m, (IMP)hook_writeToFile); }
        m = class_getInstanceMethod(fm, @selector(isWritableFileAtPath:));
        if (m) { orig_isWritableFileAtPath = method_getImplementation(m); method_setImplementation(m, (IMP)hook_isWritableFileAtPath); }
        m = class_getInstanceMethod(fm, @selector(isReadableFileAtPath:));
        if (m) { orig_isReadableFileAtPath = method_getImplementation(m); method_setImplementation(m, (IMP)hook_isReadableFileAtPath); }
        m = class_getInstanceMethod(fm, @selector(attributesOfItemAtPath:error:));
        if (m) { orig_attributesOfItemAtPath_error = method_getImplementation(m); method_setImplementation(m, (IMP)hook_attributesOfItemAtPath_error); }
        m = class_getInstanceMethod(fm, @selector(createDirectoryAtPath:withIntermediateDirectories:attributes:error:));
        if (m) { orig_createDirectoryAtPath = method_getImplementation(m); method_setImplementation(m, (IMP)hook_createDirectoryAtPath); }
        m = class_getInstanceMethod(fm, @selector(copyItemAtPath:toPath:error:));
        if (m) { orig_copyItemAtPath_toPath_error = method_getImplementation(m); method_setImplementation(m, (IMP)hook_copyItemAtPath_toPath_error); }
        m = class_getInstanceMethod(fm, @selector(moveItemAtPath:toPath:error:));
        if (m) { orig_moveItemAtPath_toPath_error = method_getImplementation(m); method_setImplementation(m, (IMP)hook_moveItemAtPath_toPath_error); }
        TweakLog("[Hooks] NSFileManager SSV hooks installed");
    }

    TweakLog("[Tweak] All hooks installed");
}

#pragma mark - Entry Point

__attribute__((constructor)) void TweakInit(void) {
    // Safe mode: if flag file exists, skip all kernel operations entirely
    if (access("/var/mobile/Documents/.filza_safe_mode", F_OK) == 0) {
        TweakLog("[Tweak] SAFE MODE — skipping exploit, sandbox escape, and kernel writes");
        TweakLog("[Tweak] Only UI hooks active. Delete /var/mobile/Documents/.filza_safe_mode to enable exploit.");
        installHooks();
        return;
    }

    // Crash recovery: if we've crashed 3+ times without success, auto-disable
    const char *successFlag = "/var/mobile/Documents/.filza_last_success";
    const char *crashCountFile = "/var/mobile/Documents/.filza_crash_count";
    if (access(successFlag, F_OK) != 0 && !tweak_is_disabled()) {
        int crashCount = 0;
        FILE *cf = fopen(crashCountFile, "r");
        if (cf) { fscanf(cf, "%d", &crashCount); fclose(cf); }
        crashCount++;
        cf = fopen(crashCountFile, "w");
        if (cf) { fprintf(cf, "%d", crashCount); fclose(cf); }
        TweakLog("[Tweak] Crash counter: %d/3 (no success flag found)", crashCount);
        if (crashCount >= 3) {
            FILE *df = fopen(TWEAK_DISABLE_FLAG, "w");
            if (df) fclose(df);
            TweakLog("[Tweak] 3 crashes detected — exploit DISABLED for safety. Delete %s to re-enable.", TWEAK_DISABLE_FLAG);
            return;
        }
    }

    if (tweak_is_disabled()) {
        TweakLog("[Tweak] Disabled by flag file — unloading");
        return;
    }
    TweakLog("\n=== TWEAK LOADED ===");
    TweakLog("[Tweak] TweakInit started");
    refreshUIDebugBypassFlag();
    installHooks();

    // Check if sandbox is already escaped
    int fd = open("/var/mobile/.sbx_check", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        close(fd); unlink("/var/mobile/.sbx_check");
        TweakLog("[Tweak] Sandbox already escaped");
        if (check_sandbox_var_rw() == 0) {
            TweakLog("[Tweak] sandbox already escaped + rw confirmed, running diagnostics");
            runSSVDiagnosticsOnce();
        } else {
            TweakLog("[Tweak] sandbox already escaped but rw not confirmed, skip diagnostics");
        }
        return;
    }

    TweakLog("[Tweak] Sandbox not yet escaped, checking UIApplication state");
    
    dispatch_async(dispatch_get_main_queue(), ^{
        UIApplication *app = [UIApplication sharedApplication];
        if (app.applicationState == UIApplicationStateActive) {
            TweakLog("[Tweak] UIApplication already active, scheduling exploit immediately");
            scheduleExploitOnce();
        }

        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
            object:nil queue:nil usingBlock:^(NSNotification *note) {
            TweakLog("[Tweak] UIApplicationDidFinishLaunchingNotification received");
            scheduleExploitOnce();
        }];

        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
            object:nil queue:nil usingBlock:^(NSNotification *note) {
            TweakLog("[Tweak] UIApplicationDidBecomeActiveNotification received");
            scheduleExploitOnce();
        }];
    });
    
    TweakLog("[Tweak] TweakInit completed");
}
