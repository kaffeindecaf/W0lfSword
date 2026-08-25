/*
 * imgio_probe — headless on-device ImageIO decode harness (research only).
 *
 * Decodes every file given on argv through the same ImageIO paths a
 * QuickLook/Filza preview would hit:
 *   - CGImageSourceCreateWithURL          (container sniff / header parse)
 *   - CGImageSourceCopyPropertiesAtIndex (metadata / IFD / EXIF parse)
 *   - CGImageSourceCreateImageAtIndex    (full pixel decode)
 *
 * A bug in any of those paths crashes THIS process, not SpringBoard or
 * Filza — so the phone never resprings and attribution is unambiguous
 * (CrashReporter names imgio_probe). Runs headless over SSH as root.
 *
 * Exit codes: 0 = all files decoded, 1 = usage, 2 = file-level failure
 * (unreadable / unsupported / decode returned NULL — NOT a crash).
 * A crash exits with the signal (139 = SIGSEGV etc.) and writes an .ips.
 *
 * Usage: imgio_probe <file> [file...]
 */

#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>

static int failures = 0;

static void probe_file(const char *path_c) {
    NSString *path = [NSString stringWithUTF8String:path_c];
    NSURL *url = [NSURL fileURLWithPath:path];
    BOOL exists = [[NSFileManager defaultManager] fileExistsAtPath:path];
    if (!exists) {
        printf("[SKIP] %s (missing)\n", path_c);
        failures++;
        return;
    }

    /* header / container parse */
    CGImageSourceRef src = CGImageSourceCreateWithURL((__bridge CFURLRef)url, NULL);
    if (!src) {
        printf("[NODEC] %s (no image source)\n", path_c);
        failures++;
        return;
    }

    size_t count = CGImageSourceGetCount(src);

    /* container-level metadata parse (whole-file IFD / EXIF walk) */
    CFDictionaryRef cprops = CGImageSourceCopyProperties(src, NULL);
    if (cprops) CFRelease(cprops);

    /* per-frame metadata parse (IFD / EXIF / container walk) */
    CFDictionaryRef props = CGImageSourceCopyPropertiesAtIndex(src, 0, NULL);
    if (props) CFRelease(props);

    /* full pixel decode */
    CGImageRef img = CGImageSourceCreateImageAtIndex(src, 0, NULL);
    if (!img) {
        printf("[NOPIX] %s (decode returned NULL, %zu frames)\n", path_c, count);
        failures++;
        CFRelease(src);
        return;
    }

    size_t w = CGImageGetWidth(img);
    size_t h = CGImageGetHeight(img);
    printf("[OK]   %s (%zux%zu, %zu frames)\n", path_c, w, h, count);
    CGImageRelease(img);

    /* thumbnail decode — the QuickLook preview path (different code path) */
    CFDictionaryRef thumb_opts = (__bridge CFDictionaryRef)@{
        (__bridge NSString *)kCGImageSourceCreateThumbnailFromImageIfAbsent: @YES,
        (__bridge NSString *)kCGImageSourceThumbnailMaxPixelSize: @512,
    };
    CGImageRef thumb = CGImageSourceCreateThumbnailAtIndex(src, 0, thumb_opts);
    if (thumb) {
        printf("[THUMB] %s (%zux%zu)\n", path_c, CGImageGetWidth(thumb), CGImageGetHeight(thumb));
        CGImageRelease(thumb);
    } else {
        printf("[NOTH]  %s (thumbnail NULL)\n", path_c);
    }

    /* orientation-transform thumbnail — the Photos preview path: applies
     * EXIF orientation (rotate/flip) + float decode during thumbnail gen */
    CFDictionaryRef xform_opts = (__bridge CFDictionaryRef)@{
        (__bridge NSString *)kCGImageSourceCreateThumbnailFromImageIfAbsent: @YES,
        (__bridge NSString *)kCGImageSourceCreateThumbnailWithTransform: @YES,
        (__bridge NSString *)kCGImageSourceShouldAllowFloat: @YES,
        (__bridge NSString *)kCGImageSourceThumbnailMaxPixelSize: @1024,
    };
    CGImageRef xthumb = CGImageSourceCreateThumbnailAtIndex(src, 0, xform_opts);
    if (xthumb) {
        printf("[XTHUMB] %s (%zux%zu)\n", path_c, CGImageGetWidth(xthumb), CGImageGetHeight(xthumb));
        CGImageRelease(xthumb);
    } else {
        printf("[NOX]   %s (transform thumbnail NULL)\n", path_c);
    }

    CFRelease(src);
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc < 2) {
            fprintf(stderr, "usage: imgio_probe <file> [file...]\n");
            return 1;
        }
        printf("=== imgio_probe: ImageIO decode harness ===\n");
        fflush(stdout);
        for (int i = 1; i < argc; i++) {
            /* print BEFORE decoding so a crash's last line names the sample */
            printf("[*] %s\n", argv[i]);
            fflush(stdout);
            probe_file(argv[i]);
            usleep(20000); /* 20ms between files */
        }
        printf("=== done: %d failure(s) ===\n", failures);
        return failures ? 2 : 0;
    }
}
