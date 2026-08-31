#ifndef tweak_log_h
#define tweak_log_h

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include <pthread.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TWEAK_LOG_PATH "/tmp/FilzaTweak.log"
#define TWEAK_LOG_MAX_SIZE (4 * 1024 * 1024)

extern pthread_mutex_t g_log_mutex;

// TweakLog writes every line to up to four sinks so the tweak is debuggable
// on BOTH a jailbroken phone (read /tmp/FilzaTweak.log over SSH) and a clean
// non-jailbroken sideload (no SSH, no /var access):
//   1. /tmp/FilzaTweak.log       — the jailbroken-device path (real /tmp)
//   2. <app sandbox>/Documents/FilzaTweak.log
//                                — readable over USB with
//                                  afcclient --documents <bundle> (house_arrest,
//                                  needs UIFileSharingEnabled in Info.plist)
//   3. os_log (subsystem com.kaffeindecaf.w0lfsword)
//                                — stream live with: idevicesyslog | grep -i wolfsword
//   4. stderr                    — always (fallback when the mutex is busy)
static void TweakLog(const char *format, ...) {
    if (!format) return;

    char buf[2048];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    fprintf(stderr, "[tweak] %s\n", buf);
    fflush(stderr);

    if (pthread_mutex_trylock(&g_log_mutex) != 0) {
        return; // another thread is mid-write; stderr already got the line
    }

    struct stat st;
    if (stat(TWEAK_LOG_PATH, &st) == 0 && st.st_size > TWEAK_LOG_MAX_SIZE) {
        char oldPath[PATH_MAX];
        snprintf(oldPath, sizeof(oldPath), "%s.old", TWEAK_LOG_PATH);
        unlink(oldPath);
        rename(TWEAK_LOG_PATH, oldPath);
    }

    FILE *f = fopen(TWEAK_LOG_PATH, "a");
    if (f) {
        struct tm t;
        time_t now = time(NULL);
        localtime_r(&now, &t);
        char ts[32];
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &t);
        fprintf(f, "[%s] %s\n", ts, buf);
        fclose(f);
    }

#ifdef __OBJC__
    // App-sandbox Documents copy — the non-jailbroken read-back path.
    static NSString *docLogPath = nil;
    if (!docLogPath) {
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        if (paths.count > 0) {
            docLogPath = [[paths objectAtIndex:0] stringByAppendingPathComponent:@"FilzaTweak.log"];
        }
    }
    if (docLogPath) {
        FILE *df = fopen([docLogPath UTF8String], "a");
        if (df) {
            struct tm t;
            time_t now = time(NULL);
            localtime_r(&now, &t);
            char ts[32];
            strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &t);
            fprintf(df, "[%s] %s\n", ts, buf);
            fclose(df);
        }
    }
    // Unified log — live streaming over USB: idevicesyslog | grep -i wolfsword
    static os_log_t slog = NULL;
    if (!slog) slog = os_log_create("com.kaffeindecaf.w0lfsword", "tweak");
    os_log_with_type(slog, OS_LOG_TYPE_DEFAULT, "%{public}s", buf);
#endif

    pthread_mutex_unlock(&g_log_mutex);
}

#ifdef __OBJC__
#import <Foundation/Foundation.h>
#import <os/log.h>
static void TweakNSLog(NSString *format, ...) {
    if (!format) return;
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    TweakLog("%s", [msg UTF8String] ?: "(nil)");
}
// A2.8: nil-safe NSString → C-string for TweakLog %s args (nil UTF8String
// would SIGSEGV). Use tstr(x) instead of [x UTF8String] in log calls.
static const char *tstr(NSString *s) {
    return s ? [s UTF8String] : "(nil)";
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* tweak_log_h */
