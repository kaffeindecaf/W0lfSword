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

#ifdef __cplusplus
extern "C" {
#endif

#define TWEAK_LOG_PATH "/tmp/FilzaTweak.log"
#define TWEAK_LOG_MAX_SIZE (4 * 1024 * 1024)  // 4MB rotation

static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static void TweakLog(const char *format, ...) {
    if (pthread_mutex_trylock(&g_log_mutex) != 0) {
        va_list args;
        va_start(args, format);
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        struct tm *t = localtime(&ts.tv_sec);
        fprintf(stderr, "[%02d:%02d:%02d] ", t->tm_hour, t->tm_min, t->tm_sec);
        vfprintf(stderr, format, args);
        fprintf(stderr, "\n");
        fflush(stderr);
        va_end(args);
        return;
    }

    struct stat st;
    if (stat(TWEAK_LOG_PATH, &st) == 0 && st.st_size > TWEAK_LOG_MAX_SIZE) {
        char oldPath[PATH_MAX];
        snprintf(oldPath, sizeof(oldPath), "%s.old", TWEAK_LOG_PATH);
        unlink(oldPath);
        rename(TWEAK_LOG_PATH, oldPath);
    }

    FILE *f = fopen(TWEAK_LOG_PATH, "a");
    if (!f) { pthread_mutex_unlock(&g_log_mutex); return; }

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);
    fprintf(f, "[%s] ", ts);

    va_list args;
    va_start(args, format);
    vfprintf(f, format, args);
    va_end(args);
    fprintf(f, "\n");
    fclose(f);

    pthread_mutex_unlock(&g_log_mutex);
}

#ifdef __OBJC__
#import <Foundation/Foundation.h>
static void TweakNSLog(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    TweakLog("%s", [msg UTF8String]);
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* tweak_log_h */
