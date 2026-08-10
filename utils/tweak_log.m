#include "tweak_log.h"
#include <pthread.h>

// Mutex shared across all translation units (not per-TU static in header).
pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
