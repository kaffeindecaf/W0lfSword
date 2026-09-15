#ifndef W0LFSWORD_ERRORS_H
#define W0LFSWORD_ERRORS_H

// D1.4: named error codes for the tweak's public API.
// 0 = success. Callers check `== 0` / `!= 0`, so any non-zero code is an
// error and the code values are safe to log and compare. Plain C enum so it
// works from .m and .c translation units alike.
enum {
    TWEAK_OK = 0,
    TWEAK_ERR_GENERIC = 1,
    TWEAK_ERR_EXPLOIT_FAILED = 2,
    TWEAK_ERR_SANDBOX_ESCAPE_FAILED = 3,
    TWEAK_ERR_SSV_ACTIVATION_FAILED = 4,
    TWEAK_ERR_KERNEL_PTR_INVALID = 5,
    TWEAK_ERR_INVALID_ARG = 6,
};

#endif /* W0LFSWORD_ERRORS_H */
