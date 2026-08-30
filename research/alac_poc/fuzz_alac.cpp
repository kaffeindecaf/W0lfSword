// libFuzzer target for ALACDecoder (C4.4 host-side).
//
// Input layout: [magic cookie][ALAC bitstream]. The first COOKIE_BYTES
// bytes feed Init(), the rest feed Decode() as one packet. Seeds produced
// by gen_seeds.cpp (encoder-generated cookie + frames) decode cleanly, so
// libFuzzer starts from valid streams and mutates toward the partialFrame
// / numSamples fields (BB-038) and the cookie size check (BB-039).
//
// Build (clang, ASAN + libFuzzer):
//   clang++ -fsanitize=fuzzer,address,undefined -g -I codec \
//     fuzz_alac.cpp codec/ALACDecoder.cpp codec/ag_dec.c codec/dp_dec.c \
//     codec/matrix_dec.c codec/ALACBitUtilities.c codec/EndianPortable.c \
//     -o fuzz_alac
// Run: ./fuzz_alac -max_total_time=120 corpus/
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include "ALACDecoder.h"
#include "ALACBitUtilities.h"

#define COOKIE_BYTES 24

// caller output buffer: 2 MB. The internal mMixBufferU/V (sized by
// frameLength from the cookie) is the BB-038 overflow target; this buffer
// just has to be big enough that the well-formed tail writes don't trip
// ASAN before the interesting internal write does.
#define SAMPLE_BYTES (2 * 1024 * 1024)

static uint8_t g_samples[SAMPLE_BYTES];

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0;

    ALACDecoder dec;
    size_t cookieLen = size < COOKIE_BYTES ? size : COOKIE_BYTES;
    if (dec.Init((void *)data, (uint32_t)cookieLen) != 0)
        return 0;

    size_t streamLen = size - cookieLen;
    if (streamLen == 0)
        return 0;

    BitBuffer bb;
    BitBufferInit(&bb, (uint8_t *)data + cookieLen, (uint32_t)streamLen);

    uint32_t outNum = 0;
    // clamp the caller-requested numSamples to something sane; the decoder
    // can still override it via the partialFrame path (that's the bug)
    uint32_t want = dec.mConfig.frameLength;
    if (want == 0 || want > 4096)
        want = 4096;

    dec.Decode(&bb, g_samples, want, dec.mConfig.numChannels, &outNum);
    return 0;
}

// ---- structure-aware mutator ------------------------------------------
//
// libFuzzer's byte-level mutations waste most of their effort on the cookie
// (24 fixed-ish bytes) and the bitstream tail. This mutator keeps a valid
// cookie in place most of the time, and spends its edits on the fields the
// decoder actually trusts: the 4-bit header of the first element (where
// partialFrame + escapeFlag live) and the following 16/32-bit numSamples.
// Falls back to stock byte mutation otherwise.

// stock libFuzzer mutation helpers (data race-free on single-threaded runs)
static size_t Rand(size_t n)
{
    return rand() % n; // NOLINT: libFuzzer forks, rand is fine
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                                          size_t max_size, unsigned int seed)
{
    srand(seed);
    (void)max_size;

    // grow input to at least COOKIE_BYTES + 8 so the interesting fields exist
    size_t target = COOKIE_BYTES + 8;
    if (size < target)
    {
        if (target > max_size)
            target = max_size;
        if (size < COOKIE_BYTES)
        {
            // pad with a valid-ish cookie: frameLength 4096, 16-bit mono
            static const uint8_t baseCookie[COOKIE_BYTES] = {
                0x00, 0x00, 0x10, 0x00, // frameLength 4096
                0x00,                   // compatibleVersion 0
                16,                     // bitDepth
                40,                     // pb
                10,                     // mb
                14,                     // kb
                1,                      // numChannels
                0xff, 0xff,             // maxRun
                0x00, 0x00, 0x00, 0x20, // maxFrameBytes
                0x00, 0x00, 0x00, 0x00, // avgBitRate
                0x00, 0x00, 0xac, 0x44  // sampleRate 44100
            };
            size_t fill = target - size;
            for (size_t i = 0; i < fill; i++)
            {
                size_t dst = size + i;
                data[dst] = (dst < COOKIE_BYTES) ? baseCookie[dst] : 0;
            }
            size = target;
        }
        else
        {
            for (size_t i = size; i < target; i++)
                data[i] = 0;
            size = target;
        }
    }

    unsigned int r = Rand(100);

    // 70%: keep the cookie valid, mutate the element header + numSamples
    if (r < 70 && size >= COOKIE_BYTES + 4)
    {
        // cookie: occasionally shrink frameLength to a tiny value - the
        // precondition for the BB-038 overflow (internal buffers sized by
        // frameLength, numSamples attacker-controlled)
        if (Rand(100) < 25)
        {
            data[0] = 0; data[1] = 0; data[2] = 0;
            data[3] = (Rand(100) < 50) ? 1 : (uint8_t)(Rand(64) + 1); // 1..64
        }
        // element header byte (bit 3 = partialFrame, bit 0 = escapeFlag)
        size_t hdr = COOKIE_BYTES;
        if (Rand(100) < 60)
            data[hdr] = (uint8_t)(0b1001 & Rand(16)); // favor partialFrame+escape
        else
            data[hdr] ^= (uint8_t)(1u << Rand(8));
        // numSamples field: bytes 1..4 after the header
        for (int i = 0; i < 4; i++)
        {
            if (Rand(100) < 40)
                data[hdr + 1 + i] ^= (uint8_t)(1u << Rand(8));
        }
        return size;
    }

    // 30%: stock byte flips / inserts / deletes
    if (r < 90)
    {
        size_t pos = Rand(size);
        if (Rand(100) < 60)
            data[pos] ^= (uint8_t)(1u << Rand(8));
        else if (size > 1)
            data[pos] = (uint8_t)Rand(256);
        return size;
    }

    // 10%: copy a chunk (mini-crossover)
    if (size + 8 <= max_size && size > 2)
    {
        size_t src = Rand(size - 1);
        size_t n = Rand(size - src);
        if (size + n > max_size)
            n = max_size - size;
        memmove(data + size, data + src, n);
        size += n;
    }
    return size;
}
