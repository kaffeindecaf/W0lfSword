// Seed generator for the ALAC libFuzzer target (C4.4).
//
// Encodes PCM sine frames with ALACEncoder and writes [cookie][bitstream]
// files - exactly the input layout the fuzz target consumes, so every seed
// decodes cleanly and libFuzzer starts from valid streams.
//
// Build: g++ -I codec gen_seeds.cpp codec/ALACEncoder.cpp codec/ag_enc.c \
//        codec/dp_enc.c codec/matrix_enc.c codec/ALACBitUtilities.c \
//        codec/EndianPortable.c -o gen_seeds
// Run:   ./gen_seeds <outdir> <channels> <bitdepth> <samplerate> <frames>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <stdint.h>
#include "ALACEncoder.h"
#include "ALACAudioTypes.h"

static void fill_pcm(uint8_t *buf, size_t bytes, int channels, int bitDepth, int sr, int frame)
{
    // sine + a little noise so the predictor has something to chew on
    for (size_t i = 0; i < bytes; ) {
        int ch = (int)((i / (size_t)(bitDepth / 8)) % (size_t)channels);
        size_t sample = i / (size_t)(bitDepth / 8) / (size_t)channels;
        double t = (double)(frame * 4096 + (int)sample) / (double)sr;
        double v = 0.6 * sin(2.0 * M_PI * 440.0 * t) + 0.2 * sin(2.0 * M_PI * 997.0 * t);
        if (bitDepth == 16) {
            int16_t s = (int16_t)(v * 12000.0);
            memcpy(buf + i, &s, 2); i += 2;
        } else if (bitDepth == 24) {
            int32_t s = (int32_t)(v * 6000000.0);
            buf[i] = s & 0xff; buf[i+1] = (s >> 8) & 0xff; buf[i+2] = (s >> 16) & 0xff;
            i += 3;
        } else {
            int32_t s = (int32_t)(v * 1000000000.0);
            memcpy(buf + i, &s, 4); i += 4;
        }
        (void)ch;
    }
}

int main(int argc, char **argv)
{
    if (argc < 6) {
        fprintf(stderr, "usage: %s <outdir> <channels> <bitdepth> <samplerate> <frames>\n", argv[0]);
        return 1;
    }
    const char *outdir = argv[1];
    int channels = atoi(argv[2]);
    int bitDepth = atoi(argv[3]);
    int sr = atoi(argv[4]);
    int frames = atoi(argv[5]);
    if (channels < 1 || channels > 2 || (bitDepth != 16 && bitDepth != 24 && bitDepth != 32)) {
        fprintf(stderr, "channels 1-2, bitdepth 16/24/32\n");
        return 1;
    }

    AudioFormatDescription input;
    memset(&input, 0, sizeof(input));
    input.mSampleRate = (alac_float64_t)sr;
    input.mFormatID = kALACFormatLinearPCM;
    input.mFormatFlags = kALACFormatFlagIsSignedInteger | kALACFormatFlagIsPacked | 1; // little endian
    input.mBytesPerPacket = (bitDepth / 8) * channels;
    input.mFramesPerPacket = 1;
    input.mBytesPerFrame = (bitDepth / 8) * channels;
    input.mChannelsPerFrame = channels;
    input.mBitsPerChannel = bitDepth;

    AudioFormatDescription output = input;
    output.mFormatID = kALACFormatAppleLossless;
    output.mFormatFlags = (bitDepth == 16) ? 1 : (bitDepth == 24) ? 3 : 4; // 1=16 2=20 3=24 4=32
    output.mBytesPerPacket = 0;
    output.mFramesPerPacket = 4096;
    output.mBytesPerFrame = 0;

    ALACEncoder enc;
    enc.SetFrameSize(4096);
    if (enc.InitializeEncoder(output) != 0) {
        fprintf(stderr, "InitializeEncoder failed\n");
        return 1;
    }

    uint8_t cookie[64];
    uint32_t cookieSize = sizeof(cookie);
    enc.GetMagicCookie(cookie, &cookieSize);

    size_t frameBytes = (size_t)(bitDepth / 8) * (size_t)channels * 4096;
    uint8_t *pcm = (uint8_t *)malloc(frameBytes);
    uint8_t *packet = (uint8_t *)malloc(frameBytes + 64);
    if (!pcm || !packet) { fprintf(stderr, "oom\n"); return 1; }

    char path[512];
    snprintf(path, sizeof(path), "%s/seed_c%d_b%d_sr%d.bin", outdir, channels, bitDepth, sr);
    FILE *f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return 1; }
    fwrite(cookie, 1, cookieSize, f);

    for (int fr = 0; fr < frames; fr++) {
        fill_pcm(pcm, frameBytes, channels, bitDepth, sr, fr);
        int32_t nbytes = (int32_t)frameBytes;
        int32_t r = enc.Encode(input, output, pcm, packet, &nbytes);
        if (r != 0) { fprintf(stderr, "encode frame %d failed (%d)\n", fr, r); break; }
        fwrite(packet, 1, nbytes, f);
    }
    fclose(f);
    printf("wrote %s (cookie %u bytes, %d frames)\n", path, cookieSize, frames);
    return 0;
}
