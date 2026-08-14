#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <xpc/xpc.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include "decompress.h"
#include "xpf.h"

xpc_object_t xpc_dictionary_create_empty(void) { return NULL; }
void xpc_dictionary_set_uint64(xpc_object_t d, const char *k, uint64_t v) {}
void xpc_release(xpc_object_t o) {}

static sigjmp_buf jmpbuf;
static void segv_handler(int sig) { (void)sig; siglongjmp(jmpbuf, 1); }

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <kernelcache> [dump_out]\n", argv[0]); return 1; }
    if (argc >= 3) {
        // dump mode: decompress kernel to raw Mach-O and exit
        int fd = open(argv[1], O_RDONLY);
        if (fd < 0) return 1;
        struct stat st; fstat(fd, &st);
        void *m = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        size_t outlen = 0;
        void *dc = kdecompress(m, st.st_size, &outlen);
        if (!dc) { fprintf(stderr, "decompress failed\n"); return 1; }
        FILE *f = fopen(argv[2], "wb");
        fwrite(dc, 1, outlen, f);
        fclose(f);
        printf("wrote %zu bytes\n", outlen);
        return 0;
    }
    int r = xpf_start_with_kernel_path(argv[1]);
    if (r != 0) { fprintf(stderr, "xpf_start failed: %s\n", xpf_get_error() ? xpf_get_error() : "?"); return 1; }
    printf("# kernel: %s\n# darwin: %s\n# xnu: %s\n# os: %s\n# fileset=%d arm64e=%d sptm=%d base=0x%llx entry=0x%llx\n",
           gXPF.kernelVersionString ? gXPF.kernelVersionString : "?",
           gXPF.darwinVersion ? gXPF.darwinVersion : "?",
           gXPF.xnuBuild ? gXPF.xnuBuild : "?",
           gXPF.osVersion ? gXPF.osVersion : "?",
           gXPF.kernelIsFileset, gXPF.kernelIsArm64e, gXPF.isSPTMDevice,
           (unsigned long long)gXPF.kernelBase, (unsigned long long)gXPF.kernelEntry);
    signal(SIGSEGV, segv_handler);
    XPFItem *item = gXPF.firstItem;
    while (item) {
        if (sigsetjmp(jmpbuf, 1)) {
            printf("0x%016llx <- %s [UNRESOLVED/crash]\n", 0ULL, item->name);
        } else {
            printf("0x%016llx <- %s\n", (unsigned long long)xpf_item_resolve(item->name), item->name);
        }
        item = item->nextItem;
    }
    return 0;
}
