// primtest2 — isolate WHICH property of the exploit's FIXED|OVERWRITE map
// gets rejected on iOS 17.1: surface-mlocked object, surface-backed target,
// or carveout regions.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <IOSurface/IOSurfaceRef.h>
#include <CoreFoundation/CoreFoundation.h>

kern_return_t mach_vm_map(vm_map_t task, mach_vm_address_t *address,
    mach_vm_size_t size, mach_vm_offset_t mask, int flags,
    mem_entry_name_port_t object, memory_object_offset_t offset, boolean_t copy,
    vm_prot_t cur, vm_prot_t max, vm_inherit_t inheritance);
kern_return_t mach_vm_allocate(vm_map_t task, mach_vm_address_t *address,
    mach_vm_size_t size, int flags);
kern_return_t mach_make_memory_entry_64(vm_map_t target_task,
    mach_vm_size_t *size, mach_vm_address_t offset, vm_prot_t permission,
    mach_port_t *object_handle, mem_entry_name_port_t parent_entry);

static const mach_vm_size_t PAGE = 0x4000;

static void test(char *name, mach_port_t obj, mach_vm_address_t addr,
                 mach_vm_size_t size, int flags, mach_vm_offset_t off) {
    mach_vm_address_t a = addr;
    kern_return_t kr = mach_vm_map(mach_task_self(), &a, size, 0, flags, obj,
                                   off, 0, VM_PROT_DEFAULT, VM_PROT_DEFAULT,
                                   VM_INHERIT_NONE);
    printf("%-58s kr=%d (0x%x)\n", name, kr, kr);
}

int main(void) {
    printf("primtest2: iOS 17.1 jailbroken root\n");

    // region surface creation attempts
    const char *regions[] = {"PurpleGfxMem", "PurpleEDRAM", "CarveoutMem",
                             "HibernationCarveoutMem", NULL};
    for (int i = 0; regions[i]; i++) {
        CFMutableDictionaryRef props = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);
        uint64_t sz = 0x8000;
        CFNumberRef n = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &sz);
        CFDictionarySetValue(props, CFSTR("IOSurfaceAllocSize"), n);
        CFDictionarySetValue(props, CFSTR("IOSurfaceMemoryRegion"),
                             CFStringCreateWithCString(kCFAllocatorDefault, regions[i], kCFStringEncodingUTF8));
        IOSurfaceRef s = IOSurfaceCreate(props);
        printf("region %-24s: %s\n", regions[i], s ? "CREATED" : "FAILED");
        if (s) {
            mach_vm_address_t base = (mach_vm_address_t)IOSurfaceGetBaseAddress(s);
            printf("   base=%#llx\n", base);
            CFRelease(s);
        }
        CFRelease(n); CFRelease(props);
    }

    // default surface (no region)
    CFMutableDictionaryRef dp = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    uint64_t dsz = 0x8000;
    CFNumberRef dn = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &dsz);
    CFDictionarySetValue(dp, CFSTR("IOSurfaceAllocSize"), dn);
    IOSurfaceRef dsurf = IOSurfaceCreate(dp);
    printf("default surface: %s\n", dsurf ? "CREATED" : "FAILED");
    mach_vm_address_t dbase = 0;
    mach_port_t dentry = 0;
    mach_vm_address_t dmap = 0;
    if (dsurf) {
        dbase = (mach_vm_address_t)IOSurfaceGetBaseAddress(dsurf);
        mach_vm_size_t esz = 0x8000;
        mach_make_memory_entry_64(mach_task_self(), &esz, dbase, VM_PROT_DEFAULT, &dentry, 0);
        mach_vm_map(mach_task_self(), &dmap, 0x8000, 0,
                    VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR, dentry, 0, 0,
                    VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        printf("default surface: base=%#llx entry=%#x map=%#llx\n", dbase, dentry, dmap);
    }

    // plain mapping A + entry
    mach_vm_address_t A = 0;
    mach_vm_size_t Asz = 0x1000 * PAGE;
    mach_vm_allocate(mach_task_self(), &A, Asz, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
    for (mach_vm_size_t k = 0; k < Asz; k += PAGE) *(volatile uint64_t *)(A + k) = 0x1234;
    mach_port_t eA = 0;
    mach_vm_size_t eAsz = Asz;
    mach_make_memory_entry_64(mach_task_self(), &eAsz, A, VM_PROT_DEFAULT, &eA, 0);
    printf("plain A=%#llx entryA=%#x\n", A, eA);

    // plain mapping B (distinct target)
    mach_vm_address_t B = 0;
    mach_vm_allocate(mach_task_self(), &B, 0x8000, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
    printf("plain B=%#llx\n", B);

    printf("----\n");
    // T1: control — entryA over B, no surface anywhere
    test("T1 entryA over plainB (no surfaces)", eA, B, 0x8000,
         VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, 0);

    // T2: surface_mlock A (wrap backing), then entryA over B
    CFMutableDictionaryRef mp = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFNumberRef an = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &Asz);
    CFDictionarySetValue(mp, CFSTR("IOSurfaceAddress"), an);
    CFDictionarySetValue(mp, CFSTR("IOSurfaceAllocSize"), an);
    IOSurfaceRef mlockSurf = IOSurfaceCreate(mp);
    printf("surface_mlock(A) (IOSurfaceAddress wrap): %s\n", mlockSurf ? "CREATED" : "FAILED");
    test("T2 entryA over plainB (A surface-mlocked)", eA, B, 0x8000,
         VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, 0);

    // T3: entryA over the default-surface mapping
    if (dmap)
        test("T3 entryA over default-surface map", eA, dmap, 0x8000,
             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, 0);
    // T4: default-surface entry over plainB
    if (dentry)
        test("T4 surface-entry over plainB", dentry, B, 0x8000,
             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, 0);
    // T5: entryA over default-surface BASE address (unmapped)
    if (dsurf)
        test("T5 entryA over surface base addr", eA, dbase, 0x8000,
             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, 0);
    // T6: entryA FIXED over the surface's map WITHOUT overwrite (expect 3)
    if (dmap)
        test("T6 entryA over surface map (no OVW)", eA, dmap, 0x8000,
             VM_FLAGS_FIXED, 0);
    // T7: entryA at base+0x4000 FIXED|OVERWRITE
    if (dmap)
        test("T7 entryA over surface map+0x4000", eA, dmap + 0x4000, 0x4000,
             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, 0);

    printf("primtest2 done\n");
    return 0;
}
