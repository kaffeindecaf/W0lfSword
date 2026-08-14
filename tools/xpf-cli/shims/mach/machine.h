#ifndef MACH_MACHINE_SHIM_H
#define MACH_MACHINE_SHIM_H
#define CPU_ARCH_ABI64       0x01000000
typedef int32_t cpu_type_t;
typedef int32_t cpu_subtype_t;
#define CPU_TYPE_ARM64       (CPU_ARCH_ABI64 | 12)
#define CPU_SUBTYPE_ARM64_ALL   0
#define CPU_SUBTYPE_ARM64_V8    1
#define CPU_SUBTYPE_ARM64E      2
#define CPU_TYPE_ARM           12
#define CPU_SUBTYPE_ARM_ALL     0
#define CPU_SUBTYPE_ARM_V6      6
#define CPU_SUBTYPE_ARM_V7      9
#define CPU_SUBTYPE_ARM_V7S     11
#define CPU_SUBTYPE_ARM_V8      13
#define CPU_SUBTYPE_MASK        0xff000000
#define CPU_TYPE_X86_64        (CPU_ARCH_ABI64 | 7)
#define CPU_SUBTYPE_X86_64_ALL  3
#define CPU_TYPE_I386           7
#define CPU_SUBTYPE_I386_ALL    3
#endif
