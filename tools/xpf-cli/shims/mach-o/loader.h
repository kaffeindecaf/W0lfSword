#ifndef MACH_O_LOADER_SHIM_H
#define MACH_O_LOADER_SHIM_H
#include <stdint.h>

#define MH_MAGIC        0xfeedface
#define MH_MAGIC_64     0xfeedfacf
#define MH_EXECUTE      0x2
#define MH_FILESET      0xc

#define LC_REQ_DYLD                 0x80000000
#define LC_SEGMENT                  0x1
#define LC_SYMTAB                   0x2
#define LC_SYMSEG                   0x3
#define LC_THREAD                   0x4
#define LC_UNIXTHREAD               0x5
#define LC_LOADFVMLIB               0x6
#define LC_IDFVMLIB                 0x7
#define LC_IDENT                    0x8
#define LC_FVMFILE                  0x9
#define LC_PREPAGE                  0xa
#define LC_DYSYMTAB                 0xb
#define LC_LOAD_DYLIB               0xc
#define LC_ID_DYLIB                 0xd
#define LC_LOAD_DYLINKER            0xe
#define LC_ID_DYLINKER              0xf
#define LC_PREBOUND_DYLIB           0x10
#define LC_ROUTINES                 0x11
#define LC_SUB_FRAMEWORK            0x12
#define LC_SUB_UMBRELLA             0x13
#define LC_SUB_CLIENT               0x14
#define LC_SUB_LIBRARY              0x15
#define LC_TWOLEVEL_HINTS           0x16
#define LC_PREBIND_CKSUM            0x17
#define LC_LOAD_WEAK_DYLIB          (0x18 | LC_REQ_DYLD)
#define LC_SEGMENT_64               0x19
#define LC_ROUTINES_64              0x1a
#define LC_UUID                     0x1b
#define LC_RPATH                    (0x1c | LC_REQ_DYLD)
#define LC_CODE_SIGNATURE           0x1d
#define LC_SEGMENT_SPLIT_INFO       0x1e
#define LC_REEXPORT_DYLIB           (0x1f | LC_REQ_DYLD)
#define LC_LAZY_LOAD_DYLIB          0x20
#define LC_ENCRYPTION_INFO          0x21
#define LC_DYLD_INFO                0x22
#define LC_DYLD_INFO_ONLY           (0x22 | LC_REQ_DYLD)
#define LC_LOAD_UPWARD_DYLIB        (0x23 | LC_REQ_DYLD)
#define LC_VERSION_MIN_MACOSX       0x24
#define LC_VERSION_MIN_IPHONEOS     0x25
#define LC_FUNCTION_STARTS          0x26
#define LC_DYLD_ENVIRONMENT         0x27
#define LC_MAIN                     (0x28 | LC_REQ_DYLD)
#define LC_DATA_IN_CODE             0x29
#define LC_SOURCE_VERSION           0x2A
#define LC_DYLIB_CODE_SIGN_DRS      0x2B
#define LC_ENCRYPTION_INFO_64       0x2C
#define LC_LINKER_OPTION            0x2D
#define LC_LINKER_OPTIMIZATION_HINT 0x2E
#define LC_VERSION_MIN_TVOS         0x2F
#define LC_VERSION_MIN_WATCHOS      0x30
#define LC_NOTE                     0x31
#define LC_BUILD_VERSION            0x32
#define LC_DYLD_EXPORTS_TRIE        (0x33 | LC_REQ_DYLD)
#define LC_DYLD_CHAINED_FIXUPS      (0x34 | LC_REQ_DYLD)
#define LC_FILESET_ENTRY            (0x35 | LC_REQ_DYLD)
#define LC_UNKNOWN                  0x3f

struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

struct segment_command_64 {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    int32_t maxprot;
    int32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct section_64 {
    char sectname[16];
    char segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
};

struct mach_header {
    uint32_t magic;
    int32_t cputype;
    int32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
};

struct mach_header_64 {
    uint32_t magic;
    int32_t cputype;
    int32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

#define ARM_THREAD_STATE64 6

struct arm_thread_state64 {
    uint64_t __x[29];
    uint64_t __fp;
    uint64_t __lr;
    uint64_t __sp;
    uint64_t __pc;
    uint32_t __cpsr;
    uint32_t __pad;
};
typedef struct arm_thread_state64 arm_thread_state64_t;

struct thread_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t flavor;
    uint32_t count;
};

struct symtab_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
};

struct dysymtab_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t ilocalsym;
    uint32_t nlocalsym;
    uint32_t iextdefsym;
    uint32_t nextdefsym;
    uint32_t iundefsym;
    uint32_t nundefsym;
    uint32_t tocoff;
    uint32_t ntoc;
    uint32_t modtaboff;
    uint32_t nmodtab;
    uint32_t extrefsymoff;
    uint32_t nextrefsyms;
    uint32_t indirectsymoff;
    uint32_t nindirectsyms;
    uint32_t extreloff;
    uint32_t nextrel;
    uint32_t locreloff;
    uint32_t nlocrel;
};

struct nlist_64 {
    union { uint32_t n_strx; } n_un;
    uint8_t n_type;
    uint8_t n_sect;
    uint16_t n_desc;
    uint64_t n_value;
};

struct uuid_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint8_t uuid[16];
};

struct fileset_entry_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t vmaddr;
    uint64_t fileoff;
    union { uint32_t entry_id; uint32_t offset; } entry_id;
    uint32_t reserved;
};

struct segment_command {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint32_t vmaddr;
    uint32_t vmsize;
    uint32_t fileoff;
    uint32_t filesize;
    int32_t maxprot;
    int32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct section {
    char sectname[16];
    char segname[16];
    uint32_t addr;
    uint32_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
};

struct linkedit_data_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
};

struct dylib_command {
    uint32_t cmd;
    uint32_t cmdsize;
    struct dylib {
        union lc_str {
            uint32_t offset;
        } name;
        uint32_t timestamp;
        uint32_t current_version;
        uint32_t compatibility_version;
    } dylib;
};
struct rpath_command {
    uint32_t cmd;
    uint32_t cmdsize;
    union lc_str_dummy { uint32_t offset; } path;
};

struct entry_point_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t entryoff;
    uint64_t stacksize;
};

struct routines_command_64 {
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t init_address;
    uint64_t init_module;
    uint64_t reserved1;
    uint64_t reserved2;
    uint64_t reserved3;
    uint64_t reserved4;
    uint64_t reserved5;
    uint64_t reserved6;
};

struct encryption_info_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t cryptoff;
    uint32_t cryptsize;
    uint32_t cryptid;
};

struct encryption_info_command_64 {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t cryptoff;
    uint32_t cryptsize;
    uint32_t cryptid;
    uint32_t pad;
};

struct build_version_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t platform;
    uint32_t minos;
    uint32_t sdk;
    uint32_t ntools;
};

#endif

