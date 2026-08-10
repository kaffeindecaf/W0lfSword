#ifndef sandbox_research_h
#define sandbox_research_h

#include <stdint.h>
#include <stddef.h>

#define SC_CONSUMED   0
#define SC_ISSUED     1

struct extension {
    void *data_ptr;
    uint64_t path_len;
    uint64_t st_ino;
    uint64_t _pad02;
    uint64_t _pad03;
    struct {
        uint8_t consumed;
        uint8_t storage_class;
        uint16_t _pad;
        uint32_t st_dev;
    } file;
};

struct extension_class_node {
    void *class_name;
    void *ext_list_head;
    uint64_t _pad[2];
};

struct extension_set {
    void *type_buckets[9];
};

struct sandbox_label {
    void *extension_set;
    uint64_t _pad[7];
};

#endif
