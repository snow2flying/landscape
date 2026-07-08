#ifndef __LD_NAT4_STATIC_H__
#define __LD_NAT4_STATIC_H__

#include "nat_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct nat_mapping_key_v4);
    __type(value, struct nat4_st_mapping_value);
    __uint(max_entries, NAT_MAPPING_CACHE_SIZE);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} nat4_st_map SEC(".maps");

#endif /* __LD_NAT4_STATIC_H__ */
