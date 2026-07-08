#ifndef __LD_NAT6_DYN_MAP_H__
#define __LD_NAT6_DYN_MAP_H__

#include "nat_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct nat_timer_key_v6);
    __type(value, struct nat_timer_value_v6);
    __uint(max_entries, NAT_MAPPING_TIMER_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} nat6_conn_timer SEC(".maps");

#endif /* __LD_NAT6_DYN_MAP_H__ */
