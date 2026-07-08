#ifndef __LD_NAT6_STATIC_H__
#define __LD_NAT6_STATIC_H__

#include "nat_common.h"

#define STATIC_NAT_MAPPING_CACHE_SIZE 1024 * 64

struct static_nat6_mapping_key {
    u32 prefixlen;
    // INGRESS: NAT Mapping Port
    // EGRESS: lan Clinet Port
    u16 port;
    u8 gress;
    u8 l3_protocol;
    u8 l4_protocol;
    u8 _pad[3];
    // INGRESS:  only use u32 for ifindex match
    // EGRESS: match lan client ip
    inet6_addr addr;
};

struct static_nat6_mapping_value {
    // INGRESS: target LAN client prefix for NPTv6 dst replace, or suffix for self-ref match
    // EGRESS: unused
    inet6_addr addr;
    // INGRESS: mapped port
    // EGRESS: unused
    __be16 port;
    u8 is_static;
    // EGRESS: used by create_ct6_egress when building static-backed CT
    // INGRESS: unused (ingress static CT always sets is_allow_reuse=1)
    u8 is_allow_reuse;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct static_nat6_mapping_key);
    __type(value, struct static_nat6_mapping_value);
    __uint(max_entries, STATIC_NAT_MAPPING_CACHE_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} nat6_static_mappings SEC(".maps");

#endif /* __LD_NAT6_STATIC_H__ */
