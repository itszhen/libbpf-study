#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800 /* Internet Protocol packet	*/
#define ETH_P_IPV6  0x86DD /* Internet Protocol packet	*/

struct lpm_key_v4 {
    __u32 prefixlen;
    __u32 data;
};

struct lpm_key_v6 {
    __u32 prefixlen;
    struct in6_addr data;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} xdp_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key_v4);
    __type(value, __u8);
} denied_ips_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key_v6);
    __type(value, __u8);
} denied_ipv6_map SEC(".maps");

SEC("xdp")
int xdp_aborted(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    bpf_printk("=== Packet Received ===");
	bpf_printk("packet size: %d", data_end-data);
    
    // Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    
    // IP
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) {
            return XDP_PASS;
        }
        bpf_printk("It is an IPv4 Packect");

        // Check if destination is in denied list using LPM trie
        struct lpm_key_v4 key_ipv4 = { .prefixlen = 32, .data = ip->daddr };
        __u8 *denied = bpf_map_lookup_elem(&denied_ips_map, &key_ipv4);
        if (denied) {
            bpf_printk("Denied IP: %pI4", &ip->daddr);
            return XDP_ABORTED;
        }
        
        // Update IPv4 counter
        __u32 key = 0;  // Index 0 for IPv4
        __u64 *count = bpf_map_lookup_elem(&xdp_stats_map, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }
    } else if (bpf_ntohs(eth->h_proto) == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) {
            return XDP_PASS;
        }
        bpf_printk("It is an IPv6 Packect");

        // Check if destination IPv6 is in denied list using LPM trie
        struct lpm_key_v6 key_ipv6 = { .prefixlen = 128, .data = ip6->daddr };
        __u8 *denied_v6 = bpf_map_lookup_elem(&denied_ipv6_map, &key_ipv6);
        if (denied_v6) {
            bpf_printk("Denied IPv6: %pI6", &ip6->daddr);
            return XDP_ABORTED;
        }
        
        // Update IPv6 counter
        __u32 key = 1;  // Index 1 for IPv6
        __u64 *count = bpf_map_lookup_elem(&xdp_stats_map, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }
    }
    
    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
