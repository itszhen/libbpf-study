#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800 /* Internet Protocol packet	*/
#define ETH_P_IPV6  0x86DD /* Internet Protocol packet	*/

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} xdp_stats_map SEC(".maps");

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
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

    bpf_printk("Ethernet Header:");
    bpf_printk("  Destination: %02x:%02x:%02x:%02x:%02x:%02x",
               eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
               eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    bpf_printk("  Source: %02x:%02x:%02x:%02x:%02x:%02x",
               eth->h_source[0], eth->h_source[1], eth->h_source[2],
               eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    bpf_printk("  Type: 0x%04x", bpf_ntohs(eth->h_proto));

    // IPv4
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) {
            return XDP_PASS;
        }
        bpf_printk("It is an IPv4 Packect");

        // Update IPv4 counter
        __u32 key = 0;  // Index 0 for IPv4
        __u64 *count = bpf_map_lookup_elem(&xdp_stats_map, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        }

        bpf_printk("IP Header:");
        bpf_printk("  Version: %d, IHL: %d", ip->version, ip->ihl);
        bpf_printk("  TOS: %d, Total Length: %d", ip->tos, bpf_ntohs(ip->tot_len));
        bpf_printk("  TTL: %d, Protocol: %d", ip->ttl, ip->protocol);
        bpf_printk("  Source: %pI4", &ip->saddr);
        bpf_printk("  Destination: %pI4", &ip->daddr);

        // Transport
        void *transp = (void *)ip + (ip->ihl * 4);
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = transp;
            if ((void *)(tcp + 1) > data_end) {
                return XDP_PASS;
            }

            bpf_printk("TCP Header:");
            bpf_printk("  Source Port: %d", bpf_ntohs(tcp->source));
            bpf_printk("  Dest Port: %d", bpf_ntohs(tcp->dest));
            bpf_printk("  Seq: %u, Ack: %u", bpf_ntohl(tcp->seq), bpf_ntohl(tcp->ack_seq));

        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = transp;
            if ((void *)(udp + 1) > data_end) {
                return XDP_PASS;
            }

            bpf_printk("UDP Header:");
            bpf_printk("  Source Port: %d", bpf_ntohs(udp->source));
            bpf_printk("  Dest Port: %d", bpf_ntohs(udp->dest));
            bpf_printk("  Length: %d", bpf_ntohs(udp->len));

        }
    } else if (bpf_ntohs(eth->h_proto) == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) {
            return XDP_PASS;
        }
        bpf_printk("It is an IPv6 Packect");

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
