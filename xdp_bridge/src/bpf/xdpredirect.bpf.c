#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800 /* Internet Protocol packet	*/
#define ETH_P_IPV6  0x86DD /* Internet Protocol packet	*/

/* MAC地址结构 */
struct eth_mac {
    __u8 addr[6];
};

/* 定义桥接接口映射表，用于存储接口对应的MAC地址 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16); /* 最多支持16个接口 */
    __type(key, __u32);      /* 接口索引 */
    __type(value, struct eth_mac);  /* MAC地址 */
} iface_map SEC(".maps");

/* 定义桥接转发规则表 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256); /* 最多支持256条规则 */
    __type(key, struct eth_mac);      /* 源MAC地址 */
    __type(value, struct eth_mac);    /* 目标MAC地址 */
} bridge_rules SEC(".maps");

/* 用于统计的计数器映射 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} xdp_stats_map SEC(".maps");

/* 辅助函数：将MAC地址转换为字符串（用于打印） */
static __always_inline void print_mac(const char *prefix, const __u8 *mac) {
    bpf_printk("%s: %02x:%02x:%02x:%02x:%02x:%02x",
               prefix,
               mac[0], mac[1], mac[2],
               mac[3], mac[4], mac[5]);
}

/* 辅助函数：比较两个MAC地址是否相同 */
static __always_inline bool mac_equal(const __u8 *mac1, const __u8 *mac2) {
    return mac1[0] == mac2[0] && mac1[1] == mac2[1] && mac1[2] == mac2[2] &&
           mac1[3] == mac2[3] && mac1[4] == mac2[4] && mac1[5] == mac2[5];
}

SEC("xdp")
int xdp_bridge(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // 获取当前接口索引
    __u32 ifindex = ctx->ingress_ifindex;

    // 获取当前接口的MAC地址
    struct eth_mac *current_mac = bpf_map_lookup_elem(&iface_map, &ifindex);
    if (!current_mac) {
        return XDP_PASS;  // 如果找不到接口信息，放行
    }

    bpf_printk("=== Packet Received on Interface %d ===", ifindex);
    print_mac("Current MAC", current_mac->addr);
    print_mac("Dest MAC", eth->h_dest);
    print_mac("Source MAC", eth->h_source);
    bpf_printk("Packet Type: 0x%04x", bpf_ntohs(eth->h_proto));

    // 检查是否是广播包
    if (eth->h_dest[0] == 0xff && eth->h_dest[1] == 0xff && 
        eth->h_dest[2] == 0xff && eth->h_dest[3] == 0xff && 
        eth->h_dest[4] == 0xff && eth->h_dest[5] == 0xff) {
        bpf_printk("Broadcast packet - forwarding to all interfaces");
        // 广播包需要转发到所有其他接口
        // 这里简单返回PASS，实际应用中需要使用XDP_REDIRECT转发到其他接口
        return XDP_PASS;
    }

    // 检查是否是发给当前接口的包
    if (mac_equal(eth->h_dest, current_mac->addr)) {
        bpf_printk("Packet destined for this interface - processing locally");
        // 处理IP包
        if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
            struct iphdr *ip = (void *)(eth + 1);
            if ((void *)(ip + 1) > data_end) {
                return XDP_PASS;
            }
            bpf_printk("IPv4 Packet for local processing");

            // 更新IPv4计数器
            __u32 key = 0;  // Index 0 for IPv4
            __u64 *count = bpf_map_lookup_elem(&xdp_stats_map, &key);
            if (count) {
                __sync_fetch_and_add(count, 1);
            }
        }
        return XDP_PASS;
    }

    // 查找转发规则
    struct eth_mac *dest_mac = bpf_map_lookup_elem(&bridge_rules, eth->h_dest);
    if (dest_mac) {
        bpf_printk("Found bridge rule - forwarding packet");
        // 更新目标MAC地址
        __u8 tmp[6];
        __builtin_memcpy(tmp, eth->h_dest, 6);
        __builtin_memcpy(eth->h_dest, dest_mac->addr, 6);
        __builtin_memcpy(eth->h_source, current_mac->addr, 6);

        // 这里简单返回PASS，实际应用中应该使用XDP_REDIRECT转发到目标接口
        // 由于XDP_REDIRECT需要指定目标接口索引，这里简化处理
        return XDP_PASS;
    }

    // 没有找到转发规则，检查是否有源MAC的规则（反向查找）
    struct eth_mac *src_dest_mac = bpf_map_lookup_elem(&bridge_rules, eth->h_source);
    if (src_dest_mac) {
        bpf_printk("Found reverse bridge rule - forwarding packet");
        // 更新源和目标MAC地址
        __builtin_memcpy(eth->h_dest, src_dest_mac->addr, 6);
        __builtin_memcpy(eth->h_source, current_mac->addr, 6);

        // 这里简单返回PASS，实际应用中应该使用XDP_REDIRECT转发到目标接口
        return XDP_PASS;
    }

    bpf_printk("No bridge rule found - dropping packet");
    return XDP_PASS; // 可以改为XDP_DROP来丢弃包
}

char __license[] SEC("license") = "GPL";