// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>


static __always_inline int parse_ethhdr(void *data, void *data_end, __u16 *nh_off,
                                        struct ethhdr **ethhdr) {
  struct ethhdr *eth = (struct ethhdr *)data;
  int hdr_size = sizeof(*eth);

  /* Byte-count bounds check; check if current pointer + size of header
   * is after data_end.
   */
  if ((void *)eth + hdr_size > data_end)
    return -1;

  *nh_off += hdr_size;
  *ethhdr = eth;

  return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_iphdr(void *data, void *data_end, __u16 *nh_off,
                                       struct iphdr **iphdr) {
  struct iphdr *ip = (struct iphdr *)data;
  int hdr_size;

  if ((void *)ip + sizeof(struct iphdr) > data_end)
    return -1;

  hdr_size = ip->ihl * 4;
  if (hdr_size < sizeof(*ip))
    return -1;
  if ((void *)ip + hdr_size > data_end)
    return -1;

  *nh_off += hdr_size;
  *iphdr = ip;

  return ip->protocol;
}

static __always_inline int parse_udphdr(void *data, void *data_end, __u16 *nh_off,
                                        struct udphdr **udphdr) {
  struct udphdr *udp = (struct udphdr *)data;
  int hdr_size = sizeof(struct udphdr);

  if ((void *)udp + hdr_size > data_end)
    return -1;
  if (bpf_ntohs(udp->len) < hdr_size)
    return -1;

  *nh_off += hdr_size;
  *udphdr = udp;

  return hdr_size;
}

SEC("xdp")
int xdp_pass_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    __u16 nh_off = 0;
    int ipproto;
    int udplen;
    int dst;
    
    if (parse_ethhdr(data, data_end, &nh_off, &eth) < 0)
        return XDP_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    if (parse_iphdr(data + nh_off, data_end, &nh_off, &ip) < 0)
        return XDP_PASS;

    ipproto = ip->protocol;
    if (ipproto != IPPROTO_UDP)
        return XDP_PASS;

    if (parse_udphdr(data + nh_off, data_end, &nh_off, &udp) < 0)
        return XDP_PASS;

    // print udp src and dst port
    dst = bpf_ntohs(udp->dest);

    if (dst < 8192*2) {
        return XDP_DROP;
    }

    return XDP_PASS;
  
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
