#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
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

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  __u32 ifindex = ctx->ingress_ifindex;

  bpf_printk("IF: %u - Received packet, parsing...", ifindex);
  __u16 nf_off = 0;
  struct ethhdr *eth;
  int eth_type = parse_ethhdr(data + nf_off, data_end, &nf_off, &eth);
  if (eth_type < 0) {
    bpf_printk("Packet is not a valid Ethernet packet, dropping");
    return XDP_DROP;
  }

  bpf_printk("IF: %u - MAC src: %02x:%02x:%02x:%02x:%02x:%02x", ifindex, eth->h_source[0],
             eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4],
             eth->h_source[5]);
  bpf_printk("IF: %u - MAC dst: %02x:%02x:%02x:%02x:%02x:%02x", ifindex, eth->h_dest[0],
             eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

  if (eth_type != bpf_ntohs(ETH_P_IP))
    goto pass;

  bpf_printk("IF: %u - IP packet, parsing...", ifindex);
  struct iphdr *ip;
  int ip_type = parse_iphdr(data + nf_off, data_end, &nf_off, &ip);
  if (ip_type < 0) {
    bpf_printk("Packet is not a valid IPv4 packet, dropping");
    return XDP_DROP;
  }

  bpf_printk("IF: %u - IP src: %pI4", ifindex, ip->addrs.saddr);
  bpf_printk("IF: %u - IP dst: %pI4", ifindex, ip->addrs.daddr);

  if (ip_type != IPPROTO_UDP)
    goto pass;

  bpf_printk("IF: %u - UDP packet, parsing...", ifindex);
  struct udphdr *udp;
  int hdr_size = parse_udphdr(data + nf_off, data_end, &nf_off, &udp);
  if (hdr_size < 0) {
    bpf_printk("Packet is not a valid UDP packet, dropping");
    return XDP_DROP;
  }

  bpf_printk("IF: %u - Port src: %u", ifindex, bpf_ntohs(udp->source));
  bpf_printk("IF: %u - Port dst: %u", ifindex, bpf_ntohs(udp->dest));

pass:
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
