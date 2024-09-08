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

  bpf_printk("Received packet, parsing...");
  __u16 nf_off = 0;
  struct ethhdr *eth;
  int eth_type = parse_ethhdr(data + nf_off, data_end, &nf_off, &eth);
  if (eth_type < 0) {
    bpf_printk("Packet is not a valid Ethernet packet, dropping");
    return XDP_DROP;
  }
  if (eth_type != bpf_ntohs(ETH_P_IP))
    goto pass;

  bpf_printk("MAC src: %x:%x:%x", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
  bpf_printk("MAC src: %x:%x:%x", eth->h_source[3], eth->h_source[4], eth->h_source[5]);
  bpf_printk("MAC dst: %x:%x:%x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
  bpf_printk("MAC dst: %x:%x:%x", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

  bpf_printk("IP packet, parsing...");
  struct iphdr *ip;
  int ip_type = parse_iphdr(data + nf_off, data_end, &nf_off, &ip);
  if (ip_type < 0) {
    bpf_printk("Packet is not a valid IPv4 packet, dropping");
    return XDP_DROP;
  }
  if (ip_type != IPPROTO_UDP)
    goto pass;

  bpf_printk("UDP packet, parsing...");
  struct udphdr *udp;
  int hdr_size = parse_udphdr(data + nf_off, data_end, &nf_off, &udp);
  if (hdr_size < 0) {
    bpf_printk("Packet is not a valid UDP packet, dropping");
    return XDP_DROP;
  }

  bpf_printk("Src: %pI4:%u", ip->addrs.saddr, bpf_ntohs(udp->source));
  bpf_printk("Dst: %pI4:%u", ip->addrs.daddr, bpf_ntohs(udp->dest));

  if (bpf_ntohs(udp->dest) != 3333) {
    bpf_printk("UDP packet not on 3333, passing...");
    goto pass;
  }

  bpf_printk("UDP packet on 3333, echoing...");
  unsigned char eth_tmp[ETH_ALEN];
  __builtin_memcpy(eth_tmp, eth->h_source, ETH_ALEN);
  __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
  __builtin_memcpy(eth->h_dest, eth_tmp, ETH_ALEN);

  __be32 ip_tmp;
  ip_tmp = ip->addrs.saddr;
  ip->addrs.saddr = ip->addrs.daddr;
  ip->addrs.daddr = ip_tmp;

  __be16 udp_tmp;
  udp_tmp = udp->source;
  udp->source = udp->dest;
  udp->dest = udp_tmp;
  udp->check = 0;

  return XDP_TX;

pass:
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
