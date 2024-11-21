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

const volatile struct {
  int redir_ifindex;
  unsigned char redir_mac[ETH_ALEN];
  __be32 redir_ip;
} redirect_cfg;

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

// Helper function to work around the volatile source.
void *memcpy_v(void *restrict dest, const volatile void *restrict src, size_t n) {
  const volatile unsigned char *src_c = src;
  volatile unsigned char *dest_c = dest;

  while (n > 0) {
    n--;
    dest_c[n] = src_c[n];
  }
  return dest;
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  
  __u16 nf_off = 0;
  struct ethhdr *eth;
  int eth_type = parse_ethhdr(data + nf_off, data_end, &nf_off, &eth);
  if (eth_type < 0) {
    
    return XDP_DROP;
  }
  if (eth_type != bpf_ntohs(ETH_P_IP))
    goto drop;
  
  
  struct iphdr *ip;
  int ip_type = parse_iphdr(data + nf_off, data_end, &nf_off, &ip);
  if (ip_type < 0) {
    
    return XDP_DROP;
  }
  if (ip_type != IPPROTO_UDP)
    goto drop;

  
  struct udphdr *udp;
  int hdr_size = parse_udphdr(data + nf_off, data_end, &nf_off, &udp);
  if (hdr_size < 0) {
    
    return XDP_DROP;
  }

  
  
  

  if (bpf_ntohs(udp->dest) != 3333) {
    
    goto drop;
  }

  
  __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
  memcpy_v(eth->h_source, redirect_cfg.redir_mac, ETH_ALEN);

  ip->addrs.daddr = ip->addrs.saddr;
  ip->addrs.saddr = redirect_cfg.redir_ip;

  __be16 udp_tmp;
  udp_tmp = udp->source;
  udp->source = udp->dest;
  udp->dest = udp_tmp;
  udp->check = 0;

  int action = bpf_redirect(redirect_cfg.redir_ifindex, 0);
    
  return action;

drop:
  return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
