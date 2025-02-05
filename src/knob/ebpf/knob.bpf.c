// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>

#include <bpf/bpf_helpers.h>

#define XSTR(x) STR(x)
#define STR(x) #x
// nr_loops is limited to 1 << 23 (~8 million) loops
#ifndef KNOB
#define KNOB 1<<10
#endif
// #pragma message "value of knob  " XSTR(KNOB)
static long important_computation (__u32 index, void *ctx){
  __u64 random_value = bpf_get_prandom_u32();
  __u64 *number = (__u64 *) ctx;
  *number+= random_value;
  return 0;
}

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

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx) {
  struct ethhdr *eth;
  __u64 number = 0;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  __u16 nf_off = 0;
  int eth_type = parse_ethhdr(data + nf_off, data_end, &nf_off, &eth);
  if (eth_type < 0) {
    bpf_printk("Packet is not a valid Ethernet packet, dropping");
    return XDP_DROP;
  }
  
  bpf_loop(KNOB, important_computation, &number, 0);
  if (number % 10000 == 0) bpf_printk("Unlikely print to trick the compiler from removing the useless code");
  return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
