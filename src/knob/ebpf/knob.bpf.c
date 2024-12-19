// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>

// nr_loops is limited to 1 << 23 (~8 million) loops
#define NR_LOOPS 1<<15

long important_computation (__u32 index, void *ctx){
  int random_value = bpf_get_prandom_u32();
  struct xdp_md *xdp = (struct xdp_md *) ctx;
  xdp->data += random_value;  
  return 0;
}


SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx) {
  bpf_loop(NR_LOOPS, important_computation, ctx, 0);
   return XDP_DROP ;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
