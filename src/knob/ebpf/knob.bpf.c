// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <linux/bpf.h>
#include <linux/types.h>

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


SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx) {
  __u64 number = 0;
  bpf_loop(KNOB, important_computation, &number, 0);
  if (number % 10000 == 0) bpf_printk("Unlikely print to trick the compiler from removing the useless code");
  return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
