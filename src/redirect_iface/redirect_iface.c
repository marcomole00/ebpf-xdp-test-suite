// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>
#include <string.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>

#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <signal.h>

#include "log.h"

// Include skeleton file
#include "redirect_iface.skel.h"

static int ifindex_iface1 = 0, ifindex_iface2 = 0, ifindex_iface3 = 0;
static unsigned char iface2_mac[ETH_ALEN], iface3_mac[ETH_ALEN];
static __be32 iface2_ip, iface3_ip;
static __u32 xdp_flags = 0;

static void cleanup_iface() {
  __u32 curr_prog_id;
  if (!bpf_xdp_query_id(ifindex_iface1, xdp_flags, &curr_prog_id)) {
    if (curr_prog_id) {
      bpf_xdp_detach(ifindex_iface1, xdp_flags, NULL);
      log_info("Detached XDP program from interface %d", ifindex_iface1);
    }
  }
}

void sigint_handler(int sig_no) {
  cleanup_iface();
  exit(0);
}

int main(int argc, const char **argv) {
  struct redirect_iface_bpf *skel = NULL;
  int err;
  const char *iface1 = NULL, *iface2 = NULL, *iface3 = NULL;

  if (argc < 3) {
    log_error("Two ifaces need to be specified (first to attach to, second to redirect to)");
    return EXIT_FAILURE;
  }

  iface1 = argv[1];
  log_info("XDP program will be attached to %s interface", iface1);
  ifindex_iface1 = if_nametoindex(iface1);
  if (!ifindex_iface1) {
    log_fatal("Error while retrieving the ifindex of %s", iface1);
    exit(1);
  } else {
    log_info("Got ifindex for iface: %s, which is %d", iface1, ifindex_iface1);
  }

  iface2 = argv[2];
  log_info("XDP program will redirect some flows to %s interface", iface2);
  ifindex_iface2 = if_nametoindex(iface2);
  if (!ifindex_iface2) {
    log_fatal("Error while retrieving the ifindex of %s", iface2);
    exit(1);
  } else {
    log_info("Got ifindex for iface: %s, which is %d", iface2, ifindex_iface2);
  }

  iface3 = argv[3];
  log_info("XDP program will redirect some flows to %s interface", iface3);
  ifindex_iface3 = if_nametoindex(iface3);
  if (!ifindex_iface3) {
    log_fatal("Error while retrieving the ifindex of %s", iface3);
    exit(1);
  } else {
    log_info("Got ifindex for iface: %s, which is %d", iface3, ifindex_iface3);
  }


  if (ifindex_iface1 == ifindex_iface2 || ifindex_iface1 == ifindex_iface3 || ifindex_iface2 == ifindex_iface3) {
    log_fatal("Ingress and egress need to be two different interfaces");
    exit(1);
  }

  /* Get MAC of redirect iface */
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) {
    log_fatal("Unable to create socket");
    exit(1);
  }

  struct ifreq req;
  strncpy(req.ifr_ifrn.ifrn_name, iface2, IF_NAMESIZE);
  if (ioctl(s, SIOCGIFHWADDR, &req) == -1) {
    log_fatal("Error in SIOCGIFHWADDR");
    exit(1);
  }
  memcpy(iface2_mac, req.ifr_ifru.ifru_hwaddr.sa_data, ETH_ALEN);
  log_info("Got MAC for iface %s, which is %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", iface2,
           iface2_mac[0], iface2_mac[1], iface2_mac[2], iface2_mac[3], iface2_mac[4],
           iface2_mac[5]);

  if (ioctl(s, SIOCGIFADDR, &req) == -1) {
    log_fatal("Error in SIOCGIFADDR");
    exit(1);
  }
  struct in_addr addr = ((struct sockaddr_in *)&req.ifr_ifru.ifru_addr)->sin_addr;
  log_info("Got IP for iface %s, which is %s", iface2, inet_ntoa(addr));
  iface2_ip = addr.s_addr;


  strncpy(req.ifr_ifrn.ifrn_name, iface3, IF_NAMESIZE);
  if (ioctl(s, SIOCGIFHWADDR, &req) == -1) {
    log_fatal("Error in SIOCGIFHWADDR");
    exit(1);
  }
  memcpy(iface3_mac, req.ifr_ifru.ifru_hwaddr.sa_data, ETH_ALEN);
  log_info("Got MAC for iface %s, which is %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", iface3,
           iface3_mac[0], iface3_mac[1], iface3_mac[2], iface3_mac[3], iface3_mac[4],
           iface3_mac[5]);

  if (ioctl(s, SIOCGIFADDR, &req) == -1) {
    log_fatal("Error in SIOCGIFADDR");
    exit(1);
  }

  addr = ((struct sockaddr_in *)&req.ifr_ifru.ifru_addr)->sin_addr;
  log_info("Got IP for iface %s, which is %s", iface3, inet_ntoa(addr));
  iface3_ip = addr.s_addr;


  close(s);



  /* Open BPF application */
  skel = redirect_iface_bpf__open();
  if (!skel) {
    log_fatal("Error while opening BPF skeleton");
    exit(1);
  }

  /* Pass redirect ifindex */
  skel->rodata->redirect_cfg.redir_ifindex = ifindex_iface2;
  skel->rodata->redirect_cfg.redir_ip = iface2_ip;
  memcpy(skel->rodata->redirect_cfg.redir_mac, iface2_mac, ETH_ALEN);
    /* Pass redirect ifindex */
  skel->rodata->redirect_cfg.redir_ifindex3 = ifindex_iface3;
  skel->rodata->redirect_cfg.redir_ip3 = iface3_ip;
  memcpy(skel->rodata->redirect_cfg.redir_mac3, iface3_mac, ETH_ALEN);
    
  

  /* Set program type to XDP */
  bpf_program__set_type(skel->progs.xdp_pass_func, BPF_PROG_TYPE_XDP);

  /* Load and verify BPF programs */
  if (redirect_iface_bpf__load(skel)) {
    log_fatal("Error while loading BPF skeleton");
    exit(1);
  }

  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = &sigint_handler;

  if (sigaction(SIGINT, &action, NULL) == -1) {
    log_error("sigation failed");
    goto cleanup;
  }

  if (sigaction(SIGTERM, &action, NULL) == -1) {
    log_error("sigation failed");
    goto cleanup;
  }

  xdp_flags = 0;
  xdp_flags |= XDP_FLAGS_DRV_MODE;
  xdp_flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;

  /* Attach the XDP program to the interface */
  err = bpf_xdp_attach(ifindex_iface1, bpf_program__fd(skel->progs.xdp_pass_func), xdp_flags, NULL);

  if (err) {
    log_fatal("Error while attaching XDP program to the interface");
    exit(1);
  }

  log_info("Successfully attached!");

  // Sleep for 20 minutes to allow for testing to be done
  sleep(1200);

cleanup:
  cleanup_iface();
  redirect_iface_bpf__destroy(skel);

  return 0;
}
