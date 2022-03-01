// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <linux/ip.h>
#include "vr_packet.h"

#define MAX_SKB_FRAGS (65536 / 4096 + 1)

struct sk_buff {
	/*
	 * This is the control buffer. It is free to use for every
	 * layer. Please put your private variables there. If you
	 * want to keep them across layers you have to do a skb_clone()
	 * first. This is owned by whoever has the skb queued ATM.
	 */
  char cb[48];
  unsigned int end;
  unsigned char *head;
};

/* This data is invariant across clones and lives at
 * the end of the header data, ie. at skb->end.
 */
struct skb_shared_info {
  struct sk_buff *frag_list;
};

unsigned char *
vr_pkt_data(struct vr_packet *pkt) {
  return pkt->vp_head + pkt->vp_data;
}

unsigned char *
skb_end_pointer(const struct sk_buff *skb) {
  unsigned char *end_ptr;
  unsigned char *head = BPF_CORE_READ(skb, head);
  unsigned int end = BPF_CORE_READ(skb, end);
  bpf_probe_read(&end_ptr, sizeof(end_ptr), (head + end));
	return end_ptr;
}

struct skb_shared_info *
skb_shinfo(struct sk_buff *skb) {
  return (struct skb_shared_info *)(skb_end_pointer(skb));
}

static struct sk_buff *
vp_os_packet(struct vr_packet *pkt) {
  void *__mptr = (void *)(pkt);
  return (struct sk_buff *)BPF_CORE_READ((struct sk_buff *)(__mptr), cb);
}

static void *
lh_network_header(struct vr_packet *pkt) {
  struct sk_buff *skb;
  struct sk_buff *frag;
  struct vr_packet *frag_pkt;
  unsigned char *network_h;
  unsigned short offset;

  if (pkt->vp_network_h < pkt->vp_end) {
    return pkt->vp_head + pkt->vp_network_h;
  }

  offset = pkt->vp_network_h - pkt->vp_end;
  skb = vp_os_packet(pkt);
#pragma clang loop unroll(full)
  for (int i = 0; i < MAX_SKB_FRAGS; i++) {
    frag = (struct sk_buff *)BPF_CORE_READ(skb_shinfo(skb), frag_list);
    frag_pkt = (struct vr_packet *)BPF_CORE_READ(frag, cb);

    if (offset < frag_pkt->vp_end) {
      return frag_pkt->vp_head + offset;
    }

    offset -= frag_pkt->vp_end;
    skb = frag;
  }

  return NULL;
}

static __inline void
parse_vr_ip4(struct vr_packet *pkt) {
  unsigned char iphdr_first_byte, ip_vsn, ip_ttl, ip_hdrlen;
  unsigned int hoge;
  struct vr_ip *iph = (struct vr_ip *)lh_network_header(pkt);
  bpf_probe_read(&iphdr_first_byte, 1, iph);
  bpf_probe_read(&ip_ttl, 1, &iph->ip_ttl);
  bpf_probe_read(&hoge, 4, &iph->ip_saddr);
  ip_vsn = iphdr_first_byte >> 4;
  ip_hdrlen = (iphdr_first_byte & 0x0f) * 4;

  bpf_printk("ip_bytes: 0x%2x\n", iphdr_first_byte);
  bpf_printk("ip_vsn: %d\n", ip_vsn);
  bpf_printk("ip_hlen: %d\n", ip_hdrlen);
  bpf_printk("ip_ttl: %d\n", ip_ttl);
  bpf_printk("ip_ttl: %d\n", hoge);
}
