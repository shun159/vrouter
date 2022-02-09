// SPDX-License-Identifier: BSD-2-Clause

#include <stdint.h>
#include <linux/types.h>
#include <linux/if.h>

#include "vr_types.h"

/* sandesh vr_interface_req */
struct vifr {
  sandesh_op h_op;
  unsigned char vifr_name[IFNAMSIZ];
  int32_t vifr_type;
  int32_t vifr_flags;
  int32_t vifr_vrf;
  int32_t vifr_idx;
  int32_t vifr_rid;
  int32_t vifr_os_idx;
  int32_t vifr_mtu;
  int16_t vifr_vlan_id;
};

/* sandesh vr_nexthop_req */
struct nhr {
  sandesh_op h_op;
  int8_t nhr_type;
  int8_t nhr_family;
  int32_t nhr_id;
  int32_t nhr_rid;
  int32_t * nhr_encap_oif_id;
  u_int32_t nhr_encap_oif_id_size;
  int32_t nhr_encap_len;
  int32_t nhr_encap_family;
  int32_t nhr_vrf;
  uint32_t nhr_tun_sip;
  uint32_t nhr_tun_dip;
  int16_t nhr_tun_sport;
  int16_t nhr_tun_dport;
  int32_t nhr_ref_cnt;
  int32_t nhr_marker;
  uint32_t nhr_flags;
  int8_t * nhr_encap;
  u_int32_t nhr_encap_size;
  int32_t * nhr_nh_list;
  u_int32_t nhr_nh_list_size;
  int32_t * nhr_label_list;
  u_int32_t nhr_label_list_size;
  int16_t nhr_nh_count;
  int8_t * nhr_tun_sip6;
  u_int32_t nhr_tun_sip6_size;
  int8_t * nhr_tun_dip6;
  u_int32_t nhr_tun_dip6_size;
  int8_t nhr_ecmp_config_hash;
  int8_t * nhr_pbb_mac;
  u_int32_t nhr_pbb_mac_size;
  int32_t nhr_encap_crypt_oif_id;
  int32_t nhr_crypt_traffic;
  int32_t nhr_crypt_path_available;
  int8_t * nhr_rw_dst_mac;
  u_int32_t nhr_rw_dst_mac_size;
  uint32_t nhr_transport_label;
  int32_t * nhr_encap_valid;
  u_int32_t nhr_encap_valid_size;
};

/* sandesh vr_route_req */
struct rtr {
  sandesh_op h_op;
  int32_t rtr_vrf_id;
  int32_t rtr_family;
  int8_t * rtr_prefix;
  u_int32_t rtr_prefix_size;
  int32_t rtr_prefix_len;
  int16_t rtr_rid;
  int16_t rtr_label_flags;
  int32_t rtr_label;
  int32_t rtr_nh_id;
  int8_t * rtr_marker;
  u_int32_t rtr_marker_size;
  int32_t rtr_marker_plen;
  int8_t * rtr_mac;
  u_int32_t rtr_mac_size;
  int32_t rtr_replace_plen;
  int32_t rtr_index;
};