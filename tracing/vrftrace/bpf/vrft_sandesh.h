// SPDX-License-Identifier: BSD-2-Clause

#include <stdint.h>
#include <linux/types.h>
#include <linux/if.h>

#include "vr_types.h"

/* sandesh vr_interface_req */
struct vifr { 
  sandesh_op h_op;
  uint32_t vifr_core;
  int32_t vifr_type;
  int32_t vifr_flags;
  int32_t vifr_vrf;
  int32_t vifr_idx;
  int32_t vifr_rid;
  int32_t vifr_os_idx;
  int32_t vifr_mtu;
  int32_t vifr_ref_cnt;
  int32_t vifr_marker;
  uint32_t vifr_ip;
  uint64_t vifr_ip6_u;
  uint64_t vifr_ip6_l;
  uint8_t pad1[2];
  int16_t vifr_vlan_id;
  int32_t vifr_nh_id;
  uint8_t pad2[7];
  int8_t vifr_transport;
};

/* sandesh vr_nexthop_req */
struct nhr {
  sandesh_op h_op;
  int8_t _pad[2];
  int8_t nhr_type;
  int8_t nhr_family;
  int32_t nhr_id;
  int32_t nhr_rid;
  uint32_t nhr_flags;
};

/* sandesh vr_route_req */
struct rtr {
  sandesh_op h_op;
  int32_t rtr_vrf_id;
  int32_t rtr_family;
  int8_t _pad[2];
  int16_t rtr_rid;
  int32_t rtr_nh_id;
  int32_t rtr_index;
};

/* sandesh vr_vrf_assign_req */
struct var { 
  /* public */
  sandesh_op h_op;
  int16_t var_rid;
  int16_t var_vif_index;
  int32_t var_vif_vrf;
  int16_t var_vlan_id;
  int16_t var_marker;
  int32_t var_nh_id;
};

/* sandesh vr_mpls_req */
struct mr { 
  sandesh_op h_op;
  int32_t mr_label;
  int16_t mr_rid;
  uint8_t pad[2];
  int32_t mr_nhid;
  int32_t mr_marker;
};

/* sandesh vr_vrf_stats_req */
struct vsr { 
  sandesh_op h_op;
  int16_t vsr_rid;
  int16_t vsr_family;
  uint8_t _pad1[2];
  int16_t vsr_type;
  int32_t vsr_vrf;
  int64_t vsr_discards;
  int64_t vsr_resolves;
  int64_t vsr_receives;
  int64_t vsr_ecmp_composites;
  int64_t vsr_l2_mcast_composites;
  int64_t vsr_fabric_composites;
  int64_t vsr_udp_tunnels;
  int64_t vsr_udp_mpls_tunnels;
  int64_t vsr_gre_mpls_tunnels;
  int64_t vsr_l2_encaps;
  int64_t vsr_encaps;
  uint8_t _pad2[6];
  int16_t vsr_marker;
  int64_t vsr_gros;
  int64_t vsr_diags;
  int64_t vsr_encap_composites;
  int64_t vsr_evpn_composites;
  int64_t vsr_vrf_translates;
  int64_t vsr_vxlan_tunnels;
  int64_t vsr_arp_virtual_proxy;
  int64_t vsr_arp_virtual_stitch;
  int64_t vsr_arp_virtual_flood;
  int64_t vsr_arp_physical_stitch;
  int64_t vsr_arp_tor_proxy;
  int64_t vsr_arp_physical_flood;
  int64_t vsr_l2_receives;
  int64_t vsr_uuc_floods;
  int64_t vsr_pbb_tunnels;
  int64_t vsr_udp_mpls_over_mpls_tunnels;
};

/* sandesh vr_mirror_req */
struct mirr { 
  sandesh_op h_op;
  int16_t mirr_index;
  int16_t mirr_rid;
  int32_t mirr_nhid;
  int32_t mirr_users;
  int32_t mirr_flags;
  int32_t mirr_marker;
  int32_t mirr_vni;
  uint8_t pad[2];
  int16_t mirr_vlan;
};

/* sandesh vr_flow_req */
struct fr { 
  flow_op fr_op;
  uint8_t pad1[2];
  int16_t fr_rid;
  int32_t fr_index;
  int16_t fr_action;
  int16_t fr_flags;
  int32_t fr_rindex;
  int32_t fr_family;
  uint64_t fr_flow_sip_u;
  uint64_t fr_flow_sip_l;
  uint64_t fr_flow_dip_u;
  uint64_t fr_flow_dip_l;
  uint16_t fr_flow_sport;
  uint16_t fr_flow_dport;
  uint8_t pad2[3];
  int8_t fr_flow_proto;
  uint16_t fr_flow_vrf;
  uint16_t fr_flow_dvrf;
  uint16_t fr_mir_id;
  uint16_t fr_sec_mir_id;
  uint32_t fr_mir_sip;
  uint16_t fr_mir_sport;
  uint16_t fr_mir_vrf;
  uint32_t fr_ecmp_nh_index;
  uint32_t fr_src_nh_index;
  uint32_t fr_flow_nh_id;
  uint16_t fr_drop_reason;
  uint8_t pad3[1];
  int8_t fr_gen_id;
  uint64_t fr_rflow_sip_u;
  uint64_t fr_rflow_sip_l;
  uint64_t fr_rflow_dip_u;
  uint64_t fr_rflow_dip_l;
  uint32_t fr_rflow_nh_id;
  uint16_t fr_rflow_sport;
  uint16_t fr_rflow_dport;
  uint16_t fr_qos_id;
  uint8_t pad4[5];
  int8_t fr_ttl;
  int16_t fr_extflags;
  int16_t fr_flags1;
  int8_t fr_underlay_ecmp_index;
  uint8_t pad5[3];
};

/* sandesh vr_response */
struct resp { 
  sandesh_op h_op;
  int32_t resp_code;
};

/* sandesh vr_flow_table_data */
struct ftable { 
  flow_op ftable_op;
  uint16_t ftable_rid;
  uint16_t ftable_dev;
  uint64_t ftable_used_entries;
  uint64_t ftable_processed;
  uint64_t ftable_deleted;
  uint64_t ftable_added;
  uint64_t ftable_created;
  uint64_t ftable_changed;
  uint32_t ftable_size;
  uint32_t ftable_hold_oflows;
  uint32_t ftable_cpus;
  uint32_t ftable_oflow_entries;
  uint32_t ftable_burst_free_tokens;
  uint32_t ftable_hold_entries;
};

/* sandesh vr_vrf_req */
struct vrf { 
  sandesh_op h_op;
  uint8_t pad[2];
  int16_t vrf_rid;
  int32_t vrf_idx;
  int32_t vrf_flags;
  int32_t vrf_hbfl_vif_idx;
  int32_t vrf_hbfr_vif_idx;
  int32_t vrf_marker;
};

/* sandesh vr_vxlan_req */
struct vxlanr { 
  sandesh_op h_op;
  uint8_t pad[2];
  int16_t vxlanr_rid;
  int32_t vxlanr_vnid;
  int32_t vxlanr_nhid;
};

/* sandesh vr_fc_map_req */
struct fmr { 
  sandesh_op h_op;
  uint16_t fmr_rid;
  int16_t fmr_marker;
  uint8_t pad[8];
 };

/* sandesh vr_qos_map_req */
struct qmr { 
  sandesh_op h_op;
  uint16_t qmr_rid;
  uint16_t qmr_id;
  uint8_t pad[6];
  int16_t qmr_marker;
};

/* sandesh vr_drop_stats_req */
struct vds { 
  sandesh_op h_op;
  int16_t vds_rid;
  int16_t vds_core;
  int64_t vds_discard;
  uint8_t pad[7];
  int8_t vds_pcpu_stats_failure_status;
  int64_t vds_pull;
  int64_t vds_invalid_if;
  int64_t vds_invalid_arp;
  int64_t vds_trap_no_if;
  int64_t vds_nowhere_to_go;
  int64_t vds_flow_queue_limit_exceeded;
  int64_t vds_flow_no_memory;
  int64_t vds_flow_invalid_protocol;
  int64_t vds_flow_nat_no_rflow;
  int64_t vds_flow_action_drop;
  int64_t vds_flow_action_invalid;
  int64_t vds_flow_unusable;
  int64_t vds_flow_table_full;
  int64_t vds_interface_tx_discard;
  int64_t vds_interface_drop;
  int64_t vds_duplicated;
  int64_t vds_push;
  int64_t vds_ttl_exceeded;
  int64_t vds_invalid_nh;
  int64_t vds_invalid_label;
  int64_t vds_invalid_protocol;
  int64_t vds_interface_rx_discard;
  int64_t vds_invalid_mcast_source;
  int64_t vds_head_alloc_fail;
  int64_t vds_pcow_fail;
  int64_t vds_mcast_df_bit;
  int64_t vds_mcast_clone_fail;
  int64_t vds_no_memory;
  int64_t vds_rewrite_fail;
  int64_t vds_misc;
  int64_t vds_invalid_packet;
  int64_t vds_cksum_err;
  int64_t vds_no_fmd;
  int64_t vds_cloned_original;
  int64_t vds_invalid_vnid;
  int64_t vds_frag_err;
  int64_t vds_invalid_source;
  int64_t vds_l2_no_route;
  int64_t vds_fragment_queue_fail;
  int64_t vds_vlan_fwd_tx;
  int64_t vds_vlan_fwd_enq;
  int64_t vds_drop_new_flow;
  int64_t vds_flow_evict;
  int64_t vds_trap_original;
  int64_t vds_leaf_to_leaf;
  int64_t vds_bmac_isid_mismatch;
  int64_t vds_pkt_loop;
  int64_t vds_no_crypt_path;
  int64_t vds_invalid_hbs_pkt;
  int64_t vds_no_frag_entry;
  int64_t vds_icmp_error;
};

/* sandesh vr_bridge_table_data */
struct btable { 
  /* public */
  sandesh_op btable_op;
  uint16_t btable_rid;
  uint16_t btable_dev;
  uint8_t pad[4];
  uint32_t btable_size;
};
