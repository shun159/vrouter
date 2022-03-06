// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <stdint.h>
#include <linux/types.h>
#include <uapi/linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "vr_packet.h"
#include "vrft_sandesh.h"
#include "vrft_maps.h"
#include "vrft_utils.h"
#include "vrft_packet.h"

#define __unused __attribute__((unused))

typedef struct vr_packet vr_packet;

static __inline int
handle_vr_interface(void *ctx, int8_t is_return, struct _vr_interface_req *req) {
    struct vifr s_req = {0};
    uint64_t idx = incr_monotonic_counter(0);
    bpf_probe_read((void *)&s_req.h_op, sizeof(s_req.h_op), (void *)1);

    READ_KERNEL(h_op);
    READ_KERNEL(vifr_core);
    READ_KERNEL(vifr_type);
    READ_KERNEL(vifr_flags);
    READ_KERNEL(vifr_vrf);
    READ_KERNEL(vifr_idx);
    READ_KERNEL(vifr_rid);
    READ_KERNEL(vifr_os_idx);
    READ_KERNEL(vifr_mtu);
    READ_KERNEL(vifr_ref_cnt);
    READ_KERNEL(vifr_marker);
    READ_KERNEL(vifr_ip);
    READ_KERNEL(vifr_ip6_u);
    READ_KERNEL(vifr_ip6_l);
    READ_KERNEL(vifr_vlan_id);
    READ_KERNEL(vifr_nh_id);
    READ_KERNEL(vifr_transport);
    READ_KERNEL_STR(vifr_name);

    bpf_map_update_elem(&vr_interface_req_map, &idx, &s_req, BPF_ANY);
    emit_vrft_event(ctx, is_return, idx);
    return 0;
}

static __inline int
handle_vr_route(void *ctx, int8_t is_return, vr_route_req *req) {
    struct rtr s_req = {0};
    uint64_t idx = incr_monotonic_counter(0);

    READ_KERNEL(h_op);
    READ_KERNEL(rtr_vrf_id);
    READ_KERNEL(rtr_family);
    READ_KERNEL(rtr_rid);
    READ_KERNEL(rtr_nh_id);
    READ_KERNEL(rtr_index);

    bpf_map_update_elem(&vr_route_req_map, &idx, &s_req, BPF_ANY);
    emit_vrft_event(ctx, is_return, idx);
    return 0;
}

static __inline int
handle_vr_nexthop(void *ctx, int8_t is_return, vr_nexthop_req *req) {
    struct nhr s_req = {0};
    uint64_t idx = incr_monotonic_counter(0);

    READ_KERNEL(h_op);
    READ_KERNEL(nhr_type);
    READ_KERNEL(nhr_family);
    READ_KERNEL(nhr_id);
    READ_KERNEL(nhr_rid);
    READ_KERNEL(nhr_flags);

    bpf_map_update_elem(&vr_nexthop_req_map, &idx, &s_req, BPF_ANY);
    emit_vrft_event(ctx, is_return, idx);
    return 0;
}

static __inline int
handle_vr_vrf_assign(void *ctx, int8_t is_return, vr_vrf_assign_req *req) {
    struct var s_req = {0};
    uint64_t idx = incr_monotonic_counter(0);

    READ_KERNEL(h_op);
    READ_KERNEL(var_rid);
    READ_KERNEL(var_vif_index);
    READ_KERNEL(var_vif_vrf);
    READ_KERNEL(var_vlan_id);
    READ_KERNEL(var_marker);
    READ_KERNEL(var_nh_id);

    bpf_map_update_elem(&vr_vrf_assign_req_map, &idx, &s_req, BPF_ANY);
    emit_vrft_event(ctx, is_return, idx);
    return 0;
}

static __inline int
handle_vr_mpls(void *ctx, int8_t is_return, vr_mpls_req *req) {
    struct mr s_req = {0};
    uint64_t idx = incr_monotonic_counter(0);

    READ_KERNEL(h_op);
    READ_KERNEL(mr_label);
    READ_KERNEL(mr_rid);
    READ_KERNEL(mr_nhid);
    READ_KERNEL(mr_marker);

    bpf_map_update_elem(&vr_mpls_req_map, &idx, &s_req, BPF_ANY);
    emit_vrft_event(ctx, is_return, idx);
    return 0;
}

static __inline int
handle_vr_vrf_stats(void *ctx, int8_t is_return, vr_vrf_stats_req *req) {
    struct vsr s_req = {0};
    uint64_t idx = incr_monotonic_counter(0);

    READ_KERNEL(h_op);
    READ_KERNEL(vsr_rid);
    READ_KERNEL(vsr_family);
    READ_KERNEL(vsr_type);
    READ_KERNEL(vsr_vrf);
    READ_KERNEL(vsr_discards);
    READ_KERNEL(vsr_resolves);
    READ_KERNEL(vsr_receives);
    READ_KERNEL(vsr_ecmp_composites);
    READ_KERNEL(vsr_l2_mcast_composites);
    READ_KERNEL(vsr_fabric_composites);
    READ_KERNEL(vsr_udp_tunnels);
    READ_KERNEL(vsr_udp_mpls_tunnels);
    READ_KERNEL(vsr_gre_mpls_tunnels);
    READ_KERNEL(vsr_l2_encaps);
    READ_KERNEL(vsr_encaps);
    READ_KERNEL(vsr_marker);
    READ_KERNEL(vsr_gros);
    READ_KERNEL(vsr_diags);
    READ_KERNEL(vsr_encap_composites);
    READ_KERNEL(vsr_evpn_composites);
    READ_KERNEL(vsr_vrf_translates);
    READ_KERNEL(vsr_vxlan_tunnels);
    READ_KERNEL(vsr_arp_virtual_proxy);
    READ_KERNEL(vsr_arp_virtual_stitch);
    READ_KERNEL(vsr_arp_virtual_flood);
    READ_KERNEL(vsr_arp_physical_stitch);
    READ_KERNEL(vsr_arp_tor_proxy);
    READ_KERNEL(vsr_arp_physical_flood);
    READ_KERNEL(vsr_l2_receives);
    READ_KERNEL(vsr_uuc_floods);
    READ_KERNEL(vsr_pbb_tunnels);
    READ_KERNEL(vsr_udp_mpls_over_mpls_tunnels);

    bpf_map_update_elem(&vr_vrf_stats_req_map, &idx, &s_req, BPF_ANY);
    emit_vrft_event(ctx, is_return, idx);
    return 0;
}

static __inline int
handle_vr_mirror(void *ctx, int8_t is_return, vr_mirror_req *req) {
    struct mirr s_req = {0};
    uint64_t idx = incr_monotonic_counter(0);

    READ_KERNEL(h_op);
    READ_KERNEL(mirr_index);
    READ_KERNEL(mirr_rid);
    READ_KERNEL(mirr_nhid);
    READ_KERNEL(mirr_users);
    READ_KERNEL(mirr_flags);
    READ_KERNEL(mirr_marker);
    READ_KERNEL(mirr_vni);
    READ_KERNEL(mirr_vlan);

    bpf_map_update_elem(&vr_mirror_req_map, &idx, &s_req, BPF_ANY);
    emit_vrft_event(ctx, is_return, idx);
    return 0;
}

static __inline int
handle_vr_flow(void *ctx, int8_t is_return, vr_flow_req *req) {
    struct fr s_req = {0};
    uint64_t idx = incr_monotonic_counter(0);

    READ_KERNEL(fr_op);
    READ_KERNEL(fr_rid);
    READ_KERNEL(fr_index);
    READ_KERNEL(fr_action);
    READ_KERNEL(fr_flags);
    READ_KERNEL(fr_rindex);
    READ_KERNEL(fr_family);
    READ_KERNEL(fr_flow_sip_u);
    READ_KERNEL(fr_flow_sip_l);
    READ_KERNEL(fr_flow_dip_u);
    READ_KERNEL(fr_flow_dip_l);
    READ_KERNEL(fr_flow_sport);
    READ_KERNEL(fr_flow_dport);
    READ_KERNEL(fr_flow_proto);
    READ_KERNEL(fr_flow_vrf);
    READ_KERNEL(fr_flow_dvrf);
    READ_KERNEL(fr_mir_id);
    READ_KERNEL(fr_sec_mir_id);
    READ_KERNEL(fr_mir_sip);
    READ_KERNEL(fr_mir_sport);
    READ_KERNEL(fr_mir_vrf);
    READ_KERNEL(fr_ecmp_nh_index);
    READ_KERNEL(fr_src_nh_index);
    READ_KERNEL(fr_flow_nh_id);
    READ_KERNEL(fr_drop_reason);
    READ_KERNEL(fr_gen_id);
    READ_KERNEL(fr_rflow_sip_u);
    READ_KERNEL(fr_rflow_sip_l);
    READ_KERNEL(fr_rflow_dip_u);
    READ_KERNEL(fr_rflow_dip_l);
    READ_KERNEL(fr_rflow_nh_id);
    READ_KERNEL(fr_rflow_sport);
    READ_KERNEL(fr_rflow_dport);
    READ_KERNEL(fr_ttl);
    READ_KERNEL(fr_extflags);
    READ_KERNEL(fr_flags1);
    READ_KERNEL(fr_qos_id);
    READ_KERNEL(fr_underlay_ecmp_index);

    SREQ_NTOHL(fr_flow_sip_u);
    SREQ_NTOHL(fr_flow_sip_l);
    SREQ_NTOHL(fr_flow_dip_u);
    SREQ_NTOHL(fr_flow_dip_l);
    SREQ_NTOHL(fr_rflow_sip_u);
    SREQ_NTOHL(fr_rflow_sip_l);
    SREQ_NTOHL(fr_rflow_dip_u);
    SREQ_NTOHL(fr_rflow_dip_l);
    SREQ_NTOHS(fr_flow_sport);
    SREQ_NTOHS(fr_flow_dport);
    SREQ_NTOHS(fr_rflow_sport);
    SREQ_NTOHS(fr_rflow_dport);

    bpf_map_update_elem(&vr_flow_req_map, &idx, &s_req, BPF_ANY);
    emit_vrft_event(ctx, is_return, idx);
    return 0;
}

static __inline int
handle_vr_response(void *ctx, int8_t is_return, vr_response *req) {
    struct resp s_req = {0};
    uint64_t idx = incr_monotonic_counter(0);

    READ_KERNEL(h_op);
    READ_KERNEL(resp_code);

    bpf_map_update_elem(&vr_response_map, &idx, &s_req, BPF_ANY);
    emit_vrft_event(ctx, is_return, idx);
    return 0;
}

static __inline int 
handle_vr_flow_table_data(void *ctx, int8_t is_return, vr_flow_table_data *req) {
    struct vrft_event e = {0};
    struct ftable s_req = {0};
    uint64_t idx = incr_monotonic_counter(0);

    READ_KERNEL(ftable_op);
    READ_KERNEL(ftable_rid);
    READ_KERNEL(ftable_size);
    READ_KERNEL(ftable_dev);
    READ_KERNEL(ftable_used_entries);
    READ_KERNEL(ftable_processed);
    READ_KERNEL(ftable_deleted);
    READ_KERNEL(ftable_added);
    READ_KERNEL(ftable_created);
    READ_KERNEL(ftable_changed);
    READ_KERNEL(ftable_hold_oflows);
    READ_KERNEL(ftable_cpus);
    READ_KERNEL(ftable_oflow_entries);
    READ_KERNEL(ftable_burst_free_tokens);
    READ_KERNEL(ftable_hold_entries);

    bpf_map_update_elem(&vr_flow_table_data_map, &idx, &s_req, BPF_ANY);
    emit_vrft_event(ctx, is_return, idx);
    return 0;
}

static __inline int
handle_vr_vrf(void *ctx, int8_t is_return, vr_vrf_req *req) {
    struct vrf s_req = {0};
    uint64_t idx = incr_monotonic_counter(0);

    READ_KERNEL(h_op);
    READ_KERNEL(vrf_rid);
    READ_KERNEL(vrf_idx);
    READ_KERNEL(vrf_flags);
    READ_KERNEL(vrf_hbfl_vif_idx);
    READ_KERNEL(vrf_hbfr_vif_idx);
    READ_KERNEL(vrf_marker);

    bpf_map_update_elem(&vr_vrf_req_map, &idx, &s_req, BPF_ANY);
    emit_vrft_event(ctx, is_return, idx);
    return 0;
}

static __inline int
handle_vr_vxlan(void *ctx, int8_t is_return, vr_vxlan_req *req) {
    struct vxlanr s_req = {0};
    uint64_t idx = incr_monotonic_counter(0);

    READ_KERNEL(h_op);
    READ_KERNEL(vxlanr_rid);
    READ_KERNEL(vxlanr_vnid);
    READ_KERNEL(vxlanr_nhid);

    bpf_map_update_elem(&vr_vxlan_req_map, &idx, &s_req, BPF_ANY);
    emit_vrft_event(ctx, is_return, idx);
    return 0;
}

static __inline int
handle_vr_fc_map(void *ctx, int8_t is_return, vr_fc_map_req *req) {
    struct fmr s_req = {0};
    uint64_t idx = incr_monotonic_counter(0);

    READ_KERNEL(h_op);
    READ_KERNEL(fmr_rid);
    READ_KERNEL(fmr_marker);

    bpf_map_update_elem(&vr_fc_map_req_map, &idx, &s_req, BPF_ANY);
    emit_vrft_event(ctx, is_return, idx);
    return 0;
}

static __inline int
handle_vr_qos_map(void *ctx, int8_t is_return, vr_qos_map_req *req) {
    struct qmr s_req = {0};
    uint64_t idx = incr_monotonic_counter(0);

    READ_KERNEL(h_op);
    READ_KERNEL(qmr_rid);
    READ_KERNEL(qmr_id);
    READ_KERNEL(qmr_marker);

    bpf_map_update_elem(&vr_qos_map_req_map, &idx, &s_req, BPF_ANY);
    emit_vrft_event(ctx, is_return, idx);
    return 0;
}

static __inline int
handle_vr_drop_stats(void *ctx, int8_t is_return, vr_drop_stats_req *req) {
    struct vds s_req = {0};
    uint64_t idx = incr_monotonic_counter(0);

    READ_KERNEL(h_op);
    READ_KERNEL(vds_rid);
    READ_KERNEL(vds_core);
    READ_KERNEL(vds_discard);
    READ_KERNEL(vds_pcpu_stats_failure_status);
    READ_KERNEL(vds_pull);
    READ_KERNEL(vds_invalid_if);
    READ_KERNEL(vds_invalid_arp);
    READ_KERNEL(vds_trap_no_if);
    READ_KERNEL(vds_nowhere_to_go);
    READ_KERNEL(vds_flow_queue_limit_exceeded);
    READ_KERNEL(vds_flow_no_memory);
    READ_KERNEL(vds_flow_invalid_protocol);
    READ_KERNEL(vds_flow_nat_no_rflow);
    READ_KERNEL(vds_flow_action_drop);
    READ_KERNEL(vds_flow_action_invalid);
    READ_KERNEL(vds_flow_unusable);
    READ_KERNEL(vds_flow_table_full);
    READ_KERNEL(vds_interface_tx_discard);
    READ_KERNEL(vds_interface_drop);
    READ_KERNEL(vds_duplicated);
    READ_KERNEL(vds_push);
    READ_KERNEL(vds_ttl_exceeded);
    READ_KERNEL(vds_invalid_nh);
    READ_KERNEL(vds_invalid_label);
    READ_KERNEL(vds_invalid_protocol);
    READ_KERNEL(vds_interface_rx_discard);
    READ_KERNEL(vds_invalid_mcast_source);
    READ_KERNEL(vds_head_alloc_fail);
    READ_KERNEL(vds_pcow_fail);
    READ_KERNEL(vds_mcast_df_bit);
    READ_KERNEL(vds_mcast_clone_fail);
    READ_KERNEL(vds_no_memory);
    READ_KERNEL(vds_rewrite_fail);
    READ_KERNEL(vds_misc);
    READ_KERNEL(vds_invalid_packet);
    READ_KERNEL(vds_cksum_err);
    READ_KERNEL(vds_no_fmd);
    READ_KERNEL(vds_cloned_original);
    READ_KERNEL(vds_invalid_vnid);
    READ_KERNEL(vds_frag_err);
    READ_KERNEL(vds_invalid_source);
    READ_KERNEL(vds_l2_no_route);
    READ_KERNEL(vds_fragment_queue_fail);
    READ_KERNEL(vds_vlan_fwd_tx);
    READ_KERNEL(vds_vlan_fwd_enq);
    READ_KERNEL(vds_drop_new_flow);
    READ_KERNEL(vds_flow_evict);
    READ_KERNEL(vds_trap_original);
    READ_KERNEL(vds_leaf_to_leaf);
    READ_KERNEL(vds_bmac_isid_mismatch);
    READ_KERNEL(vds_pkt_loop);
    READ_KERNEL(vds_no_crypt_path);
    READ_KERNEL(vds_invalid_hbs_pkt);
    READ_KERNEL(vds_no_frag_entry);
    READ_KERNEL(vds_icmp_error);

    bpf_map_update_elem(&vr_drop_stats_req_map, &idx, &s_req, BPF_ANY);
    emit_vrft_event(ctx, is_return, idx);
    return 0;
}

static __inline int
handle_vr_bridge_table_data(void *ctx, int8_t is_return, vr_bridge_table_data *req) {
    struct btable s_req = {0};
    uint64_t idx = incr_monotonic_counter(0);

    READ_KERNEL(btable_op);
    READ_KERNEL(btable_rid);
    READ_KERNEL(btable_dev);
    READ_KERNEL(btable_size);

    bpf_map_update_elem(&vr_bridge_table_data_map, &idx, &s_req, BPF_ANY);
    emit_vrft_event(ctx, is_return, idx);
    return 0;
}

static __inline int
handle_vr_packet(void *ctx, int8_t is_return, struct vr_packet *req) {
    struct vr_packet s_req = {0};
    struct packet_data pkt_data = {0};
    uint32_t pull_len;
    uint64_t idx = incr_monotonic_counter(0);

    unsigned char eth_dmac[VR_ETHER_ALEN] = {0};
    unsigned char eth_smac[VR_ETHER_ALEN] = {0};
    unsigned short eth_proto;

    READ_KERNEL(vp_head);
    READ_KERNEL(vp_data);
    READ_KERNEL(vp_type);
    READ_KERNEL(vp_end);
    READ_KERNEL(vp_network_h);

    struct vr_eth *eth = (struct  vr_eth *)vr_pkt_data(&s_req);
    bpf_probe_read_kernel(&eth_proto, sizeof(eth_proto), &eth->eth_proto);
    bpf_probe_read_kernel(&eth_dmac, VR_ETHER_ALEN, &eth->eth_dmac);
    bpf_probe_read_kernel(&eth_smac, VR_ETHER_ALEN, &eth->eth_smac);

    __builtin_memcpy(&pkt_data.eth_dmac, &eth_dmac, sizeof(pkt_data.eth_dmac));
    __builtin_memcpy(&pkt_data.eth_smac, &eth_smac, sizeof(pkt_data.eth_smac));
    __builtin_memcpy(&pkt_data.eth_proto, &eth_proto, sizeof(pkt_data.eth_proto));

    // For debugging
    switch (s_req.vp_type) {
    case VP_TYPE_ARP:
        bpf_printk("ARP packet received\n");
        break;
    case VP_TYPE_IP:
        bpf_printk("IPv4 packet received\n");
        parse_vr_ip4(&s_req, &pkt_data);
        break;
    case VP_TYPE_IP6:
        bpf_printk("IPv6 packet received\n");
        break;
    case VP_TYPE_IPOIP:
        bpf_printk("IPv4overIPv4 packet received\n");
        break;
    case VP_TYPE_IP6OIP:
        bpf_printk("IPv4overIPv6 packet received\n");
        break;
    case VP_TYPE_AGENT:
        bpf_printk("vrouter agent packet received\n");
        break;
    case VP_TYPE_PBB:
        bpf_printk("PBB packet received\n");
        break;
    default:
        bpf_printk("Unknown Type received: %d\n", s_req.vp_type);
    }

    bpf_map_update_elem(&vr_packet_map, &idx, &pkt_data, BPF_ANY);
    emit_vrft_event(ctx, is_return, idx);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
unsigned int _version SEC("version") = 0xFFFFFFFE;
