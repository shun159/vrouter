#pragma once

#include <stdint.h>
#include <linux/types.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "vrft_sandesh.h"
#include "vrouter.h"

#define __unused __attribute__((unused))

static uint64_t get_func_ip(void *ctx);

#define READ_KERNEL(field)    \
    bpf_probe_read_kernel(    \
        s_req.field,          \
        sizeof(s_req.field),  \
        &req->field           \
    );

struct vrft_event {
    uint64_t tstamp;
    uint64_t faddr;
    uint32_t processor_id;
    uint8_t is_return;
    uint8_t __pad1[3];
    uint64_t arg_size;
    uint64_t index;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(uint32_t));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, uint32_t);
    __type(value, uint64_t);
} sreq_index SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 24);
    __type(key, uint64_t);
    __type(value, struct vifr);
} vr_interface_req_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 24);
    __type(key, uint64_t);
    __type(value, struct nhr);
} vr_nexthop_req_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 24);
    __type(key, uint64_t);
    __type(value, struct rtr);
} vr_route_req_map SEC(".maps");

static __inline int
emit_vrft_event(void *ctx, int8_t is_return, size_t arg_size) {
   struct vrft_event e = {0};
    e.tstamp = bpf_ktime_get_ns();
    e.faddr = get_func_ip(ctx);
    e.processor_id = bpf_get_smp_processor_id();
    e.is_return = is_return;
    e.arg_size = (uint64_t)arg_size;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

static __inline uint64_t
add_idx_by_1(uint32_t key) {
    uint64_t init_val = 0;
    uint64_t *value = bpf_map_lookup_elem(&sreq_index, &key);

    if (value) {
        uint64_t ret = *value;
        __sync_fetch_and_add(value, 1);
        return ret;
    }
    else {
        bpf_map_update_elem(&sreq_index, &key, &init_val, BPF_ANY);
        return 0;
    }
}

static __inline int
vr_interface_body(void *ctx, int8_t is_return, vr_interface_req *req) {
    struct vrft_event e = {0};
    struct vifr s_req = {0};
    uint64_t idx = add_idx_by_1(0);
  
    bpf_probe_read_kernel_str(s_req.vifr_name, sizeof(s_req.vifr_name) - 1, &req->vifr_name);
    READ_KERNEL(h_op);
    READ_KERNEL(vifr_type);
    READ_KERNEL(vifr_flags);
    READ_KERNEL(vifr_vrf);
    READ_KERNEL(vifr_idx);
    READ_KERNEL(vifr_rid);
    READ_KERNEL(vifr_os_idx);
    READ_KERNEL(vifr_mtu);
    READ_KERNEL(vifr_vlan_id);

    e.tstamp = bpf_ktime_get_ns();
    e.faddr = get_func_ip(ctx);
    e.processor_id = bpf_get_smp_processor_id();
    e.is_return = is_return;
    e.arg_size = (uint64_t)sizeof(vr_interface_req);
    e.index = idx;

    bpf_map_update_elem(&vr_route_req_map, &idx, &s_req, BPF_ANY);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

static __inline int
vr_route_body(void *ctx, int8_t is_return, vr_route_req *req) {
    struct vrft_event e = {0};
    struct rtr s_req = {0};
    uint64_t idx = add_idx_by_1(0);

    READ_KERNEL(h_op);
    READ_KERNEL(rtr_vrf_id);
    READ_KERNEL(rtr_family);
    READ_KERNEL(rtr_prefix);
    READ_KERNEL(rtr_prefix_size);
    READ_KERNEL(rtr_prefix_len);
    READ_KERNEL(rtr_rid);
    READ_KERNEL(rtr_label_flags);
    READ_KERNEL(rtr_label);
    READ_KERNEL(rtr_nh_id);
    READ_KERNEL(rtr_marker);
    READ_KERNEL(rtr_marker_size);
    READ_KERNEL(rtr_marker_plen);
    READ_KERNEL(rtr_mac);
    READ_KERNEL(rtr_mac_size);
    READ_KERNEL(rtr_replace_plen);
    READ_KERNEL(rtr_index);

    e.tstamp = bpf_ktime_get_ns();
    e.faddr = get_func_ip(ctx);
    e.processor_id = bpf_get_smp_processor_id();
    e.is_return = is_return;
    e.arg_size = (uint64_t)sizeof(vr_interface_req);
    e.index = idx;

    bpf_map_update_elem(&vr_nexthop_req_map, &idx, &s_req, BPF_ANY);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

static __inline int
vr_nexthop_body(void *ctx, int8_t is_return, vr_nexthop_req *req) {
    struct vrft_event e = {0};
    struct nhr s_req = {0};
    uint64_t idx = add_idx_by_1(0);

    READ_KERNEL(h_op);
    READ_KERNEL(nhr_type);
    READ_KERNEL(nhr_family);
    READ_KERNEL(nhr_id);
    READ_KERNEL(nhr_rid);
    READ_KERNEL(nhr_encap_oif_id);
    READ_KERNEL(nhr_encap_oif_id_size);
    READ_KERNEL(nhr_encap_len);
    READ_KERNEL(nhr_encap_family);
    READ_KERNEL(nhr_vrf);
    READ_KERNEL(nhr_tun_sip);
    READ_KERNEL(nhr_tun_dip);
    READ_KERNEL(nhr_tun_sport);
    READ_KERNEL(nhr_tun_dport);
    READ_KERNEL(nhr_ref_cnt);
    READ_KERNEL(nhr_marker);
    READ_KERNEL(nhr_flags);
    READ_KERNEL(nhr_encap);
    READ_KERNEL(nhr_encap_size);
    READ_KERNEL(nhr_nh_list);
    READ_KERNEL(nhr_nh_list_size);
    READ_KERNEL(nhr_label_list);
    READ_KERNEL(nhr_label_list_size);
    READ_KERNEL(nhr_nh_count);
    READ_KERNEL(nhr_tun_sip6);
    READ_KERNEL(nhr_tun_sip6_size);
    READ_KERNEL(nhr_tun_dip6);
    READ_KERNEL(nhr_tun_dip6_size);
    READ_KERNEL(nhr_ecmp_config_hash);
    READ_KERNEL(nhr_pbb_mac);
    READ_KERNEL(nhr_pbb_mac_size);
    READ_KERNEL(nhr_encap_crypt_oif_id);
    READ_KERNEL(nhr_crypt_traffic);
    READ_KERNEL(nhr_crypt_path_available);
    READ_KERNEL(nhr_rw_dst_mac);
    READ_KERNEL(nhr_rw_dst_mac_size);
    READ_KERNEL(nhr_transport_label);
    READ_KERNEL(nhr_encap_valid);
    READ_KERNEL(nhr_encap_valid_size);

    e.tstamp = bpf_ktime_get_ns();
    e.faddr = get_func_ip(ctx);
    e.processor_id = bpf_get_smp_processor_id();
    e.is_return = is_return;
    e.arg_size = (uint64_t)sizeof(vr_interface_req);
    e.index = idx;

    bpf_map_update_elem(&vr_nexthop_req_map, &idx, &s_req, BPF_ANY);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

static __inline int
vr_vrf_assign_body(void *ctx, int8_t is_return, vr_vrf_assign_req *req) {
    //bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return, sizeof(vr_vrf_assign_req));
}

static __inline int
vr_mpls_body(void *ctx, int8_t is_return, vr_mpls_req *req) {
    //bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return, sizeof(vr_mpls_req));
}

static __inline int
vr_vrf_stats_body(void *ctx, int8_t is_return, vr_vrf_stats_req *req) {
    //bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return, sizeof(vr_vrf_stats_req));
}

static __inline int
vr_mirror_body(void *ctx, int8_t is_return, vr_mirror_req *req) {
    //bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return, sizeof(vr_vrf_req));
}

static __inline int
vr_flow_body(void *ctx, int8_t is_return, vr_flow_req *req) {
    //bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return, sizeof(vr_flow_req));
}

static __inline int
vr_response_body(void *ctx, int8_t is_return, vr_response *req) {
    //bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return, sizeof(vr_response));
}

static __inline int 
vr_flow_table_data_body(void *ctx, int8_t is_return, vr_flow_table_data *req) {
    //bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return, sizeof(vr_flow_table_data));
}

static __inline int
vr_vrf_body(void *ctx, int8_t is_return, vr_vrf_req *req) {
    //bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return, sizeof(vr_vrf_req));
}

static __inline int
vr_vxlan_body(void *ctx, int8_t is_return, vr_vxlan_req *req) {
    //bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return, sizeof(vr_vxlan_req));
}

static __inline int
vr_fc_map_body(void *ctx, int8_t is_return, vr_fc_map_req *req) {
    //bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return, sizeof(vr_fc_map_req));
}

static __inline int
vr_qos_map_body(void *ctx, int8_t is_return, vr_qos_map_req *req) {
    //bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return, sizeof(vr_qos_map_req));
}

static __inline int
vr_drop_stats_body(void *ctx, int8_t is_return, vr_drop_stats_req *req) {
    //bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return, sizeof(vr_drop_stats_req));
}

static __inline int
vr_bridge_table_data_body(void *ctx, int8_t is_return, vr_bridge_table_data *req) {
    //bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return, sizeof(vr_bridge_table_data));
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
unsigned int _version SEC("version") = 0xFFFFFFFE;
