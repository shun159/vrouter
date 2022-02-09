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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 24);
    __type(key, uint64_t);
    __type(value, struct vifr);
} arg_data SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, uint32_t);
    __type(value, uint64_t);
} sreq_index SEC(".maps");


#define KPROBE(sname, processor)                       \
SEC("kprobe/##sname")                                  \
int sname##1(struct pt_regs *ctx) {                    \
    sname *req = (sname *)PT_REGS_PARM1(ctx);      \
    return processor(ctx, 0, req);                   \
}                                                      \
SEC("kprobe/##sname")                                  \
int sname##2(struct pt_regs *ctx) {                    \
    sname *req = (sname *)PT_REGS_PARM2(ctx);      \
    return processor(ctx, 0, req);                   \
}                                                      \
SEC("kprobe/##sname")                                  \
int sname##3(struct pt_regs *ctx) {                    \
    sname *req = (sname *)PT_REGS_PARM3(ctx);      \
    return processor(ctx, 0, req);                   \
}                                                      \
SEC("kprobe/##sname")                                  \
int sname##4(struct pt_regs *ctx) {                    \
    sname *req = (sname *)PT_REGS_PARM4(ctx);      \
    return processor(ctx, 0, req);                   \
}                                                      \
SEC("kprobe/##sname")                                  \
int sname##5(struct pt_regs *ctx) {                    \
    sname *req = (sname *)PT_REGS_PARM5(ctx);      \
    return processor(ctx, 0, req);                   \
}                                                      


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
  
    bpf_probe_read_kernel_str(s_req.vifr_name, sizeof(s_req.vifr_name) - 1, &req->vifr_name);
    bpf_probe_read_kernel(&s_req.h_op, sizeof(s_req.h_op), &req->h_op);
    bpf_probe_read_kernel(&s_req.vifr_type, sizeof(s_req.vifr_type), &req->vifr_type);
    bpf_probe_read_kernel(&s_req.vifr_flags, sizeof(s_req.vifr_flags), &req->vifr_flags);
    bpf_probe_read_kernel(&s_req.vifr_vrf, sizeof(s_req.vifr_vrf), &req->vifr_vrf);
    bpf_probe_read_kernel(&s_req.vifr_idx, sizeof(s_req.vifr_idx), &req->vifr_idx);
    bpf_probe_read_kernel(&s_req.vifr_rid, sizeof(s_req.vifr_rid), &req->vifr_rid);
    bpf_probe_read_kernel(&s_req.vifr_os_idx, sizeof(s_req.vifr_os_idx), &req->vifr_os_idx);
    bpf_probe_read_kernel(&s_req.vifr_mtu, sizeof(s_req.vifr_mtu), &req->vifr_mtu);
    bpf_probe_read_kernel(&s_req.vifr_vlan_id, sizeof(s_req.vifr_vlan_id), &req->vifr_vlan_id);

    uint64_t idx = add_idx_by_1(0);

    e.tstamp = bpf_ktime_get_ns();
    e.faddr = get_func_ip(ctx);
    e.processor_id = bpf_get_smp_processor_id();
    e.is_return = is_return;
    e.arg_size = (uint64_t)sizeof(vr_interface_req);
    e.index = idx;

    bpf_printk("vifr_size: %d\n", sizeof(struct vifr));

    bpf_map_update_elem(&arg_data, &idx, &s_req, BPF_ANY);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

static __inline int
vr_route_body(void *ctx, int8_t is_return, vr_route_req *req) {
    //bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return, sizeof(vr_route_req));
}

static __inline int
vr_nexthop_body(void *ctx, int8_t is_return, vr_nexthop_req *req) {
    //bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return, sizeof(vr_nexthop_req));
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
