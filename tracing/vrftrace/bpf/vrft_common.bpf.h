#pragma once

#include <stdint.h>
#include <linux/types.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "vrouter.h"

#define __unused __attribute__((unused))

static uint64_t get_func_ip(void *ctx);

struct vrft_event {
    uint64_t tstamp;
    uint64_t faddr;
    uint32_t processor_id;
    uint8_t is_return;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(uint32_t));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK);
	__uint(max_entries, 32);
	__uint(map_flags, 0);
	__uint(key_size, 0);
	__uint(value_size, sizeof(__u32));
} arg_data SEC(".maps");

static __inline int
emit_vrft_event(void *ctx, int8_t is_return) {
   struct vrft_event e = {0};

    e.tstamp = bpf_ktime_get_ns();
    e.faddr = get_func_ip(ctx);
    e.processor_id = bpf_get_smp_processor_id();
    e.is_return = is_return;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

static __inline int
vr_interface_body(void *ctx, int8_t is_return, vr_interface_req *req) {
    bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return);
}

static __inline int
vr_route_body(void *ctx, int8_t is_return, vr_route_req *req) {
    bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return);
}

static __inline int
vr_nexthop_body(void *ctx, int8_t is_return, vr_nexthop_req *req) {
    bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return);
}

static __inline int
vr_vrf_assign_body(void *ctx, int8_t is_return, vr_vrf_assign_req *req) {
    bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return);
}

static __inline int
vr_mpls_body(void *ctx, int8_t is_return, vr_mpls_req *req) {
    bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return);
}

static __inline int
vr_vrf_stats_body(void *ctx, int8_t is_return, vr_vrf_stats_req *req) {
    bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return);
}

static __inline int
vr_mirror_body(void *ctx, int8_t is_return, vr_mirror_req *req) {
    bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return);
}

static __inline int
vr_flow_body(void *ctx, int8_t is_return, vr_flow_req *req) {
    bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return);
}

static __inline int
vr_response_body(void *ctx, int8_t is_return, vr_response *req) {
    bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return);
}

static __inline int
vr_flow_table_data_body(void *ctx, int8_t is_return, vr_flow_table_data *req) {
    bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return);
}

static __inline int
vr_vrf_body(void *ctx, int8_t is_return, vr_vrf_req *req) {
    bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return);
}

static __inline int
vr_vxlan_body(void *ctx, int8_t is_return, vr_vxlan_req *req) {
    bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return);
}

static __inline int
vr_fc_map_body(void *ctx, int8_t is_return, vr_fc_map_req *req) {
    bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return);
}

static __inline int
vr_qos_map_body(void *ctx, int8_t is_return, vr_qos_map_req *req) {
    bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return);
}

static __inline int
vr_drop_stats_body(void *ctx, int8_t is_return, vr_drop_stats_req *req) {
    bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return);
}

static __inline int
vr_bridge_table_data_body(void *ctx, int8_t is_return, vr_bridge_table_data *req) {
    bpf_map_push_elem(&arg_data, &req, 0);
    return emit_vrft_event(ctx, is_return);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
