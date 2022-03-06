// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(uint32_t));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10240);
    __type(key, uint32_t);
    __type(value, uint64_t);
} sreq_index SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries,  10240);
    __type(key, uint64_t);
    __type(value, struct vifr);
} vr_interface_req_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries,  10240);
    __type(key, uint64_t);
    __type(value, struct nhr);
} vr_nexthop_req_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries,  10240);
    __type(key, uint64_t);
    __type(value, struct rtr);
} vr_route_req_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries,  10240);
    __type(key, uint64_t);
    __type(value, struct var);
} vr_vrf_assign_req_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries,  10240);
    __type(key, uint64_t);
    __type(value, struct mr);
} vr_mpls_req_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries,  10240);
    __type(key, uint64_t);
    __type(value, struct vsr);
} vr_vrf_stats_req_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries,  10240);
    __type(key, uint64_t);
    __type(value, struct mirr);
} vr_mirror_req_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries,  10240);
    __type(key, uint64_t);
    __type(value, struct fr);
} vr_flow_req_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries,  10240);
    __type(key, uint64_t);
    __type(value, struct resp);
} vr_response_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries,  10240);
    __type(key, uint64_t);
    __type(value, struct ftable);
} vr_flow_table_data_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries,  10240);
    __type(key, uint64_t);
    __type(value, struct vrf);
} vr_vrf_req_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries,  10240);
    __type(key, uint64_t);
    __type(value, struct vxlanr);
} vr_vxlan_req_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries,  10240);
    __type(key, uint64_t);
    __type(value, struct vxlanr);
} vr_fc_map_req_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries,  10240);
    __type(key, uint64_t);
    __type(value, struct qmr);
} vr_qos_map_req_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries,  10240);
    __type(key, uint64_t);
    __type(value, struct vds);
} vr_drop_stats_req_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries,  10240);
    __type(key, uint64_t);
    __type(value, struct btable);
} vr_bridge_table_data_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries,  10240);
    __type(key, uint64_t);
    __type(value, struct packet_data);
} vr_packet_map SEC(".maps");
