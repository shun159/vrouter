// SPDX-License-Identifier: BSD-2-Clause

#include <linux/ptrace.h>

#include "vrft_common.bpf.h"

static __inline uint64_t
get_func_ip(void *ctx) {
    return PT_REGS_IP((struct pt_regs *)ctx) - 1;
}

/*
 * vr_interface_req
 */

SEC("kprobe/vr_interface_req1")
int vr_interface_req1(struct pt_regs *ctx) { 
    vr_interface_req *req = (vr_interface_req *)PT_REGS_PARM1(ctx);
    return vr_interface_body(ctx, 0, req);
}

SEC("kprobe/vr_interface_req2")
int vr_interface_req2(struct pt_regs *ctx) { 
    vr_interface_req *req = (vr_interface_req *)PT_REGS_PARM2(ctx);
    return vr_interface_body(ctx, 0, req);
}

SEC("kprobe/vr_interface_req3")
int vr_interface_req3(struct pt_regs *ctx) { 
    vr_interface_req *req = (vr_interface_req *)PT_REGS_PARM3(ctx);
    return vr_interface_body(ctx, 0, req);
}

SEC("kprobe/vr_interface_req4")
int vr_interface_req4(struct pt_regs *ctx) { 
    vr_interface_req *req = (vr_interface_req *)PT_REGS_PARM4(ctx);
    return vr_interface_body(ctx, 0, req);
}

SEC("kprobe/vr_interface_req5")
int vr_interface_req5(struct pt_regs *ctx) { 
    vr_interface_req *req = (vr_interface_req *)PT_REGS_PARM5(ctx);
    return vr_interface_body(ctx, 0, req);
}

/*
 * vr_route_req
 */

SEC("kprobe/vr_route_req1")
int vr_route_req1(struct pt_regs *ctx) { 
    vr_route_req *req = (vr_route_req *)PT_REGS_PARM1(ctx);
    return vr_route_body(ctx, 0, req);
}

SEC("kprobe/vr_route_req2")
int vr_route_req2(struct pt_regs *ctx) { 
    vr_route_req *req = (vr_route_req *)PT_REGS_PARM2(ctx);
    return vr_route_body(ctx, 0, req);
}

SEC("kprobe/vr_route_req3")
int vr_route_req3(struct pt_regs *ctx) { 
    vr_route_req *req = (vr_route_req *)PT_REGS_PARM3(ctx);
    return vr_route_body(ctx, 0, req);
}

SEC("kprobe/vr_route_req4")
int vr_route_req4(struct pt_regs *ctx) { 
    vr_route_req *req = (vr_route_req *)PT_REGS_PARM4(ctx);
    return vr_route_body(ctx, 0, req);
}

SEC("kprobe/vr_route_req5")
int vr_route_req5(struct pt_regs *ctx) { 
    vr_route_req *req = (vr_route_req *)PT_REGS_PARM5(ctx);
    return vr_route_body(ctx, 0, req);
}

/*
 * vr_nexthop_req
 */

SEC("kprobe/vr_nexthop_req1")
int vr_nexthop_req1(struct pt_regs *ctx) { 
    vr_nexthop_req *req = (vr_nexthop_req *)PT_REGS_PARM1(ctx);
    return vr_nexthop_body(ctx, 0, req);
}

SEC("kprobe/vr_nexthop_req2")
int vr_nexthop_req2(struct pt_regs *ctx) { 
    vr_nexthop_req *req = (vr_nexthop_req *)PT_REGS_PARM2(ctx);
    return vr_nexthop_body(ctx, 0, req);
}

SEC("kprobe/vr_nexthop_req3")
int vr_nexthop_req3(struct pt_regs *ctx) { 
    vr_nexthop_req *req = (vr_nexthop_req *)PT_REGS_PARM3(ctx);
    return vr_nexthop_body(ctx, 0, req);
}

SEC("kprobe/vr_nexthop_req4")
int vr_nexthop_req4(struct pt_regs *ctx) { 
    vr_nexthop_req *req = (vr_nexthop_req *)PT_REGS_PARM4(ctx);
    return vr_nexthop_body(ctx, 0, req);
}

SEC("kprobe/vr_nexthop_req5")
int vr_nexthop_req5(struct pt_regs *ctx) { 
    vr_nexthop_req *req = (vr_nexthop_req *)PT_REGS_PARM5(ctx);
    return vr_nexthop_body(ctx, 0, req);
}

/*
 * vr_vrf_assign_req
 */

SEC("kprobe/vr_vrf_assign_req1")
int vr_vrf_assign_req1(struct pt_regs *ctx) {
    vr_vrf_assign_req *req = (vr_vrf_assign_req *)PT_REGS_PARM1(ctx);
    return vr_vrf_assign_body(ctx, 0, req);
}

SEC("kprobe/vr_vrf_assign_req2")
int vr_vrf_assign_req2(struct pt_regs *ctx) {
    vr_vrf_assign_req *req = (vr_vrf_assign_req *)PT_REGS_PARM2(ctx);
    return vr_vrf_assign_body(ctx, 0, req);
}

SEC("kprobe/vr_vrf_assign_req3")
int vr_vrf_assign_req3(struct pt_regs *ctx) {
    vr_vrf_assign_req *req = (vr_vrf_assign_req *)PT_REGS_PARM3(ctx);
    return vr_vrf_assign_body(ctx, 0, req);
}

SEC("kprobe/vr_vrf_assign_req4")
int vr_vrf_assign_req4(struct pt_regs *ctx) {
    vr_vrf_assign_req *req = (vr_vrf_assign_req *)PT_REGS_PARM4(ctx);
    return vr_vrf_assign_body(ctx, 0, req);
}

SEC("kprobe/vr_vrf_assign_req5")
int vr_vrf_assign_req5(struct pt_regs *ctx) {
    vr_vrf_assign_req *req = (vr_vrf_assign_req *)PT_REGS_PARM5(ctx);
    return vr_vrf_assign_body(ctx, 0, req);
}

/*
 * vr_mpls_req
 */

SEC("kprobe/vr_mpls_req1")
int vr_mpls_req1(struct pt_regs *ctx) {
    vr_mpls_req *req = (vr_mpls_req *)PT_REGS_PARM1(ctx);
    return vr_mpls_body(ctx, 0, req);
}

SEC("kprobe/vr_mpls_req2")
int vr_mpls_req2(struct pt_regs *ctx) {
    vr_mpls_req *req = (vr_mpls_req *)PT_REGS_PARM2(ctx);
    return vr_mpls_body(ctx, 0, req);
}

SEC("kprobe/vr_mpls_req3")
int vr_mpls_req3(struct pt_regs *ctx) {
    vr_mpls_req *req = (vr_mpls_req *)PT_REGS_PARM3(ctx);
    return vr_mpls_body(ctx, 0, req);
}

SEC("kprobe/vr_mpls_req4")
int vr_mpls_req4(struct pt_regs *ctx) {
    vr_mpls_req *req = (vr_mpls_req *)PT_REGS_PARM4(ctx);
    return vr_mpls_body(ctx, 0, req);
}

SEC("kprobe/vr_mpls_req5")
int vr_mpls_req5(struct pt_regs *ctx) {
    vr_mpls_req *req = (vr_mpls_req *)PT_REGS_PARM5(ctx);
    return vr_mpls_body(ctx, 0, req);
}

/*
 * vr_vrf_stats_req
 */

SEC("kprobe/vr_vrf_stats_req1")
int vr_vrf_stats_req1(struct pt_regs *ctx) {
    vr_vrf_stats_req *req = (vr_vrf_stats_req *)PT_REGS_PARM1(ctx);
    return vr_vrf_stats_body(ctx, 0, req);
}

SEC("kprobe/vr_vrf_stats_req2")
int vr_vrf_stats_req2(struct pt_regs *ctx) {
    vr_vrf_stats_req *req = (vr_vrf_stats_req *)PT_REGS_PARM2(ctx);
    return vr_vrf_stats_body(ctx, 0, req);
}

SEC("kprobe/vr_vrf_stats_req3")
int vr_vrf_stats_req3(struct pt_regs *ctx) {
    vr_vrf_stats_req *req = (vr_vrf_stats_req *)PT_REGS_PARM3(ctx);
    return vr_vrf_stats_body(ctx, 0, req);
}

SEC("kprobe/vr_vrf_stats_req4")
int vr_vrf_stats_req4(struct pt_regs *ctx) {
    vr_vrf_stats_req *req = (vr_vrf_stats_req *)PT_REGS_PARM4(ctx);
    return vr_vrf_stats_body(ctx, 0, req);
}

SEC("kprobe/vr_vrf_stats_req5")
int vr_vrf_stats_req5(struct pt_regs *ctx) {
    vr_vrf_stats_req *req = (vr_vrf_stats_req *)PT_REGS_PARM5(ctx);
    return vr_vrf_stats_body(ctx, 0, req);
}

/*
 * vr_mirror_req
 */

SEC("kprobe/vr_mirror_req1")
int vr_mirror_req1(struct pt_regs *ctx) {
    vr_mirror_req *req = (vr_mirror_req *)PT_REGS_PARM1(ctx);
    return vr_mirror_body(ctx, 0, req);
}

SEC("kprobe/vr_mirror_req2")
int vr_mirror_req2(struct pt_regs *ctx) {
    vr_mirror_req *req = (vr_mirror_req *)PT_REGS_PARM2(ctx);
    return vr_mirror_body(ctx, 0, req);
}

SEC("kprobe/vr_mirror_req3")
int vr_mirror_req3(struct pt_regs *ctx) {
    vr_mirror_req *req = (vr_mirror_req *)PT_REGS_PARM3(ctx);
    return vr_mirror_body(ctx, 0, req);
}

SEC("kprobe/vr_mirror_req4")
int vr_mirror_req4(struct pt_regs *ctx) {
    vr_mirror_req *req = (vr_mirror_req *)PT_REGS_PARM4(ctx);
    return vr_mirror_body(ctx, 0, req);
}

SEC("kprobe/vr_mirror_req5")
int vr_mirror_req5(struct pt_regs *ctx) {
    vr_mirror_req *req = (vr_mirror_req *)PT_REGS_PARM5(ctx);
    return vr_mirror_body(ctx, 0, req);
}

/*
 * vr_flow_req
 */

SEC("kprobe/vr_flow_req1")
int vr_flow_req1(struct pt_regs *ctx) {
    vr_flow_req *req = (vr_flow_req *)PT_REGS_PARM1(ctx);
    return vr_flow_body(ctx, 0, req);
}

SEC("kprobe/vr_flow_req2")
int vr_flow_req2(struct pt_regs *ctx) {
    vr_flow_req *req = (vr_flow_req *)PT_REGS_PARM2(ctx);
    return vr_flow_body(ctx, 0, req);
}

SEC("kprobe/vr_flow_req3")
int vr_flow_req3(struct pt_regs *ctx) {
    vr_flow_req *req = (vr_flow_req *)PT_REGS_PARM3(ctx);
    return vr_flow_body(ctx, 0, req);
}

SEC("kprobe/vr_flow4")
int vr_flow_req4(struct pt_regs *ctx) {
    vr_flow_req *req = (vr_flow_req *)PT_REGS_PARM4(ctx);
    return vr_flow_body(ctx, 0, req);
}

SEC("kprobe/vr_flow_req5")
int vr_flow_req5(struct pt_regs *ctx) {
    vr_flow_req *req = (vr_flow_req *)PT_REGS_PARM5(ctx);
    return vr_flow_body(ctx, 0, req);
}

/*
 * vr_response
 */

SEC("kprobe/vr_response1")
int vr_response1(struct pt_regs *ctx) {
    vr_response *req = (vr_response *)PT_REGS_PARM1(ctx);
    return vr_response_body(ctx, 0, req);
}

SEC("kprobe/vr_response2")
int vr_response2(struct pt_regs *ctx) {
    vr_response *req = (vr_response *)PT_REGS_PARM2(ctx);
    return vr_response_body(ctx, 0, req);
}

SEC("kprobe/vr_response3")
int vr_response3(struct pt_regs *ctx) {
    vr_response *req = (vr_response *)PT_REGS_PARM3(ctx);
    return vr_response_body(ctx, 0, req);
}

SEC("kprobe/vr_response4")
int vr_response4(struct pt_regs *ctx) {
    vr_response *req = (vr_response *)PT_REGS_PARM4(ctx);
    return vr_response_body(ctx, 0, req);
}

SEC("kprobe/vr_response5")
int vr_response5(struct pt_regs *ctx) {
    vr_response *req = (vr_response *)PT_REGS_PARM5(ctx);
    return vr_response_body(ctx, 0, req);
}

/*
 * vr_flow_table_data
 */

SEC("kprobe/vr_flow_table_data1")
int vr_flow_table_data1(struct pt_regs *ctx) {
    vr_flow_table_data *req = (vr_flow_table_data *)PT_REGS_PARM1(ctx);
    return vr_flow_table_data_body(ctx, 0, req);
}

SEC("kprobe/vr_flow_table_data2")
int vr_flow_table_data2(struct pt_regs *ctx) {
    vr_flow_table_data *req = (vr_flow_table_data *)PT_REGS_PARM2(ctx);
    return vr_flow_table_data_body(ctx, 0, req);
}

SEC("kprobe/vr_flow_table_data3")
int vr_flow_table_data3(struct pt_regs *ctx) {
    vr_flow_table_data *req = (vr_flow_table_data *)PT_REGS_PARM3(ctx);
    return vr_flow_table_data_body(ctx, 0, req);
}

SEC("kprobe/vr_flow_table_data4")
int vr_flow_table_data4(struct pt_regs *ctx) {
    vr_flow_table_data *req = (vr_flow_table_data *)PT_REGS_PARM4(ctx);
    return vr_flow_table_data_body(ctx, 0, req);
}

SEC("kprobe/vr_flow_table_data5")
int vr_flow_table_data5(struct pt_regs *ctx) {
    vr_flow_table_data *req = (vr_flow_table_data *)PT_REGS_PARM5(ctx);
    return vr_flow_table_data_body(ctx, 0, req);
}

/*
 * vr_vrf_req
 */

SEC("kprobe/vr_vrf_req1")
int vr_vrf_req1(struct pt_regs *ctx) {
    vr_vrf_req *req = (vr_vrf_req *)PT_REGS_PARM1(ctx);
    return vr_vrf_body(ctx, 0, req);
}

SEC("kprobe/vr_vrf_req2")
int vr_vrf_req2(struct pt_regs *ctx) {
    vr_vrf_req *req = (vr_vrf_req *)PT_REGS_PARM2(ctx);
    return vr_vrf_body(ctx, 0, req);
}

SEC("kprobe/vr_vrf_req3")
int vr_vrf_req3(struct pt_regs *ctx) {

    vr_vrf_req *req = (vr_vrf_req *)PT_REGS_PARM3(ctx);
    return vr_vrf_body(ctx, 0, req);
}

SEC("kprobe/vr_vrf_req4")
int vr_vrf_req4(struct pt_regs *ctx) {
    vr_vrf_req *req = (vr_vrf_req *)PT_REGS_PARM4(ctx);
    return vr_vrf_body(ctx, 0, req);
}

SEC("kprobe/vr_vrf_req5")
int vr_vrf_req5(struct pt_regs *ctx) {
    vr_vrf_req *req = (vr_vrf_req *)PT_REGS_PARM5(ctx);
    return vr_vrf_body(ctx, 0, req);
}

/*
 * vr_vxlan_req
 */

SEC("kprobe/vr_vxlan_req1")
int vr_vxlan_req1(struct pt_regs *ctx) {
    vr_vxlan_req *req = (vr_vxlan_req *)PT_REGS_PARM1(ctx);
    return vr_vxlan_body(ctx, 0, req);
}

SEC("kprobe/vr_vxlan_req2")
int vr_vxlan_req2(struct pt_regs *ctx) {
    vr_vxlan_req *req = (vr_vxlan_req *)PT_REGS_PARM2(ctx);
    return vr_vxlan_body(ctx, 0, req);
}

SEC("kprobe/vr_vxlan_req3")
int vr_vxlan_req3(struct pt_regs *ctx) {
    vr_vxlan_req *req = (vr_vxlan_req *)PT_REGS_PARM3(ctx);
    return vr_vxlan_body(ctx, 0, req);
}

SEC("kprobe/vr_vxlan_req4")
int vr_vxlan_req4(struct pt_regs *ctx) {
    vr_vxlan_req *req = (vr_vxlan_req *)PT_REGS_PARM4(ctx);
    return vr_vxlan_body(ctx, 0, req);
}

SEC("kprobe/vr_vxlan_req5")
int vr_vxlan_req5(struct pt_regs *ctx) {
    vr_vxlan_req *req = (vr_vxlan_req *)PT_REGS_PARM5(ctx);
    return vr_vxlan_body(ctx, 0, req);
}

/*
 * vr_fc_map_req
 */

SEC("kprobe/vr_fc_map_req1")
int vr_fc_map_req1(struct pt_regs *ctx) {
    vr_fc_map_req *req = (vr_fc_map_req *)PT_REGS_PARM1(ctx);
    return vr_fc_map_body(ctx, 0, req);
}

SEC("kprobe/vr_fc_map_req2")
int vr_fc_map_req2(struct pt_regs *ctx) {
    vr_fc_map_req *req = (vr_fc_map_req *)PT_REGS_PARM2(ctx);
    return vr_fc_map_body(ctx, 0, req);
}

SEC("kprobe/vr_fc_map_req3")
int vr_fc_map_req3(struct pt_regs *ctx) {
    vr_fc_map_req *req = (vr_fc_map_req *)PT_REGS_PARM3(ctx);
    return vr_fc_map_body(ctx, 0, req);
}

SEC("kprobe/vr_fc_map_req4")
int vr_fc_map_req4(struct pt_regs *ctx) {
    vr_fc_map_req *req = (vr_fc_map_req *)PT_REGS_PARM4(ctx);
    return vr_fc_map_body(ctx, 0, req);
}

SEC("kprobe/vr_fc_map_req5")
int vr_fc_map_req5(struct pt_regs *ctx) {
    vr_fc_map_req *req = (vr_fc_map_req *)PT_REGS_PARM5(ctx);
    return vr_fc_map_body(ctx, 0, req);
}

/*
 * vr_qos_map_req
 */

SEC("kprobe/vr_qos_map_req1")
int vr_qos_map_req1(struct pt_regs *ctx) {
    vr_qos_map_req *req = (vr_qos_map_req *)PT_REGS_PARM1(ctx);
    return vr_qos_map_body(ctx, 0, req);
}

SEC("kprobe/vr_qos_map_req2")
int vr_qos_map_req2(struct pt_regs *ctx) {
    vr_qos_map_req *req = (vr_qos_map_req *)PT_REGS_PARM2(ctx);
    return vr_qos_map_body(ctx, 0, req);
}

SEC("kprobe/vr_qos_map_req3")
int vr_qos_map_req3(struct pt_regs *ctx) {
    vr_qos_map_req *req = (vr_qos_map_req *)PT_REGS_PARM3(ctx);
    return vr_qos_map_body(ctx, 0, req);
}

SEC("kprobe/vr_qos_map_req4")
int vr_qos_map_req4(struct pt_regs *ctx) {
    vr_qos_map_req *req = (vr_qos_map_req *)PT_REGS_PARM4(ctx);
    return vr_qos_map_body(ctx, 0, req);
}

SEC("kprobe/vr_qos_map_req5")
int vr_qos_map_req5(struct pt_regs *ctx) {
    vr_qos_map_req *req = (vr_qos_map_req *)PT_REGS_PARM5(ctx);
    return vr_qos_map_body(ctx, 0, req);
}

/*
 * vr_drop_stats_req
 */

SEC("kprobe/vr_drop_stats_req1")
int vr_drop_stats_req1(struct pt_regs *ctx) {
    vr_drop_stats_req *req = (vr_drop_stats_req *)PT_REGS_PARM1(ctx);
    return vr_drop_stats_body(ctx, 0, req);
}

SEC("kprobe/vr_drop_stats_req2")
int vr_drop_stats_req2(struct pt_regs *ctx) {
    vr_drop_stats_req *req = (vr_drop_stats_req *)PT_REGS_PARM2(ctx);
    return vr_drop_stats_body(ctx, 0, req);
}

SEC("kprobe/vr_drop_stats_req3")
int vr_drop_stats_req3(struct pt_regs *ctx) {
    vr_drop_stats_req *req = (vr_drop_stats_req *)PT_REGS_PARM3(ctx);
    return vr_drop_stats_body(ctx, 0, req);
}

SEC("kprobe/vr_drop_stats_req4")
int vr_drop_stats_req4(struct pt_regs *ctx) {
    vr_drop_stats_req *req = (vr_drop_stats_req *)PT_REGS_PARM4(ctx);
    return vr_drop_stats_body(ctx, 0, req);
}

SEC("kprobe/vr_drop_stats_req5")
int vr_drop_stats_req5(struct pt_regs *ctx) {
    vr_drop_stats_req *req = (vr_drop_stats_req *)PT_REGS_PARM5(ctx);
    return vr_drop_stats_body(ctx, 0, req);
}

/*
 * vr_bridge_table_data
 */

SEC("kprobe/vr_bridge_table_data1")
int vr_bridge_table_data1(struct pt_regs *ctx) {
    vr_bridge_table_data *data = (vr_bridge_table_data *)PT_REGS_PARM1(ctx);
    return vr_bridge_table_data_body(ctx, 0, data);
}

SEC("kprobe/vr_bridge_table_data2")
int vr_bridge_table_data2(struct pt_regs *ctx) {
    vr_bridge_table_data *data = (vr_bridge_table_data *)PT_REGS_PARM2(ctx);
    return vr_bridge_table_data_body(ctx, 0, data);
}

SEC("kprobe/vr_bridge_table_data3")
int vr_bridge_table_data3(struct pt_regs *ctx) {
    vr_bridge_table_data *data = (vr_bridge_table_data *)PT_REGS_PARM3(ctx);
    return vr_bridge_table_data_body(ctx, 0, data);
}

SEC("kprobe/vr_bridge_table_data4")
int vr_bridge_table_data4(struct pt_regs *ctx) {
    vr_bridge_table_data *data = (vr_bridge_table_data *)PT_REGS_PARM4(ctx);
    return vr_bridge_table_data_body(ctx, 0, data);
}

SEC("kprobe/vr_bridge_table_data5")
int vr_bridge_table_data5(struct pt_regs *ctx) {
    vr_bridge_table_data *data = (vr_bridge_table_data *)PT_REGS_PARM5(ctx);
    return vr_bridge_table_data_body(ctx, 0, data);
}
