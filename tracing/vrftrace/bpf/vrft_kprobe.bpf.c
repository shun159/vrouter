// SPDX-License-Identifier: BSD-2-Clause

#include <linux/ptrace.h>

#include "vrft_common.bpf.h"

static __inline uint64_t
get_func_ip(void *ctx) {
    return PT_REGS_IP((struct pt_regs *)ctx) - 1;
}

#define KPROBE(sname, processor)                 \
SEC("kprobe/##sname##1")                         \
int sname##1(struct pt_regs *ctx) {              \
    sname *req = (sname *)PT_REGS_PARM1(ctx);    \
    return processor(ctx, 0, req);               \
}                                                \
                                                 \
SEC("kprobe/##sname##2")                         \
int sname##2(struct pt_regs *ctx) {              \
    sname *req = (sname *)PT_REGS_PARM2(ctx);    \
    return processor(ctx, 0, req);               \
}                                                \
                                                 \
SEC("kprobe/##sname##3")                         \
int sname##3(struct pt_regs *ctx) {              \
    sname *req = (sname *)PT_REGS_PARM3(ctx);    \
    return processor(ctx, 0, req);               \
}                                                \
                                                 \
SEC("kprobe/##sname##4")                         \
int sname##4(struct pt_regs *ctx) {              \
    sname *req = (sname *)PT_REGS_PARM4(ctx);    \
    return processor(ctx, 0, req);               \
}                                                \
                                                 \
SEC("kprobe/##sname##5")                         \
int sname##5(struct pt_regs *ctx) {              \
    sname *req = (sname *)PT_REGS_PARM5(ctx);    \
    return processor(ctx, 0, req);               \
}

KPROBE(vr_interface_req, vr_interface_body);
KPROBE(vr_route_req, vr_route_body);
KPROBE(vr_nexthop_req, vr_nexthop_body);
KPROBE(vr_vrf_assign_req, vr_vrf_assign_body);
KPROBE(vr_mpls_req, vr_mpls_body);
KPROBE(vr_vrf_stats_req, vr_vrf_stats_body);
KPROBE(vr_mirror_req, vr_mirror_body);
KPROBE(vr_flow_req, vr_flow_body);
KPROBE(vr_response, vr_response_body);
KPROBE(vr_flow_table_data, vr_flow_table_data_body);
KPROBE(vr_vrf_req, vr_vrf_body);
KPROBE(vr_vxlan_req, vr_vxlan_body);
KPROBE(vr_fc_map_req, vr_fc_map_body);
KPROBE(vr_qos_map_req, vr_qos_map_body);
KPROBE(vr_drop_stats_req, vr_drop_stats_body);
KPROBE(vr_bridge_table_data, vr_bridge_table_data_body);
