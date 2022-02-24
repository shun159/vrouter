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

KPROBE(vr_interface_req, handle_vr_interface);
KPROBE(vr_route_req, handle_vr_route);
KPROBE(vr_nexthop_req, handle_vr_nexthop);
KPROBE(vr_vrf_assign_req, handle_vr_vrf_assign);
KPROBE(vr_mpls_req, handle_vr_mpls);
KPROBE(vr_vrf_stats_req, handle_vr_vrf_stats);
KPROBE(vr_mirror_req, handle_vr_mirror);
KPROBE(vr_flow_req, handle_vr_flow);
KPROBE(vr_response, handle_vr_response);
KPROBE(vr_flow_table_data, handle_vr_flow_table_data);
KPROBE(vr_vrf_req, handle_vr_vrf);
KPROBE(vr_vxlan_req, handle_vr_vxlan);
KPROBE(vr_fc_map_req, handle_vr_fc_map);
KPROBE(vr_qos_map_req, handle_vr_qos_map);
KPROBE(vr_drop_stats_req, handle_vr_drop_stats);
KPROBE(vr_bridge_table_data, handle_vr_bridge_table_data);
KPROBE(vr_packet, handle_vr_packet);
