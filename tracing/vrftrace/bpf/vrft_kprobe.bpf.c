// SPDX-License-Identifier: BSD-2-Clause

#include <linux/ptrace.h>

#include "vrft_common.bpf.h"

static __inline uint64_t
get_func_ip(void *ctx)
{
    return PT_REGS_IP((struct pt_regs *)ctx) - 1;
}

SEC("kprobe/vrft_main")
int vrft_main(struct pt_regs *ctx)
{
    return vrft_body(ctx, 0);
}
