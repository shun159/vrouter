#pragma once

#include <stdint.h>
#include <linux/types.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define __unused __attribute__((unused))

static uint64_t get_func_ip(void *ctx);

struct vrft_event {
    uint64_t tstamp;
    uint64_t faddr;
    uint32_t processor_id;
    uint8_t is_return;
    uint8_t _pad[43]; // for future use
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(uint32_t));
} events SEC(".maps");


static __inline int
vrft_body(void *ctx, int8_t is_return)
{
    int error;
    uint32_t idx = 0;
    struct vrft_event e = {0};

    e.tstamp = bpf_ktime_get_ns();
    e.faddr = get_func_ip(ctx);
    e.processor_id = bpf_get_smp_processor_id();
    e.is_return = is_return;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
