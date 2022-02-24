#define READ_KERNEL(FIELD)      \
    bpf_probe_read(             \
        (void *)&s_req.FIELD,   \
        sizeof(s_req.FIELD),    \
        &req->FIELD             \
    );

#define READ_KERNEL_STR(FIELD)  \
    char *FIELD;                \
    bpf_probe_read(             \
        (void *)&FIELD,         \
        sizeof(FIELD),          \
        &req->FIELD             \
    );                          \
    bpf_probe_read_str(         \
        (void *)&s_req.FIELD,   \
        sizeof(s_req.FIELD),    \
        FIELD                   \
    );

#define SREQ_NTOHL(FIELD) \
    s_req.FIELD = bpf_ntohl(s_req.FIELD);

#define SREQ_NTOHS(FIELD) \
    s_req.FIELD = bpf_ntohs(s_req.FIELD);

static uint64_t get_func_ip(void *ctx);

struct vrft_event {
    uint64_t tstamp;
    uint64_t faddr;
    uint32_t processor_id;
    uint8_t is_return;
    uint8_t __pad1[3];
    uint64_t index;
};

static __inline int
emit_vrft_event(void *ctx, int8_t is_return, uint64_t index) {
   struct vrft_event e = {0};
    e.tstamp = bpf_ktime_get_ns();
    e.faddr = get_func_ip(ctx);
    e.processor_id = bpf_get_smp_processor_id();
    e.is_return = is_return;
    e.index = index;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

static __inline uint64_t
incr_monotonic_counter(uint32_t key) {
    uint64_t init_val = 0;
    uint64_t *value = bpf_map_lookup_elem(&sreq_index, &key);

    if (value) {
        uint64_t ret = *value;
        (void)__sync_fetch_and_add(value, 1);
        return ret;
    }
    else {
        bpf_map_update_elem(&sreq_index, &key, &init_val, BPF_ANY);
        return 0;
    }
}
