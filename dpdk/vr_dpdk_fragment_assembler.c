/*
 * Copyright (c) 2015 Semihalf. All rights reserved.
 */

#include <vr_dpdk.h>
#include <vr_fragment.h>
#include <vr_os.h>
#include <vr_packet.h>

/**
 * @name Private variables
 * @{
 */

/* Hash table buckets used by the assembler */
struct fragment_bucket {
    struct vr_fragment *frag_list;
};
static struct fragment_bucket **assembler_table;

/* Per CPU queues used to enqueue packets for the assembler */
struct per_cpu_fragment_queue {
    struct vr_fragment_queue queue;
};
static struct per_cpu_fragment_queue *per_cpu_queues;

static int assembler_scan_index;
static int assembler_scan_thresh = 1024;

/** @} */

/**
 * @name Private functions
 * @{
 */
static void
dpdk_fragment_assemble_queue(void *arg)
{
    struct per_cpu_fragment_queue *queue = (struct per_cpu_fragment_queue *)arg;
    struct vr_fragment_queue *fq = &queue->queue;
    vr_fragment_assemble_queue(fq);
}

static void
dpdk_assembler_table_exit(void)
{
    int i;

    vr_assembler_table_scan_exit();

    if (assembler_table) {
        for (i = 0; i < vr_dpdk.nb_fwd_lcores; ++i) {
            if (assembler_table[i] != NULL) {
                vr_free(assembler_table[i], VR_ASSEMBLER_TABLE_OBJECT);
                assembler_table[i] = NULL;
            }
        }

        vr_free(assembler_table, VR_ASSEMBLER_TABLE_OBJECT);
        assembler_table = NULL;
    }

    return;
}

static int
dpdk_assembler_table_init(void)
{
    unsigned int size;
    int i;

    /* Allocate array of pointers to the assembler tables for each fwd lcore */
    size = sizeof(struct fragment_bucket *) * vr_dpdk.nb_fwd_lcores;
    assembler_table = vr_zalloc(size, VR_ASSEMBLER_TABLE_OBJECT);
    if (!assembler_table) {
        RTE_LOG(ERR, VROUTER, "%s:%d Allocation for %u failed\n",
                __FUNCTION__, __LINE__, size);
        return -ENOMEM;
    }

    /* Now allocate the assembler tables for each fwd lcore */
    size = sizeof(struct fragment_bucket) * VR_ASSEMBLER_BUCKET_COUNT;
    for (i = 0; i < vr_dpdk.nb_fwd_lcores; ++i) {
        assembler_table[i] = vr_zalloc(size, VR_ASSEMBLER_TABLE_OBJECT);
        if (!assembler_table[i]) {
            RTE_LOG(ERR, VROUTER, "%s:%d Allocation for %u failed\n",
                    __FUNCTION__, __LINE__, size);
            return -ENOMEM;
        }
    }

    /* Intentionally the vr_assembler_table_scan_init() is not called here as
     * it would set up timers on the timer lcore. For the timers the forwarding
     * lcores are used, therefore allowing for complete lock elimination. */

    return 0;
}

static int
dpdk_fragment_queue_init(void)
{
    unsigned int size;

    size = sizeof(struct per_cpu_fragment_queue) * vr_dpdk.nb_fwd_lcores;
    per_cpu_queues = vr_zalloc(size, VR_FRAGMENT_QUEUE_OBJECT);

    if (!per_cpu_queues) {
        RTE_LOG(ERR, VROUTER, "%s: Error allocating fragmentation queues\n",
                __func__);
        return -ENOMEM;
    }

    return 0;
}

static void
dpdk_fragment_queue_exit(void)
{
    int i;

    if (!per_cpu_queues) {
        return;
    }

    for (i = 0; i < vr_dpdk.nb_fwd_lcores; ++i) {
        if (per_cpu_queues[i].queue.vfq_tail != NULL)
            vr_fragment_queue_free(&per_cpu_queues[i].queue);
    }

    vr_free(per_cpu_queues, VR_FRAGMENT_QUEUE_OBJECT);
    per_cpu_queues = NULL;
}

/** @} */

/**
 * @name Public functions
 * @{
 */

/**
 * Enqueue a packet to per cpu queue and schedule work to
 * enqueue/process it to assembler_table[]
 *
 * Executed only from the forwarding lcores.
 */
int
dpdk_fragment_assembler_enqueue(struct vrouter *router, struct vr_packet *pkt,
                                struct vr_forwarding_md *fmd)
{
    int ret;
    unsigned int cpu;
    struct vr_dpdk_lcore *lcore;

    cpu = vr_get_cpu();
    if (cpu >= vr_num_cpus || cpu < VR_DPDK_FWD_LCORE_ID) {
        RTE_LOG(ERR, VROUTER, "%s:%d Enqueue to the assembler can only be "
                "done on forwarding lcores, not on cpu %u\n",
                __FUNCTION__, __LINE__, cpu);
        PKT_LOG(VP_DROP_FRAGMENTS, pkt, 0, VR_DPDK_FRAGMENT_ASSEMBLER_C, __LINE__);
        vr_pfree(pkt, VP_DROP_FRAGMENTS);
        return -EINVAL;
    }

    /* Enqueue the packet to per CPU queue */
    ret = vr_fragment_enqueue(router,
            &per_cpu_queues[cpu - VR_DPDK_FWD_LCORE_ID].queue, pkt, fmd);

    if (!ret) {
        lcore = vr_dpdk.lcores[cpu];
        /* Schedule work to enqueue/process by the assembler */
        vr_dpdk_lcore_schedule_assembler_work(lcore,
                dpdk_fragment_assemble_queue,
                &per_cpu_queues[cpu - VR_DPDK_FWD_LCORE_ID].queue);
    }

    return 0;
}

/**
 * Assemble packet
 */
void
dpdk_fragment_sync_assemble(struct vr_fragment_queue_element *vfqe)
{
    uint32_t hash, index;
    unsigned int cpu;
    struct fragment_bucket *bucket;

    cpu = vr_get_cpu() - VR_DPDK_FWD_LCORE_ID;
    assert(cpu >= 0 && cpu < (vr_num_cpus - VR_DPDK_FWD_LCORE_ID));

    hash = vr_fragment_get_hash(&vfqe->fqe_pnode);
    index = (hash % VR_ASSEMBLER_BUCKET_COUNT);
    bucket = &assembler_table[cpu][index];

    vr_fragment_assemble(&bucket->frag_list, vfqe);
}

/**
 * A callback for timeouts.
 * - Clean stale entries in assembler_table[][]
 *
 * Called on forwarding lcores only.
 */
void
dpdk_fragment_assembler_table_scan(void *arg)
{
    unsigned int i, j, scanned = 0;
    unsigned int cpu;
    struct fragment_bucket *vfb;

    cpu = vr_get_cpu() - VR_DPDK_FWD_LCORE_ID;
    assert(cpu >= 0 && cpu < (vr_num_cpus - VR_DPDK_FWD_LCORE_ID));

    i = assembler_scan_index;
    for (j = 0; j < VR_ASSEMBLER_BUCKET_COUNT; j++) {
        vfb = &assembler_table[cpu][(i + j) % VR_ASSEMBLER_BUCKET_COUNT];

        if (vfb->frag_list)
            scanned += vr_assembler_table_scan(&vfb->frag_list);

        if (scanned > assembler_scan_thresh) {
            j++;
            break;
        }
    }

    assembler_scan_index = (i + j) % VR_ASSEMBLER_BUCKET_COUNT;
    return;
}

/**
 * Init the fragment assembler.
 *
 * Called only once during initialization on the master lcore only.
 */
int
dpdk_fragment_assembler_init(void)
{
    int ret;

    if ((ret = dpdk_fragment_queue_init()))
        return ret;

    if ((ret = dpdk_assembler_table_init()))
        return ret;

    return 0;
}

/**
 * Exit the fragment assembler and clean up all related data.
 *
 * Called only once on the master lcore after the forwarding lcores exited.
 * Therefore we can securely free everything inside dpdk_fragment_queue_exit()
 * and dpdk_assembler_table_exit(). If someone adds call to this in other
 * place, she/he has to take care of possible races between the master and
 * forwarding lcores as assembler tasks might be using the fragment table or
 * per cpu queues at the same time.
 */
void
dpdk_fragment_assembler_exit(void)
{
    dpdk_fragment_queue_exit();
    dpdk_assembler_table_exit();
}

/** @} */
