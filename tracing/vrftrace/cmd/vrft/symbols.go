package main

/*
#cgo LDFLAGS: -lelf -lz -lbpf -ldl -lm

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <errno.h>
#include <fts.h>
#include <search.h>

#include <gelf.h>
#include <libelf.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#define MAX_POS 10

static const char *s_structs[] = {
    //
    // sandesh_md definitions
    //
    "vr_null_object", "vr_interface_req",
    "vr_nexthop_req", "vr_route_req",
    "vr_mpls_req" "vr_mirror_req",
    "vr_flow_req", "vr_vrf_assign_req",
    "vr_vrf_stats_req", "vr_pkt_drop_log_req",
    "vr_drop_stats_req", "vr_info_req",
    "vr_response", "vr_vxlan_req",
    "vrouter_ops", "vr_flow_table_data",
    "vr_mem_stats_req", "vr_qos_map_req",
    "vr_fc_map_req", "vr_flow_response",
    "vr_bridge_table_data", "vr_hugepage_config",
    "vr_vrf_req",
};
static size_t s_structs_len = sizeof s_structs / sizeof s_structs[0];
static ENTRY s_structs_e, *s_structs_eptr;

static const char *s_processors[] = {
    //
    // netlink message handlers.
    //
    "vrouter_ops_process", "vr_flow_req_process",
    "vr_flow_response_process", "vr_route_req_process",
    "vr_interface_req_process", "vr_mpls_req_process",
    "vr_mirror_req_process", "vr_vrf_req_process",
    "vr_response_process", "vr_nexthop_req_process",
    "vr_vrf_assign_req_process", "vr_vrf_stats_req_process",
    "vr_pkt_drop_log_req_process", "vr_info_req_process",
    "vr_drop_stats_req_process", "vr_vxlan_req_process",
    "vr_mem_stats_req_process", "vr_fc_map_req_process",
    "vr_qos_map_req_process", "vr_flow_table_data_process",
    "vr_bridge_table_data_process", "vr_hugepage_config_process",

    //
    // SANDESH_OP_* handler and processors.
    //
    "vr_flow_set_mirror", "vr_add_flow_req",
    "vr_flow_set_req_is_invalid", "vr_flow_schedule_transition",
    "vr_flow_delete", "vr_flow_update_link_local_port",
    "vr_flow_force_evict", "vr_flow_set",
    "vif_drv_add", "vr_interface_delete",
    "vif_set_flags", "vr_interface_mirror_md_set",
    "vr_interface_change", "vif_transport_valid",
    "vr_interface_add", "vr_interface_add_response",
    "vr_interface_copy_bond_info", "vr_interface_make_req",
    "vr_interface_req_get_size", "vr_interface_req_free_fat_flow_config",
    "vr_interface_req_destroy", "vr_interface_get",
    "vif_vrf_table_get", "vif_fat_flow_cfg_is_changed",
    "vif_fat_flow_cfg_build", "vif_fat_flow_add",
    "mtrie_stats_get", "mtrie_stats_dump", "vr_message_dump_init",
    "vr_mirror_del", "vr_mirror_add", "vr_mirror_make_req",
    "vr_mirror_get", "vr_mpls_del", "vr_mpls_add",
    "vr_mpls_make_req", "vr_mpls_get", "nh_ecmp_store_ecmp_config_hash",
    "vr_nexthop_delete","nh_resolve_add", "nh_l2_rcv_add",
    "nh_rcv_add", "nh_vrf_translate_add",
    "nh_composite_add", "nh_tunnel_add", "nh_indirect_add",
    "nh_encap_add", "nh_discard_add", "vr_nexthop_valid_request",
    "vr_nexthop_size", "vr_nexthop_valid_change", "vr_nexthop_add",
    "vr_nexthop_req_get_size", "vr_nexthop_make_req", "vr_nexthop_req_destroy",
    "vr_nexthop_get", "vrouter_ops_destroy", "vr_pkt_droplog_config",
    "vr_pkt_drop_log_clear", "vr_inet6_fill_flow_from_req", "vr_inet6_fill_rflow_from_req",
    "vr_qos_map_request_validate", "vr_qos_map_req_destroy", "vr_qos_map_delete",
    "vr_qos_map_dump", "vr_qos_map_get", "vr_qos_map_add", "vr_fc_map_req_destroy",
    "vr_fc_map_delete", "vr_fc_map_dump", "vr_fc_map_get", "vr_fc_map_add",
    "vr_route_delete", "vr_route_add", "vr_route_get", "vr_route_dump",
    "vr_inet_vrf_stats_dump", "vr_inet_vrf_stats_get", "vr_inet_vrf_stats_op",
    "vr_vrf_stats_op", "inet_route_add", "inet_route_del", "bridge_entry_add",
    "bridge_entry_del", "vr_drop_stats_clear", "vr_vrf_assign_dump", "vr_vrf_assign_get",
    "vr_vrf_assign_set", "vr_vrf_table_entry_del", "vr_vrf_table_entry_add",
    "vr_vrf_table_make_req", "vr_vrf_table_entry_get", "vr_vxlan_make_req",
    "vr_vxlan_dump", "vr_vxlan_get", "vr_vxlan_del", "vr_vxlan_add"
};
static size_t s_processors_len = sizeof s_processors / sizeof s_processors[0];
static ENTRY s_processors_e, *s_processors_eptr;

static inline int
init_hset(void) {
    int i;
    char *key;

    hcreate(1000);

    for (i = 0; i < s_structs_len; i++) {
        key = strdup(s_structs[i]);
        s_structs_e.key = key;
        s_structs_e.data = (void *)true;
        s_structs_eptr = hsearch(s_structs_e, ENTER);
        if (s_structs_eptr == NULL) {
            fprintf(stderr, "init_pos_target_maps Failed\n");
            return -1;
        }
    }

    for (i = 0; i < s_processors_len; i++) {
        key = strdup(s_processors[i]);
        s_processors_e.key = key;
        s_processors_e.data = (void *)true;
        s_processors_eptr = hsearch(s_processors_e, ENTER);
        if (s_processors_eptr == NULL) {
            fprintf(stderr, "init_hset Failed\n");
            return -1;
        }
    }

    return 0;
}

static inline bool
sname_is_allowed(const char *key) {
    char *k;

    k = strdup(key);
    s_structs_e.key = k;
    s_structs_eptr = hsearch(s_structs_e, FIND);

    return s_structs_eptr ? (bool)(s_structs_eptr->data) : false;
}

static inline bool
func_is_sreq_processor(const char *key) {
    char *k;

    k = strdup(key);
    s_processors_e.key = k;
    s_processors_eptr = hsearch(s_processors_e, FIND);

    return s_processors_eptr ? (bool)(s_processors_eptr->data) : false;
}

const char*
btf_str_by_offset_from_type(const struct btf *btf, const struct btf_type *t) {
    return btf__str_by_offset(btf, t->name_off);
}

const struct btf_type*
btf_type_by_id_from_type(const struct btf *btf, const struct btf_type *t) {
    return btf__type_by_id(btf, t->type);
}

static inline __u16
btf_find_sandesh_pos(const struct btf *btf, const struct btf_type *t) {
    const struct btf_type *func_proto;
    const struct btf_param *params;
    const char *st_name;
    uint16_t ret = 0;

    func_proto = btf__type_by_id(btf, t->type);
    params = btf_params(func_proto);

    for (uint16_t i = 0; i < btf_vlen(func_proto); i++) {
        t = btf__type_by_id(btf, params[i].type);

        while (btf_is_mod(t) || btf_is_typedef(t))
            t = btf__type_by_id(btf, t->type);

        if (btf_is_struct(t) || btf_is_union(t))
            return ret;
    }

    for (uint16_t i = 0; i < btf_vlen(func_proto) && i < MAX_POS - 1; i++) {
        t = btf__type_by_id(btf, params[i].type);

        if (!btf_is_ptr(t))
            continue;

        t = btf__type_by_id(btf, t->type);
        st_name = btf__str_by_offset(btf, t->name_off);

        if (!sname_is_allowed(st_name))
          continue;

        ret = i + 1;

        break;
    }

    return ret;
}

#ifndef MAX_ERRNO
#define MAX_ERRNO       4095

#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)

static inline bool
IS_ERR(const void *ptr) {
    return IS_ERR_VALUE((unsigned long)ptr);
}

static inline bool
IS_ERR_OR_NULL(const void *ptr) {
    return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

static inline long
PTR_ERR(const void *ptr) {
    return (long) ptr;
}
#endif
*/
import "C"

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unsafe"
)

const VROUTER_BTF_FILE = "bpf/vrouter.btf"
const KERNEL_ADDR_SPACE = 0x00ffffffffffffff

type SymInfo struct {
	Pos uint16
}

type SymsDB struct {
	Availfuncs map[string]bool
	Address    map[uint64]string
	SymInfo    map[string]SymInfo
}

func NewSymsDB(traceOpt string) (SymsDB, error) {
	symsdb := SymsDB{}
	C.init_hset()
	if err := symsdb.fillAvailfuncs(); err != nil {
		fmt.Errorf("fillAvailfuncs: %s\n", err)
		return symsdb, err
	}

	if err := symsdb.fillAddress(); err != nil {
		fmt.Errorf("fillAddress: %s\n", err)
		return symsdb, err
	}

	if err := symsdb.fillSymInfo(traceOpt); err != nil {
		fmt.Errorf("fillSymInfo: %s\n", err)
		return symsdb, err
	}
	return symsdb, nil
}

func (s *SymsDB) fillAddress() error {
	s.Address = make(map[uint64]string)
	re := regexp.MustCompile(`\t+\[vrouter\]`)
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return err
	}
	defer f.Close()

	if os.Getegid() != 0 {
		err := errors.New("non-root users cannot read address info")
		return err
	}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.Split(sc.Text(), " ")
		symbol := line[2]
		switch line[1] {
		// Ignore data symbols
		case "b", "B", "d", "D", "r", "R":
			continue
		}

		addr, err := strconv.ParseUint(line[0], 16, 64)
		if err != nil {
			return err
		}

		if addr == 0 ||
			addr == math.MaxUint64 ||
			addr < uint64(KERNEL_ADDR_SPACE) {
			continue
		}

		if re.MatchString(symbol) {
			symbol = re.ReplaceAllString(symbol, "")
			s.Address[addr] = symbol
		}
	}

	return nil
}

func (s *SymsDB) fillSymInfo(traceOpt string) error {
	s.SymInfo = make(map[string]SymInfo)
	path := C.CString(VROUTER_BTF_FILE)
	vrouter_btf := C.btf__parse_elf(path, nil)
	defer C.free(unsafe.Pointer(path))

	for id := 0; id <= int(C.btf__get_nr_types(vrouter_btf)); id++ {
		t := C.btf__type_by_id(vrouter_btf, C.uint(id))
		if !C.btf_is_func(t) {
			continue
		}

		cfname := C.btf_str_by_offset_from_type(vrouter_btf, t)
		fname := C.GoString(cfname)

		if !s.isAvailfunc(fname) {
			continue
		}

		if traceOpt == "sandesh" {
			pos := C.btf_find_sandesh_pos(vrouter_btf, t)
			if pos > 0 || C.func_is_sreq_processor(cfname) {
				s.SymInfo[fname] = SymInfo{Pos: uint16(pos)}
			} else {
				continue
			}
		} else {
			errmsg := fmt.Sprintf("%s is not supported yet\n", traceOpt)
			return errors.New(errmsg)
		}
	}
	return nil
}

func (s *SymsDB) isAvailfunc(fname string) bool {
	_, ok := s.Availfuncs[fname]
	return ok
}

func (s *SymsDB) fillAvailfuncs() error {
	re := regexp.MustCompile(` \[vrouter\]`)
	s.Availfuncs = make(map[string]bool)
	f, err := os.Open("/sys/kernel/debug/tracing/available_filter_functions")
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if re.MatchString(line) {
			fname := re.ReplaceAllString(line, "")
			s.Availfuncs[fname] = true
		}
	}

	return nil
}
