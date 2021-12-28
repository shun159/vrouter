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

#include <gelf.h>
#include <libelf.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#define MAX_POS 10

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

    bool abort = false;
    for (uint16_t i = 0; i < btf_vlen(func_proto); i++) {
    	t = btf__type_by_id(btf, params[i].type);

      	while (btf_is_mod(t) || btf_is_typedef(t)) {
        	t = btf__type_by_id(btf, t->type);
      	}

      	if (btf_is_struct(t) || btf_is_union(t)) {
        	abort = true;
        	break;
      	}
    }

    if (abort) {
      	return ret;
    }

    for (uint16_t i = 0; i < btf_vlen(func_proto) && i < MAX_POS - 1; i++) {
      	t = btf__type_by_id(btf, params[i].type);
		if (!btf_is_ptr(t)) {
        	continue;
      	}

      	t = btf__type_by_id(btf, t->type);
      	st_name = btf__str_by_offset(btf, t->name_off);

   		if (strcmp(st_name, "vr_null_object") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_interface_req") == 0 || strcmp(st_name, "vr_interface") == 0){
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_nexthop_req") == 0 || strcmp(st_name, "vr_nexthop") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_route_req") == 0 || strcmp(st_name, "vr_rtable") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_mpls_req") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_mirror_req") == 0 || strcmp(st_name, "vr_mirror_entry") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_flow_req") == 0 || strcmp(st_name, "vr_flow") == 0){
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_vrf_assign_req") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_vrf_stats_req") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_pkt_drop_log_req") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_drop_stats_req") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_info_req") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_response") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_vxlan_req") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vrouter_ops") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_flow_table_data") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_mem_stats_req") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_qos_map_req") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_fc_map_req") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_flow_response") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_bridge_table_data") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_hugepage_config") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_vrf_req") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vrouter") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_message") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_info_t") == 0) {
			ret = i + 1;
      	} else if (strcmp(st_name, "vr_htable_t") == 0) {
			ret = i + 1;
        } else {
			continue;
		}

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

const VROUTER_BTF_FILE = "vrouter.btf"
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

	if C.IS_ERR_OR_NULL(unsafe.Pointer(vrouter_btf)) {
		return errors.New("btf__parse_raw failed")
	}

	for id := 0; id <= int(C.btf__get_nr_types(vrouter_btf)); id++ {
		t := C.btf__type_by_id(vrouter_btf, C.uint(id))

		if C.IS_ERR_OR_NULL(unsafe.Pointer(t)) {
			continue
		}

		if !C.btf_is_func(t) {
			continue
		}

		cfname := C.btf_str_by_offset_from_type(vrouter_btf, t)
		fname := C.GoString(cfname)

		if !s.isAvailfunc(fname) {
			continue
		}

		if traceOpt == "sandesh" {
			if pos := C.btf_find_sandesh_pos(vrouter_btf, t); pos > 0 {
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
