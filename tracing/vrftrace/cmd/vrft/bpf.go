package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	bpf "github.com/aquasecurity/libbpfgo"
)

const KPROBE_PROG = "./vrft_kprobe.bpf.o"
const ATTACH_RESULT_FMT = "\rAttaching program (total: %d, succeeded: %d, failed: %d)"

var maxSandeshPos = 5
var sandeshStructs = []string{
	"vr_interface_req",
	"vr_route_req",
	"vr_nexthop_req",
	"vr_vrf_assign_req",
	"vr_mpls_req",
	"vr_vrf_stats_req",
	"vr_mirror_req",
	"vr_flow_req",
	"vr_response",
	"vr_flow_table_data",
	"vr_vrf_req",
	"vr_vxlan_req",
	"vr_fc_map_req",
	"vr_qos_map_req",
	"vr_drop_stats_req",
	"vr_bridge_table_data",
}
var progNames = []string{}
var progDb = make(map[string]*bpf.BPFProg)
var mapNames = []string{}
var mapDb = make(map[string]*bpf.BPFMap)

func initBPF(symdb *SymsDB) (*bpf.PerfBuffer, error) {
	initBPFProgs()
	initBPFMaps()

	bpfmod, err := bpfModCreate()
	if err != nil {
		return nil, err
	}

	if err := bpfProgCreate(bpfmod); err != nil {
		return nil, err
	}

	if err := attachKprobes(symdb); err != nil {
		return nil, err
	}

	if err := bpfMapCreate(bpfmod); err != nil {
		return nil, err
	}

	perf, err := createPerfbuf(bpfmod, perfMapCb(symdb))
	if err != nil {
		return nil, err
	}

	return perf, nil
}

func initBPFProgs() {
	for _, st := range sandeshStructs {
		for i := 1; i <= maxSandeshPos; i++ {
			name := strings.Join([]string{st, strconv.Itoa(i)}, "")
			progNames = append(progNames, name)
		}
	}
}

func initBPFMaps() {
	for _, st := range sandeshStructs {
		name := strings.Join([]string{st, "_map"}, "")
		mapNames = append(mapNames, name)
	}
}

func bpfModCreate() (*bpf.Module, error) {
	if bpfmod, err := bpf.NewModuleFromFile(KPROBE_PROG); err != nil {
		return nil, err
	} else {
		return bpfmod, nil
	}
}

func updateProgDb(bpfmod *bpf.Module) error {
	for _, progname := range progNames {
		if prog, err := bpfmod.GetProgram(progname); err != nil {
			return err
		} else {
			progDb[progname] = prog
		}
	}
	return nil
}

func bpfProgCreate(bpfmod *bpf.Module) error {
	if err := bpfmod.BPFLoadObject(); err != nil {
		return err
	} else {
		return updateProgDb(bpfmod)
	}
}

func bpfMapCreate(bpfmod *bpf.Module) error {
	for _, mapname := range mapNames {
		if bpfmap, err := bpfmod.GetMap(mapname); err != nil {
			return err
		} else {
			mapDb[mapname] = bpfmap
		}
	}
	return nil
}

func attachKprobes(symdb *SymsDB) error {
	var succeed int
	var failed int
	var err error
	total := len(symdb.SymInfo)

	for symbol, syminfo := range symdb.SymInfo {
		if err := attachKprobe(symbol, syminfo); err != nil {
			failed = failed + 1
			err = errors.New("Attach kprobe failed")
			break
		}
		succeed = succeed + 1
		fmt.Printf(ATTACH_RESULT_FMT, total, succeed, failed)
	}
	fmt.Println("")

	return err
}

func attachKprobe(symbol string, syminfo SymInfo) error {
	prog_name := strings.Join([]string{syminfo.Sname, strconv.Itoa(int(syminfo.Pos))}, "")
	if prog, ok := progDb[prog_name]; ok {
		if link, err := prog.AttachKprobe(symbol); err != nil || link == nil {
			return errors.New("Attach kprobe failed: %s")
		}
	} else {
		return errors.New("symbol doesn't exist: %s")
	}
	return nil
}

func createPerfbuf(bpfmod *bpf.Module, e chan []byte) (*bpf.PerfBuffer, error) {
	p, err := bpfmod.InitPerfBuf("events", e, nil, 64)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func findMap(sname string) *bpf.BPFMap {
	map_name := strings.Join([]string{sname, "_map"}, "")
	if bpfmap, ok := mapDb[map_name]; ok {
		return bpfmap
	} else {
		return nil
	}
}
