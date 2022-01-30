package main

import "C"
import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	bpf "github.com/aquasecurity/tracee/libbpfgo"
)

var PROG_NAMES = []string{
	"vr_interface_req1",
	"vr_interface_req2",
	"vr_interface_req3",
	"vr_interface_req4",
	"vr_interface_req5",
	"vr_route_req1",
	"vr_route_req2",
	"vr_route_req3",
	"vr_route_req4",
	"vr_route_req5",
	"vr_nexthop_req1",
	"vr_nexthop_req2",
	"vr_nexthop_req3",
	"vr_nexthop_req4",
	"vr_nexthop_req5",
	"vr_vrf_assign_req1",
	"vr_vrf_assign_req2",
	"vr_vrf_assign_req3",
	"vr_vrf_assign_req4",
	"vr_vrf_assign_req5",
	"vr_mpls_req1",
	"vr_mpls_req2",
	"vr_mpls_req3",
	"vr_mpls_req4",
	"vr_mpls_req5",
	"vr_vrf_stats_req1",
	"vr_vrf_stats_req2",
	"vr_vrf_stats_req3",
	"vr_vrf_stats_req4",
	"vr_vrf_stats_req5",
	"vr_mirror_req1",
	"vr_mirror_req2",
	"vr_mirror_req3",
	"vr_mirror_req4",
	"vr_mirror_req5",
	"vr_flow_req1",
	"vr_flow_req2",
	"vr_flow_req3",
	"vr_flow_req4",
	"vr_flow_req5",
	"vr_response1",
	"vr_response2",
	"vr_response3",
	"vr_response4",
	"vr_response5",
	"vr_flow_table_data1",
	"vr_flow_table_data2",
	"vr_flow_table_data3",
	"vr_flow_table_data4",
	"vr_flow_table_data5",
	"vr_vrf_req1",
	"vr_vrf_req2",
	"vr_vrf_req3",
	"vr_vrf_req4",
	"vr_vrf_req5",
	"vr_vxlan_req1",
	"vr_vxlan_req2",
	"vr_vxlan_req3",
	"vr_vxlan_req4",
	"vr_vxlan_req5",
	"vr_fc_map_req1",
	"vr_fc_map_req2",
	"vr_fc_map_req3",
	"vr_fc_map_req4",
	"vr_fc_map_req5",
	"vr_qos_map_req1",
	"vr_qos_map_req2",
	"vr_qos_map_req3",
	"vr_qos_map_req4",
	"vr_qos_map_req5",
	"vr_drop_stats_req1",
	"vr_drop_stats_req2",
	"vr_drop_stats_req3",
	"vr_drop_stats_req4",
	"vr_drop_stats_req5",
	"vr_bridge_table_data1",
	"vr_bridge_table_data2",
	"vr_bridge_table_data3",
	"vr_bridge_table_data4",
	"vr_bridge_table_data5",
}

type PerfEvent struct {
	Tstamp      uint64
	Faddr       uint64
	ProcessorId uint32
	IsReturn    uint8
}

func bpfModCreate() (*bpf.Module, error) {
	bpfmod, err := bpf.NewModuleFromFile("./vrft_kprobe.bpf.o")
	if err != nil {
		return nil, err
	}

	return bpfmod, nil
}

func bpfProgCreate(bpfmod *bpf.Module) (map[string]*bpf.BPFProg, error) {
	progs := make(map[string]*bpf.BPFProg)
	err := bpfmod.BPFLoadObject()
	if err != nil {
		return nil, err
	}

	for _, progname := range PROG_NAMES {
		prog, err := bpfmod.GetProgram(progname)
		if err != nil {
			return nil, err
		}
		progs[progname] = prog
	}

	return progs, nil
}

func attachKprobe(symdb *SymsDB, progs map[string]*bpf.BPFProg) error {
	var succeed int
	var failed int
	var err error
	var prog *bpf.BPFProg
	total := len(symdb.SymInfo)

	for symbol, syminfo := range symdb.SymInfo {
		prog_name := syminfo.Sname + strconv.Itoa(int(syminfo.Pos))
		prog, _ = progs[prog_name]

		if prog != nil {
			link, err := prog.AttachKprobe(symbol)
			if link == nil || err != nil {
				failed = failed + 1
				fmt.Printf("Attach kprobe failed for %s\n", symbol)
				err = errors.New("Attach kprobe failed")
				break
			}
			succeed = succeed + 1
			fmt.Printf("\rAttaching program (total: %d, succeeded: %d, failed: %d)", total, succeed, failed)
		}
	}
	fmt.Println("")

	return err
}

func kProbeCb(symdb *SymsDB, bpfmap *bpf.BPFMap) chan []byte {
	e := make(chan []byte, 1000)
	go func() {
		for b := range e {
			tstamp := binary.LittleEndian.Uint64(b[0:8])
			faddr := binary.LittleEndian.Uint64(b[8:16])
			processor_id := binary.LittleEndian.Uint32(b[16:20])
			arg_size := binary.LittleEndian.Uint64(b[24:32])
			if s, ok := symdb.Address[faddr]; ok {
				fmt.Printf("%-20d %03d %-64.64s %+v bytes\n", tstamp, processor_id, s, arg_size)
			}
		}
	}()
	return e
}

func createPerfbuf(bpfmod *bpf.Module, e chan []byte) (*bpf.PerfBuffer, error) {
	p, err := bpfmod.InitPerfBuf("events", e, nil, 64)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func signalHandler() chan os.Signal {
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT)
	return sig
}

func TracerRun(symdb *SymsDB) error {
	bpfmod, err := bpfModCreate()
	if err != nil {
		return err
	}

	prog, err := bpfProgCreate(bpfmod)
	if err != nil {
		return err
	}

	if err := attachKprobe(symdb, prog); err != nil {
		return err
	}

	// Get stack map(need to be refactored)
	bpfmap, err := bpfmod.GetMap("arg_data")
	if err != nil {
		return err
	}

	e := kProbeCb(symdb, bpfmap)

	perf, err := createPerfbuf(bpfmod, e)
	if err != nil {
		return err
	}

	sig := signalHandler()

	perf.Start()

	<-sig

	perf.Stop()

	return nil
}
