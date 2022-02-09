package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

type PerfEvent struct {
	Tstamp      uint64
	Faddr       uint64
	ProcessorId uint32
	IsReturn    uint8
	Idx         uint64
	Fname       string
	Sname       string
}

func parsePerfEvent(b []byte, symdb SymsDB) PerfEvent {
	perf := PerfEvent{}
	perf.Tstamp = binary.LittleEndian.Uint64(b[0:8])
	perf.Faddr = binary.LittleEndian.Uint64(b[8:16])
	perf.ProcessorId = binary.LittleEndian.Uint32(b[16:20])
	perf.Idx = binary.LittleEndian.Uint64(b[32:40])
	if s, ok := symdb.Address[perf.Faddr]; ok {
		perf.Fname = s
		if syminfo, ok := symdb.SymInfo[perf.Fname]; ok {
			perf.Sname = syminfo.Sname
		}
	}
	return perf
}

func perfMapCb(symdb *SymsDB, bpfmap *bpf.BPFMap) chan []byte {
	e := make(chan []byte, 1000)
	go func() {
		for b := range e {
			perf := parsePerfEvent(b, *symdb)
			idx := perf.Idx
			fmt.Printf("%-20d %03d %-20.20s %s\n", perf.Tstamp, perf.ProcessorId, perf.Fname, perf.Sname)
			data, err := bpfmap.GetValue(unsafe.Pointer(&idx))
			if err != nil {
				fmt.Printf("map error: %+v\n", err)
				continue
			}
			fmt.Printf("data: %+v\n", data)
		}
	}()
	return e
}

func signalHandler() chan os.Signal {
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT)
	return sig
}

func TracerRun(symdb *SymsDB) error {
	initBPFProgs()

	bpfmod, err := bpfModCreate()
	if err != nil {
		return err
	}

	if err := bpfProgCreate(bpfmod); err != nil {
		return err
	}

	if err := attachKprobes(symdb); err != nil {
		return err
	}

	// Get stack map(need to be refactored)
	bpfmap, err := bpfmod.GetMap("arg_data")
	if err != nil {
		return err
	}

	e := perfMapCb(symdb, bpfmap)

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
