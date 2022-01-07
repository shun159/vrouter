package main

import "C"
import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	bpf "github.com/aquasecurity/tracee/libbpfgo"
)

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

func bpfProgCreate(bpfmod *bpf.Module) (*bpf.BPFProg, error) {
	err := bpfmod.BPFLoadObject()
	if err != nil {
		return nil, err
	}

	prog, err := bpfmod.GetProgram("vrft_main")
	if err != nil {
		return nil, err
	}

	return prog, nil
}

func attachKprobe(symdb *SymsDB, prog *bpf.BPFProg) error {
	var succeed int
	var failed int
	var err error
	total := len(symdb.SymInfo)

	for symbol := range symdb.SymInfo {
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
	fmt.Println("")
	bufio.NewWriter(os.Stdout).Flush()

	return err
}

func kProbeCb(symdb *SymsDB) chan []byte {
	e := make(chan []byte, 360)
	go func() {
		for b := range e {
			tstamp := binary.LittleEndian.Uint64(b[0:8])
			faddr := binary.LittleEndian.Uint64(b[8:16])
			processor_id := binary.LittleEndian.Uint32(b[16:20])
			if s, ok := symdb.Address[faddr]; ok {
				fmt.Printf("%-20d %03d %-64.64s\n", tstamp, processor_id, s)
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

	e := kProbeCb(symdb)

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
