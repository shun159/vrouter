package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

func perfMapCb(symdb *SymsDB) chan []byte {
	e := make(chan []byte, 1000)
	go func() {
		for b := range e {
			perf := parsePerfEvent(b, *symdb)
			idx := perf.Idx
			fmt.Printf("%-20d %03d %-50.50s %s\n", perf.Tstamp, perf.ProcessorId, perf.Fname, perf.Sname)

			bpfmap := findMap(perf.Sname)
			if bpfmap == nil {
				fmt.Printf("Map doesn't exist for %+s\n", perf.Fname)
				continue
			}

			data, err := bpfmap.GetValue(unsafe.Pointer(&idx))
			if err != nil {
				fmt.Printf("map error: %+v\n", err)
				continue
			} else {
				bpfmap.DeleteKey(unsafe.Pointer(&idx))
			}

			if req := parseSreq(perf, data); req != nil {
				fmt.Printf("data: %+v\n", req)
			} else {
				fmt.Printf("data: %+v\n", data)
			}
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
	perf, err := initBPF(symdb)
	if err != nil {
		return err
	}

	sig := signalHandler()
	perf.Start()
	<-sig
	perf.Stop()

	return nil
}
