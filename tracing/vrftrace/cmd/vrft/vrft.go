package main

import (
	"flag"
	"log"
)

var (
	traceOpt = flag.String("t", "sandesh", "Trace vr.sandesh function calls")
)

func main() {
	flag.Parse()

	if err := setRlimits(); err != nil {
		log.Fatalf("Failed to set_rlimit: %s\n", err)
		return
	}

	symdb, _ := NewSymsDB(*traceOpt)
	if err := TracerRun(&symdb); err != nil {
		panic(err)
	}
}
