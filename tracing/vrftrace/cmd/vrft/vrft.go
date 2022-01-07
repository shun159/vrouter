package main

import (
	"flag"
	"log"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	traceOpt = flag.String("t", "sandesh", "Trace vr.sandesh function calls")
)

func getNoFile(rLimit *syscall.Rlimit) error {
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, rLimit)

	if err != nil {
		return err
	}

	return nil
}

func setNoFile() error {
	var rLimit syscall.Rlimit
	err := getNoFile(&rLimit)

	if err != nil {
		return err
	}

	rLimit.Max = rLimit.Max
	rLimit.Cur = rLimit.Max
	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)

	if err != nil {
		return err
	}

	return nil
}

func setMemlock() error {
	var rLimit syscall.Rlimit
	rLimit.Max = unix.RLIM_INFINITY
	rLimit.Cur = unix.RLIM_INFINITY
	err := syscall.Setrlimit(unix.RLIMIT_MEMLOCK, &rLimit)

	if err != nil {
		return err
	}

	return nil
}

func setRlimits() error {
	if err := setMemlock(); err != nil {
		return err
	}

	if err := setNoFile(); err != nil {
		return err
	}

	return nil
}

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
