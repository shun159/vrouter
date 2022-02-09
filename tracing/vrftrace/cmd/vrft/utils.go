package main

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

func setNoFile() error {
	var rLimit syscall.Rlimit

	rLimit.Max = unix.RLIM_INFINITY
	rLimit.Cur = 8192 * 1024

	if err := syscall.Setrlimit(syscall.RLIMIT_STACK, &rLimit); err != nil {
		return err
	} else {
		return nil
	}
}

func setMemlock() error {
	var rLimit syscall.Rlimit

	rLimit.Max = unix.RLIM_INFINITY
	rLimit.Cur = unix.RLIM_INFINITY

	if err := syscall.Setrlimit(unix.RLIMIT_MEMLOCK, &rLimit); err != nil {
		return fmt.Errorf("error setting rlimit: %v", err)
	} else {
		return nil
	}
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
