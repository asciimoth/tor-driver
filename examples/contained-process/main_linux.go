//go:build linux

// Command contained-process starts Tor in the supplied cgroup v2 scope and
// installs a fail-closed nftables boundary for Tor and its children.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	tor "github.com/asciimoth/tor-driver"
	"github.com/asciimoth/tor-driver/direct"
)

func run() error {
	torPath := flag.String("tor", "", "absolute path to Tor")
	cgroupParent := flag.String("cgroup-parent", "", "delegated cgroup v2 parent; empty uses the current cgroup")
	flag.Parse()
	if *torPath == "" {
		return fmt.Errorf("-tor is required")
	}
	contained, err := direct.NewContainedSystem(direct.LinuxContainmentConfig{CgroupParent: *cgroupParent})
	if err != nil {
		return err
	}
	defer func() { _ = contained.Close() }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	driver, err := tor.Start(ctx, tor.Config{TorExecutable: *torPath}, contained.Dependencies(direct.Network(), direct.Network(), direct.NewLogger(os.Stderr)))
	if err != nil {
		return err
	}
	defer func() { _ = driver.Close() }()
	if err = driver.WaitReady(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	return driver.Close()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
