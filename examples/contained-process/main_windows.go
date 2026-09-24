//go:build windows

// Command contained-process reports that strict Windows process containment is
// unavailable. Executable-scoped firewall rules do not contain descendants.
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
	torPath := flag.String("tor", "", "absolute path to Tor; empty searches PATH")
	flag.Parse()
	cfg, err := direct.FindExecutables(tor.Config{TorExecutable: *torPath})
	if err != nil {
		return err
	}
	contained, err := direct.NewContainedSystem(direct.WindowsContainmentConfig{Executables: []string{cfg.TorExecutable}})
	if err != nil {
		return err
	}
	defer func() { _ = contained.Close() }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	driver, err := tor.Start(ctx, cfg, contained.Dependencies(direct.Network(), direct.Network(), direct.NewLogger(os.Stderr)))
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
