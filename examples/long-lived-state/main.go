// Command long-lived-state keeps Tor guard and consensus state in a private,
// caller-selected directory across intentional process restarts.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	tor "github.com/asciimoth/tor-driver"
	"github.com/asciimoth/tor-driver/direct"
)

func run() error {
	torPath := flag.String("tor", "", "absolute path to Tor")
	state := flag.String("state", "", "absolute private directory for persistent Tor state")
	flag.Parse()
	if *torPath == "" || *state == "" || !filepath.IsAbs(*state) {
		return fmt.Errorf("-tor and an absolute -state are required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cfg := tor.Config{TorExecutable: *torPath, StateDirectory: *state}
	driver, err := tor.Start(ctx, cfg, direct.Dependencies(direct.Network(), direct.Network(), direct.NewLogger(os.Stderr)))
	if err != nil {
		return err
	}
	defer func() { _ = driver.Close() }()
	if err = driver.WaitReady(ctx); err != nil {
		return err
	}
	fmt.Println("Tor is ready; interrupt the process to keep its guard state")
	<-ctx.Done()
	return driver.Close()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
