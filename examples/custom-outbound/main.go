// Command custom-outbound shows how to wrap a gonnect Network before Tor uses
// it for relay connections.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync/atomic"

	"github.com/asciimoth/gonnect"
	tor "github.com/asciimoth/tor-driver"
	"github.com/asciimoth/tor-driver/direct"
)

type countingNetwork struct {
	gonnect.RejectNetwork
	backend gonnect.Network
	dials   atomic.Uint64
}

func (n *countingNetwork) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	n.dials.Add(1)
	return n.backend.Dial(ctx, network, address)
}

func run() error {
	torPath := flag.String("tor", "", "absolute path to Tor; empty searches PATH")
	flag.Parse()
	system, cfg, err := direct.NewBestEffortSystem(tor.Config{TorExecutable: *torPath})
	if err != nil {
		return err
	}
	defer func() { _ = system.Close() }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	outgoing := &countingNetwork{backend: direct.Network()}
	logger := direct.NewLogger(os.Stderr)
	driver, err := tor.Start(ctx, cfg, system.Dependencies(direct.Network(), outgoing, logger))
	if err != nil {
		return err
	}
	defer func() { _ = driver.Close() }()
	if err = driver.WaitReady(ctx); err != nil {
		return err
	}
	fmt.Printf("Tor is ready after %d backend dials\n", outgoing.dials.Load())
	<-ctx.Done()
	return driver.Close()
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
