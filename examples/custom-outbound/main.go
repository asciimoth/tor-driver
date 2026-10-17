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
	"github.com/asciimoth/tor-driver/examples/internal/debugtor"
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	runtime, err := debugtor.New(ctx, *torPath, "", "custom-outbound")
	if err != nil {
		return err
	}
	defer func() { _ = runtime.Close() }()

	outgoing := &countingNetwork{backend: debugtor.Network()}
	driver, err := tor.Start(ctx, tor.Config{}, runtime.Dependencies(outgoing))
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
