// Command long-lived-state keeps Tor guard and consensus state in a private,
// caller-selected directory across intentional process restarts.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/asciimoth/gobox"
	tor "github.com/asciimoth/tor-driver"
	"github.com/asciimoth/tor-driver/examples/internal/debugtor"
)

func run() error {
	torPath := flag.String("tor", "", "absolute path to Tor; empty searches PATH")
	state := flag.String("state", "", "debug backend root for persistent Tor state")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	runtime, err := debugtor.New(ctx, *torPath, *state, "long-lived-state")
	if err != nil {
		return err
	}
	defer func() { _ = runtime.Close() }()
	cfg := tor.Config{StateDirectory: gobox.Path{Root: gobox.Persistent, Rel: "state"}}
	driver, err := tor.Start(ctx, cfg, runtime.Dependencies(debugtor.Network()))
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
