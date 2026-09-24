// Command service-only hosts HTTP without creating a client Network.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	driver, err := tor.Start(ctx, cfg, direct.Dependencies(direct.Network(), direct.Network(), direct.NewLogger(os.Stderr)))
	if err != nil {
		return err
	}
	defer func() { _ = driver.Close() }()
	service, err := driver.NewService(ctx, tor.ServiceConfig{Ports: []uint16{80}})
	if err != nil {
		return err
	}
	defer func() { _ = service.Close() }()
	listener, err := service.Listen(ctx, "tcp", ":80")
	if err != nil {
		return err
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "hello from an onion service")
	})}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	defer func() { _ = server.Close() }()
	if err = service.WaitPublished(ctx); err != nil {
		return err
	}
	fmt.Println("http://" + service.Address())
	select {
	case <-ctx.Done():
		drainCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return service.Drain(drainCtx)
	case err = <-serveDone:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
