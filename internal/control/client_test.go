package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSafeCookie(t *testing.T) {
	for _, tamper := range []bool{false, true} {
		t.Run(fmt.Sprint(tamper), func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = server.Close() }()
			cookie := bytes.Repeat([]byte{1}, 32)
			nonce := bytes.Repeat([]byte{2}, 32)
			serverNonce := bytes.Repeat([]byte{3}, 32)
			seenAuth := make(chan bool, 1)
			go func() {
				defer func() { _ = server.Close() }()
				r := bufio.NewReader(server)
				line, _ := r.ReadString('\n')
				if line != "PROTOCOLINFO 1\r\n" {
					seenAuth <- false
					return
				}
				_, _ = fmt.Fprint(server, "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/must/not/read\"\r\n250 OK\r\n")
				line, _ = r.ReadString('\n')
				if line != "AUTHCHALLENGE SAFECOOKIE "+hex.EncodeToString(nonce)+"\r\n" {
					seenAuth <- false
					return
				}
				hash := cookieMAC(serverKey, cookie, nonce, serverNonce)
				if tamper {
					hash[0] ^= 1
				}
				_, _ = fmt.Fprintf(server, "250 AUTHCHALLENGE SERVERHASH=%x SERVERNONCE=%x\r\n", hash, serverNonce)
				line, err := r.ReadString('\n')
				if tamper {
					seenAuth <- err != nil && line == ""
					return
				}
				valid := line == "AUTHENTICATE "+hex.EncodeToString(cookieMAC(clientKey, cookie, nonce, serverNonce))+"\r\n"
				_, _ = fmt.Fprint(server, "250 OK\r\n")
				seenAuth <- valid
			}()
			c := New(client)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := c.Authenticate(ctx, cookie, bytes.NewReader(nonce))
			_ = c.Close()
			if (err != nil) != tamper {
				t.Fatalf("tamper=%v error=%v", tamper, err)
			}
			select {
			case ok := <-seenAuth:
				if !ok {
					t.Fatal("incorrect authentication exchange")
				}
			case <-ctx.Done():
				t.Fatal("authentication stalled")
			}
		})
	}
}
func TestMultilineAndInterleavedEvent(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c := New(a)
	defer func() { _ = c.Close() }()
	go func() {
		r := bufio.NewReader(b)
		_, _ = r.ReadString('\n')
		_, _ = fmt.Fprint(b, "250-first=yes\r\n650 NOTICE event\r\n250+document=\r\nhello\r\n..dot\r\n.\r\n250 OK\r\n")
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := c.Do(ctx, "GETINFO first document")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.Lines, "|") != "first=yes|document=|hello|.dot|OK" {
		t.Fatal(r)
	}
	select {
	case event := <-c.Events():
		if strings.Join(event.Lines, "|") != "NOTICE event" {
			t.Fatalf("event = %q", event.Lines)
		}
	case <-ctx.Done():
		t.Fatal("interleaved event was not delivered")
	}
}
func TestCancellationClosesControl(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c := New(a)
	defer func() { _ = c.Close() }()
	read := make(chan struct{})
	go func() { r := bufio.NewReader(b); _, _ = r.ReadString('\n'); close(read); _, _ = io.Copy(io.Discard, r) }()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := c.Do(ctx, "GETINFO version"); result <- err }()
	<-read
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("expected cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("did not cancel")
	}
	select {
	case <-c.Done():
	case <-time.After(time.Second):
		t.Fatal("control left open")
	}
}
func TestInjectionAndCookieLength(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c := New(a)
	defer func() { _ = c.Close() }()
	if _, err := c.Do(context.Background(), "GETINFO version\r\nSIGNAL HALT"); err == nil {
		t.Fatal("injection accepted")
	}
	if err := c.Authenticate(context.Background(), []byte("short"), bytes.NewReader(nil)); err == nil {
		t.Fatal("short cookie accepted")
	}
}
