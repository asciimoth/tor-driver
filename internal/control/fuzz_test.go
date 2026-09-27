package control

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

type corpusConn struct {
	*bytes.Reader
	gate     chan struct{}
	gateOnce sync.Once
}

func commandCorpusConn(data []byte) *corpusConn {
	return &corpusConn{Reader: bytes.NewReader(data), gate: make(chan struct{})}
}

func (c *corpusConn) Read(p []byte) (int, error) {
	if c.gate != nil {
		<-c.gate
	}
	return c.Reader.Read(p)
}
func (c *corpusConn) Write(p []byte) (int, error) {
	c.openGate()
	return len(p), nil
}
func (c *corpusConn) Close() error { c.openGate(); return nil }
func (c *corpusConn) openGate() {
	if c.gate != nil {
		c.gateOnce.Do(func() { close(c.gate) })
	}
}
func (c *corpusConn) LocalAddr() net.Addr              { return corpusAddr("local") }
func (c *corpusConn) RemoteAddr() net.Addr             { return corpusAddr("remote") }
func (c *corpusConn) SetDeadline(time.Time) error      { return nil }
func (c *corpusConn) SetReadDeadline(time.Time) error  { return nil }
func (c *corpusConn) SetWriteDeadline(time.Time) error { return nil }

type corpusAddr string

func (a corpusAddr) Network() string { return "corpus" }
func (a corpusAddr) String() string  { return string(a) }

func FuzzReplies(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("250 OK\r\n"),
		[]byte("250-key=value\r\n650 NOTICE event\r\n250 OK\r\n"),
		[]byte("250+document=\r\nhello\r\n..dot\r\n.\r\n250 OK\r\n"),
		[]byte("250 missing-newline"),
		[]byte("999 BAD\r\n"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2*maxReply {
			t.Skip()
		}
		conn := commandCorpusConn(data)
		client := New(conn)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_, _ = client.Do(ctx, "GETINFO version")
		cancel()
		_ = client.Close()
	})
}
