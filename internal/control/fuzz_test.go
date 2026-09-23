package control

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

type corpusConn struct{ *bytes.Reader }

func (c *corpusConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *corpusConn) Close() error                     { return nil }
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
		conn := &corpusConn{Reader: bytes.NewReader(data)}
		client := New(conn)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		_, _ = client.Do(ctx, "GETINFO version")
		cancel()
		_ = client.Close()
	})
}
