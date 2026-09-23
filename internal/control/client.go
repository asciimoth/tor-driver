// Package control implements the small, private subset of Tor control protocol
// needed by the driver. It has no filesystem or network creation side effects.
package control

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
)

const maxReply = 1 << 20

type Reply struct {
	Code  int
	Lines []string
}
type Event struct {
	Lines []string
}
type Error struct{ Code int }

func (e *Error) Error() string { return fmt.Sprintf("tor control: status %d", e.Code) }

type Client struct {
	conn    net.Conn
	reader  *bufio.Reader
	serial  chan struct{}
	replies chan Reply
	events  chan Event
	done    chan struct{}
	once    sync.Once
	mu      sync.Mutex
	err     error
}

func New(conn net.Conn) *Client {
	c := &Client{conn: conn, reader: bufio.NewReaderSize(conn, 64<<10), serial: make(chan struct{}, 1), replies: make(chan Reply, 1), events: make(chan Event, 64), done: make(chan struct{})}
	go c.readLoop()
	return c
}
func (c *Client) Done() <-chan struct{} { return c.done }
func (c *Client) Events() <-chan Event  { return c.events }
func (c *Client) Err() error            { c.mu.Lock(); defer c.mu.Unlock(); return c.err }
func (c *Client) fail(err error) {
	c.once.Do(func() { c.mu.Lock(); c.err = err; c.mu.Unlock(); _ = c.conn.Close(); close(c.done) })
}
func (c *Client) Close() error { c.fail(net.ErrClosed); return nil }

// Do serializes requests. Cancellation AFTER transmission closes the control
// channel, because otherwise a late reply could be mistaken for the next one.
// With TAKEOWNERSHIP that also terminates Tor: intentional fail-closed behavior.
func (c *Client) Do(ctx context.Context, command string) (Reply, error) {
	if strings.ContainsAny(command, "\r\n\x00") {
		return Reply{}, errors.New("tor control: command injection rejected")
	}
	select {
	case c.serial <- struct{}{}:
	case <-ctx.Done():
		return Reply{}, ctx.Err()
	case <-c.done:
		return Reply{}, c.Err()
	}
	defer func() { <-c.serial }()
	if err := ctx.Err(); err != nil {
		return Reply{}, err
	}
	stop := context.AfterFunc(ctx, func() { c.fail(ctx.Err()) })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := c.conn.SetWriteDeadline(deadline); err != nil {
		c.fail(err)
		return Reply{}, err
	}
	if _, err := io.WriteString(c.conn, command+"\r\n"); err != nil {
		c.fail(err)
		return Reply{}, err
	}
	result := func(r Reply) (Reply, error) {
		stop()
		if err := ctx.Err(); err != nil {
			return Reply{}, err
		}
		if r.Code != 250 {
			return r, &Error{Code: r.Code}
		}
		return r, nil
	}
	select {
	case r := <-c.replies:
		return result(r)
	case <-ctx.Done():
		c.fail(ctx.Err())
		return Reply{}, ctx.Err()
	case <-c.done:
		select {
		case r := <-c.replies:
			return result(r)
		default:
			return Reply{}, c.Err()
		}
	}
}
func (c *Client) readLoop() {
	for {
		r, err := c.readReply()
		if err != nil {
			c.fail(err)
			return
		}
		select {
		case c.replies <- r:
		case <-c.done:
			return
		}
	}
}
func (c *Client) line() (string, error) {
	b, err := c.reader.ReadSlice('\n')
	if err != nil {
		return "", err
	}
	if len(b) < 2 || b[len(b)-2] != '\r' {
		return "", errors.New("tor control: missing CRLF")
	}
	return string(b[:len(b)-2]), nil
}
func split(line string) (int, byte, string, error) {
	if len(line) < 4 {
		return 0, 0, "", errors.New("tor control: short line")
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil || code < 100 || code > 699 || !strings.ContainsRune(" -+", rune(line[3])) {
		return 0, 0, "", errors.New("tor control: malformed status")
	}
	return code, line[3], line[4:], nil
}
func (c *Client) data() ([]string, int, error) {
	var lines []string
	n := 0
	for {
		s, err := c.line()
		if err != nil {
			return nil, n, err
		}
		n += len(s) + 2
		if n > maxReply {
			return nil, n, errors.New("tor control: oversized data")
		}
		if s == "." {
			return lines, n, nil
		}
		if strings.HasPrefix(s, "..") {
			s = s[1:]
		}
		lines = append(lines, s)
	}
}
func (c *Client) readEvent(body string, sep byte) (Event, error) {
	e := Event{Lines: []string{body}}
	n := 0
	for {
		if sep == '+' {
			lines, size, err := c.data()
			if err != nil {
				return Event{}, err
			}
			n += size
			e.Lines = append(e.Lines, lines...)
		}
		if sep == ' ' {
			return e, nil
		}
		s, err := c.line()
		if err != nil {
			return Event{}, err
		}
		n += len(s) + 2
		if n > maxReply {
			return Event{}, errors.New("tor control: oversized event")
		}
		code, next, nextBody, err := split(s)
		if err != nil {
			return Event{}, err
		}
		if code != 650 {
			return Event{}, errors.New("tor control: malformed event")
		}
		e.Lines = append(e.Lines, nextBody)
		sep = next
	}
}
func (c *Client) readReply() (Reply, error) {
	r := Reply{}
	n := 0
	for {
		s, err := c.line()
		if err != nil {
			return r, err
		}
		n += len(s) + 2
		if n > maxReply {
			return r, errors.New("tor control: oversized reply")
		}
		code, sep, body, err := split(s)
		if err != nil {
			return r, err
		}
		if code == 650 {
			e, eventErr := c.readEvent(body, sep)
			if eventErr != nil {
				return r, eventErr
			}
			select {
			case c.events <- e:
			case <-c.done:
				return r, c.Err()
			default:
				return r, errors.New("tor control: event backlog exceeded")
			}
			continue
		}
		if r.Code != 0 && code != r.Code {
			return r, errors.New("tor control: mixed response codes")
		}
		r.Code = code
		r.Lines = append(r.Lines, body)
		if sep == '+' {
			lines, size, err := c.data()
			if err != nil {
				return r, err
			}
			n += size
			if n > maxReply {
				return r, errors.New("tor control: oversized reply")
			}
			r.Lines = append(r.Lines, lines...)
		}
		if sep == ' ' {
			return r, nil
		}
	}
}

const serverKey = "Tor safe cookie authentication server-to-controller hash"
const clientKey = "Tor safe cookie authentication controller-to-server hash"

func cookieMAC(key string, cookie, client, server []byte) []byte {
	h := hmac.New(sha256.New, []byte(key))
	h.Write(cookie)
	h.Write(client)
	h.Write(server)
	return h.Sum(nil)
}

// Authenticate uses only the caller-supplied cookie; it never opens the path
// advertised by PROTOCOLINFO and never downgrades to COOKIE or a password.
func (c *Client) Authenticate(ctx context.Context, cookie []byte, random io.Reader) error {
	if len(cookie) != 32 {
		return errors.New("tor control: cookie must contain 32 bytes")
	}
	r, err := c.Do(ctx, "PROTOCOLINFO 1")
	if err != nil {
		return err
	}
	safe := false
	for _, line := range r.Lines {
		if !strings.HasPrefix(line, "AUTH ") {
			continue
		}
		for _, field := range strings.Fields(line) {
			if strings.HasPrefix(field, "METHODS=") {
				for _, m := range strings.Split(strings.TrimPrefix(field, "METHODS="), ",") {
					if m == "SAFECOOKIE" {
						safe = true
					}
				}
			}
		}
	}
	if !safe {
		return errors.New("tor control: SAFECOOKIE required")
	}
	client := make([]byte, 32)
	if _, err = io.ReadFull(random, client); err != nil {
		return err
	}
	r, err = c.Do(ctx, "AUTHCHALLENGE SAFECOOKIE "+hex.EncodeToString(client))
	if err != nil {
		return err
	}
	var server, hash []byte
	for _, line := range r.Lines {
		for _, field := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(field, "SERVERNONCE="); ok {
				server, err = hex.DecodeString(v)
				if err != nil {
					return err
				}
			}
			if v, ok := strings.CutPrefix(field, "SERVERHASH="); ok {
				hash, err = hex.DecodeString(v)
				if err != nil {
					return err
				}
			}
		}
	}
	if len(server) != 32 || len(hash) != 32 || !hmac.Equal(hash, cookieMAC(serverKey, cookie, client, server)) {
		return errors.New("tor control: SAFECOOKIE server proof failed")
	}
	_, err = c.Do(ctx, "AUTHENTICATE "+hex.EncodeToString(cookieMAC(clientKey, cookie, client, server)))
	return err
}

// Value extracts a GETINFO or ADD_ONION key without interpreting quoted text.
func Value(r Reply, key string) (string, bool) {
	for _, s := range r.Lines {
		if v, ok := strings.CutPrefix(s, key+"="); ok {
			return v, true
		}
	}
	return "", false
}

// QuotedWords handles Tor's quoted endpoint lists. No filesystem access.
func QuotedWords(s string) ([]string, error) {
	var result []string
	for strings.TrimSpace(s) != "" {
		s = strings.TrimSpace(s)
		if s[0] != '"' {
			return nil, errors.New("tor control: expected quoted endpoint")
		}
		end := 1
		for ; end < len(s); end++ {
			if s[end] == '\\' {
				end++
				continue
			}
			if s[end] == '"' {
				break
			}
		}
		if end >= len(s) {
			return nil, errors.New("tor control: unterminated endpoint")
		}
		v, err := strconv.Unquote(s[:end+1])
		if err != nil {
			return nil, err
		}
		result = append(result, v)
		s = s[end+1:]
	}
	return result, nil
}
