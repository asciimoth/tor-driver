package control

import (
	"bytes"
	"context"
	"net/textproto"
	"reflect"
	"testing"
	"time"

	binecontrol "github.com/cretz/bine/control"
)

// Keep a small differential corpus against Bine. Bine is used only as an
// independent control-protocol parser; the production driver stays on the
// bounded parser in this package.
func TestReplyCorpusMatchesBine(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire string
	}{
		{name: "single", wire: "250 OK\r\n"},
		{name: "values", wire: "250-key=first\r\n250-other=second\r\n250 OK\r\n"},
		{name: "rejection", wire: "551 COMMAND_UNRECOGNIZED\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bineConn := binecontrol.NewConn(textproto.NewConn(&corpusConn{Reader: bytes.NewReader([]byte(tc.wire))}))
			want, err := bineConn.ReadResponse()
			if err != nil {
				t.Fatal(err)
			}

			client := New(&corpusConn{Reader: bytes.NewReader([]byte(tc.wire))})
			defer func() { _ = client.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, _ := client.Do(ctx, "GETINFO conformance")

			if got.Code != want.Err.Code || !reflect.DeepEqual(got.Lines, want.DataWithReply()) {
				t.Fatalf("private parser = (%d, %q), Bine = (%d, %q)", got.Code, got.Lines, want.Err.Code, want.DataWithReply())
			}
		})
	}
}
