package tordriver

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/asciimoth/gobox"
)

const maxTransportRoutes = 1 << 23

// The index of each fixed-size digest is the route ID that Tor may have
// recorded in its guard state. Keep old records so IDs are never reassigned.
type routeAssignments struct {
	next     uint32
	files    gobox.Files
	name     string
	records  []byte
	reusable map[[sha256.Size]byte]uint32
}

func (p *routeAssignments) load(ctx context.Context, files gobox.Files, directory string) error {
	p.files = files
	p.name = path.Join(directory, "tor-driver-routes-v1")
	data, err := files.ReadFile(ctx, p.name, (maxTransportRoutes+1)*sha256.Size)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("tor-driver: read bridge route assignments: %w", err)
	}
	if len(data) < 2*sha256.Size || len(data)%sha256.Size != 0 {
		return errors.New("tor-driver: incomplete bridge route assignments")
	}
	records := data[:len(data)-sha256.Size]
	if sha256.Sum256(records) != [sha256.Size]byte(data[len(records):]) {
		return errors.New("tor-driver: corrupt bridge route assignments")
	}
	p.records = records
	p.next = uint32(len(records) / sha256.Size)
	p.reusable = make(map[[sha256.Size]byte]uint32)
	for offset := 0; offset < len(records); offset += sha256.Size {
		// A bridge that was retired and added again has a newer assignment.
		p.reusable[[sha256.Size]byte(data[offset:])] = uint32(offset / sha256.Size)
	}
	return nil
}

func (p *routeAssignments) save(ctx context.Context, additions []byte) (err error) {
	records := append(p.records, additions...)
	checksum := sha256.Sum256(records)
	tmp := p.name + ".tmp"
	file, err := p.files.Open(ctx, tmp, gobox.OpenOptions{Write: true, Create: true, Truncate: true, Mode: 0600})
	if err != nil {
		return fmt.Errorf("tor-driver: open temporary bridge route assignments: %w", err)
	}
	defer func() {
		if err != nil {
			removeErr := p.files.Remove(context.WithoutCancel(ctx), tmp)
			if !errors.Is(removeErr, fs.ErrNotExist) {
				err = errors.Join(err, removeErr)
			}
		}
	}()
	data := append(records, checksum[:]...)
	n, err := file.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	if err = errors.Join(err, file.Close()); err != nil {
		return fmt.Errorf("tor-driver: write bridge route assignments: %w", err)
	}
	if err := p.files.Rename(ctx, tmp, p.name); err != nil {
		return fmt.Errorf("tor-driver: replace bridge route assignments: %w", err)
	}
	p.records = records
	return nil
}

func bridgeRouteKey(b Bridge) [sha256.Size]byte {
	// Frame each string by its byte length. Go transport values can contain
	// any bytes, including separators, NUL, and invalid UTF-8.
	var data []byte
	field := func(s string) {
		data = binary.AppendUvarint(data, uint64(len(s)))
		data = append(data, s...)
	}
	field(string(b.Transport))
	field(b.Address)
	field(strings.ToUpper(string(b.Fingerprint)))
	for _, k := range slices.Sorted(maps.Keys(b.Args)) {
		field(k)
		field(b.Args[k])
	}
	return sha256.Sum256(data)
}
