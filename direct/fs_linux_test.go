//go:build linux

package direct

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecureFileSystemOperations(t *testing.T) {
	system := System{}
	base := t.TempDir()
	private := filepath.Join(base, "one", "two")
	if err := system.PrivateDir(private, nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(private)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("private mode = %o", info.Mode().Perm())
	}
	path := filepath.Join(private, "value")
	if err = system.WriteFile(path, []byte("value"), 0600, nil); err != nil {
		t.Fatal(err)
	}
	data, err := system.ReadFile(path, 5)
	if err != nil || string(data) != "value" {
		t.Fatalf("ReadFile() = (%q, %v)", data, err)
	}
	if _, err = system.ReadFile(path, 4); err == nil {
		t.Fatal("oversized file was accepted")
	}
	if err = system.RemoveAll(filepath.Join(base, "one")); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed file remains: %v", err)
	}
}

func TestSecureFileSystemRejectsPathReplacementLinks(t *testing.T) {
	system := System{}
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("outside"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := system.PrivateDir(filepath.Join(link, "child"), nil); err == nil {
		t.Fatal("PrivateDir followed an ancestor symlink")
	}
	if err := system.WriteFile(filepath.Join(link, "created"), []byte("bad"), 0600, nil); err == nil {
		t.Fatal("WriteFile followed an ancestor symlink")
	}
	if _, err := system.ReadFile(filepath.Join(link, "secret"), 64); err == nil {
		t.Fatal("ReadFile followed an ancestor symlink")
	}
	if _, err := os.Stat(filepath.Join(outside, "created")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("outside file was created")
	}

	tree := filepath.Join(base, "tree")
	if err := os.Mkdir(tree, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(tree, "outside-link")); err != nil {
		t.Fatal(err)
	}
	if err := system.RemoveAll(tree); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(secret)
	if err != nil || string(data) != "outside" {
		t.Fatalf("RemoveAll changed symlink target: (%q, %v)", data, err)
	}
	if err = system.RemoveAll(link); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(outside); err != nil {
		t.Fatal("top-level symlink target was removed")
	}
	if err = system.PrivateDir(string(filepath.Separator), nil); err == nil || !strings.Contains(err.Error(), "filesystem root") {
		t.Fatalf("filesystem root error = %v", err)
	}
}
