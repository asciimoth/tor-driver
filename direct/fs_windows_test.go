//go:build windows

package direct

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsSecureFileSystemOperations(t *testing.T) {
	system := System{}
	base := t.TempDir()
	private := filepath.Join(base, "one", "two")
	if err := system.PrivateDir(private, nil); err != nil {
		t.Fatal(err)
	}
	assertPrivateDirectoryDACL(t, private)

	path := filepath.Join(private, "value")
	if err := system.WriteFile(path, []byte("value"), 0600, nil); err != nil {
		t.Fatal(err)
	}
	if err := system.WriteFile(path, []byte("replacement"), 0600, nil); !errors.Is(err, os.ErrExist) {
		t.Fatalf("exclusive WriteFile() error = %v", err)
	}
	data, err := system.ReadFile(path, 5)
	if err != nil || string(data) != "value" {
		t.Fatalf("ReadFile() = (%q, %v)", data, err)
	}
	if _, err = system.ReadFile(path, 4); err == nil {
		t.Fatal("oversized file was accepted")
	}
	if _, err = system.ReadFile(path, 0); err == nil {
		t.Fatal("invalid read limit was accepted")
	}
	if err = system.RemoveAll(filepath.Join(base, "one")); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed file remains: %v", err)
	}
}

func TestWindowsPrivateDirRejectsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := (System{}).PrivateDir(path, nil); err == nil {
		t.Fatal("PrivateDir accepted a file")
	}
}

func assertPrivateDirectoryDACL(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("directory DACL permits inheritance")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl == nil || dacl.AceCount != 2 {
		t.Fatalf("DACL ACE count = %v", dacl)
	}

	var token windows.Token
	err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{user.User.Sid.String(): false, "S-1-5-18": false}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(dacl, index, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatalf("ACE %d type = %d", index, ace.Header.AceType)
		}
		if ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			t.Fatalf("ACE %d is inherited", index)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if _, ok := want[sid]; !ok {
			t.Fatalf("unexpected DACL SID %s", sid)
		}
		want[sid] = true
	}
	for sid, found := range want {
		if !found {
			t.Fatalf("DACL does not contain %s", sid)
		}
	}
}
