//go:build linux

package direct

import (
	"errors"
	"os/user"
	"strings"
	"testing"

	tor "github.com/asciimoth/tor-driver"
)

func TestSelectLinuxIdentityKeepsUnprivilegedCaller(t *testing.T) {
	called := false
	cfg, report, err := selectLinuxIdentity(tor.Config{}, 1000, func(string) (*user.User, error) {
		called = true
		return nil, errors.New("must not be called")
	})
	if err != nil {
		t.Fatal(err)
	}
	if called || cfg.Identity != nil || report.Identity != nil || report.PrivilegeDrop || report.AutomaticIdentity {
		t.Fatalf("unexpected identity decision: cfg=%#v report=%+v lookup=%v", cfg.Identity, report, called)
	}
}

func TestSelectLinuxIdentityPreservesExplicitIdentity(t *testing.T) {
	original := &tor.Identity{UID: 123, GID: 456}
	cfg, report, err := selectLinuxIdentity(tor.Config{Identity: original}, 0, func(string) (*user.User, error) {
		t.Fatal("explicit identity caused account lookup")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Identity == original {
		t.Fatal("explicit identity was not copied")
	}
	if got, want := *cfg.Identity, *original; got != want {
		t.Fatalf("identity = %+v, want %+v", got, want)
	}
	if report.Identity == nil || *report.Identity != *original || !report.PrivilegeDrop || report.AutomaticIdentity {
		t.Fatalf("report = %+v", report)
	}
	original.UID = 999
	if cfg.Identity.UID != 123 || report.Identity.UID != 123 {
		t.Fatal("returned identity aliases the input")
	}
}

func TestSelectLinuxIdentityFindsNobodyForRoot(t *testing.T) {
	cfg, report, err := selectLinuxIdentity(tor.Config{}, 0, func(name string) (*user.User, error) {
		if name != "nobody" {
			t.Fatalf("lookup name = %q", name)
		}
		return &user.User{Uid: "65534", Gid: "65533"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := tor.Identity{UID: 65534, GID: 65533}
	if cfg.Identity == nil || *cfg.Identity != want || report.Identity == nil || *report.Identity != want {
		t.Fatalf("cfg identity = %#v, report = %+v", cfg.Identity, report)
	}
	if !report.AutomaticIdentity || !report.PrivilegeDrop {
		t.Fatalf("report = %+v", report)
	}
}

func TestSelectLinuxIdentityRejectsUnsafeNobodyAccount(t *testing.T) {
	tests := []struct {
		name    string
		account *user.User
		err     error
	}{
		{name: "missing", err: errors.New("not found")},
		{name: "root UID", account: &user.User{Uid: "0", Gid: "65534"}},
		{name: "root GID", account: &user.User{Uid: "65534", Gid: "0"}},
		{name: "invalid UID", account: &user.User{Uid: "nobody", Gid: "65534"}},
		{name: "invalid GID", account: &user.User{Uid: "65534", Gid: "nobody"}},
		{name: "large UID", account: &user.User{Uid: "4294967296", Gid: "65534"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := selectLinuxIdentity(tor.Config{}, 0, func(string) (*user.User, error) {
				return test.account, test.err
			})
			if err == nil || !strings.Contains(err.Error(), "nobody") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
