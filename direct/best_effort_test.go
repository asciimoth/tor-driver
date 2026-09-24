package direct

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	tor "github.com/asciimoth/tor-driver"
)

func TestBestEffortReportIsCopied(t *testing.T) {
	system := &BestEffortSystem{report: BestEffortReport{Identity: &tor.Identity{UID: 12, GID: 34}}}
	report := system.Report()
	report.Identity.UID = 99
	if got := system.Report().Identity.UID; got != 12 {
		t.Fatalf("stored UID = %d, want 12", got)
	}
}

func TestBestEffortCloseIsIdempotent(t *testing.T) {
	want := errors.New("close failure")
	calls := 0
	system := &BestEffortSystem{close: func() error {
		calls++
		return want
	}}
	for range 2 {
		if err := system.Close(); !errors.Is(err, want) {
			t.Fatalf("Close() = %v, want %v", err, want)
		}
	}
	if calls != 1 {
		t.Fatalf("close calls = %d, want 1", calls)
	}
}

func TestBestEffortSelectionsDescribeContainment(t *testing.T) {
	want := errors.New("unavailable")
	_, closeProcess, report := fallbackSelection(want, BestEffortReport{})
	if closeProcess != nil || report.Containment || !errors.Is(report.ContainmentError, want) {
		t.Fatalf("fallback report = %+v", report)
	}
}

func TestBestEffortDependenciesReportFallbackOnce(t *testing.T) {
	want := errors.New("no delegated cgroup")
	system := &BestEffortSystem{
		processes: System{},
		report:    BestEffortReport{ContainmentError: want},
		executables: []executableDecision{
			{name: "Tor", path: "/usr/bin/tor", automatic: true},
			{name: "managed transport obfs4", path: "/opt/lyrebird", automatic: false},
		},
	}
	var output bytes.Buffer
	logger := NewLogger(&output)
	for range 2 {
		deps := system.Dependencies(nil, nil, logger)
		if deps.FS != system || deps.Processes != system {
			t.Fatal("Dependencies did not select the best-effort adapter")
		}
	}
	if got := strings.Count(output.String(), "no delegated cgroup"); got != 1 {
		t.Fatalf("fallback log count = %d, want 1: %q", got, output.String())
	}
	for _, wantText := range []string{
		`selected Tor executable from PATH discovery: "/usr/bin/tor"`,
		`selected managed transport obfs4 executable from explicit configuration: "/opt/lyrebird"`,
		"will keep the current operating-system identity",
		"selected the ordinary process adapter",
	} {
		if got := strings.Count(output.String(), wantText); got != 1 {
			t.Fatalf("log count for %q = %d, want 1: %q", wantText, got, output.String())
		}
	}
}

func TestBestEffortDependenciesLogPrivilegeAndContainmentDecisions(t *testing.T) {
	tests := []struct {
		name   string
		report BestEffortReport
		want   string
	}{
		{
			name:   "automatic drop",
			report: BestEffortReport{Identity: &tor.Identity{UID: 65534, GID: 65534}, AutomaticIdentity: true, PrivilegeDrop: true, Containment: true},
			want:   "will drop Linux root privileges to automatically selected UID 65534 GID 65534",
		},
		{
			name:   "explicit drop",
			report: BestEffortReport{Identity: &tor.Identity{UID: 123, GID: 456}, PrivilegeDrop: true, Containment: true},
			want:   "will drop Linux root privileges to explicitly configured UID 123 GID 456",
		},
		{
			name:   "explicit request",
			report: BestEffortReport{Identity: &tor.Identity{UID: 123, GID: 456}, Containment: true},
			want:   "will request explicitly configured Linux UID 123 GID 456",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			system := &BestEffortSystem{processes: System{}, report: test.report}
			var output bytes.Buffer
			system.Dependencies(nil, nil, NewLogger(&output))
			if !strings.Contains(output.String(), test.want) || !strings.Contains(output.String(), "selected strict platform process containment") {
				t.Fatalf("decision log = %q", output.String())
			}
		})
	}
}

func TestExecutableDecisionsTrackPathDiscovery(t *testing.T) {
	requested := tor.Config{
		Transports: []tor.TransportConfig{{Kind: tor.Obfs4, Executable: "/explicit/lyrebird"}},
	}
	resolved := requested
	resolved.TorExecutable = "/found/tor"
	decisions := executableDecisions(requested, resolved)
	if len(decisions) != 2 {
		t.Fatalf("decision count = %d, want 2", len(decisions))
	}
	if !decisions[0].automatic || decisions[0].path != "/found/tor" {
		t.Fatalf("Tor decision = %+v", decisions[0])
	}
	if decisions[1].automatic || decisions[1].path != "/explicit/lyrebird" {
		t.Fatalf("transport decision = %+v", decisions[1])
	}
}
