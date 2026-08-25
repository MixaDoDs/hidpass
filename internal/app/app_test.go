package app

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hidpass/internal/discovery"
	"hidpass/internal/privilege"
	"hidpass/internal/state"
	"hidpass/internal/udev"
)

func testApp(t *testing.T) (*App, *bytes.Buffer) {
	t.Helper()
	tmp := t.TempDir()
	dev := filepath.Join(tmp, "dev")
	class := filepath.Join(tmp, "sys", "class", "hidraw")
	if err := os.MkdirAll(dev, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(class, 0755); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	e := &privilege.Escalator{Executable: "/usr/bin/hidpass", EUID: func() int { return 1000 }, Look: func(name string) (string, error) { return "/usr/bin/pkexec", nil }, Run: func(name string, args ...string) error { return nil }}
	a := &App{
		In: strings.NewReader(""), Out: &out, Err: &out,
		Scanner:   discovery.New(discovery.Config{DevGlob: filepath.Join(dev, "hidraw*"), SysClass: class, Runner: emptyRunner{}}),
		Store:     state.Store{Path: filepath.Join(tmp, "etc", "hidpass", "devices.json")},
		Udev:      udev.Manager{RulesPath: filepath.Join(tmp, "etc", "udev", "rules.d", "70-hidpass.rules"), Run: func(string, ...string) ([]byte, error) { return nil, nil }},
		Escalator: e, EUID: func() int { return 1000 }, Executable: "/usr/bin/hidpass",
		VerifyRoot: func(string) error { return nil }, LookPath: func(name string) (string, error) { return "", errors.New("missing") },
		VerifyElevation: func(string, int) error { return nil },
		Glob:            filepath.Glob, Stat: os.Stat,
	}
	return a, &out
}

type emptyRunner struct{}

func (emptyRunner) Run(string, ...string) ([]byte, error) { return nil, errors.New("not found") }

func TestScanDebugEmptyExplainsBothSources(t *testing.T) {
	a, out := testApp(t)
	if err := a.Run([]string{"scan", "--debug"}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "/dev/hidraw*: 0 nodes") || !strings.Contains(s, "/sys/class/hidraw: 0 entries") {
		t.Fatalf("debug output:\n%s", s)
	}
}

func TestPrivilegedAddWritesStateRulesAndReloads(t *testing.T) {
	a, out := testApp(t)
	a.EUID = func() int { return 0 }
	var calls []string
	a.Udev.Run = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	payload := "W3sidmlkIjoiMzczZSIsInBpZCI6IjAwMWUiLCJuYW1lIjoiTUFZQSIsImNhdGVnb3J5IjoibW91c2UifV0" // JSON, RawURL base64
	if err := a.Run([]string{"--privileged", "add", payload}); err != nil {
		t.Fatal(err)
	}
	f, err := a.Store.Load()
	if err != nil || len(f.Devices) != 1 {
		t.Fatalf("state %#v err %v", f, err)
	}
	b, err := os.ReadFile(a.Udev.RulesPath)
	if err != nil || !strings.Contains(string(b), `TAG+="uaccess"`) {
		t.Fatalf("rules %q err %v", b, err)
	}
	if len(calls) != 2 || !strings.Contains(calls[0], "--reload-rules") || !strings.Contains(calls[1], "trigger --subsystem-match=hidraw") {
		t.Fatalf("calls %#v", calls)
	}
	if !strings.Contains(out.String(), "physically reconnect") {
		t.Fatalf("missing reconnect notice: %s", out.String())
	}
}

func TestPrivilegedMarkerCannotRunUnprivileged(t *testing.T) {
	a, _ := testApp(t)
	if err := a.Run([]string{"--privileged", "apply"}); err == nil || !strings.Contains(err.Error(), "requires root") {
		t.Fatalf("error %v", err)
	}
}

func TestExplicitSudoInvocationRunsInProcess(t *testing.T) {
	a, out := testApp(t)
	a.EUID = func() int { return 0 }
	a.Escalator.Run = func(string, ...string) error {
		t.Fatal("root normal command must not recursively execute itself")
		return nil
	}
	if err := a.Run([]string{"allow", "373e:001e"}); err != nil {
		t.Fatal(err)
	}
	f, err := a.Store.Load()
	if err != nil || len(f.Devices) != 1 || f.Devices[0].ID() != "373e:001e" {
		t.Fatalf("state %#v, error %v", f, err)
	}
	if !strings.Contains(out.String(), "started as root") {
		t.Fatalf("missing root warning: %s", out.String())
	}
}
