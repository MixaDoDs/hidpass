package udev

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MixaDoDs/hidpass/internal/model"
)

func TestGenerateRules(t *testing.T) {
	b, err := Generate([]model.AllowedDevice{
		{VID: "373E", PID: "1E", Name: "LAMZU\nMAYA", Category: "mouse"},
		{VID: "0fd9", PID: "006d", Name: "Stream Deck", Category: "streamdeck"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	want := `KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="373e", ATTRS{idProduct}=="001e", MODE="0666", TAG+="uaccess", TAG+="udev-acl"`
	if !strings.Contains(s, want) {
		t.Fatalf("missing hidraw rule %q in:\n%s", want, s)
	}
	usb := `SUBSYSTEM=="usb", ATTR{idVendor}=="373e", ATTR{idProduct}=="001e", MODE="0664", TAG+="uaccess"`
	if !strings.Contains(s, usb) {
		t.Fatalf("missing usb rule %q in:\n%s", usb, s)
	}
	if strings.Contains(s, "LAMZU\nMAYA") {
		t.Fatal("comment injection was not sanitized")
	}
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.Contains(line, "MODE=") && !strings.Contains(line, "ATTRS{idVendor}") && !strings.Contains(line, "ATTR{idVendor}") {
			t.Fatalf("MODE without VID/PID:\n%s", s)
		}
	}
}

func TestIsPersistentRulesPath(t *testing.T) {
	if !IsPersistentRulesPath("/etc/udev/rules.d/70-hidpass.rules") {
		t.Fatal("expected /etc/udev/rules.d to be persistent")
	}
	if IsPersistentRulesPath("/run/udev/rules.d/70-hidpass.rules") {
		t.Fatal("/run/udev/rules.d must not be treated as persistent")
	}
	if IsPersistentRulesPath("/tmp/70-hidpass.rules") {
		t.Fatal("tmp path is not persistent")
	}
}

func TestWriteAtomicModeReloadScopeAndRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "etc", "udev", "rules.d", "70-hidpass.rules")
	var calls []string
	m := Manager{RulesPath: path, Run: func(name string, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(append([]string{name}, args...), " "))
		return nil, nil
	}}
	if err := m.Write([]model.AllowedDevice{{VID: "373e", PID: "001e", Name: "MAYA"}}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Fatalf("rules mode %o, want 0644", info.Mode().Perm())
	}
	if filepath.Base(path) != RulesFileName {
		t.Fatalf("filename %s", filepath.Base(path))
	}
	if err := m.Reload(); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 {
		t.Fatalf("calls %#v", calls)
	}
	if calls[0] != "udevadm control --reload-rules" {
		t.Fatalf("reload = %q", calls[0])
	}
	if calls[1] != "udevadm trigger --subsystem-match=hidraw --action=change" {
		t.Fatalf("trigger hidraw = %q", calls[1])
	}
	if calls[2] != "udevadm trigger --subsystem-match=usb --action=change" {
		t.Fatalf("trigger usb = %q", calls[2])
	}
	if err := m.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("rules still present: %v", err)
	}
}
