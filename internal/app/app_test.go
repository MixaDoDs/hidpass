package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MixaDoDs/hidpass/internal/classify"
	"github.com/MixaDoDs/hidpass/internal/discovery"
	"github.com/MixaDoDs/hidpass/internal/model"
	"github.com/MixaDoDs/hidpass/internal/privilege"
	"github.com/MixaDoDs/hidpass/internal/state"
	"github.com/MixaDoDs/hidpass/internal/udev"
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
		Glob:            func(string) ([]string, error) { return nil, nil }, Stat: os.Stat,
		Getenv: func(string) string { return "" }, HasACL: func(string) bool { return false },
	}
	return a, &out
}

type emptyRunner struct{}

func (emptyRunner) Run(string, ...string) ([]byte, error) { return nil, errors.New("not found") }

type stubScanner struct{ devices []model.Device }

func (s stubScanner) Scan() (discovery.Result, error) {
	return discovery.Result{Devices: s.devices}, nil
}

func b64devices(t *testing.T, devices ...model.AllowedDevice) string {
	t.Helper()
	b, err := json.Marshal(devices)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

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
	payload := b64devices(t, model.AllowedDevice{VID: "373e", PID: "001e", Name: "MAYA", Category: "mouse"})
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
	if len(calls) != 4 || !strings.Contains(calls[0], "--reload-rules") || calls[1] != "udevadm trigger --subsystem-match=hidraw --action=change" || calls[2] != "udevadm trigger --subsystem-match=usb --action=change" || calls[3] != "udevadm settle --timeout=5" {
		t.Fatalf("calls %#v", calls)
	}
	if strings.HasSuffix(calls[1], "trigger") && !strings.Contains(calls[1], "--subsystem-match=hidraw") {
		t.Fatalf("unfiltered trigger: %#v", calls)
	}
	if !strings.Contains(out.String(), "physically reconnect") {
		t.Fatalf("missing reconnect notice: %s", out.String())
	}
}

func TestInstallDoesNotSaveStateIfRulesWriteFails(t *testing.T) {
	a, _ := testApp(t)
	a.EUID = func() int { return 0 }
	blocker := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	a.Udev.RulesPath = filepath.Join(blocker, "70-hidpass.rules")
	payload := b64devices(t, model.AllowedDevice{VID: "373e", PID: "001e", Name: "MAYA", Category: "mouse"})
	if err := a.Run([]string{"--privileged", "add", payload}); err == nil {
		t.Fatal("expected rules write failure")
	}
	f, err := a.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Devices) != 0 {
		t.Fatalf("state was saved despite rules write failure: %#v", f)
	}
}

func TestPrivilegedAddRefusesSecurityDevice(t *testing.T) {
	a, out := testApp(t)
	a.EUID = func() int { return 0 }
	payload := b64devices(t, model.AllowedDevice{VID: "1050", PID: "0407", Name: "Mouse", Category: "mouse"})
	if err := a.Run([]string{"--privileged", "add", payload}); err == nil {
		t.Fatal("expected security device refusal")
	}
	f, err := a.Store.Load()
	if err != nil || len(f.Devices) != 0 {
		t.Fatalf("yubikey sneaked through auto/add: %#v err %v", f, err)
	}
	if !strings.Contains(out.String(), "security device") {
		t.Fatalf("missing refusal text: %s", out.String())
	}
}

func TestPrivilegedAllowPermitsSecurityDevice(t *testing.T) {
	a, _ := testApp(t)
	a.EUID = func() int { return 0 }
	payload := b64devices(t, model.AllowedDevice{VID: "1050", PID: "0407", Name: "YubiKey", Category: "other-hid"})
	if err := a.Run([]string{"--privileged", "allow", payload}); err != nil {
		t.Fatal(err)
	}
	f, err := a.Store.Load()
	if err != nil || len(f.Devices) != 1 || f.Devices[0].ID() != "1050:0407" {
		t.Fatalf("explicit allow failed: %#v err %v", f, err)
	}
}

func TestPrivilegedUninstallRemovesRulesAndState(t *testing.T) {
	a, _ := testApp(t)
	a.EUID = func() int { return 0 }
	var calls []string
	a.Udev.Run = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	payload := b64devices(t, model.AllowedDevice{VID: "373e", PID: "001e", Name: "MAYA", Category: "other-hid"})
	if err := a.Run([]string{"--privileged", "add", payload}); err != nil {
		t.Fatal(err)
	}
	calls = nil
	if err := a.Run([]string{"--privileged", "uninstall"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a.Udev.RulesPath); !os.IsNotExist(err) {
		t.Fatalf("rules still present: %v", err)
	}
	if _, err := os.Stat(a.Store.Path); !os.IsNotExist(err) {
		t.Fatalf("state still present: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(a.Store.Path)); !os.IsNotExist(err) {
		t.Fatalf("empty state dir still present: %v", err)
	}
	if len(calls) != 4 || calls[1] != "udevadm trigger --subsystem-match=hidraw --action=change" || calls[2] != "udevadm trigger --subsystem-match=usb --action=change" || calls[3] != "udevadm settle --timeout=5" {
		t.Fatalf("uninstall trigger %#v", calls)
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

// Regression: an empty line is the [Y/n] default, but a closed stdin is not an
// answer. `hidpass auto </dev/null` used to allow every device unprompted.
func TestAutoRefusesToGrantWithoutAnAnswer(t *testing.T) {
	a, out := testApp(t)
	dev := t.TempDir()
	for _, n := range []string{"hidraw0", "hidraw1"} {
		if err := os.WriteFile(filepath.Join(dev, n), nil, 0644); err != nil {
			t.Fatal(err)
		}
	}
	a.Scanner = discovery.New(discovery.Config{DevGlob: filepath.Join(dev, "hidraw*"), SysClass: t.TempDir(), Runner: idRunner{}})
	a.Escalator.Run = func(name string, args ...string) error {
		t.Fatalf("elevated without confirmation: %s %v", name, args)
		return nil
	}
	err := a.Run([]string{"auto"})
	if err == nil || !strings.Contains(err.Error(), "before an answer") {
		t.Fatalf("error = %v, output:\n%s", err, out.String())
	}
}

// idRunner reports one distinct USB mouse per hidraw node.
type idRunner struct{}

func (idRunner) Run(name string, args ...string) ([]byte, error) {
	pid := "001e"
	if strings.HasSuffix(args[len(args)-1], "hidraw1") {
		pid = "002f"
	}
	return []byte("ID_BUS=usb\nID_VENDOR_ID=373e\nID_MODEL_ID=" + pid + "\nID_INPUT_MOUSE=1\n"), nil
}

func TestSubcommandHelpIsNotAnError(t *testing.T) {
	a, out := testApp(t)
	if err := a.Run([]string{"scan", "--help"}); err != nil {
		t.Fatalf("scan --help = %v", err)
	}
	if !strings.Contains(out.String(), "-debug") {
		t.Fatalf("usage not printed: %s", out.String())
	}
}

func TestAutoAsksOncePerVIDPIDAndHonoursTheAnswer(t *testing.T) {
	for _, tt := range []struct {
		answer  string
		granted bool
	}{{"n\n", false}, {"y\n", true}, {"\n", false}} {
		t.Run(strings.TrimSpace(tt.answer)+"/", func(t *testing.T) {
			a, out := testApp(t)
			dev := t.TempDir()
			// Two nodes, one VID:PID: one rule covers both, so one question.
			for _, n := range []string{"hidraw0", "hidraw1"} {
				if err := os.WriteFile(filepath.Join(dev, n), nil, 0644); err != nil {
					t.Fatal(err)
				}
			}
			a.Scanner = discovery.New(discovery.Config{DevGlob: filepath.Join(dev, "hidraw*"), SysClass: t.TempDir(), Runner: sameIDRunner{}})
			a.In = strings.NewReader(tt.answer)
			granted := false
			a.Escalator.Run = func(string, ...string) error { granted = true; return nil }
			if err := a.Run([]string{"auto"}); err != nil {
				t.Fatal(err)
			}
			if granted != tt.granted {
				t.Fatalf("answer %q granted=%v, output:\n%s", tt.answer, granted, out.String())
			}
			if n := strings.Count(out.String(), "Allow "); n != 1 {
				t.Fatalf("asked %d times for one VID:PID:\n%s", n, out.String())
			}
		})
	}
}

// sameIDRunner reports the same USB mouse on every hidraw node, as a device
// with two hidraw interfaces but no readable sysfs parent does.
type sameIDRunner struct{}

func (sameIDRunner) Run(string, ...string) ([]byte, error) {
	return []byte("ID_BUS=usb\nID_VENDOR_ID=373e\nID_MODEL_ID=001e\nID_INPUT_MOUSE=1\n"), nil
}
func TestAutoDefaultDeniesKeyboard(t *testing.T) {
	if autoDefaultAllow(classify.Keyboard) || autoDefaultAllow(classify.Mouse) {
		t.Fatal("keyboard/mouse should default to deny")
	}
	if !autoDefaultAllow(classify.StreamDeck) {
		t.Fatal("streamdeck should default to allow")
	}
	if hidrawSeatWarning(classify.Keyboard) == "" || hidrawSeatWarning(classify.Mouse) == "" {
		t.Fatal("expected seat warning for keyboard/mouse")
	}
	if hidrawSeatWarning(classify.StreamDeck) != "" {
		t.Fatal("no warning for streamdeck")
	}
}

func TestAutoKeyboardEmptyAnswerDoesNotAdd(t *testing.T) {
	a, out := testApp(t)
	a.EUID = func() int { return 0 }
	a.In = strings.NewReader("\n")
	a.Scanner = stubScanner{devices: []model.Device{{
		VID: "1234", PID: "5678", Name: "Test Keyboard", Category: classify.Keyboard,
	}}}
	if err := a.Run([]string{"auto"}); err != nil {
		t.Fatal(err)
	}
	f, err := a.Store.Load()
	if err != nil || len(f.Devices) != 0 {
		t.Fatalf("keyboard was added on default: %#v err %v", f, err)
	}
	s := out.String()
	if !strings.Contains(s, "[y/N]") {
		t.Fatalf("expected default-deny prompt: %s", s)
	}
	if !strings.Contains(s, "keylogging") {
		t.Fatalf("expected keylogging warning: %s", s)
	}
}

func TestAutoYesStillAddsKeyboardWithWarning(t *testing.T) {
	a, out := testApp(t)
	a.EUID = func() int { return 0 }
	a.Scanner = stubScanner{devices: []model.Device{{
		VID: "1234", PID: "5678", Name: "Test Keyboard", Category: classify.Keyboard,
	}}}
	if err := a.Run([]string{"auto", "--yes"}); err != nil {
		t.Fatal(err)
	}
	f, err := a.Store.Load()
	if err != nil || len(f.Devices) != 1 {
		t.Fatalf("keyboard was not added with --yes: %#v err %v", f, err)
	}
	if !strings.Contains(out.String(), "keylogging") {
		t.Fatalf("expected warning with --yes: %s", out.String())
	}
}

func TestDoctorPersistentRulesPathAndMissingSeat(t *testing.T) {
	a, out := testApp(t)
	a.Udev.RulesPath = "/run/udev/rules.d/70-hidpass.rules"
	a.Getenv = func(string) string { return "" }
	a.Stat = func(path string) (os.FileInfo, error) {
		if strings.Contains(path, "/run/systemd/seats") {
			return nil, os.ErrNotExist
		}
		return os.Stat(path)
	}
	if err := a.Run([]string{"doctor"}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "/run") || !strings.Contains(s, "WARN") {
		t.Fatalf("expected volatile path warning:\n%s", s)
	}
	if !strings.Contains(s, "logind") && !strings.Contains(s, "XDG_SEAT") {
		t.Fatalf("expected seat warning:\n%s", s)
	}

	out.Reset()
	a.Udev.RulesPath = "/etc/udev/rules.d/70-hidpass.rules"
	if err := a.Run([]string{"doctor"}); err != nil {
		t.Fatal(err)
	}
	s = out.String()
	if !strings.Contains(s, "persistent") || !strings.Contains(s, "reboot") {
		t.Fatalf("expected persistence mention:\n%s", s)
	}
}
