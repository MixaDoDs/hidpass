package discovery

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type fakeRunner struct {
	properties map[string]string
	errors     map[string]error
	called     []string
}

func (f *fakeRunner) Run(name string, args ...string) ([]byte, error) {
	f.called = append(f.called, name+" "+strings.Join(args, " "))
	node := strings.TrimPrefix(args[len(args)-1], "--name=")
	return []byte(f.properties[node]), f.errors[node]
}

func TestParseProperties(t *testing.T) {
	p := ParseProperties([]byte("DEVPATH=/devices/a=b\nID_VENDOR_ID=373e\nBROKEN\nID_MODEL=MAYA_X\n"))
	if p["DEVPATH"] != "/devices/a=b" || p["ID_VENDOR_ID"] != "373e" || p["ID_MODEL"] != "MAYA_X" {
		t.Fatalf("parsed %#v", p)
	}
}

type fixture struct {
	root, dev, class, devices string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	root := t.TempDir()
	f := fixture{root: root, dev: filepath.Join(root, "dev"), class: filepath.Join(root, "sys", "class", "hidraw"), devices: filepath.Join(root, "sys", "devices")}
	for _, d := range []string{f.dev, f.class, f.devices} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f fixture) addNode(t *testing.T, node string, usb string, iface string, attrs map[string]string, caps map[string]string) {
	t.Helper()
	usbPath := filepath.Join(f.devices, usb)
	ifacePath := filepath.Join(usbPath, iface)
	hidPath := filepath.Join(ifacePath, "0003:0000:0000.0001")
	hidrawPath := filepath.Join(hidPath, "hidraw", node)
	if err := os.MkdirAll(hidrawPath, 0755); err != nil {
		t.Fatal(err)
	}
	// Real /sys/class/hidraw/hidrawN/device is a symlink to the HID device.
	if err := os.Symlink(hidPath, filepath.Join(hidrawPath, "device")); err != nil {
		t.Fatal(err)
	}
	for name, value := range attrs {
		if err := os.WriteFile(filepath.Join(usbPath, name), []byte(value+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if len(caps) > 0 {
		capDir := filepath.Join(hidPath, "input", "input9", "capabilities")
		if err := os.MkdirAll(capDir, 0755); err != nil {
			t.Fatal(err)
		}
		for name, value := range caps {
			if err := os.WriteFile(filepath.Join(capDir, name), []byte(value+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.Symlink(hidrawPath, filepath.Join(f.class, node)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dev, node), nil, 0644); err != nil {
		t.Fatal(err)
	}
}

func (f fixture) scanner(r Runner) *Scanner {
	return New(Config{DevGlob: filepath.Join(f.dev, "hidraw*"), SysClass: f.class, Runner: r})
}

func TestSysfsFallbackSymlinkResolutionAndCapabilities(t *testing.T) {
	f := newFixture(t)
	f.addNode(t, "hidraw3", "pci/usb1/1-2", "1-2:1.0", map[string]string{
		"idVendor": "373E", "idProduct": "001E", "manufacturer": "LAMZU", "product": "MAYA X 8K Receiver",
	}, map[string]string{"key": bitmap(0x110), "rel": bitmap(0, 1)})
	runner := &fakeRunner{properties: map[string]string{filepath.Join(f.dev, "hidraw3"): "DEVPATH=/devices/...\nID_BUS=usb\n"}, errors: map[string]error{}}
	r, err := f.scanner(runner).Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Devices) != 1 {
		t.Fatalf("devices %#v diagnostics %#v", r.Devices, r.Diagnostics)
	}
	d := r.Devices[0]
	if d.ID() != "373e:001e" || d.Name != "LAMZU MAYA X 8K Receiver" || d.Category != "mouse" {
		t.Fatalf("device %#v", d)
	}
	if !r.Nodes[0].FallbackUsed || !strings.Contains(r.Nodes[0].ResolvedDevice, "0003:") || r.Nodes[0].USBParent == "" {
		t.Fatalf("node %#v", r.Nodes[0])
	}
}

func TestMultipleHidrawNodesDeduplicateByUSBParent(t *testing.T) {
	f := newFixture(t)
	attrs := map[string]string{"idVendor": "1234", "idProduct": "5678", "manufacturer": "NuPhy", "product": "Air60 HE"}
	f.addNode(t, "hidraw0", "pci/usb1/1-3", "1-3:1.0", attrs, nil)
	f.addNode(t, "hidraw1", "pci/usb1/1-3", "1-3:1.1", attrs, nil)
	runner := &fakeRunner{properties: map[string]string{}, errors: map[string]error{}}
	for _, n := range []string{"hidraw0", "hidraw1"} {
		path := filepath.Join(f.dev, n)
		runner.properties[path] = "ID_BUS=usb\nID_VENDOR_ID=1234\nID_MODEL_ID=5678\nID_INPUT_KEYBOARD=1\nID_VENDOR=NuPhy\nID_MODEL=Air60_HE\n"
	}
	r, err := f.scanner(runner).Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Devices) != 1 || len(r.Devices[0].Nodes) != 2 || r.Devices[0].Category != "keyboard" {
		t.Fatalf("devices %#v", r.Devices)
	}
}

func TestSameVIDPIDDifferentPhysicalParentsRemainSeparate(t *testing.T) {
	f := newFixture(t)
	attrs := map[string]string{"idVendor": "1234", "idProduct": "5678"}
	f.addNode(t, "hidraw0", "usb1/1-3", "1-3:1.0", attrs, nil)
	f.addNode(t, "hidraw1", "usb1/1-4", "1-4:1.0", attrs, nil)
	runner := &fakeRunner{properties: map[string]string{}, errors: map[string]error{}}
	for _, n := range []string{"hidraw0", "hidraw1"} {
		path := filepath.Join(f.dev, n)
		runner.properties[path] = "ID_BUS=usb\nID_VENDOR_ID=1234\nID_MODEL_ID=5678\n"
	}
	r, err := f.scanner(runner).Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Devices) != 2 {
		t.Fatalf("devices %#v", r.Devices)
	}
}

func TestMissingPhysicalPathDoesNotCollapseIdenticalDevices(t *testing.T) {
	f := newFixture(t)
	for _, n := range []string{"hidraw0", "hidraw1"} {
		if err := os.WriteFile(filepath.Join(f.dev, n), nil, 0644); err != nil {
			t.Fatal(err)
		}
	}
	runner := &fakeRunner{properties: map[string]string{}, errors: map[string]error{}}
	for _, n := range []string{"hidraw0", "hidraw1"} {
		path := filepath.Join(f.dev, n)
		runner.properties[path] = "ID_BUS=usb\nID_VENDOR_ID=1234\nID_MODEL_ID=5678\n"
	}
	r, err := f.scanner(runner).Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Devices) != 2 {
		t.Fatalf("devices %#v", r.Devices)
	}
}

func TestNonUSBIsSkippedEvenIfSysfsHasUSBAncestor(t *testing.T) {
	f := newFixture(t)
	f.addNode(t, "hidraw2", "usb1/1-2", "1-2:1.0", map[string]string{"idVendor": "1234", "idProduct": "5678"}, nil)
	runner := &fakeRunner{properties: map[string]string{filepath.Join(f.dev, "hidraw2"): "ID_BUS=bluetooth\nID_VENDOR_ID=1234\nID_MODEL_ID=5678\n"}, errors: map[string]error{}}
	r, err := f.scanner(runner).Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Devices) != 0 || len(r.Diagnostics) == 0 {
		t.Fatalf("result %#v", r)
	}
}

// Regression: old discovery walked /sys/bus/usb/devices, whose entries are
// symlinks. WalkDir does not enter them. The new scan is rooted in hidraw and
// resolves /sys/class/hidraw/<node>/device, so an irrelevant symlink-only bus
// directory must not affect discovery.
func TestRegressionDoesNotWalkSysBusUSBDeviceSymlinks(t *testing.T) {
	f := newFixture(t)
	f.addNode(t, "hidraw7", "usb2/2-5", "2-5:1.2", map[string]string{"idVendor": "0fd9", "idProduct": "006d", "product": "Stream Deck"}, nil)
	bus := filepath.Join(f.root, "sys", "bus", "usb", "devices")
	if err := os.MkdirAll(bus, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.devices, "usb2", "2-5"), filepath.Join(bus, "2-5")); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{properties: map[string]string{filepath.Join(f.dev, "hidraw7"): "ID_BUS=usb\n"}, errors: map[string]error{filepath.Join(f.dev, "hidraw7"): errors.New("udevadm fixture failure")}}
	r, err := f.scanner(runner).Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Devices) != 1 || r.Devices[0].Category != "streamdeck" {
		t.Fatalf("devices %#v", r.Devices)
	}
	if len(runner.called) != 1 || strings.Contains(runner.called[0], "/sys/bus/usb/devices") {
		t.Fatalf("calls %#v", runner.called)
	}
}

// bitmap renders bits the way the kernel does: one machine word per
// space-separated field, %lx (unpadded), most-significant word first.
func bitmap(bits ...int) string {
	words := []uint64{0}
	for _, b := range bits {
		i := b / strconv.IntSize
		for len(words) <= i {
			words = append(words, 0)
		}
		words[i] |= 1 << uint(b%strconv.IntSize)
	}
	fields := make([]string, 0, len(words))
	for i := len(words) - 1; i >= 0; i-- {
		fields = append(fields, strconv.FormatUint(words[i], 16))
	}
	return strings.Join(fields, " ")
}
