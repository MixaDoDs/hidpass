// Package discovery finds hidraw nodes first and resolves their USB parents.
// It intentionally never walks /sys/bus/usb/devices: that directory consists
// largely of symlinks, and filepath.WalkDir does not follow them.
package discovery

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/MixaDoDs/hidpass/internal/classify"
	"github.com/MixaDoDs/hidpass/internal/model"
)

type Runner interface {
	Run(name string, args ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

type Config struct {
	DevGlob  string
	SysClass string
	Runner   Runner
}

func DefaultConfig() Config {
	return Config{DevGlob: "/dev/hidraw*", SysClass: "/sys/class/hidraw", Runner: ExecRunner{}}
}

type Capabilities struct {
	Key  []string
	Rel  []string
	Abs  []string
	Prop []string
}

type NodeReport struct {
	Node           string
	Properties     map[string]string
	UdevError      string
	ClassLink      string
	ResolvedDevice string
	USBParent      string
	HIDBus         string
	FallbackUsed   bool
	FallbackError  string
	VID            string
	PID            string
	Manufacturer   string
	Product        string
	Capabilities   Capabilities
}

type Result struct {
	Devices     []model.Device
	Nodes       []NodeReport
	DevCount    int
	SysfsCount  int
	Diagnostics []string
}

type Scanner struct{ cfg Config }

func New(cfg Config) *Scanner {
	if cfg.DevGlob == "" {
		cfg.DevGlob = "/dev/hidraw*"
	}
	if cfg.SysClass == "" {
		cfg.SysClass = "/sys/class/hidraw"
	}
	if cfg.Runner == nil {
		cfg.Runner = ExecRunner{}
	}
	return &Scanner{cfg: cfg}
}

func ParseProperties(data []byte) map[string]string {
	props := make(map[string]string)
	s := bufio.NewScanner(bytes.NewReader(data))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		if i := strings.IndexByte(line, '='); i > 0 {
			props[line[:i]] = line[i+1:]
		}
	}
	return props
}

func (s *Scanner) Scan() (Result, error) {
	var result Result
	nodes, globErr := filepath.Glob(s.cfg.DevGlob)
	if globErr != nil {
		return result, fmt.Errorf("find hidraw nodes using %q: %w", s.cfg.DevGlob, globErr)
	}
	result.DevCount = len(nodes)
	entries, err := os.ReadDir(s.cfg.SysClass)
	if err == nil {
		result.SysfsCount = len(entries)
	} else if !errors.Is(err, os.ErrNotExist) {
		result.Diagnostics = append(result.Diagnostics, fmt.Sprintf("cannot read %s: %v", s.cfg.SysClass, err))
	}

	// A test or unusual container may expose sysfs entries without matching
	// /dev nodes. They are diagnostic only: udevadm --name requires a node.
	sort.Strings(nodes)
	groups := make(map[string]*group)
	for _, node := range nodes {
		report := s.inspect(node)
		result.Nodes = append(result.Nodes, report)
		if report.VID == "" || report.PID == "" {
			result.Diagnostics = append(result.Diagnostics, fmt.Sprintf("Found %s, but neither udev nor sysfs exposed a valid USB VID/PID.", node))
			continue
		}
		bus := strings.ToLower(strings.TrimSpace(report.Properties["ID_BUS"]))
		switch {
		case bus != "" && bus != "usb":
			result.Diagnostics = append(result.Diagnostics, fmt.Sprintf("Skipping %s: ID_BUS=%s (not USB).", node, bus))
			continue
		case bus == "":
			// Missing ID_BUS is not assumed to be USB. A sysfs parent with
			// USB idVendor/idProduct is acceptable evidence.
			if report.USBParent == "" {
				result.Diagnostics = append(result.Diagnostics, fmt.Sprintf("Skipping %s: ID_BUS is empty and no USB sysfs parent was found.", node))
				continue
			}
		}
		// ID_BUS is not enough: udev's hidraw rules import usb_id whenever *any*
		// ancestor is USB, so a Bluetooth HID paired to a USB dongle reports
		// ID_BUS=usb and the dongle's VID:PID. The HID device directory names
		// the real transport, and only BUS_USB may be granted by VID:PID.
		if report.HIDBus != "" && report.HIDBus != busUSB {
			result.Diagnostics = append(result.Diagnostics, fmt.Sprintf("Skipping %s: HID bus %s, not USB; a VID:PID rule would grant every device behind the same adapter.", node, busName(report.HIDBus)))
			continue
		}
		pathKey := report.USBParent
		if pathKey == "" {
			pathKey = physicalKey(report.Properties["DEVPATH"])
		}
		if pathKey == "" {
			// With no physical identity, merging would incorrectly collapse two
			// identical devices. Prefer duplicate display over false identity.
			pathKey = node
		}
		key := report.VID + ":" + report.PID + "@" + pathKey
		g := groups[key]
		if g == nil {
			g = &group{vid: report.VID, pid: report.PID, path: pathKey}
			groups[key] = g
		}
		g.add(report)
	}

	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		result.Devices = append(result.Devices, groups[k].device())
	}
	return result, nil
}

func (s *Scanner) inspect(node string) NodeReport {
	r := NodeReport{Node: node, Properties: make(map[string]string)}
	out, err := s.cfg.Runner.Run("udevadm", "info", "--query=property", "--name="+node)
	r.Properties = ParseProperties(out)
	if err != nil {
		r.UdevError = commandError(err, out)
	}
	r.VID, r.PID, _ = normalizeMaybe(r.Properties["ID_VENDOR_ID"], r.Properties["ID_MODEL_ID"])

	base := filepath.Base(node)
	classPath := filepath.Join(s.cfg.SysClass, base)
	if target, err := os.Readlink(classPath); err == nil {
		r.ClassLink = target
	} else {
		r.ClassLink = "(unreadable: " + err.Error() + ")"
	}
	devicePath := filepath.Join(classPath, "device")
	resolved, err := filepath.EvalSymlinks(devicePath)
	if err != nil {
		r.FallbackError = fmt.Sprintf("resolve %s: %v", devicePath, err)
		return r
	}
	r.ResolvedDevice = resolved
	if m := hidDeviceDir.FindStringSubmatch(filepath.Base(resolved)); m != nil {
		r.HIDBus = strings.ToLower(m[1])
	}
	parent, attrs, err := findUSBParent(resolved)
	if err != nil {
		r.FallbackError = err.Error()
	} else {
		r.USBParent = parent
		r.Manufacturer = attrs["manufacturer"]
		r.Product = attrs["product"]
		if r.VID == "" || r.PID == "" {
			r.FallbackUsed = true
			r.VID, r.PID, _ = normalizeMaybe(attrs["idVendor"], attrs["idProduct"])
		}
	}
	r.Capabilities = readCapabilities(resolved)
	return r
}

// The kernel names a HID device directory BUS:VID:PID.INSTANCE, where BUS is
// the hid.h BUS_* code: 0003 USB, 0005 Bluetooth, 0018 I2C.
const busUSB = "0003"

var hidDeviceDir = regexp.MustCompile(`^([0-9A-Fa-f]{4}):[0-9A-Fa-f]{4}:[0-9A-Fa-f]{4}\.[0-9A-Fa-f]+$`)

func busName(bus string) string {
	switch bus {
	case "0005":
		return "bluetooth"
	case "0018":
		return "i2c"
	}
	return "0x" + bus
}

func normalizeMaybe(vid, pid string) (string, string, error) {
	if vid == "" || pid == "" {
		return "", "", errors.New("missing VID/PID")
	}
	return model.NormalizePair(vid, pid)
}

func findUSBParent(start string) (string, map[string]string, error) {
	path := filepath.Clean(start)
	for {
		vid, e1 := readTrimmed(filepath.Join(path, "idVendor"))
		pid, e2 := readTrimmed(filepath.Join(path, "idProduct"))
		if e1 == nil && e2 == nil {
			if _, _, err := model.NormalizePair(vid, pid); err == nil {
				attrs := map[string]string{"idVendor": vid, "idProduct": pid}
				attrs["manufacturer"], _ = readTrimmed(filepath.Join(path, "manufacturer"))
				attrs["product"], _ = readTrimmed(filepath.Join(path, "product"))
				return path, attrs, nil
			}
		}
		parent := filepath.Dir(path)
		if parent == path {
			break
		}
		path = parent
	}
	return "", nil, fmt.Errorf("no ancestor of %s contains readable idVendor and idProduct", start)
}

func readTrimmed(path string) (string, error) {
	b, err := os.ReadFile(path)
	return strings.TrimSpace(string(b)), err
}

func readCapabilities(root string) Capabilities {
	var c Capabilities
	// Input capability files normally sit a few directories below a HID
	// interface. Bound depth and never follow symlinked directories.
	rootDepth := strings.Count(filepath.Clean(root), string(filepath.Separator))
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		depth := strings.Count(filepath.Clean(path), string(filepath.Separator)) - rootDepth
		if d.IsDir() && depth > 5 {
			return filepath.SkipDir
		}
		if d.IsDir() || filepath.Base(filepath.Dir(path)) != "capabilities" {
			return nil
		}
		value, err := readTrimmed(path)
		if err != nil || value == "" {
			return nil
		}
		switch filepath.Base(path) {
		case "key":
			c.Key = append(c.Key, value)
		case "rel":
			c.Rel = append(c.Rel, value)
		case "abs":
			c.Abs = append(c.Abs, value)
		case "prop":
			c.Prop = append(c.Prop, value)
		}
		return nil
	})
	return c
}

// usbInterface matches a USB interface directory such as 1-2:1.3 or
// 1-5.3.1:1.0. Matching a bare ":" would also match the PCI addresses that
// every DEVPATH starts with, collapsing the whole machine into one key.
var usbInterface = regexp.MustCompile(`^[0-9]+-[0-9.]+:[0-9]+\.[0-9]+$`)

func physicalKey(devpath string) string {
	// Trim known interface descendants. The result is diagnostic/dedup data,
	// not a reconstructed sysfs path, so unknown layouts remain intact.
	for _, marker := range []string{"/hidraw/", "/input/", "/usbmisc/"} {
		if i := strings.Index(devpath, marker); i >= 0 {
			devpath = devpath[:i]
		}
	}
	parts := strings.Split(devpath, "/")
	for i, p := range parts {
		if usbInterface.MatchString(p) {
			return strings.Join(parts[:i], "/")
		}
	}
	return devpath
}

func commandError(err error, out []byte) string {
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		return err.Error()
	}
	return err.Error() + ": " + msg
}

type group struct {
	vid, pid, path, vendor, product string
	nodes                           []string
	categories                      []string
	security                        bool
	securityWhy                     string
}

func (g *group) add(r NodeReport) {
	vendor := first(r.Properties["ID_VENDOR_FROM_DATABASE"], cleanUdev(r.Properties["ID_VENDOR"]), r.Manufacturer)
	product := first(r.Properties["ID_MODEL_FROM_DATABASE"], cleanUdev(r.Properties["ID_MODEL"]), r.Product)
	if len(vendor) > len(g.vendor) {
		g.vendor = vendor
	}
	if len(product) > len(g.product) {
		g.product = product
	}
	g.nodes = append(g.nodes, r.Node)
	g.categories = append(g.categories, classify.Classify(classify.Evidence{
		Properties: r.Properties, KeyBits: r.Capabilities.Key, RelBits: r.Capabilities.Rel,
		AbsBits: r.Capabilities.Abs, PropBits: r.Capabilities.Prop,
		VID: r.VID, PID: r.PID, Vendor: vendor, Product: product,
	}))
	if sensitive, why := classify.SecurityDevice(r.VID, vendor, product); sensitive {
		g.security, g.securityWhy = true, why
	}
	for _, key := range []string{"ID_FIDO_TOKEN", "ID_SECURITY_TOKEN"} {
		v := strings.ToLower(strings.TrimSpace(r.Properties[key]))
		if v == "1" || v == "yes" || v == "true" {
			g.security, g.securityWhy = true, "udev property "+key
		}
	}
}

func (g *group) device() model.Device {
	name := strings.TrimSpace(g.vendor + " " + g.product)
	if name == "" {
		name = "Unknown USB HID device"
	}
	sort.Strings(g.nodes)
	return model.Device{VID: g.vid, PID: g.pid, Vendor: g.vendor, Product: g.product, Name: name,
		Category: classify.Merge(g.categories), PhysicalPath: g.path, Nodes: g.nodes,
		Security: g.security, SecurityWhy: g.securityWhy}
}

func first(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func cleanUdev(s string) string { return strings.ReplaceAll(strings.TrimSpace(s), "_", " ") }
