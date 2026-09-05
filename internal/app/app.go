package app

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/MixaDoDs/hidpass/internal/classify"
	"github.com/MixaDoDs/hidpass/internal/discovery"
	"github.com/MixaDoDs/hidpass/internal/model"
	"github.com/MixaDoDs/hidpass/internal/privilege"
	"github.com/MixaDoDs/hidpass/internal/state"
	"github.com/MixaDoDs/hidpass/internal/udev"
)

var (
	Version = "dev"
	Commit  = "unknown"
)

// Scanner finds connected hidraw devices. *discovery.Scanner implements it.
type Scanner interface {
	Scan() (discovery.Result, error)
}

type App struct {
	In              io.Reader
	Out             io.Writer
	Err             io.Writer
	Scanner         Scanner
	Store           state.Store
	Udev            udev.Manager
	Escalator       *privilege.Escalator
	EUID            func() int
	Executable      string
	LookPath        func(string) (string, error)
	Glob            func(string) ([]string, error)
	Stat            func(string) (os.FileInfo, error)
	VerifyRoot      func(string) error
	VerifyElevation func(string, int) error
	Getenv          func(string) string
	HasACL          func(string) bool
}

func Default() (*App, error) {
	esc, err := privilege.Default()
	if err != nil {
		return nil, err
	}
	return &App{
		In: os.Stdin, Out: os.Stdout, Err: os.Stderr,
		Scanner: discovery.New(discovery.DefaultConfig()), Store: state.DefaultStore(),
		Udev: udev.DefaultManager(), Escalator: esc, EUID: os.Geteuid,
		Executable: esc.Executable, LookPath: exec.LookPath, Glob: filepath.Glob,
		Stat: os.Stat, VerifyRoot: privilege.VerifyRootExecutable,
		VerifyElevation: privilege.ValidateExecutableForElevation,
		Getenv:          os.Getenv, HasACL: hasPOSIXACL,
	}, nil
}

func (a *App) Run(args []string) error {
	if len(args) == 0 {
		a.usage(a.Err)
		return errors.New("a command is required")
	}
	if args[0] == "--privileged" {
		return a.runPrivileged(args[1:])
	}
	switch args[0] {
	case "scan":
		return a.scan(args[1:])
	case "list":
		return a.list(args[1:])
	case "auto":
		return a.auto(args[1:])
	case "allow":
		return a.allow(args[1:])
	case "remove":
		return a.remove(args[1:])
	case "apply":
		return a.apply(args[1:])
	case "uninstall":
		return a.uninstall(args[1:])
	case "doctor":
		return a.doctor(args[1:])
	case "version":
		if len(args) != 1 {
			return errors.New("version takes no arguments")
		}
		fmt.Fprintf(a.Out, "hidpass %s (%s)\n", Version, Commit)
		return nil
	case "help", "--help", "-h":
		a.usage(a.Out)
		return nil
	default:
		a.usage(a.Err)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func (a *App) usage(w io.Writer) {
	fmt.Fprintln(w, `Usage: hidpass <command> [options]

Safely grant the active desktop user WebHID access to selected USB devices.

Commands:
  scan [--debug]       Find and classify connected USB hidraw devices
  list                 List configured VID:PID entries
  auto [--yes]         Interactively select connected devices
  allow <VID:PID>      Add an explicit device ID
  remove <VID:PID>     Remove a configured device ID
  apply                Rebuild rules and reload udev
  uninstall            Remove hidpass udev rules and saved state
  doctor               Diagnose the local hidraw/udev environment
  version              Print build version`)
}

func (a *App) scan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	debug := fs.Bool("debug", false, "show udev and sysfs evidence for every node")
	if err := fs.Parse(args); err != nil {
		return helpOrError(err)
	}
	if fs.NArg() != 0 {
		return errors.New("scan takes no positional arguments")
	}
	r, err := a.Scanner.Scan()
	if err != nil {
		return err
	}
	if *debug {
		a.printDebug(r)
	}
	for _, d := range r.Devices {
		fmt.Fprintf(a.Out, "%s  %-11s %s\n", d.ID(), d.Category, d.Name)
	}
	if len(r.Devices) == 0 {
		fmt.Fprintln(a.Out, "No USB HID devices with a usable VID:PID were found.")
		if !*debug {
			fmt.Fprintln(a.Out, "Run `hidpass scan --debug` to see hidraw and sysfs diagnostics.")
		}
	}
	for _, d := range r.Diagnostics {
		fmt.Fprintln(a.Err, "warning:", d)
	}
	return nil
}

var debugProps = []string{"DEVPATH", "ID_BUS", "ID_VENDOR_ID", "ID_MODEL_ID", "ID_VENDOR", "ID_MODEL", "ID_MODEL_FROM_DATABASE", "ID_VENDOR_FROM_DATABASE", "ID_INPUT_KEYBOARD", "ID_INPUT_MOUSE", "ID_INPUT_TOUCHPAD", "ID_INPUT_TABLET", "ID_INPUT_JOYSTICK", "ID_FIDO_TOKEN", "ID_SECURITY_TOKEN"}

func (a *App) printDebug(r discovery.Result) {
	fmt.Fprintf(a.Out, "/dev/hidraw*: %d nodes\n/sys/class/hidraw: %d entries\n", r.DevCount, r.SysfsCount)
	for _, n := range r.Nodes {
		fmt.Fprintf(a.Out, "\nnode: %s\nudevadm:\n", n.Node)
		if n.UdevError != "" {
			fmt.Fprintf(a.Out, "  error: %s\n", n.UdevError)
		}
		printed := false
		for _, k := range debugProps {
			if v, ok := n.Properties[k]; ok {
				fmt.Fprintf(a.Out, "  %s=%s\n", k, v)
				printed = true
			}
		}
		if !printed && n.UdevError == "" {
			fmt.Fprintln(a.Out, "  (no relevant properties)")
		}
		if n.Properties["ID_VENDOR_ID"] == "" || n.Properties["ID_MODEL_ID"] == "" {
			fmt.Fprintf(a.Out, "  note: Found %s, but udev did not expose ID_VENDOR_ID/ID_MODEL_ID. Trying sysfs fallback...\n", n.Node)
		}
		fmt.Fprintln(a.Out, "sysfs:")
		fmt.Fprintf(a.Out, "  /sys/class/hidraw/%s -> %s\n", filepath.Base(n.Node), valueOr(n.ClassLink, "(not resolved)"))
		fmt.Fprintf(a.Out, "  resolved device path: %s\n", valueOr(n.ResolvedDevice, "(not resolved)"))
		fmt.Fprintf(a.Out, "  usb parent: %s\n", valueOr(n.USBParent, "(not found)"))
		if n.FallbackUsed {
			fmt.Fprintf(a.Out, "  udev VID/PID missing; sysfs fallback: %s:%s\n", n.VID, n.PID)
		}
		if n.FallbackError != "" {
			fmt.Fprintf(a.Out, "  fallback error: %s\n", n.FallbackError)
		}
		if len(n.Capabilities.Key)+len(n.Capabilities.Rel)+len(n.Capabilities.Abs)+len(n.Capabilities.Prop) > 0 {
			fmt.Fprintf(a.Out, "  capabilities: key=%v rel=%v abs=%v prop=%v\n", n.Capabilities.Key, n.Capabilities.Rel, n.Capabilities.Abs, n.Capabilities.Prop)
		}
	}
}

func (a *App) list(args []string) error {
	if len(args) != 0 {
		return errors.New("list takes no arguments")
	}
	f, err := a.Store.Load()
	if err != nil {
		return err
	}
	if len(f.Devices) == 0 {
		fmt.Fprintln(a.Out, "No devices are configured.")
		return nil
	}
	for _, d := range f.Devices {
		fmt.Fprintf(a.Out, "%s  %-11s %s\n", d.ID(), valueOr(d.Category, "other-hid"), valueOr(d.Name, "(unnamed)"))
	}
	return nil
}

func hidrawSeatWarning(category string) string {
	switch category {
	case classify.Keyboard:
		return "WARNING: hidraw access on a keyboard exposes raw HID reports for the whole seat. That can be used to read keystrokes (keylogging) or inject key events. Only allow this if you trust every program that will open the device."
	case classify.Mouse:
		return "WARNING: hidraw access on a mouse exposes raw HID reports for the whole seat. That can be used to track movement or inject input. Only allow this if you trust every program that will open the device."
	default:
		return ""
	}
}

func autoDefaultAllow(category string) bool {
	switch category {
	case classify.Keyboard, classify.Mouse:
		return false
	default:
		return true
	}
}

func (a *App) auto(args []string) error {
	fs := flag.NewFlagSet("auto", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	yes := fs.Bool("yes", false, "allow every non-security device without prompting")
	if err := fs.Parse(args); err != nil {
		return helpOrError(err)
	}
	if fs.NArg() != 0 {
		return errors.New("auto takes no positional arguments")
	}
	r, err := a.Scanner.Scan()
	if err != nil {
		return err
	}
	if len(r.Devices) == 0 {
		fmt.Fprintln(a.Out, "No eligible USB HID devices were found. Run `hidpass scan --debug` for details.")
		return nil
	}
	// Fail before asking several questions if this development binary cannot
	// safely be elevated. An already-root invocation is handled in-process.
	for _, d := range r.Devices {
		if !d.Security {
			if err := a.verifyElevation(); err != nil {
				return err
			}
			break
		}
	}
	// A rule matches a VID:PID, not a port, so two identical devices share one
	// decision. Asking about each of them separately would promise a per-device
	// choice that the generated rule cannot honour.
	instances := make(map[string]int)
	for _, d := range r.Devices {
		instances[d.ID()]++
	}
	reader := bufio.NewReader(a.In)
	asked := make(map[string]bool)
	var selected []model.AllowedDevice
	for _, d := range r.Devices {
		if d.Security {
			fmt.Fprintf(a.Out, "Skip  %s [%-11s] %s (sensitive security device: %s)\n", d.ID(), d.Category, d.Name, d.SecurityWhy)
			continue
		}
		if asked[d.ID()] {
			continue
		}
		asked[d.ID()] = true
		if warn := hidrawSeatWarning(d.Category); warn != "" {
			fmt.Fprintln(a.Out, warn)
		}
		allow := *yes
		if !*yes {
			shared := ""
			if n := instances[d.ID()]; n > 1 {
				shared = fmt.Sprintf(" (%d connected devices share this ID; one rule covers all of them)", n)
			}
			hint := "[Y/n]"
			if !autoDefaultAllow(d.Category) {
				hint = "[y/N]"
			}
			fmt.Fprintf(a.Out, "Allow %s [%s] %s%s? %s ", d.ID(), d.Category, d.Name, shared, hint)
			answer, readErr := reader.ReadString('\n')
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return fmt.Errorf("read confirmation: %w", readErr)
			}
			answer = strings.ToLower(strings.TrimSpace(answer))
			// End of input is not an answer: without this, `hidpass auto </dev/null`
			// would apply category defaults to every device without confirmation.
			if answer == "" && errors.Is(readErr, io.EOF) {
				fmt.Fprintln(a.Out)
				return errors.New("standard input ended before an answer; nothing was changed (use `hidpass auto --yes` for unattended runs)")
			}
			switch {
			case answer == "y" || answer == "yes":
				allow = true
			case answer == "n" || answer == "no":
				allow = false
			default:
				allow = autoDefaultAllow(d.Category)
			}
		}
		if allow {
			selected = append(selected, model.AllowedDevice{VID: d.VID, PID: d.PID, Name: d.Name, Category: d.Category})
		}
	}
	if len(selected) == 0 {
		fmt.Fprintln(a.Out, "No devices selected; configuration was not changed.")
		return nil
	}
	return a.sendDevices("add", selected)
}

func (a *App) allow(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: hidpass allow <VID:PID>")
	}
	vid, pid, err := model.NormalizeID(args[0])
	if err != nil {
		return err
	}
	d := model.AllowedDevice{VID: vid, PID: pid}
	// Scan only enriches presentation metadata. Explicit allow must still work
	// when the device is disconnected or udevadm is unavailable.
	if r, scanErr := a.Scanner.Scan(); scanErr == nil {
		for _, found := range r.Devices {
			if found.ID() == d.ID() {
				d.Name, d.Category = found.Name, found.Category
				break
			}
		}
	}
	return a.sendDevices("allow", []model.AllowedDevice{d})
}

func (a *App) sendDevices(op string, devices []model.AllowedDevice) error {
	b, err := json.Marshal(devices)
	if err != nil {
		return err
	}
	payload := base64.RawURLEncoding.EncodeToString(b)
	return a.doPrivileged(op, payload)
}

func (a *App) remove(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: hidpass remove <VID:PID>")
	}
	vid, pid, err := model.NormalizeID(args[0])
	if err != nil {
		return err
	}
	if err := a.verifyElevation(); err != nil {
		return err
	}
	return a.doPrivileged("remove", vid+":"+pid)
}

func (a *App) apply(args []string) error {
	if len(args) != 0 {
		return errors.New("apply takes no arguments")
	}
	if err := a.verifyElevation(); err != nil {
		return err
	}
	return a.doPrivileged("apply")
}

func (a *App) uninstall(args []string) error {
	if len(args) != 0 {
		return errors.New("uninstall takes no arguments")
	}
	if err := a.verifyElevation(); err != nil {
		return err
	}
	return a.doPrivileged("uninstall")
}

func (a *App) verifyElevation() error {
	if a.EUID() == 0 || a.VerifyElevation == nil {
		return nil
	}
	return a.VerifyElevation(a.Executable, a.EUID())
}

func (a *App) doPrivileged(args ...string) error {
	if a.EUID() == 0 {
		// The user explicitly started the normal command through sudo. At this
		// point the current process already has root privileges, so spawning and
		// then rejecting the same user-owned binary adds no security. Avoid the
		// recursive helper and perform only the fixed privileged operation.
		fmt.Fprintln(a.Err, "warning: hidpass was started as root; scanning as root is unnecessary. Install hidpass and run it without sudo next time.")
		return a.performPrivileged(args)
	}
	if err := a.verifyElevation(); err != nil {
		return err
	}
	if err := a.Escalator.Do(args...); err != nil {
		return elevationError(err)
	}
	return nil
}

func (a *App) runPrivileged(args []string) error {
	if a.EUID() != 0 {
		return errors.New("internal --privileged mode requires root; run a normal hidpass command and let it invoke pkexec or sudo")
	}
	if err := a.VerifyRoot(a.Executable); err != nil {
		return err
	}
	return a.performPrivileged(args)
}

func (a *App) performPrivileged(args []string) error {
	if len(args) == 0 {
		return errors.New("missing privileged operation")
	}
	// sudo without secure_path forwards the caller's PATH, which would decide
	// which "udevadm" this root process executes.
	os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
	switch args[0] {
	case "add", "allow":
		if len(args) != 2 {
			return errors.New("invalid privileged " + args[0] + " request")
		}
		decoded, err := base64.RawURLEncoding.DecodeString(args[1])
		if err != nil || len(decoded) > 1024*1024 {
			return errors.New("invalid privileged device payload")
		}
		var devices []model.AllowedDevice
		if err := json.Unmarshal(decoded, &devices); err != nil || len(devices) == 0 || len(devices) > 1024 {
			return errors.New("invalid privileged device list")
		}
		explicit := args[0] == "allow"
		var accepted []model.AllowedDevice
		for _, d := range devices {
			vid, pid, err := model.NormalizePair(d.VID, d.PID)
			if err != nil {
				return err
			}
			d.VID, d.PID = vid, pid
			if !explicit {
				if sensitive, why := classify.SecurityDevice(d.VID, d.Name, d.Category); sensitive {
					fmt.Fprintf(a.Err, "refusing to auto-add security device %s: %s (use `hidpass allow %s` to override)\n", d.ID(), why, d.ID())
					continue
				}
			}
			accepted = append(accepted, d)
		}
		if len(accepted) == 0 {
			return errors.New("no devices were added; security devices cannot be added via auto (use `hidpass allow VID:PID` to override)")
		}
		f, err := a.Store.Load()
		if err != nil {
			return err
		}
		for _, d := range accepted {
			state.Add(&f, d)
		}
		if err := a.install(f); err != nil {
			return err
		}
		fmt.Fprintf(a.Out, "Configured %d device(s).\n", len(accepted))
	case "remove":
		if len(args) != 2 {
			return errors.New("invalid privileged remove request")
		}
		vid, pid, err := model.NormalizeID(args[1])
		if err != nil {
			return err
		}
		f, err := a.Store.Load()
		if err != nil {
			return err
		}
		removed := state.Remove(&f, vid+":"+pid)
		if err := a.install(f); err != nil {
			return err
		}
		if removed {
			fmt.Fprintf(a.Out, "Removed %s.\n", vid+":"+pid)
			fmt.Fprintln(a.Out, "Access already granted to a connected node stays until the device is reconnected: udev only re-applies uaccess, it never revokes it.")
		} else {
			fmt.Fprintf(a.Out, "%s was not configured; rules were rebuilt unchanged.\n", vid+":"+pid)
		}
	case "apply":
		if len(args) != 1 {
			return errors.New("invalid privileged apply request")
		}
		f, err := a.Store.Load()
		if err != nil {
			return err
		}
		if err := a.install(f); err != nil {
			return err
		}
		fmt.Fprintf(a.Out, "Rebuilt rules for %d device(s).\n", len(f.Devices))
	case "uninstall":
		if len(args) != 1 {
			return errors.New("invalid privileged uninstall request")
		}
		if err := a.Udev.Remove(); err != nil {
			return err
		}
		if err := a.Store.Remove(); err != nil {
			return err
		}
		if err := a.Udev.Reload(); err != nil {
			return fmt.Errorf("removed hidpass files, but udev reload failed: %w", err)
		}
		fmt.Fprintln(a.Out, "Removed hidpass udev rules and saved device state.")
	default:
		return fmt.Errorf("unknown privileged operation %q", args[0])
	}
	a.printReconnectNotice()
	return nil
}

func (a *App) install(f state.File) error {
	if err := state.Validate(&f); err != nil {
		return fmt.Errorf("refusing invalid configuration: %w", err)
	}
	// Generate first, then write rules, then persist state. If Write fails,
	// devices.json must not move ahead of the udev rules file.
	if _, err := udev.Generate(f.Devices); err != nil {
		return err
	}
	if err := a.Udev.Write(f.Devices); err != nil {
		return fmt.Errorf("rules could not be written; configuration was not saved: %w", err)
	}
	if err := a.Store.Save(f); err != nil {
		return fmt.Errorf("rules were written, but state could not be saved (run `hidpass apply` after fixing the problem): %w", err)
	}
	if err := a.Udev.Reload(); err != nil {
		return fmt.Errorf("rules and state were written, but udev reload failed: %w", err)
	}
	return nil
}

func (a *App) printReconnectNotice() {
	fmt.Fprintln(a.Out, "udev rules reloaded, hidraw devices triggered, and pending events settled.")
	fmt.Fprintln(a.Out, "If access is still not updated, physically reconnect the device/dongle; some firmware resets expose a new HID interface.")
}

func (a *App) getenv(key string) string {
	if a.Getenv != nil {
		return a.Getenv(key)
	}
	return os.Getenv(key)
}

func (a *App) doctor(args []string) error {
	if len(args) != 0 {
		return errors.New("doctor takes no arguments")
	}
	type check struct {
		name, value string
		ok          bool
	}
	var checks []check
	for _, command := range []string{"udevadm", "pkexec", "sudo"} {
		path, err := a.LookPath(command)
		checks = append(checks, check{command, valueOr(path, "not found"), err == nil})
	}
	nodes, err := a.Glob("/dev/hidraw*")
	checks = append(checks, check{"/dev/hidraw*", fmt.Sprintf("%d node(s)", len(nodes)), err == nil && len(nodes) > 0})
	if info, statErr := a.Stat("/sys/class/hidraw"); statErr == nil {
		checks = append(checks, check{"/sys/class/hidraw", "present", info.IsDir()})
	} else {
		checks = append(checks, check{"/sys/class/hidraw", statErr.Error(), false})
	}
	method, elevErr := privilege.Select(a.EUID(), a.LookPath)
	rulesDir := filepath.Dir(a.Udev.RulesPath)
	dirInfo, dirErr := a.Stat(rulesDir)
	dirReady := dirErr == nil && dirInfo.IsDir()
	dirStatus := "directory present"
	if dirErr != nil {
		dirStatus = dirErr.Error()
	} else if !dirInfo.IsDir() {
		dirStatus = "path is not a directory"
	}
	checks = append(checks, check{"udev rules directory", dirStatus, dirReady})
	canElevate := elevErr == nil && (dirReady || os.IsNotExist(dirErr))
	checks = append(checks, check{"rules write via elevation", valueOr(string(method), errorText(elevErr)), canElevate})

	persistent := udev.IsPersistentRulesPath(a.Udev.RulesPath)
	persistMsg := a.Udev.RulesPath + " (persistent; udev loads /etc/udev/rules.d after reboot)"
	if !persistent {
		persistMsg = a.Udev.RulesPath + " (not /etc/udev/rules.d; /run is tmpfs and will not survive reboot)"
	}
	checks = append(checks, check{"udev rules path", persistMsg, persistent})

	rulesInfo, rulesErr := a.Stat(a.Udev.RulesPath)
	rulesPresent := rulesErr == nil
	if rulesPresent {
		checks = append(checks, check{"current rule file", fmt.Sprintf("present (%d bytes)", rulesInfo.Size()), true})
	} else if os.IsNotExist(rulesErr) {
		checks = append(checks, check{"current rule file", "not created yet", true})
	} else {
		checks = append(checks, check{"current rule file", rulesErr.Error(), false})
	}

	f, stateErr := a.Store.Load()
	configured := 0
	if stateErr == nil {
		configured = len(f.Devices)
		checks = append(checks, check{"configured devices", fmt.Sprintf("%d", configured), true})
	} else {
		checks = append(checks, check{"configured devices", stateErr.Error(), false})
	}
	if configured > 0 && !rulesPresent {
		checks = append(checks, check{"rules vs state", "devices are configured but rules file is missing; run hidpass apply", false})
	}

	session := a.getenv("XDG_SESSION_TYPE")
	seat := a.getenv("XDG_SEAT")
	seatOK := session != "" || seat != ""
	seatMsg := fmt.Sprintf("XDG_SESSION_TYPE=%s XDG_SEAT=%s", valueOr(session, "(empty)"), valueOr(seat, "(empty)"))
	if !seatOK {
		if _, err := a.Stat("/run/systemd/seats/seat0"); err == nil {
			seatOK = true
			seatMsg = "/run/systemd/seats/seat0 present"
		} else if _, err := a.Stat("/run/systemd/seats"); err == nil {
			seatOK = true
			seatMsg = "/run/systemd/seats present"
		} else {
			seatMsg = "no XDG_SESSION_TYPE/XDG_SEAT and no systemd-logind seat; uaccess may not apply"
		}
	}
	checks = append(checks, check{"logind seat", seatMsg, seatOK})

	if rulesPresent && configured > 0 && len(nodes) > 0 {
		aclFn := a.HasACL
		if aclFn == nil {
			aclFn = hasPOSIXACL
		}
		aclOK := false
		for _, n := range nodes {
			if aclFn(n) {
				aclOK = true
				break
			}
		}
		if aclOK {
			checks = append(checks, check{"hidraw uaccess ACL", "at least one /dev/hidraw* has a POSIX ACL", true})
		} else {
			checks = append(checks, check{"hidraw uaccess ACL", "rules exist but no /dev/hidraw* has a uaccess ACL; reconnect the device or check logind", false})
		}
	}

	max := 0
	for _, c := range checks {
		if len(c.name) > max {
			max = len(c.name)
		}
	}
	for _, c := range checks {
		status := "OK"
		if !c.ok {
			status = "WARN"
		}
		fmt.Fprintf(a.Out, "%-*s  %-4s  %s\n", max, c.name, status, c.value)
	}
	return nil
}

func hasPOSIXACL(path string) bool {
	sz, err := syscall.Getxattr(path, "system.posix_acl_access", nil)
	return err == nil && sz > 0
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// helpOrError keeps `hidpass scan --help` from exiting 1: flag already printed
// the usage text, so there is nothing left to report.
func helpOrError(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func elevationError(err error) error {
	if privilege.IsCancellation(err) {
		return errors.New("authorization was cancelled; configuration was not changed")
	}
	return err
}
