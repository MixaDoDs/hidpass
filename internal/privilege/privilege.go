package privilege

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

type Method string

const (
	Direct Method = "direct"
	Pkexec Method = "pkexec"
	Sudo   Method = "sudo"
)

type LookPath func(string) (string, error)

func Select(euid int, look LookPath) (Method, error) {
	if euid == 0 {
		return Direct, nil
	}
	if _, err := look("pkexec"); err == nil {
		return Pkexec, nil
	}
	if _, err := look("sudo"); err == nil {
		return Sudo, nil
	}
	return "", fmt.Errorf("privileged operation required, but neither pkexec nor sudo is installed")
}

type Escalator struct {
	Executable string
	EUID       func() int
	Look       LookPath
	Run        func(name string, args ...string) error
}

func Default() (*Escalator, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate current executable: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return nil, fmt.Errorf("resolve current executable: %w", err)
	}
	return &Escalator{Executable: exe, EUID: os.Geteuid, Look: exec.LookPath, Run: func(name string, args ...string) error {
		cmd := exec.Command(name, args...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		return cmd.Run()
	}}, nil
}

func (e *Escalator) Command(args ...string) (Method, string, []string, error) {
	method, err := Select(e.EUID(), e.Look)
	if err != nil {
		return "", "", nil, err
	}
	inner := append([]string{"--privileged"}, args...)
	switch method {
	case Direct:
		return method, e.Executable, inner, nil
	case Pkexec:
		return method, "pkexec", append([]string{e.Executable}, inner...), nil
	case Sudo:
		return method, "sudo", append([]string{"--", e.Executable}, inner...), nil
	default:
		return "", "", nil, fmt.Errorf("unknown escalation method %q", method)
	}
}

func (e *Escalator) Do(args ...string) error {
	_, name, commandArgs, err := e.Command(args...)
	if err != nil {
		return err
	}
	if err := e.Run(name, commandArgs...); err != nil {
		return fmt.Errorf("privileged helper failed: %w", err)
	}
	return nil
}

func inspectExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat executable %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("executable %s is not a regular file", path)
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("executable %s is group/world writable; run chmod 0755 %s", path, path)
	}
	if info.Mode()&os.ModeSetuid != 0 {
		return fmt.Errorf("refusing setuid hidpass binary %s; remove the setuid bit and use pkexec/sudo", path)
	}
	return nil
}

// VerifyRootExecutable validates the already-running helper image. It may be
// user-owned: pkexec/sudo grant root only for an authenticated invocation.
// hidpass never needs or accepts the setuid bit.
func VerifyRootExecutable(path string) error {
	if err := inspectExecutable(path); err != nil {
		return fmt.Errorf("refusing privileged mode: %w", err)
	}
	return nil
}

// ValidateExecutableForElevation applies the same safety check before asking
// pkexec/sudo. A normal user-owned mode-0755 development binary is valid if
// it is not sitting in a world-writable directory. The intended trusted path
// is a root-owned install such as /usr/local/bin/hidpass (not user-writable).
// hidpass does not use setuid.
//
// euid is the calling process effective UID: directory checks are skipped
// when already running as root (the helper uses VerifyRootExecutable).
func ValidateExecutableForElevation(path string, euid int) error {
	if err := inspectExecutable(path); err != nil {
		return fmt.Errorf("cannot elevate: %w", err)
	}
	if euid == 0 {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat executable before elevation: %w", err)
	}
	// Handing a binary owned by a third user to pkexec/sudo would let that user
	// rewrite it and inherit the root privileges this invocation authenticates.
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != 0 && int(st.Uid) != euid {
		return fmt.Errorf("cannot elevate executable %s: it is owned by uid %d, neither root nor you", path, st.Uid)
	}
	return rejectUntrustedParents(path)
}

func rejectUntrustedParents(path string) error {
	resolved := path
	if r, err := filepath.EvalSymlinks(path); err == nil {
		resolved = r
	}
	dir := filepath.Dir(resolved)
	immediate := dir
	for {
		info, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("cannot elevate %s: stat directory %s: %w", path, dir, err)
		}
		worldWritable := info.Mode().Perm()&0002 != 0
		sticky := info.Mode()&os.ModeSticky != 0
		// Sticky world-writable dirs such as /tmp are acceptable as ancestors
		// of a private subdirectory, but the binary itself must not live in
		// a world-writable directory (anyone could replace a /tmp/hidpass).
		if worldWritable && (!sticky || dir == immediate) {
			return fmt.Errorf("cannot elevate %s: directory %s is world-writable; install hidpass to a root-owned path such as /usr/local/bin", path, dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return nil
}

func IsCancellation(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "exit status 126") || strings.Contains(s, "dismissed") || strings.Contains(s, "cancelled")
}
