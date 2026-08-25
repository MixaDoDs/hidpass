package privilege

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// VerifyRootExecutable validates the already-running helper image. It may be
// user-owned: pkexec/sudo grant root only for an authenticated invocation.
// hidpass never needs or accepts the setuid bit.
func VerifyRootExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat privileged executable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing privileged mode: executable %s is not a regular file", path)
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("refusing privileged mode: executable %s is group/world writable; run chmod 0755 %s", path, path)
	}
	if info.Mode()&os.ModeSetuid != 0 {
		return fmt.Errorf("refusing setuid hidpass binary %s; remove the setuid bit and use pkexec/sudo", path)
	}
	return nil
}

// ValidateExecutableForElevation applies the same safety check before asking
// pkexec/sudo. A normal user-owned mode-0755 development binary is valid.
func ValidateExecutableForElevation(path string, euid int) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat executable before elevation: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("cannot elevate executable %s: it is not a regular file", path)
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("cannot elevate executable %s because it is group/world writable; run chmod 0755 %s", path, path)
	}
	if info.Mode()&os.ModeSetuid != 0 {
		return fmt.Errorf("refusing setuid hidpass binary %s; remove the setuid bit and use pkexec/sudo", path)
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
