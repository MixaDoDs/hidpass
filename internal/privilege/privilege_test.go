package privilege

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func lookWith(names ...string) LookPath {
	return func(name string) (string, error) {
		for _, n := range names {
			if name == n {
				return "/usr/bin/" + n, nil
			}
		}
		return "", errors.New("not found")
	}
}

func TestSelect(t *testing.T) {
	if got, _ := Select(0, lookWith()); got != Direct {
		t.Fatalf("root = %s", got)
	}
	if got, _ := Select(1000, lookWith("pkexec", "sudo")); got != Pkexec {
		t.Fatalf("desktop = %s", got)
	}
	if got, _ := Select(1000, lookWith("sudo")); got != Sudo {
		t.Fatalf("fallback = %s", got)
	}
	if _, err := Select(1000, lookWith()); err == nil {
		t.Fatal("expected no-method error")
	}
}

func TestEscalatorCommandNoRecursion(t *testing.T) {
	e := Escalator{Executable: "/usr/local/bin/hidpass", EUID: func() int { return 1000 }, Look: lookWith("pkexec")}
	method, name, args, err := e.Command("apply")
	if err != nil {
		t.Fatal(err)
	}
	if method != Pkexec || name != "pkexec" || !reflect.DeepEqual(args, []string{"/usr/local/bin/hidpass", "--privileged", "apply"}) {
		t.Fatalf("got %s %s %#v", method, name, args)
	}
}

func TestUserOwnedExecutableMayElevate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hidpass")
	if err := os.WriteFile(path, []byte("test"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := ValidateExecutableForElevation(path, os.Geteuid()); err != nil {
		t.Fatalf("normal user-owned 0755 binary was rejected: %v", err)
	}
	if err := VerifyRootExecutable(path); err != nil {
		t.Fatalf("already-running helper rejected user-owned binary: %v", err)
	}
}

func TestWritableOrSetuidExecutableIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hidpass")
	if err := os.WriteFile(path, []byte("test"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0775); err != nil {
		t.Fatal(err)
	}
	if err := ValidateExecutableForElevation(path, os.Geteuid()); err == nil {
		t.Fatal("group-writable executable was accepted")
	}
	if err := os.Chmod(path, 0755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	if err := ValidateExecutableForElevation(path, os.Geteuid()); err == nil {
		t.Fatal("setuid executable was accepted")
	}
}

func TestForeignOwnedExecutableIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hidpass")
	if err := os.WriteFile(path, []byte("test"), 0755); err != nil {
		t.Fatal(err)
	}
	// The file belongs to this uid, so a caller claiming to be somebody else is
	// exactly the "owned by a third user" case pkexec must not be handed.
	if err := ValidateExecutableForElevation(path, os.Geteuid()+1); err == nil {
		t.Fatal("executable owned by another user was accepted")
	}
}
