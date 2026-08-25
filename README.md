# hidpass

`hidpass` is a Linux CLI for discovering configurable USB HID/WebHID devices
and granting the active local desktop user narrowly scoped access to their
`/dev/hidraw*` interfaces. It creates one rule per selected VID:PID using
`TAG+="uaccess"`; it never uses `MODE="0666"` or changes every hidraw node.

## Architecture and Linux HID/udev considerations

Discovery starts at `/dev/hidraw*`, asks udev for each node's properties, then
resolves `/sys/class/hidraw/<node>/device` and walks **upward** until it finds a
parent containing valid `idVendor` and `idProduct`. It does not walk
`/sys/bus/usb/devices`: entries there are commonly symlinks and Go's
`filepath.WalkDir` deliberately does not traverse symlinked directories.

A physical USB device can publish several HID interfaces (keyboard, consumer
control, mouse, vendor-specific). `hidpass` groups interfaces by VID:PID plus
the resolved USB-parent path. Two identical devices on different ports remain
separate in scan output, while their common VID:PID needs only one udev rule.

Classification combines `ID_INPUT_*` properties and Linux input capability
bitmaps. Stream Deck identity additionally uses Elgato's vendor ID and product
identity. Composite devices can be imperfectly described by firmware/udev, so
unknown devices remain `other-hid` and are confirmed interactively.

`TAG+="uaccess"` is interpreted by systemd-logind for the active local seat. It
is safer than global mode bits but is not intended for headless/non-seat users.
Reload/trigger does not reliably recalculate ACLs for every existing node, so a
physical reconnect can still be required. Bluetooth hidraw devices lack USB
VID/PID ancestry and are not targeted by this MVP.

Sensitive authenticators and hardware wallets (YubiKey/FIDO, Ledger, Trezor,
Nitrokey, etc.) are excluded by `auto`, including `auto --yes`. An informed
user can still use explicit `allow VID:PID`.

## Project layout

```text
cmd/hidpass/        executable entry point
internal/app/       CLI and user-facing workflow
internal/discovery/ hidraw-first udev/sysfs discovery and deduplication
internal/classify/  input capability classification and security policy
internal/model/     shared validated data types
internal/state/     atomic devices.json persistence
internal/udev/      deterministic rule generation, atomic write, reload
internal/privilege/ minimal pkexec/sudo privileged helper invocation
```

Only the short state/rule/reload operation elevates. The normal process scans
without root and invokes the same installed binary as an internal helper using
`pkexec` (preferred, showing the desktop Polkit dialog) or `sudo` (fallback).
The executable may be a normal user-owned development build: `pkexec`/`sudo`
grants root privileges only for the authenticated invocation. It must be a
regular file, must not be group/world writable, and must not be setuid.

## Build, test, and install

Go 1.18 or newer is sufficient and there are no third-party dependencies.

```bash
go test ./...
go build -trimpath -ldflags "-X hidpass/internal/app.Version=0.1.0" -o hidpass ./cmd/hidpass
sudo install -o root -g root -m 0755 hidpass /usr/local/bin/hidpass
```

Some old/nonstandard Go toolchains require `GOFLAGS=-buildvcs=false` outside a
Git repository. The included `Makefile` uses that compatibility flag; its
default build reports version `dev`, while release builds can inject a version
with the standard Go linker command shown above.

```bash
hidpass scan
hidpass scan --debug
hidpass auto
hidpass auto --yes
hidpass allow 373e:001e
hidpass remove 373e:001e
hidpass list
hidpass apply
hidpass doctor
```

Configuration is stored at `/etc/hidpass/devices.json`. Rules are fully rebuilt
at `/etc/udev/rules.d/70-hidpass.rules`, followed by:

```text
udevadm control --reload-rules
udevadm trigger
```

## Security boundary

Authorization currently relies on the distribution's default policy for
executing the selected binary via `pkexec`; there is no broad bundled Polkit
rule. Packaging can add an action-specific policy/helper in a future release.
The privileged protocol accepts only `add`, `remove`, and `apply`, validates all
VID/PID values, caps payload size/count, writes fixed paths, and never executes
payload content.
