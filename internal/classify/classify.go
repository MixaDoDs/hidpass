package classify

import (
	"strconv"
	"strings"
)

const (
	Other      = "other-hid"
	Keyboard   = "keyboard"
	Mouse      = "mouse"
	StreamDeck = "streamdeck"
	Touchpad   = "touchpad"
	Tablet     = "tablet"
	Joystick   = "joystick"
)

// Evidence deliberately combines udev input properties, sysfs input
// capability bitmaps, and identity strings. This avoids name-only keyboard
// and mouse guesses while still recognizing devices such as Stream Decks.
type Evidence struct {
	Properties map[string]string
	KeyBits    []string
	RelBits    []string
	AbsBits    []string
	PropBits   []string
	VID        string
	PID        string
	Vendor     string
	Product    string
}

func Classify(e Evidence) string {
	p := e.Properties
	name := strings.ToLower(e.Vendor + " " + e.Product + " " + p["ID_MODEL_FROM_DATABASE"] + " " + p["ID_MODEL"])

	// Elgato's USB vendor ID plus product identity is stronger than a generic
	// substring. The substring also supports compatible/rebranded decks.
	if (e.VID == "0fd9" && strings.Contains(name, "stream")) || strings.Contains(name, "stream deck") || strings.Contains(name, "stream_deck") {
		return StreamDeck
	}
	// udev's own verdict, when it has one, beats every bitmap guess below.
	for _, c := range []struct{ property, category string }{
		{"ID_INPUT_TOUCHPAD", Touchpad}, {"ID_INPUT_TABLET", Tablet},
		{"ID_INPUT_JOYSTICK", Joystick}, {"ID_INPUT_KEYBOARD", Keyboard},
		{"ID_INPUT_MOUSE", Mouse},
	} {
		if yes(p, c.property) {
			return c.category
		}
	}
	pointer := has(e.AbsBits, 0) && has(e.AbsBits, 1) // ABS_X and ABS_Y
	switch {
	// INPUT_PROP_BUTTONPAD is the only touchpad-specific signal. BTN_TOUCH is
	// shared with touchscreens, digitizers and touch-surface gamepads, so it
	// decides only after the pen and gamepad buttons have been ruled out.
	case pointer && has(e.PropBits, 2):
		return Touchpad
	case pointer && has(e.KeyBits, 0x140): // BTN_TOOL_PEN
		return Tablet
	case pointer && has(e.KeyBits, 0x130): // BTN_GAMEPAD
		return Joystick
	case pointer && has(e.KeyBits, 0x14a): // BTN_TOUCH
		return Touchpad
	// Alphabetic keys (KEY_Q and KEY_P) distinguish keyboards from mice, which
	// also expose a key bitmap for their buttons.
	case has(e.KeyBits, 16) && has(e.KeyBits, 25):
		return Keyboard
	case has(e.RelBits, 0) && has(e.RelBits, 1) && has(e.KeyBits, 0x110): // BTN_LEFT
		return Mouse
	}
	return Other
}

func yes(m map[string]string, key string) bool {
	v := strings.ToLower(strings.TrimSpace(m[key]))
	return v == "1" || v == "yes" || v == "true"
}

// has decodes Linux sysfs input capability bitmaps. The kernel prints one
// machine word per space-separated field with %lx (so a word is *not*
// zero-padded), most-significant word first, which puts bit zero in the
// right-most field. A 32-bit process reads the kernel's compat format, whose
// fields are 32-bit, so strconv.IntSize is the correct word width either way.
func has(bitmaps []string, bit int) bool {
	if bit < 0 {
		return false
	}
	for _, bitmap := range bitmaps {
		fields := strings.Fields(bitmap)
		i := len(fields) - 1 - bit/strconv.IntSize
		if i < 0 {
			continue
		}
		word, err := strconv.ParseUint(fields[i], 16, 64)
		if err != nil {
			continue
		}
		if word&(1<<uint(bit%strconv.IntSize)) != 0 {
			return true
		}
	}
	return false
}

// SecurityDevice excludes authenticators and hardware wallets from auto mode.
// Explicit `allow` remains possible, so policy does not make recovery or
// unusual configurations impossible.
func SecurityDevice(vid, vendor, product string) (bool, string) {
	s := strings.ToLower(strings.Join([]string{vendor, product}, " "))
	terms := []string{
		"yubikey", "yubico", "fido", "u2f", "fido2", "security key", "security_key",
		"ledger", "trezor", "nitrokey", "onlykey", "solo key", "solokey",
		"hardware wallet", "hardware_wallet", "titan security", "feitian",
		"jacarta", "hyperfido",
	}
	for _, term := range terms {
		if strings.Contains(s, term) {
			return true, "identity contains " + term
		}
	}
	// Well-known vendor IDs are an additional safeguard when product strings
	// are absent or generic. 1209 (pid.codes), 0483 (STMicro), 1d50 (OpenMoko)
	// and 1fc9 (NXP) cover many non-security products, so they are not
	// excluded wholesale. Google 18d1 also covers some non-key products;
	// auto-skip is conservative, and explicit `allow` still works.
	switch strings.ToLower(strings.TrimSpace(vid)) {
	case "1050":
		return true, "Yubico vendor ID"
	case "2c97":
		return true, "Ledger vendor ID"
	case "20a0":
		return true, "Nitrokey vendor ID"
	case "534c":
		return true, "Trezor vendor ID"
	case "18d1":
		return true, "Google Titan vendor ID"
	case "096e":
		return true, "Feitian vendor ID"
	case "2581":
		return true, "Plug-up/Happlink vendor ID"
	case "2ccf":
		return true, "Hypersecu vendor ID"
	case "311f":
		return true, "eWBM/TrustKey vendor ID"
	case "349e":
		return true, "Token2 vendor ID"
	case "32a3":
		return true, "GoTrust vendor ID"
	case "1a44":
		return true, "VASCO vendor ID"
	case "1e0d":
		return true, "Neowave vendor ID"
	case "24dc":
		return true, "JaCarta vendor ID"
	case "2abe":
		return true, "Bluink vendor ID"
	case "1ea8":
		return true, "Excelsecu vendor ID"
	}
	return false, ""
}

// Merge chooses the most informative category across a composite device's
// interfaces. A keyboard interface wins over a mouse-like consumer interface.
func Merge(categories []string) string {
	priority := map[string]int{Other: 0, Mouse: 10, Keyboard: 20, Joystick: 30, Tablet: 40, Touchpad: 50, StreamDeck: 60}
	best := Other
	for _, c := range categories {
		if priority[c] > priority[best] {
			best = c
		}
	}
	return best
}
