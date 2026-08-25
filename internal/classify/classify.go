package classify

import "strings"

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
	if yes(p, "ID_INPUT_TOUCHPAD") || ((has(e.AbsBits, 0) && has(e.AbsBits, 1)) && (has(e.KeyBits, 0x14a) || has(e.PropBits, 2))) {
		return Touchpad
	}
	if yes(p, "ID_INPUT_TABLET") || (has(e.KeyBits, 0x140) && has(e.AbsBits, 0) && has(e.AbsBits, 1)) {
		return Tablet
	}
	if yes(p, "ID_INPUT_JOYSTICK") || (has(e.KeyBits, 0x130) && has(e.AbsBits, 0) && has(e.AbsBits, 1)) {
		return Joystick
	}
	// Alphabetic keys (KEY_Q and KEY_P) distinguish keyboards from mice,
	// which also expose a key bitmap for their buttons.
	if yes(p, "ID_INPUT_KEYBOARD") || (has(e.KeyBits, 16) && has(e.KeyBits, 25)) {
		return Keyboard
	}
	if yes(p, "ID_INPUT_MOUSE") || (has(e.RelBits, 0) && has(e.RelBits, 1) && has(e.KeyBits, 0x110)) {
		return Mouse
	}
	return Other
}

func yes(m map[string]string, key string) bool {
	v := strings.ToLower(strings.TrimSpace(m[key]))
	return v == "1" || v == "yes" || v == "true"
}

// has decodes Linux sysfs input bitmaps. Words are printed most-significant
// first, while bit zero is in the right-most machine word. Parsing each word
// independently also works on both 32-bit and 64-bit kernels.
func has(bitmaps []string, bit int) bool {
	for _, bitmap := range bitmaps {
		fields := strings.Fields(bitmap)
		remaining := bit
		for i := len(fields) - 1; i >= 0; i-- {
			wordBits := len(fields[i]) * 4
			if remaining < wordBits {
				nibbleFromRight := remaining / 4
				char := fields[i][len(fields[i])-1-nibbleFromRight]
				var value byte
				switch {
				case char >= '0' && char <= '9':
					value = char - '0'
				case char >= 'a' && char <= 'f':
					value = char - 'a' + 10
				case char >= 'A' && char <= 'F':
					value = char - 'A' + 10
				default:
					break
				}
				if value&(1<<uint(remaining%4)) != 0 {
					return true
				}
				break
			}
			remaining -= wordBits
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
		"yubikey", "yubico", "fido", "security key", "security_key",
		"ledger", "trezor", "nitrokey", "onlykey", "solo key", "solokey",
		"hardware wallet", "hardware_wallet",
	}
	for _, term := range terms {
		if strings.Contains(s, term) {
			return true, "identity contains " + term
		}
	}
	// Well-known vendor IDs are an additional safeguard when product strings
	// are absent or generic. 1050 is Yubico; 2c97 is Ledger; 1209 covers many
	// open hardware devices, so it is intentionally not excluded wholesale.
	switch strings.ToLower(vid) {
	case "1050":
		return true, "Yubico vendor ID"
	case "2c97":
		return true, "Ledger vendor ID"
	case "20a0":
		return true, "Nitrokey vendor ID"
	case "534c":
		return true, "Trezor vendor ID"
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
