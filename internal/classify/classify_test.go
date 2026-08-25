package classify

import (
	"strconv"
	"strings"
	"testing"
)

func TestClassifyPropertiesAndCapabilities(t *testing.T) {
	keyKeyboard := makeBitmap(25, 16)
	keyMouse := makeBitmap(0x110)
	tests := []struct {
		name string
		e    Evidence
		want string
	}{
		{"keyboard property", Evidence{Properties: map[string]string{"ID_INPUT_KEYBOARD": "1"}}, Keyboard},
		{"keyboard capabilities", Evidence{Properties: map[string]string{}, KeyBits: []string{keyKeyboard}}, Keyboard},
		{"mouse capabilities", Evidence{Properties: map[string]string{}, KeyBits: []string{keyMouse}, RelBits: []string{makeBitmap(0, 1)}}, Mouse},
		{"streamdeck", Evidence{Properties: map[string]string{}, VID: "0fd9", Product: "Stream Deck XL"}, StreamDeck},
		{"not name-only keyboard", Evidence{Properties: map[string]string{}, Product: "Amazing Keyboard"}, Other},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.e); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// makeBitmap renders bits the way the kernel does: one machine word per
// space-separated field, %lx (unpadded), most-significant word first.
func makeBitmap(bits ...int) string {
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

func TestSecurityDevice(t *testing.T) {
	for _, tc := range []struct{ vid, vendor, product string }{
		{"1050", "", "Generic"},
		{"2c97", "", "Nano"},
		{"20a0", "", "Generic"},
		{"534c", "", "Generic"},
		{"1209", "Nitrokey", "Nitrokey 3"},
		{"", "SatoshiLabs", "Trezor Model T"},
		{"", "", "FIDO Security Key"},
	} {
		if ok, _ := SecurityDevice(tc.vid, tc.vendor, tc.product); !ok {
			t.Errorf("expected exclusion for %#v", tc)
		}
	}
	if ok, why := SecurityDevice("373e", "LAMZU", "MAYA X"); ok {
		t.Fatalf("normal mouse excluded: %s", why)
	}
}

// Regression: real kernel bitmaps are unpadded machine words, so a mouse
// prints "1f0000 0 0 0 0". Deriving the word width from a field's length made
// every bit above the right-most word unreachable.
func TestRealKernelBitmapsFromSysfs(t *testing.T) {
	mouseKey := []string{"1f0000 0 0 0 0"}
	if !has(mouseKey, 0x110) {
		t.Fatalf("BTN_LEFT not found in %q", mouseKey)
	}
	if has(mouseKey, 16) || has(mouseKey, 25) {
		t.Fatal("alphabetic keys reported for a mouse bitmap")
	}
	if got := Classify(Evidence{Properties: map[string]string{}, KeyBits: mouseKey, RelBits: []string{"1943"}}); got != Mouse {
		t.Fatalf("real mouse classified as %q", got)
	}
	keyboard := []string{"1000002000007 ff8039fad941d7ff 9ebeffcdffefffff febffbffdffffffe"}
	if got := Classify(Evidence{Properties: map[string]string{}, KeyBits: keyboard}); got != Keyboard {
		t.Fatalf("real keyboard classified as %q", got)
	}
}

// Regression: the touchpad heuristic used to run first and swallow pens and
// gamepads, including devices udev had already identified explicitly.
func TestPointerDevicesAreNotAllTouchpads(t *testing.T) {
	absXY := makeBitmap(0, 1)
	pen := makeBitmap(0x140, 0x14a) // BTN_TOOL_PEN + BTN_TOUCH
	pad := makeBitmap(0x130, 0x14a) // BTN_GAMEPAD + BTN_TOUCH
	touchpad := makeBitmap(0x14a)   // BTN_TOUCH only
	for _, tt := range []struct {
		name string
		e    Evidence
		want string
	}{
		{"pen tablet by capabilities", Evidence{Properties: map[string]string{}, KeyBits: []string{pen}, AbsBits: []string{absXY}}, Tablet},
		{"gamepad by capabilities", Evidence{Properties: map[string]string{}, KeyBits: []string{pad}, AbsBits: []string{absXY}}, Joystick},
		{"touch surface by capabilities", Evidence{Properties: map[string]string{}, KeyBits: []string{touchpad}, AbsBits: []string{absXY}}, Touchpad},
		{"buttonpad property wins", Evidence{Properties: map[string]string{"ID_INPUT_TABLET": "1"}, KeyBits: []string{touchpad}, AbsBits: []string{absXY}}, Tablet},
		{"joystick property wins", Evidence{Properties: map[string]string{"ID_INPUT_JOYSTICK": "1"}, KeyBits: []string{touchpad}, AbsBits: []string{absXY}}, Joystick},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.e); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
