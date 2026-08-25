package classify

import "testing"

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

func makeBitmap(bits ...int) string {
	max := 0
	for _, b := range bits {
		if b > max {
			max = b
		}
	}
	nibbles := max/4 + 1
	chars := make([]byte, nibbles)
	for i := range chars {
		chars[i] = '0'
	}
	for _, bit := range bits {
		i := nibbles - 1 - bit/4
		v := byte(0)
		if chars[i] >= '0' && chars[i] <= '9' {
			v = chars[i] - '0'
		} else {
			v = chars[i] - 'a' + 10
		}
		v |= 1 << uint(bit%4)
		if v < 10 {
			chars[i] = '0' + v
		} else {
			chars[i] = 'a' + v - 10
		}
	}
	return string(chars)
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
