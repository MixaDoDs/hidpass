package udev

import (
	"strings"
	"testing"

	"hidpass/internal/model"
)

func TestGenerateRules(t *testing.T) {
	b, err := Generate([]model.AllowedDevice{
		{VID: "373E", PID: "1E", Name: "LAMZU\nMAYA", Category: "mouse"},
		{VID: "0fd9", PID: "006d", Name: "Stream Deck", Category: "streamdeck"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	want := `KERNEL=="hidraw*", ATTRS{idVendor}=="373e", ATTRS{idProduct}=="001e", TAG+="uaccess"`
	if !strings.Contains(s, want) {
		t.Fatalf("missing rule %q in:\n%s", want, s)
	}
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(line, "#") && (strings.Contains(line, "0666") || strings.Contains(line, "MODE=")) {
			t.Fatalf("unsafe global mode in rules:\n%s", s)
		}
	}
	if strings.Contains(s, "LAMZU\nMAYA") {
		t.Fatal("comment injection was not sanitized")
	}
}
