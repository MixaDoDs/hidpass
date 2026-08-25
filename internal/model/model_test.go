package model

import "testing"

func TestNormalizeID(t *testing.T) {
	tests := []struct {
		in, want string
		bad      bool
	}{
		{"373E:1E", "373e:001e", false},
		{"3e:1", "003e:0001", false},
		{"0fd9:006d", "0fd9:006d", false},
		{"xyz:1", "", true},
		{"12345:1", "", true},
		{"1234", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			vid, pid, err := NormalizeID(tt.in)
			if (err != nil) != tt.bad {
				t.Fatalf("error = %v, bad=%v", err, tt.bad)
			}
			if !tt.bad && vid+":"+pid != tt.want {
				t.Fatalf("got %s:%s, want %s", vid, pid, tt.want)
			}
		})
	}
}
