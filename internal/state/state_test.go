package state

import (
	"path/filepath"
	"testing"
	"time"

	"hidpass/internal/model"
)

func TestStoreRoundTripAndMutation(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "etc", "hidpass", "devices.json")}
	f, err := s.Load()
	if err != nil || f.Version != CurrentVersion || len(f.Devices) != 0 {
		t.Fatalf("empty load: %#v, %v", f, err)
	}
	added := model.AllowedDevice{VID: "373E", PID: "1E", Name: "MAYA", Category: "mouse", AddedAt: time.Unix(1, 0).UTC()}
	if !Add(&f, added) {
		t.Fatal("first add said existing")
	}
	if err := s.Save(f); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Devices) != 1 || got.Devices[0].ID() != "373e:001e" {
		t.Fatalf("round trip = %#v", got)
	}
	if !Remove(&got, "373e:001e") || len(got.Devices) != 0 {
		t.Fatalf("remove = %#v", got)
	}
}

func TestStoreRejectsDuplicate(t *testing.T) {
	f := File{Version: CurrentVersion, Devices: []model.AllowedDevice{{VID: "1", PID: "2"}, {VID: "0001", PID: "0002"}}}
	if err := Validate(&f); err == nil {
		t.Fatal("expected duplicate error")
	}
}
