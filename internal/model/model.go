package model

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

var hexID = regexp.MustCompile(`^[0-9a-fA-F]{1,4}$`)

// Device is one physical USB device. Nodes contains all of its hidraw
// interfaces; callers must not assume that one hidraw node is one device.
type Device struct {
	VID          string
	PID          string
	Vendor       string
	Product      string
	Name         string
	Category     string
	PhysicalPath string
	Nodes        []string
	Security     bool
	SecurityWhy  string
}

func (d Device) ID() string { return d.VID + ":" + d.PID }

// AllowedDevice is the small, auditable record persisted in devices.json.
type AllowedDevice struct {
	VID      string    `json:"vid"`
	PID      string    `json:"pid"`
	Name     string    `json:"name,omitempty"`
	Category string    `json:"category,omitempty"`
	AddedAt  time.Time `json:"added_at,omitempty"`
}

func (d AllowedDevice) ID() string { return d.VID + ":" + d.PID }

// NormalizeID accepts the conventional VID:PID form. Short components are
// left-padded so CLI input such as 3e:1 is unambiguous and canonical.
func NormalizeID(s string) (vid, pid string, err error) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) != 2 || !hexID.MatchString(parts[0]) || !hexID.MatchString(parts[1]) {
		return "", "", fmt.Errorf("invalid USB ID %q (expected hexadecimal VID:PID, for example 373e:001e)", s)
	}
	return strings.ToLower(fmt.Sprintf("%04s", parts[0])), strings.ToLower(fmt.Sprintf("%04s", parts[1])), nil
}

func NormalizePair(vid, pid string) (string, string, error) {
	return NormalizeID(vid + ":" + pid)
}
