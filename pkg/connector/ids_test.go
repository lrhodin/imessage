package connector

import (
	"testing"
)

func TestMakeUserID(t *testing.T) {
	got := makeUserID("tel:+15551234567")
	if string(got) != "tel:+15551234567" {
		t.Errorf("makeUserID = %q, want %q", string(got), "tel:+15551234567")
	}
}

func TestMakeMessageID(t *testing.T) {
	got := makeMessageID("abc-def-123")
	if string(got) != "abc-def-123" {
		t.Errorf("makeMessageID = %q, want %q", string(got), "abc-def-123")
	}
}
