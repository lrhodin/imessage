package connector

import (
	"testing"
)

func TestNormalizePhone(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"+1 (555) 123-4567", "+15551234567"},
		{"15551234567", "15551234567"},
		{"+1-555-123-4567", "+15551234567"},
		{"", ""},
		{"+", "+"},
		{"abc", ""},
		{"+44 20 7946 0958", "+442079460958"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizePhone(tt.input)
			if got != tt.want {
				t.Errorf("normalizePhone(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestPhoneSuffixes(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"+15551234567", []string{"+15551234567", "15551234567", "5551234567", "1234567"}},
		{"+4412345678901", []string{"+4412345678901", "4412345678901", "2345678901", "5678901"}},
		{"5551234", []string{"5551234"}},
		{"+1234567", []string{"+1234567", "1234567"}},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := phoneSuffixes(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("phoneSuffixes(%q) returned %d items, want %d: %v", tt.input, len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("phoneSuffixes(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestStripNonBase64(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"SGVsbG8=", "SGVsbG8="},
		{"SGVs bG8=", "SGVsbG8="},
		{"abc" + "!@#" + "def", "abcdef"},
		{"", ""},
		{"ABCD+/==", "ABCD+/=="},
	}
	for _, tt := range tests {
		got := stripNonBase64(tt.input)
		if got != tt.want {
			t.Errorf("stripNonBase64(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestStripIdentifierPrefix(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"tel:+15551234567", "+15551234567"},
		{"mailto:user@example.com", "user@example.com"},
		{"+15551234567", "+15551234567"},
		{"user@example.com", "user@example.com"},
		{"", ""},
		{"tel:mailto:nested", "nested"},
	}
	for _, tt := range tests {
		got := stripIdentifierPrefix(tt.input)
		if got != tt.want {
			t.Errorf("stripIdentifierPrefix(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestAddIdentifierPrefix(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"+15551234567", "tel:+15551234567"},
		{"user@example.com", "mailto:user@example.com"},
		{"12345", "tel:12345"},
		{"tel:+1555", "tel:+1555"},
		{"mailto:a@b.com", "mailto:a@b.com"},
		{"some-guid", "some-guid"},
		{"", ""},
	}
	for _, tt := range tests {
		got := addIdentifierPrefix(tt.input)
		if got != tt.want {
			t.Errorf("addIdentifierPrefix(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestIsNumeric(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"12345", true},
		{"0", true},
		{"", false},
		{"12a45", false},
		{"+1234", false},
		{"123.45", false},
	}
	for _, tt := range tests {
		got := isNumeric(tt.input)
		if got != tt.want {
			t.Errorf("isNumeric(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestIdentifierToDisplaynameParams(t *testing.T) {
	tests := []struct {
		input string
		phone string
		email string
		id    string
	}{
		{"tel:+15551234567", "+15551234567", "", "+15551234567"},
		{"mailto:user@example.com", "", "user@example.com", "user@example.com"},
		{"+15551234567", "+15551234567", "", "+15551234567"},
		{"some-guid", "", "", "some-guid"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := identifierToDisplaynameParams(tt.input)
			if got.Phone != tt.phone {
				t.Errorf("Phone = %q, want %q", got.Phone, tt.phone)
			}
			if got.Email != tt.email {
				t.Errorf("Email = %q, want %q", got.Email, tt.email)
			}
			if got.ID != tt.id {
				t.Errorf("ID = %q, want %q", got.ID, tt.id)
			}
		})
	}
}
