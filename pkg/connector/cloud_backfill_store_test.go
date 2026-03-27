package connector

import "testing"

func TestParticipantSetsMatch(t *testing.T) {
	self := "tel:+15551234567"
	selfEmail := "mailto:user@example.com"
	// isSelf checks against all known handles (phone + email).
	isSelf := func(h string) bool {
		n := normalizeIdentifierForPortalID(h)
		return n == normalizeIdentifierForPortalID(self) || n == normalizeIdentifierForPortalID(selfEmail)
	}

	tests := []struct {
		name   string
		a, b   []string
		isSelf func(string) bool
		want   bool
	}{
		{
			name:   "identical sets",
			a:      []string{"tel:+15551111111", "tel:+15552222222", self},
			b:      []string{"tel:+15552222222", "tel:+15551111111", self},
			isSelf: isSelf,
			want:   true,
		},
		{
			name:   "self in a but not b",
			a:      []string{"tel:+15551111111", self},
			b:      []string{"tel:+15551111111"},
			isSelf: isSelf,
			want:   true,
		},
		{
			name:   "self in b but not a",
			a:      []string{"tel:+15551111111"},
			b:      []string{"tel:+15551111111", self},
			isSelf: isSelf,
			want:   true,
		},
		{
			name:   "self email handle in a, phone handle absent",
			a:      []string{"tel:+15551111111", selfEmail},
			b:      []string{"tel:+15551111111"},
			isSelf: isSelf,
			want:   true,
		},
		{
			name:   "non-self member differs",
			a:      []string{"tel:+15551111111", "tel:+15552222222"},
			b:      []string{"tel:+15551111111", "tel:+15553333333"},
			isSelf: isSelf,
			want:   false,
		},
		{
			name:   "diff is 1 but differing member is not self",
			a:      []string{"tel:+15551111111", "tel:+15552222222", "tel:+15554444444"},
			b:      []string{"tel:+15551111111", "tel:+15552222222"},
			isSelf: isSelf,
			want:   false,
		},
		{
			name:   "both empty",
			a:      []string{},
			b:      []string{},
			isSelf: isSelf,
			want:   false,
		},
		{
			name:   "empty set a",
			a:      []string{},
			b:      []string{"tel:+15551111111"},
			isSelf: isSelf,
			want:   false,
		},
		{
			name:   "empty set b",
			a:      []string{"tel:+15551111111"},
			b:      []string{},
			isSelf: isSelf,
			want:   false,
		},
		{
			name:   "nil isSelf disallows any difference",
			a:      []string{"tel:+15551111111", self},
			b:      []string{"tel:+15551111111"},
			isSelf: nil,
			want:   false,
		},
		{
			name:   "duplicates in input",
			a:      []string{"tel:+15551111111", "tel:+15551111111"},
			b:      []string{"tel:+15551111111"},
			isSelf: isSelf,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := participantSetsMatch(tt.a, tt.b, tt.isSelf)
			if got != tt.want {
				t.Errorf("participantSetsMatch(%v, %v) = %v, want %v",
					tt.a, tt.b, got, tt.want)
			}
		})
	}
}
