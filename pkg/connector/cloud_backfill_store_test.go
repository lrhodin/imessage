package connector

import "testing"

func TestParticipantSetsMatch(t *testing.T) {
	self := "tel:+15551234567"

	tests := []struct {
		name       string
		a, b       []string
		selfHandle string
		want       bool
	}{
		{
			name:       "identical sets",
			a:          []string{"tel:+15551111111", "tel:+15552222222", self},
			b:          []string{"tel:+15552222222", "tel:+15551111111", self},
			selfHandle: self,
			want:       true,
		},
		{
			name:       "self in a but not b",
			a:          []string{"tel:+15551111111", self},
			b:          []string{"tel:+15551111111"},
			selfHandle: self,
			want:       true,
		},
		{
			name:       "self in b but not a",
			a:          []string{"tel:+15551111111"},
			b:          []string{"tel:+15551111111", self},
			selfHandle: self,
			want:       true,
		},
		{
			name:       "non-self member differs",
			a:          []string{"tel:+15551111111", "tel:+15552222222"},
			b:          []string{"tel:+15551111111", "tel:+15553333333"},
			selfHandle: self,
			want:       false,
		},
		{
			name:       "diff is 1 but differing member is not self",
			a:          []string{"tel:+15551111111", "tel:+15552222222", "tel:+15554444444"},
			b:          []string{"tel:+15551111111", "tel:+15552222222"},
			selfHandle: self,
			want:       false,
		},
		{
			name:       "both empty",
			a:          []string{},
			b:          []string{},
			selfHandle: self,
			want:       false,
		},
		{
			name:       "empty set a",
			a:          []string{},
			b:          []string{"tel:+15551111111"},
			selfHandle: self,
			want:       false,
		},
		{
			name:       "empty set b",
			a:          []string{"tel:+15551111111"},
			b:          []string{},
			selfHandle: self,
			want:       false,
		},
		{
			name:       "empty selfHandle disallows any difference",
			a:          []string{"tel:+15551111111", self},
			b:          []string{"tel:+15551111111"},
			selfHandle: "",
			want:       false,
		},
		{
			name:       "duplicates in input",
			a:          []string{"tel:+15551111111", "tel:+15551111111"},
			b:          []string{"tel:+15551111111"},
			selfHandle: self,
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := participantSetsMatch(tt.a, tt.b, tt.selfHandle)
			if got != tt.want {
				t.Errorf("participantSetsMatch(%v, %v, %q) = %v, want %v",
					tt.a, tt.b, tt.selfHandle, got, tt.want)
			}
		})
	}
}
