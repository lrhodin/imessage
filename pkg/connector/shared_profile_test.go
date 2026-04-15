package connector

import (
	"bytes"
	"testing"
)

func TestSharedProfileRowAsProfileRecord(t *testing.T) {
	tests := []struct {
		name       string
		row        *sharedProfileRow
		wantName   string
		wantFirst  string
		wantLast   string
		wantAvatar []byte
	}{
		{
			name: "full record",
			row: &sharedProfileRow{
				DisplayName: "Alice Example",
				FirstName:   "Alice",
				LastName:    "Example",
				Avatar:      []byte{0x89, 0x50, 0x4e, 0x47},
			},
			wantName:   "Alice Example",
			wantFirst:  "Alice",
			wantLast:   "Example",
			wantAvatar: []byte{0x89, 0x50, 0x4e, 0x47},
		},
		{
			name: "no avatar",
			row: &sharedProfileRow{
				DisplayName: "Bob",
				FirstName:   "Bob",
			},
			wantName:  "Bob",
			wantFirst: "Bob",
		},
		{
			name: "empty avatar slice is treated as absent",
			row: &sharedProfileRow{
				DisplayName: "Carol",
				FirstName:   "Carol",
				Avatar:      []byte{},
			},
			wantName:  "Carol",
			wantFirst: "Carol",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.row.asProfileRecord()
			if got.DisplayName != tt.wantName {
				t.Errorf("DisplayName = %q, want %q", got.DisplayName, tt.wantName)
			}
			if got.FirstName != tt.wantFirst {
				t.Errorf("FirstName = %q, want %q", got.FirstName, tt.wantFirst)
			}
			if got.LastName != tt.wantLast {
				t.Errorf("LastName = %q, want %q", got.LastName, tt.wantLast)
			}
			if len(tt.wantAvatar) == 0 {
				if got.Avatar != nil {
					t.Errorf("Avatar = %v, want nil", *got.Avatar)
				}
			} else {
				if got.Avatar == nil {
					t.Fatalf("Avatar = nil, want %v", tt.wantAvatar)
				}
				if !bytes.Equal(*got.Avatar, tt.wantAvatar) {
					t.Errorf("Avatar = %v, want %v", *got.Avatar, tt.wantAvatar)
				}
			}
		})
	}
}

// TestSharedProfileRowAvatarIsolation confirms asProfileRecord copies the
// avatar slice so later mutations to the row don't leak into the returned
// WrappedProfileRecord (which callers treat as read-only).
func TestSharedProfileRowAvatarIsolation(t *testing.T) {
	row := &sharedProfileRow{
		DisplayName: "Dave",
		Avatar:      []byte{0x01, 0x02, 0x03, 0x04},
	}
	rec := row.asProfileRecord()
	row.Avatar[0] = 0xff
	if rec.Avatar == nil || (*rec.Avatar)[0] != 0x01 {
		t.Errorf("Avatar was not isolated: got %v", rec.Avatar)
	}
}
