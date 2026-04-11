package imessage

import (
	"errors"
	"testing"
)

func TestTapbackFromEmoji(t *testing.T) {
	tests := []struct {
		emoji string
		want  TapbackType
	}{
		{"❤", TapbackLove},
		{"♥", TapbackLove},
		{"💙", TapbackLove},
		{"💚", TapbackLove},
		{"🤎", TapbackLove},
		{"🖤", TapbackLove},
		{"🤍", TapbackLove},
		{"🧡", TapbackLove},
		{"💛", TapbackLove},
		{"💜", TapbackLove},
		{"💖", TapbackLove},
		{"❣", TapbackLove},
		{"💕", TapbackLove},
		{"💟", TapbackLove},
		{"👍", TapbackLike},
		{"👎", TapbackDislike},
		{"😂", TapbackLaugh},
		{"😹", TapbackLaugh},
		{"😆", TapbackLaugh},
		{"🤣", TapbackLaugh},
		{"❕", TapbackEmphasis},
		{"❗", TapbackEmphasis},
		{"‼", TapbackEmphasis},
		{"❓", TapbackQuestion},
		{"❔", TapbackQuestion},
		{"🎉", 0}, // unknown emoji
	}
	for _, tt := range tests {
		t.Run(tt.emoji, func(t *testing.T) {
			got := TapbackFromEmoji(tt.emoji)
			if got != tt.want {
				t.Errorf("TapbackFromEmoji(%q) = %d, want %d", tt.emoji, got, tt.want)
			}
		})
	}
}

func TestTapbackFromName(t *testing.T) {
	tests := []struct {
		name string
		want TapbackType
	}{
		{"love", TapbackLove},
		{"like", TapbackLike},
		{"dislike", TapbackDislike},
		{"laugh", TapbackLaugh},
		{"emphasize", TapbackEmphasis},
		{"question", TapbackQuestion},
		{"unknown", 0},
		{"", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TapbackFromName(tt.name)
			if got != tt.want {
				t.Errorf("TapbackFromName(%q) = %d, want %d", tt.name, got, tt.want)
			}
		})
	}
}

func TestTapbackType_Emoji(t *testing.T) {
	tests := []struct {
		typ  TapbackType
		want string
	}{
		{0, ""},
		{TapbackLove, "\u2764\ufe0f"},
		{TapbackLike, "\U0001f44d\ufe0f"},
		{TapbackDislike, "\U0001f44e\ufe0f"},
		{TapbackLaugh, "\U0001f602"},
		{TapbackEmphasis, "\u203c\ufe0f"},
		{TapbackQuestion, "\u2753\ufe0f"},
		{TapbackType(9999), "\ufffd"},
	}
	for _, tt := range tests {
		got := tt.typ.Emoji()
		if got != tt.want {
			t.Errorf("TapbackType(%d).Emoji() = %q, want %q", tt.typ, got, tt.want)
		}
	}
}

func TestTapbackType_String(t *testing.T) {
	// String() delegates to Emoji()
	if TapbackLove.String() != TapbackLove.Emoji() {
		t.Errorf("String() != Emoji()")
	}
}

func TestTapbackType_Name(t *testing.T) {
	tests := []struct {
		typ  TapbackType
		want string
	}{
		{0, ""},
		{TapbackLove, "love"},
		{TapbackLike, "like"},
		{TapbackDislike, "dislike"},
		{TapbackLaugh, "laugh"},
		{TapbackEmphasis, "emphasize"},
		{TapbackQuestion, "question"},
		{TapbackType(9999), ""},
	}
	for _, tt := range tests {
		got := tt.typ.Name()
		if got != tt.want {
			t.Errorf("TapbackType(%d).Name() = %q, want %q", tt.typ, got, tt.want)
		}
	}
}

func TestTapbackConstants(t *testing.T) {
	if TapbackLove != 2000 {
		t.Errorf("TapbackLove = %d, want 2000", TapbackLove)
	}
	if TapbackLike != 2001 {
		t.Errorf("TapbackLike = %d, want 2001", TapbackLike)
	}
	if TapbackDislike != 2002 {
		t.Errorf("TapbackDislike = %d, want 2002", TapbackDislike)
	}
	if TapbackLaugh != 2003 {
		t.Errorf("TapbackLaugh = %d, want 2003", TapbackLaugh)
	}
	if TapbackEmphasis != 2004 {
		t.Errorf("TapbackEmphasis = %d, want 2004", TapbackEmphasis)
	}
	if TapbackQuestion != 2005 {
		t.Errorf("TapbackQuestion = %d, want 2005", TapbackQuestion)
	}
	if TapbackRemoveOffset != 1000 {
		t.Errorf("TapbackRemoveOffset = %d, want 1000", TapbackRemoveOffset)
	}
}

func TestTapback_Parse_BPPrefix(t *testing.T) {
	tb := &Tapback{
		TargetGUID: "bp:some-guid-1234",
		Type:       TapbackLove,
	}
	result, err := tb.Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TargetGUID != "some-guid-1234" {
		t.Errorf("TargetGUID = %q, want %q", result.TargetGUID, "some-guid-1234")
	}
	if result.Remove {
		t.Error("Remove should be false")
	}
	if result.TargetPart != 0 {
		t.Errorf("TargetPart = %d, want 0", result.TargetPart)
	}
}

func TestTapback_Parse_PPrefix(t *testing.T) {
	tb := &Tapback{
		TargetGUID: "p:3/some-guid-5678",
		Type:       TapbackLaugh,
	}
	result, err := tb.Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TargetGUID != "some-guid-5678" {
		t.Errorf("TargetGUID = %q, want %q", result.TargetGUID, "some-guid-5678")
	}
	if result.TargetPart != 3 {
		t.Errorf("TargetPart = %d, want 3", result.TargetPart)
	}
}

func TestTapback_Parse_RemoveFlag(t *testing.T) {
	// 3001 = TapbackLike + TapbackRemoveOffset
	tb := &Tapback{
		TargetGUID: "bp:guid-remove",
		Type:       TapbackType(3001),
	}
	result, err := tb.Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Remove {
		t.Error("Remove should be true for type 3001")
	}
	if result.Type != TapbackLike {
		t.Errorf("Type = %d, want %d (TapbackLike)", result.Type, TapbackLike)
	}
}

func TestTapback_Parse_RemoveBoundary(t *testing.T) {
	// Type 3999 should trigger remove
	tb := &Tapback{
		TargetGUID: "bp:guid",
		Type:       TapbackType(3999),
	}
	result, err := tb.Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Remove {
		t.Error("Remove should be true for type 3999")
	}

	// Type 4000 should NOT trigger remove
	tb2 := &Tapback{
		TargetGUID: "bp:guid",
		Type:       TapbackType(4000),
	}
	result2, err := tb2.Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result2.Remove {
		t.Error("Remove should be false for type 4000")
	}
}

func TestTapback_Parse_InvalidPFormat(t *testing.T) {
	// p: prefix with wrong number of parts (no slash)
	tb := &Tapback{
		TargetGUID: "p:guid-no-slash",
		Type:       TapbackLove,
	}
	_, err := tb.Parse()
	if !errors.Is(err, ErrUnknownNormalTapbackTarget) {
		t.Errorf("expected ErrUnknownNormalTapbackTarget, got: %v", err)
	}
}

func TestTapback_Parse_InvalidPartIndex(t *testing.T) {
	// p: prefix with non-numeric part index
	tb := &Tapback{
		TargetGUID: "p:abc/guid-1234",
		Type:       TapbackLove,
	}
	_, err := tb.Parse()
	if !errors.Is(err, ErrInvalidTapbackTargetPart) {
		t.Errorf("expected ErrInvalidTapbackTargetPart, got: %v", err)
	}
}

func TestTapback_Parse_UnknownTargetType(t *testing.T) {
	// Neither bp: nor p: prefix
	tb := &Tapback{
		TargetGUID: "unknown:guid-1234",
		Type:       TapbackLove,
	}
	_, err := tb.Parse()
	if !errors.Is(err, ErrUnknownTapbackTargetType) {
		t.Errorf("expected ErrUnknownTapbackTargetType, got: %v", err)
	}
}

func TestTapbackRoundTrip(t *testing.T) {
	names := []string{"love", "like", "dislike", "laugh", "emphasize", "question"}
	for _, name := range names {
		typ := TapbackFromName(name)
		if typ == 0 {
			t.Fatalf("TapbackFromName(%q) returned 0", name)
		}
		gotName := typ.Name()
		if gotName != name {
			t.Errorf("round-trip failed: TapbackFromName(%q).Name() = %q", name, gotName)
		}
	}
}
