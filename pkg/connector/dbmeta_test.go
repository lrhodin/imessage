package connector

import (
	"encoding/json"
	"testing"
)

func TestGetDBMetaTypes(t *testing.T) {
	c := &IMConnector{}
	mt := c.GetDBMetaTypes()

	if mt.Portal == nil {
		t.Fatal("Portal factory should not be nil")
	}
	if mt.Ghost == nil {
		t.Fatal("Ghost factory should not be nil")
	}
	if mt.Message == nil {
		t.Fatal("Message factory should not be nil")
	}
	if mt.UserLogin == nil {
		t.Fatal("UserLogin factory should not be nil")
	}
	if mt.Reaction != nil {
		t.Error("Reaction factory should be nil")
	}

	// Verify types
	if _, ok := mt.Portal().(*PortalMetadata); !ok {
		t.Error("Portal() should return *PortalMetadata")
	}
	if _, ok := mt.Ghost().(*GhostMetadata); !ok {
		t.Error("Ghost() should return *GhostMetadata")
	}
	if _, ok := mt.Message().(*MessageMetadata); !ok {
		t.Error("Message() should return *MessageMetadata")
	}
	if _, ok := mt.UserLogin().(*UserLoginMetadata); !ok {
		t.Error("UserLogin() should return *UserLoginMetadata")
	}
}

func TestPortalMetadata_JSON(t *testing.T) {
	pm := &PortalMetadata{
		ThreadID:     "thread-123",
		SenderGuid:   "sender-456",
		GroupName:    "My Group",
	}
	data, err := json.Marshal(pm)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var pm2 PortalMetadata
	if err := json.Unmarshal(data, &pm2); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if pm2 != *pm {
		t.Errorf("round-trip mismatch: got %+v, want %+v", pm2, *pm)
	}
}

func TestMessageMetadata_JSON(t *testing.T) {
	mm := &MessageMetadata{HasAttachments: true}
	data, err := json.Marshal(mm)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var mm2 MessageMetadata
	if err := json.Unmarshal(data, &mm2); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if mm2.HasAttachments != true {
		t.Error("HasAttachments should be true")
	}
}

func TestUserLoginMetadata_JSON(t *testing.T) {
	ulm := &UserLoginMetadata{
		Platform:        "darwin",
		ChatsSynced:     true,
		PreferredHandle: "tel:+15551234567",
		HardwareKey:     "base64stuff",
	}
	data, err := json.Marshal(ulm)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var ulm2 UserLoginMetadata
	if err := json.Unmarshal(data, &ulm2); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if ulm2.Platform != "darwin" {
		t.Errorf("Platform = %q, want %q", ulm2.Platform, "darwin")
	}
	if ulm2.PreferredHandle != "tel:+15551234567" {
		t.Errorf("PreferredHandle = %q, want %q", ulm2.PreferredHandle, "tel:+15551234567")
	}
}

func TestGhostMetadata_JSON(t *testing.T) {
	gm := &GhostMetadata{}
	data, err := json.Marshal(gm)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	var gm2 GhostMetadata
	if err := json.Unmarshal(data, &gm2); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
}

func TestPortalMetadata_OmitEmpty(t *testing.T) {
	pm := &PortalMetadata{}
	data, err := json.Marshal(pm)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	// Empty struct should marshal to "{}" since all fields are omitempty
	if string(data) != "{}" {
		t.Errorf("empty PortalMetadata marshaled to %s, want {}", string(data))
	}
}
