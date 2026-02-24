// mautrix-imessage - A Matrix-iMessage puppeting bridge.
// Copyright (C) 2024 Ludvig Rhodin
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package connector

import (
	"maunium.net/go/mautrix/bridgev2/database"
)

type PortalMetadata struct {
	ThreadID   string `json:"thread_id,omitempty"`
	SenderGuid string `json:"sender_guid,omitempty"` // Persistent iMessage group UUID
	GroupName  string `json:"group_name,omitempty"`   // iMessage cv_name for outbound routing
}

type GhostMetadata struct{}

type MessageMetadata struct {
	HasAttachments bool `json:"has_attachments,omitempty"`
}

type UserLoginMetadata struct {
	Platform    string `json:"platform,omitempty"`
	ChatsSynced bool   `json:"chats_synced,omitempty"`

	// Persisted rustpush state (restored across restarts)
	APSState    string `json:"aps_state,omitempty"`
	IDSUsers    string `json:"ids_users,omitempty"`
	IDSIdentity string `json:"ids_identity,omitempty"`
	DeviceID    string `json:"device_id,omitempty"`

	// Hardware key for cross-platform (non-macOS) operation.
	// Base64-encoded JSON HardwareConfig extracted from a real Mac.
	// Copied at login time and paired to user's login — must not be changed after setup.
	HardwareKey string `json:"hardware_key,omitempty"`

	// CloudKitBackfill records whether this user opted in to CloudKit message
	// history backfill during login. Requires the server to have cloudkit_backfill
	// enabled. Set once at login time and not changed afterwards.
	CloudKitBackfill bool `json:"cloudkit_backfill,omitempty"`

	// PreferredHandle is the user-chosen handle for outgoing messages
	// (e.g. "tel:+15551234567" or "mailto:user@example.com").
	PreferredHandle string `json:"preferred_handle,omitempty"`

	// iCloud account persist data for TokenProvider restoration.
	// Allows CardDAV contacts and CloudKit to work across restarts.
	AccountUsername          string `json:"account_username,omitempty"`
	AccountHashedPasswordHex string `json:"account_hashed_password_hex,omitempty"`
	AccountPET               string `json:"account_pet,omitempty"`
	AccountADSID             string `json:"account_adsid,omitempty"`
	AccountDSID              string `json:"account_dsid,omitempty"`
	AccountSPDBase64         string `json:"account_spd_base64,omitempty"`

	// Cached MobileMe delegate JSON — seeded on restore so contacts work
	// without needing to refresh (which requires a still-valid PET).
	MmeDelegateJSON string `json:"mme_delegate_json,omitempty"`

	// External CardDAV contact sync — set via the !im carddav command.
	// When configured, this overrides iCloud contacts for this user.
	CardDAVEmail             string `json:"carddav_email,omitempty"`
	CardDAVURL               string `json:"carddav_url,omitempty"`
	CardDAVUsername          string `json:"carddav_username,omitempty"`
	CardDAVPasswordEncrypted string `json:"carddav_password_encrypted,omitempty"`
}

// CardDAVIsConfigured returns true if external CardDAV credentials are stored
// for this user login.
func (m *UserLoginMetadata) CardDAVIsConfigured() bool {
	return m.CardDAVEmail != "" && m.CardDAVPasswordEncrypted != ""
}

// GetCardDAVConfig builds a CardDAVConfig from the stored login metadata.
func (m *UserLoginMetadata) GetCardDAVConfig() CardDAVConfig {
	return CardDAVConfig{
		Email:             m.CardDAVEmail,
		URL:               m.CardDAVURL,
		Username:          m.CardDAVUsername,
		PasswordEncrypted: m.CardDAVPasswordEncrypted,
	}
}

func (c *IMConnector) GetDBMetaTypes() database.MetaTypes {
	return database.MetaTypes{
		Portal: func() any {
			return &PortalMetadata{}
		},
		Ghost: func() any {
			return &GhostMetadata{}
		},
		Message: func() any {
			return &MessageMetadata{}
		},
		Reaction: nil,
		UserLogin: func() any {
			return &UserLoginMetadata{}
		},
	}
}
