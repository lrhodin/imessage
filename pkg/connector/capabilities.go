// mautrix-imessage - A Matrix-iMessage puppeting bridge.
// Copyright (C) 2024 Ludvig Rhodin
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package connector

import (
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/event"
)

var caps = &event.RoomFeatures{
	ID: "fi.mau.imessage.capabilities.2025_02",

	Formatting: map[event.FormattingFeature]event.CapabilitySupportLevel{
		event.FmtBold:   event.CapLevelDropped,
		event.FmtItalic: event.CapLevelDropped,
	},
	File: map[event.CapabilityMsgType]*event.FileFeatures{
		event.MsgImage: {
			MimeTypes: map[string]event.CapabilitySupportLevel{
				"*/*": event.CapLevelFullySupported,
			},
		},
		event.CapMsgGIF: {
			MimeTypes: map[string]event.CapabilitySupportLevel{
				"image/gif": event.CapLevelFullySupported,
			},
		},
		event.MsgVideo: {
			MimeTypes: map[string]event.CapabilitySupportLevel{
				"*/*": event.CapLevelFullySupported,
			},
		},
		event.MsgAudio: {
			MimeTypes: map[string]event.CapabilitySupportLevel{
				"*/*": event.CapLevelFullySupported,
			},
		},
		event.CapMsgVoice: {
			MimeTypes: map[string]event.CapabilitySupportLevel{
				"*/*": event.CapLevelFullySupported,
			},
		},
		event.MsgFile: {
			MimeTypes: map[string]event.CapabilitySupportLevel{
				"*/*": event.CapLevelFullySupported,
			},
		},
	},
	MaxTextLength:       0,
	Reply:               event.CapLevelFullySupported,
	Edit:                event.CapLevelFullySupported,
	Delete:              event.CapLevelFullySupported,
	DeleteChat:          true,
	Reaction:            event.CapLevelFullySupported,
	ReactionCount:       1,
	ReadReceipts:        true,
	TypingNotifications: true,
}

var capsDM *event.RoomFeatures

func init() {
	c := *caps
	capsDM = &c
	capsDM.ID = "fi.mau.imessage.capabilities.2025_02+dm"
}

var generalCaps = &bridgev2.NetworkGeneralCapabilities{
	DisappearingMessages: false,
	AggressiveUpdateInfo: true,
}

func (c *IMConnector) GetCapabilities() *bridgev2.NetworkGeneralCapabilities {
	return generalCaps
}

func (c *IMConnector) GetBridgeInfoVersion() (info, capabilities int) {
	return 1, 1
}
