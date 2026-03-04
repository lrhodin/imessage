// mautrix-imessage - A Matrix-iMessage puppeting bridge.
// Copyright (C) 2024 Ludvig Rhodin
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package connector

import (
	"go.mau.fi/util/ffmpeg"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/event"
)

func supportedIfFFmpeg() event.CapabilitySupportLevel {
	if ffmpeg.Supported() {
		return event.CapLevelPartialSupport
	}
	return event.CapLevelRejected
}

const iMessageMaxFileSize = 2000 * 1024 * 1024 // 2 GB

var caps = &event.RoomFeatures{
	ID: "fi.mau.imessage.capabilities.2025_03",

	Formatting: map[event.FormattingFeature]event.CapabilitySupportLevel{
		event.FmtBold:   event.CapLevelDropped,
		event.FmtItalic: event.CapLevelDropped,
	},
	File: map[event.CapabilityMsgType]*event.FileFeatures{
		event.MsgImage: {
			MimeTypes: map[string]event.CapabilitySupportLevel{
				"image/jpeg": event.CapLevelFullySupported,
				"image/png":  event.CapLevelFullySupported,
				"image/gif":  event.CapLevelFullySupported,
				"image/heic": event.CapLevelFullySupported,
				"image/heif": event.CapLevelFullySupported,
				"image/webp": event.CapLevelFullySupported,
				"image/tiff": event.CapLevelFullySupported,
				"image/bmp":  event.CapLevelFullySupported,
				"image/avif": event.CapLevelFullySupported,
			},
			Caption: event.CapLevelDropped,
			MaxSize: iMessageMaxFileSize,
		},
		event.CapMsgGIF: {
			MimeTypes: map[string]event.CapabilitySupportLevel{
				"image/gif": event.CapLevelFullySupported,
			},
			Caption: event.CapLevelDropped,
			MaxSize: iMessageMaxFileSize,
		},
		event.MsgVideo: {
			MimeTypes: map[string]event.CapabilitySupportLevel{
				"video/mp4":       event.CapLevelFullySupported,
				"video/quicktime": supportedIfFFmpeg(),
				"video/x-m4v":    event.CapLevelFullySupported,
				"video/3gpp":     event.CapLevelPartialSupport,
			},
			Caption: event.CapLevelDropped,
			MaxSize: iMessageMaxFileSize,
		},
		event.MsgAudio: {
			MimeTypes: map[string]event.CapabilitySupportLevel{
				"audio/mpeg":   event.CapLevelFullySupported,
				"audio/mp3":    event.CapLevelFullySupported,
				"audio/aac":    event.CapLevelFullySupported,
				"audio/mp4":    event.CapLevelFullySupported,
				"audio/x-caf":  event.CapLevelFullySupported,
				"audio/ogg":    event.CapLevelFullySupported,
				"audio/wav":    event.CapLevelFullySupported,
				"audio/x-wav":  event.CapLevelFullySupported,
				"audio/aiff":   event.CapLevelFullySupported,
				"audio/x-aiff": event.CapLevelFullySupported,
				"audio/x-m4a":  event.CapLevelFullySupported,
			},
			Caption: event.CapLevelDropped,
			MaxSize: iMessageMaxFileSize,
		},
		event.CapMsgVoice: {
			MimeTypes: map[string]event.CapabilitySupportLevel{
				"audio/ogg":   event.CapLevelFullySupported,
				"audio/x-caf": event.CapLevelFullySupported,
				"audio/aac":   event.CapLevelFullySupported,
				"audio/mp4":   event.CapLevelFullySupported,
			},
			Caption: event.CapLevelDropped,
			MaxSize: iMessageMaxFileSize,
		},
		event.MsgFile: {
			MimeTypes: map[string]event.CapabilitySupportLevel{
				"*/*": event.CapLevelFullySupported,
			},
			Caption: event.CapLevelDropped,
			MaxSize: iMessageMaxFileSize,
		},
	},
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
	capsDM.ID = "fi.mau.imessage.capabilities.2025_03+dm"
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
