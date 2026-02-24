// mautrix-imessage - A Matrix-iMessage puppeting bridge.
// Copyright (C) 2024 Ludvig Rhodin
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package connector

import (
	"context"
	"fmt"
	"math"
	"runtime"
	"time"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"

	"github.com/lrhodin/imessage/pkg/rustpushgo"
)

func isRunningOnMacOS() bool {
	return runtime.GOOS == "darwin"
}

type IMConnector struct {
	Bridge *bridgev2.Bridge
	Config IMConfig

	// BridgeSecret is the HMAC key used to derive per-user CardDAV encryption
	// keys. Set from the AS token in main.go's PostInit hook.
	BridgeSecret string
}

var _ bridgev2.NetworkConnector = (*IMConnector)(nil)

func (c *IMConnector) GetName() bridgev2.BridgeName {
	return bridgev2.BridgeName{
		DisplayName:      "iMessage",
		NetworkURL:       "https://support.apple.com/messages",
		NetworkIcon:      "mxc://maunium.net/tManJEpANASZvDVzvRvhILdl",
		NetworkID:        "imessage",
		BeeperBridgeType: "imessagego",
		DefaultPort:      29332,
	}
}

func (c *IMConnector) Init(bridge *bridgev2.Bridge) {
	c.Bridge = bridge
}

func (c *IMConnector) Start(ctx context.Context) error {
	// Override backfill defaults for iMessage CloudKit sync.
	// Applied in Start() because Init() runs before config YAML is loaded.
	// Only apply when CloudKit backfill is enabled — otherwise leave the
	// mautrix defaults alone (backfill won't be used).
	if c.Config.CloudKitBackfill {
		// The mautrix defaults (max_initial_messages=50, batch_size=100) are too
		// low — CloudKit chats can have tens of thousands of messages, and many
		// small backward batch_send requests create fragmented DAG branches that
		// clients can't paginate through. High max_initial_messages ensures all
		// messages are delivered in one forward batch during room creation.
		cfg := &c.Bridge.Config.Backfill
		if !cfg.Enabled {
			cfg.Enabled = true
		}
		if cfg.MaxInitialMessages < 100 {
			cfg.MaxInitialMessages = math.MaxInt32 // uncapped — backfill everything CloudKit downloaded
		}
		// Catchup should match the initial cap — unlimited when uncapped,
		// capped when the user caps max_initial_messages.
		cfg.MaxCatchupMessages = cfg.MaxInitialMessages
		if !cfg.Queue.Enabled {
			cfg.Queue.Enabled = true
		}
		if cfg.Queue.BatchSize <= 100 {
			cfg.Queue.BatchSize = 10000
		}
		if cfg.MaxInitialMessages < math.MaxInt32 {
			// User explicitly capped initial messages — disable backward
			// backfill so the cap is the final word on message count.
			cfg.Queue.MaxBatches = 0
		} else if cfg.Queue.MaxBatches == 0 {
			cfg.Queue.MaxBatches = -1
		}
	}

	return nil
}

func (c *IMConnector) GetLoginFlows() []bridgev2.LoginFlow {
	flows := []bridgev2.LoginFlow{}
	if isRunningOnMacOS() {
		flows = append(flows, bridgev2.LoginFlow{
			Name:        "Apple ID",
			Description: "Log in with your Apple ID to send and receive iMessages",
			ID:          LoginFlowIDAppleID,
		})
	}
	flows = append(flows, bridgev2.LoginFlow{
		Name:        "Apple ID (External Key)",
		Description: "Log in using a hardware key extracted from a Mac. Works on any platform.",
		ID:          LoginFlowIDExternalKey,
	})
	return flows
}

func (c *IMConnector) CreateLogin(ctx context.Context, user *bridgev2.User, flowID string) (bridgev2.LoginProcess, error) {
	switch flowID {
	case LoginFlowIDAppleID:
		if !isRunningOnMacOS() {
			return nil, fmt.Errorf("Apple ID login requires macOS. Use 'External Key' login on other platforms.")
		}
		return &AppleIDLogin{User: user, Main: c}, nil
	case LoginFlowIDExternalKey:
		return &ExternalKeyLogin{User: user, Main: c}, nil
	default:
		return nil, fmt.Errorf("unknown login flow: %s", flowID)
	}
}

func (c *IMConnector) LoadUserLogin(ctx context.Context, login *bridgev2.UserLogin) error {
	meta := login.Metadata.(*UserLoginMetadata)

	rustpushgo.InitLogger()

	var cfg *rustpushgo.WrappedOsConfig
	var err error

	if meta.HardwareKey != "" {
		// Cross-platform mode: use hardware key with open-absinthe NAC emulation.
		if meta.DeviceID != "" {
			cfg, err = rustpushgo.CreateConfigFromHardwareKeyWithDeviceId(meta.HardwareKey, meta.DeviceID)
		} else {
			cfg, err = rustpushgo.CreateConfigFromHardwareKey(meta.HardwareKey)
		}
	} else if isRunningOnMacOS() {
		// Local macOS mode: use IOKit + AAAbsintheContext.
		if meta.DeviceID != "" {
			cfg, err = rustpushgo.CreateLocalMacosConfigWithDeviceId(meta.DeviceID)
		} else {
			cfg, err = rustpushgo.CreateLocalMacosConfig()
		}
	} else {
		return fmt.Errorf("no hardware key configured and not running on macOS — re-login with 'External Key' flow")
	}
	if err != nil {
		return fmt.Errorf("failed to create config: %w", err)
	}

	usersStr := &meta.IDSUsers
	identityStr := &meta.IDSIdentity
	apsStateStr := &meta.APSState

	client := &IMClient{
		Main:               c,
		UserLogin:          login,
		config:             cfg,
		users:              rustpushgo.NewWrappedIdsUsers(usersStr),
		identity:           rustpushgo.NewWrappedIdsngmIdentity(identityStr),
		connection:         rustpushgo.Connect(cfg, rustpushgo.NewWrappedApsState(apsStateStr)),
		contactsReady:      false,
		contactsReadyCh:    make(chan struct{}),
		cloudStore:         newCloudBackfillStore(c.Bridge.DB.Database, login.ID),
		recentUnsends:         make(map[string]time.Time),
		recentOutboundUnsends: make(map[string]time.Time),
		smsPortals:            make(map[string]bool),
		imGroupNames:        make(map[string]string),
		imGroupGuids:        make(map[string]string),
		imGroupParticipants: make(map[string][]string),
		gidAliases:          make(map[string]string),
		lastGroupForMember:  make(map[string]networkid.PortalKey),
		forwardBackfillSem: make(chan struct{}, 3),
	}

	login.Client = client
	return nil
}
