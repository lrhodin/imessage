// mautrix-imessage - A Matrix-iMessage puppeting bridge.
// Copyright (C) 2024 Ludvig Rhodin
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package connector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image"
	"image/jpeg"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	_ "image/gif"
	_ "image/png"

	_ "golang.org/x/image/tiff"

	"github.com/rs/zerolog"
	"go.mau.fi/util/ptr"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/simplevent"
	"maunium.net/go/mautrix/bridgev2/status"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/lrhodin/imessage/imessage"
	"github.com/lrhodin/imessage/pkg/rustpushgo"
)

// IMClient implements bridgev2.NetworkAPI using the rustpush iMessage protocol
// library for real-time messaging. Contact resolution uses iCloud CardDAV.
type IMClient struct {
	Main      *IMConnector
	UserLogin *bridgev2.UserLogin

	// Rustpush (primary — real-time send/receive)
	client     *rustpushgo.Client
	config     *rustpushgo.WrappedOsConfig
	users      *rustpushgo.WrappedIdsUsers
	identity   *rustpushgo.WrappedIdsngmIdentity
	connection *rustpushgo.WrappedApsConnection
	handle     string   // Primary iMessage handle used for sending (e.g., tel:+1234567890)
	allHandles []string // All registered handles (for IsThisUser checks)

	// iCloud token provider (auth for CardDAV, CloudKit, etc.)
	tokenProvider **rustpushgo.WrappedTokenProvider

	// Cloud contacts (iCloud CardDAV)
	cloudContacts *cloudContactsClient

	// Contacts readiness gate for CloudKit message sync.
	contactsReady     bool
	contactsReadyLock sync.RWMutex
	contactsReadyCh   chan struct{}

	// Background goroutine lifecycle
	stopChan chan struct{}

	// Unsend re-delivery suppression
	recentUnsends     map[string]time.Time
	recentUnsendsLock sync.Mutex

	// SMS portal tracking: portal IDs known to be SMS-only contacts
	smsPortals     map[string]bool
	smsPortalsLock sync.RWMutex

	// Group portal fuzzy-matching index: maps each member to the set of
	// group portal IDs containing that member. Lazily populated from DB.
	groupPortalIndex map[string]map[string]bool
	groupPortalMu    sync.RWMutex

	// Actual iMessage group names (cv_name) keyed by portal ID.
	// Populated from incoming messages; used for outbound routing.
	imGroupNames   map[string]string
	imGroupNamesMu sync.RWMutex

	// Persistent iMessage group UUIDs (sender_guid/gid) keyed by portal ID.
	// Populated from incoming messages; used for outbound routing so that
	// Apple Messages recipients match messages to the correct group thread.
	imGroupGuids   map[string]string
	imGroupGuidsMu sync.RWMutex

	// Last active group portal per member. Updated on every incoming group
	// message so typing indicators route to the correct group.
	lastGroupForMember   map[string]networkid.PortalKey
	lastGroupForMemberMu sync.RWMutex

}

var _ bridgev2.NetworkAPI = (*IMClient)(nil)
var _ bridgev2.EditHandlingNetworkAPI = (*IMClient)(nil)
var _ bridgev2.ReactionHandlingNetworkAPI = (*IMClient)(nil)
var _ bridgev2.ReadReceiptHandlingNetworkAPI = (*IMClient)(nil)
var _ bridgev2.TypingHandlingNetworkAPI = (*IMClient)(nil)
var _ bridgev2.IdentifierResolvingNetworkAPI = (*IMClient)(nil)

var _ rustpushgo.MessageCallback = (*IMClient)(nil)
var _ rustpushgo.UpdateUsersCallback = (*IMClient)(nil)

// ============================================================================
// Lifecycle
// ============================================================================

func (c *IMClient) loadSenderGuidsFromDB(log zerolog.Logger) {
	ctx := context.Background()
	portals, err := c.Main.Bridge.GetAllPortalsWithMXID(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to load portals for sender_guid cache")
		return
	}

	loadedGuids := 0
	loadedNames := 0
	for _, portal := range portals {
		if portal.Receiver != c.UserLogin.ID {
			continue // Skip portals for other users
		}
		if meta, ok := portal.Metadata.(*PortalMetadata); ok {
			if meta.SenderGuid != "" {
				c.imGroupGuidsMu.Lock()
				c.imGroupGuids[string(portal.ID)] = meta.SenderGuid
				c.imGroupGuidsMu.Unlock()
				loadedGuids++
			}
			if meta.GroupName != "" {
				c.imGroupNamesMu.Lock()
				c.imGroupNames[string(portal.ID)] = meta.GroupName
				c.imGroupNamesMu.Unlock()
				loadedNames++
			}
		}
	}
	if loadedGuids > 0 {
		log.Info().Int("count", loadedGuids).Msg("Pre-populated sender_guid cache from database")
	}
	if loadedNames > 0 {
		log.Info().Int("count", loadedNames).Msg("Pre-populated group name cache from database")
	}
}

func (c *IMClient) Connect(ctx context.Context) {
	log := c.UserLogin.Log.With().Str("component", "imessage").Logger()
	c.UserLogin.BridgeState.Send(status.BridgeState{StateEvent: status.StateConnecting})

	rustpushgo.InitLogger()

	// Validate that the software keystore still has the signing keys referenced
	// by the saved user state.  If the keystore file was deleted/reset while the
	// bridge DB kept the old state, every IDS operation would fail with
	// "Keystore error Key not found".  Detect this early and ask the user to
	// re-login instead of producing a cryptic send-time error.
	if c.users != nil && !c.users.ValidateKeystore() {
		log.Error().Msg("Keystore keys missing for saved user state — clearing stale login, please re-login")
		meta := c.UserLogin.Metadata.(*UserLoginMetadata)
		meta.IDSUsers = ""
		meta.IDSIdentity = ""
		meta.APSState = ""
		_ = c.UserLogin.Save(ctx)
		c.UserLogin.BridgeState.Send(status.BridgeState{
			StateEvent: status.StateBadCredentials,
			Message:    "Signing keys lost — please re-login to iMessage",
		})
		return
	}

	// Restore token provider from persisted credentials if not already set
	if c.tokenProvider == nil || *c.tokenProvider == nil {
		meta := c.UserLogin.Metadata.(*UserLoginMetadata)
		if meta.AccountUsername != "" && meta.AccountPET != "" && meta.AccountSPDBase64 != "" {
			log.Info().Msg("Restoring iCloud TokenProvider from persisted credentials")
			tp, err := rustpushgo.RestoreTokenProvider(c.config, c.connection,
				meta.AccountUsername, meta.AccountHashedPasswordHex,
				meta.AccountPET, meta.AccountSPDBase64)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to restore TokenProvider — cloud services unavailable")
			} else {
				c.tokenProvider = &tp
				// Don't seed the cached MobileMe delegate — it's likely expired.
				// Instead, let get_mme_token() detect the empty delegate and call
				// refresh_mme(), which triggers the full auto-refresh chain:
				//   expired PET → get_token() → login_email_pass() → fresh PET
				//   → login_apple_delegates() → fresh MobileMe delegate
				log.Info().Msg("TokenProvider restored — MobileMe delegate will be refreshed on first use")
			}
		}
	}

	client, err := rustpushgo.NewClient(c.connection, c.users, c.identity, c.config, c.tokenProvider, c, c)
	if err != nil {
		log.Err(err).Msg("Failed to create rustpush client")
		c.UserLogin.BridgeState.Send(status.BridgeState{
			StateEvent: status.StateBadCredentials,
			Message:    fmt.Sprintf("Failed to connect: %v", err),
		})
		return
	}
	c.client = client

	// Get our handle (precedence: config > login metadata > first handle)
	handles := client.GetHandles()
	c.allHandles = handles
	if len(handles) > 0 {
		c.handle = handles[0]
		preferred := c.Main.Config.PreferredHandle
		if preferred == "" {
			if meta, ok := c.UserLogin.Metadata.(*UserLoginMetadata); ok {
				preferred = meta.PreferredHandle
			}
		}
		if preferred != "" {
			found := false
			for _, h := range handles {
				if h == preferred {
					c.handle = h
					found = true
					break
				}
			}
			if !found {
				log.Warn().Str("preferred", preferred).Strs("available", handles).
					Msg("Preferred handle not found among registered handles, using first available")
			}
		} else {
			log.Warn().Strs("available", handles).
				Msg("No preferred_handle configured — using first available. Run the install script to select one.")
		}
	}

	// Persist the selected handle to metadata so it's stable across restarts.
	if c.handle != "" {
		if meta, ok := c.UserLogin.Metadata.(*UserLoginMetadata); ok && meta.PreferredHandle != c.handle {
			meta.PreferredHandle = c.handle
			log.Info().Str("handle", c.handle).Msg("Persisted selected handle to metadata")
		}
	}

	log.Info().Str("selected_handle", c.handle).Strs("handles", handles).Msg("Connected to iMessage")

	// Persist state after connect (APS tokens, IDS keys, device ID)
	c.persistState(log)

	// Pre-populate sender_guid cache from existing portal metadata
	go c.loadSenderGuidsFromDB(log)

	// Start periodic state saver (every 5 minutes)
	c.stopChan = make(chan struct{})
	go c.periodicStateSave(log)

	c.UserLogin.BridgeState.Send(status.BridgeState{StateEvent: status.StateConnected})

	// Set up contact source: iCloud CardDAV via TokenProvider
	c.cloudContacts = newCloudContactsClient(c.client, log)
	if c.cloudContacts != nil {
		log.Info().Str("url", c.cloudContacts.baseURL).Msg("Cloud contacts available (iCloud CardDAV)")
		if syncErr := c.cloudContacts.SyncContacts(log); syncErr != nil {
			log.Warn().Err(syncErr).Msg("Initial CardDAV sync failed")
		} else {
			c.setContactsReady(log)
			c.persistMmeDelegate(log)
		}
		go c.periodicCloudContactSync(log)
	} else {
		// No cloud contacts available — retry periodically.
		// The MobileMe delegate may have been expired on startup;
		// periodic retries will pick up a fresh delegate once available.
		log.Warn().Msg("Cloud contacts unavailable on startup, will retry periodically")
		go c.retryCloudContacts(log)
	}

}

func (c *IMClient) Disconnect() {
	if c.stopChan != nil {
		close(c.stopChan)
		c.stopChan = nil
	}
	if c.client != nil {
		c.client.Stop()
		c.client.Destroy()
		c.client = nil
	}

}

func (c *IMClient) IsLoggedIn() bool {
	return c.client != nil
}

func (c *IMClient) LogoutRemote(ctx context.Context) {
	c.Disconnect()
}

func (c *IMClient) IsThisUser(_ context.Context, userID networkid.UserID) bool {
	return c.isMyHandle(string(userID))
}

func (c *IMClient) GetCapabilities(ctx context.Context, portal *bridgev2.Portal) *event.RoomFeatures {
	if portal.RoomType == database.RoomTypeDM {
		return capsDM
	}
	return caps
}

// ============================================================================
// Callbacks from rustpush
// ============================================================================

// OnMessage is called by rustpush when a message is received via APNs.
func (c *IMClient) OnMessage(msg rustpushgo.WrappedMessage) {
	log := c.UserLogin.Log.With().
		Str("component", "imessage").
		Str("msg_uuid", msg.Uuid).
		Logger()

	// Send delivery receipt if requested
	if msg.SendDelivered && msg.Sender != nil && !msg.IsDelivered && !msg.IsReadReceipt {
		go func() {
			conv := c.makeConversation(msg.Participants, msg.GroupName)
			if err := c.client.SendDeliveryReceipt(conv, c.handle); err != nil {
				log.Warn().Err(err).Msg("Failed to send delivery receipt")
			}
		}()
	}

	if msg.IsDelivered {
		c.handleDeliveryReceipt(log, msg)
		return
	}

	if msg.IsReadReceipt {
		c.handleReadReceipt(log, msg)
		return
	}
	if msg.IsTyping {
		c.handleTyping(log, msg)
		return
	}
	if msg.IsError {
		log.Warn().
			Str("for_uuid", ptrStringOr(msg.ErrorForUuid, "")).
			Uint64("status", ptrUint64Or(msg.ErrorStatus, 0)).
			Str("status_str", ptrStringOr(msg.ErrorStatusStr, "")).
			Msg("Received iMessage error")
		return
	}
	if msg.IsPeerCacheInvalidate {
		log.Debug().Msg("Peer cache invalidated")
		return
	}
	if msg.IsTapback {
		c.handleTapback(log, msg)
		return
	}
	if msg.IsEdit {
		c.handleEdit(log, msg)
		return
	}
	if msg.IsUnsend {
		c.handleUnsend(log, msg)
		return
	}
	if msg.IsRename {
		c.handleRename(log, msg)
		return
	}
	if msg.IsParticipantChange {
		c.handleParticipantChange(log, msg)
		return
	}

	c.handleMessage(log, msg)
}

// UpdateUsers is called when IDS keys are refreshed.
// NOTE: This callback runs on the Tokio async runtime thread.  We must NOT
// make blocking FFI calls back into Rust (e.g. connection.State()) on this
// thread or the runtime will panic with "Cannot block the current thread
// from within a runtime".  Spawn a goroutine so the callback returns
// immediately and the blocking work happens on a regular OS thread.
func (c *IMClient) UpdateUsers(users *rustpushgo.WrappedIdsUsers) {
	c.users = users

	go func() {
		log := c.UserLogin.Log.With().Str("component", "imessage").Logger()
		// Persist all state (APS tokens, IDS keys, identity, device ID) — not just
		// IDSUsers — so a crash between periodic saves doesn't lose APS state.
		c.persistState(log)
		log.Debug().Msg("IDS users updated, full state persisted")
	}()
}

// ============================================================================
// Incoming message handlers
// ============================================================================

func (c *IMClient) handleMessage(log zerolog.Logger, msg rustpushgo.WrappedMessage) {
	if c.wasUnsent(msg.Uuid) {
		log.Debug().Str("uuid", msg.Uuid).Msg("Suppressing re-delivery of unsent message")
		return
	}

	sender := c.makeEventSender(msg.Sender)
	portalKey := c.makePortalKey(msg.Participants, msg.GroupName, msg.Sender, msg.SenderGuid)

	// Track SMS portals so outbound replies use the correct service type
	if msg.IsSms {
		c.markPortalSMS(string(portalKey.ID))
	}

	if msg.Text != nil && *msg.Text != "" && strings.TrimRight(*msg.Text, "\ufffc \n") != "" {
		c.Main.Bridge.QueueRemoteEvent(c.UserLogin, &simplevent.Message[*rustpushgo.WrappedMessage]{
			EventMeta: simplevent.EventMeta{
				Type:         bridgev2.RemoteEventMessage,
				PortalKey:    portalKey,
				CreatePortal: true,
				Sender:       sender,
				Timestamp:    time.UnixMilli(int64(msg.TimestampMs)),
				LogContext: func(lc zerolog.Context) zerolog.Context {
					return lc.Str("msg_uuid", msg.Uuid)
				},
			},
			Data:               &msg,
			ID:                 makeMessageID(msg.Uuid),
			ConvertMessageFunc: convertMessage,
		})
	}

	attIndex := 0
	for _, att := range msg.Attachments {
		// Skip rich link sideband attachments (handled in convertMessage)
		if att.MimeType == "x-richlink/meta" || att.MimeType == "x-richlink/image" {
			continue
		}
		attID := msg.Uuid
		if attIndex > 0 || (msg.Text != nil && *msg.Text != "") {
			attID = fmt.Sprintf("%s_att%d", msg.Uuid, attIndex)
		}
		attMsg := &attachmentMessage{
			WrappedMessage: &msg,
			Attachment:     &att,
			Index:          attIndex,
		}
		attIndex++
		c.Main.Bridge.QueueRemoteEvent(c.UserLogin, &simplevent.Message[*attachmentMessage]{
			EventMeta: simplevent.EventMeta{
				Type:         bridgev2.RemoteEventMessage,
				PortalKey:    portalKey,
				CreatePortal: true,
				Sender:       sender,
				Timestamp:    time.UnixMilli(int64(msg.TimestampMs)),
				LogContext: func(lc zerolog.Context) zerolog.Context {
					return lc.Str("msg_uuid", attID)
				},
			},
			Data:               attMsg,
			ID:                 makeMessageID(attID),
			ConvertMessageFunc: convertAttachment,
		})
	}
}

func (c *IMClient) handleTapback(log zerolog.Logger, msg rustpushgo.WrappedMessage) {
	portalKey := c.makePortalKey(msg.Participants, msg.GroupName, msg.Sender, msg.SenderGuid)
	targetGUID := ptrStringOr(msg.TapbackTargetUuid, "")
	emoji := tapbackTypeToEmoji(msg.TapbackType, msg.TapbackEmoji)

	evtType := bridgev2.RemoteEventReaction
	if msg.TapbackRemove {
		evtType = bridgev2.RemoteEventReactionRemove
	}

	c.Main.Bridge.QueueRemoteEvent(c.UserLogin, &simplevent.Reaction{
		EventMeta: simplevent.EventMeta{
			Type:      evtType,
			PortalKey: portalKey,
			Sender:    c.makeEventSender(msg.Sender),
			Timestamp: time.UnixMilli(int64(msg.TimestampMs)),
		},
		TargetMessage: makeMessageID(targetGUID),
		Emoji:         emoji,
	})
}

func (c *IMClient) handleEdit(log zerolog.Logger, msg rustpushgo.WrappedMessage) {
	portalKey := c.makePortalKey(msg.Participants, msg.GroupName, msg.Sender, msg.SenderGuid)
	targetGUID := ptrStringOr(msg.EditTargetUuid, "")
	newText := ptrStringOr(msg.EditNewText, "")

	c.Main.Bridge.QueueRemoteEvent(c.UserLogin, &simplevent.Message[string]{
		EventMeta: simplevent.EventMeta{
			Type:      bridgev2.RemoteEventEdit,
			PortalKey: portalKey,
			Sender:    c.makeEventSender(msg.Sender),
			Timestamp: time.UnixMilli(int64(msg.TimestampMs)),
		},
		Data:          newText,
		ID:            makeMessageID(msg.Uuid),
		TargetMessage: makeMessageID(targetGUID),
		ConvertEditFunc: func(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, existing []*database.Message, text string) (*bridgev2.ConvertedEdit, error) {
			var targetPart *database.Message
			if len(existing) > 0 {
				targetPart = existing[0]
			}
			return &bridgev2.ConvertedEdit{
				ModifiedParts: []*bridgev2.ConvertedEditPart{{
					Part: targetPart,
					Type: event.EventMessage,
					Content: &event.MessageEventContent{
						MsgType: event.MsgText,
						Body:    text,
					},
				}},
			}, nil
		},
	})
}

func (c *IMClient) handleUnsend(log zerolog.Logger, msg rustpushgo.WrappedMessage) {
	portalKey := c.makePortalKey(msg.Participants, msg.GroupName, msg.Sender, msg.SenderGuid)
	targetGUID := ptrStringOr(msg.UnsendTargetUuid, "")

	c.trackUnsend(targetGUID)

	c.Main.Bridge.QueueRemoteEvent(c.UserLogin, &simplevent.MessageRemove{
		EventMeta: simplevent.EventMeta{
			Type:      bridgev2.RemoteEventMessageRemove,
			PortalKey: portalKey,
			Sender:    c.makeEventSender(msg.Sender),
			Timestamp: time.UnixMilli(int64(msg.TimestampMs)),
		},
		TargetMessage: makeMessageID(targetGUID),
	})
}

func (c *IMClient) handleRename(log zerolog.Logger, msg rustpushgo.WrappedMessage) {
	portalKey := c.makePortalKey(msg.Participants, msg.GroupName, msg.Sender, msg.SenderGuid)
	newName := ptrStringOr(msg.NewChatName, "")

	// Update the cached iMessage group name to the NEW name so outbound
	// messages (portalToConversation) use it. makePortalKey cached whatever
	// was in the conversation envelope (msg.GroupName), which may be the old
	// name. Also persist to portal metadata so it survives restarts.
	if newName != "" {
		portalID := string(portalKey.ID)
		c.imGroupNamesMu.Lock()
		c.imGroupNames[portalID] = newName
		c.imGroupNamesMu.Unlock()

		go func() {
			ctx := context.Background()
			portal, err := c.Main.Bridge.GetExistingPortalByKey(ctx, portalKey)
			if err == nil && portal != nil {
				meta := &PortalMetadata{}
				if existing, ok := portal.Metadata.(*PortalMetadata); ok {
					*meta = *existing
				}
				if meta.GroupName != newName {
					meta.GroupName = newName
					portal.Metadata = meta
					_ = portal.Save(ctx)
				}
			}
		}()
	}

	c.Main.Bridge.QueueRemoteEvent(c.UserLogin, &simplevent.ChatInfoChange{
		EventMeta: simplevent.EventMeta{
			Type:      bridgev2.RemoteEventChatInfoChange,
			PortalKey: portalKey,
			Sender:    c.makeEventSender(msg.Sender),
			Timestamp: time.UnixMilli(int64(msg.TimestampMs)),
		},
		ChatInfoChange: &bridgev2.ChatInfoChange{
			ChatInfo: &bridgev2.ChatInfo{
				Name: &newName,
			},
		},
	})
}

func (c *IMClient) handleParticipantChange(log zerolog.Logger, msg rustpushgo.WrappedMessage) {
	// Resolve the existing portal from the OLD participant list.
	oldPortalKey := c.makePortalKey(msg.Participants, msg.GroupName, msg.Sender, msg.SenderGuid)

	if len(msg.NewParticipants) == 0 {
		// No new participant list — fall back to a resync with current info.
		log.Warn().Msg("Participant change with empty NewParticipants, falling back to resync")
		c.Main.Bridge.QueueRemoteEvent(c.UserLogin, &simplevent.ChatResync{
			EventMeta: simplevent.EventMeta{
				Type:      bridgev2.RemoteEventChatResync,
				PortalKey: oldPortalKey,
			},
			GetChatInfoFunc: c.GetChatInfo,
		})
		return
	}

	// Compute new portal ID from the NEW participant list using the same
	// normalization / dedup / sort logic as makePortalKey's group branch.
	sorted := make([]string, 0, len(msg.NewParticipants))
	for _, p := range msg.NewParticipants {
		normalized := normalizeIdentifierForPortalID(p)
		if normalized == "" || c.isMyHandle(normalized) {
			continue
		}
		sorted = append(sorted, normalized)
	}
	sorted = append(sorted, normalizeIdentifierForPortalID(c.handle))
	sort.Strings(sorted)
	deduped := sorted[:0]
	for i, s := range sorted {
		if i == 0 || s != sorted[i-1] {
			deduped = append(deduped, s)
		}
	}
	newPortalIDStr := strings.Join(deduped, ",")
	oldPortalIDStr := string(oldPortalKey.ID)

	// If the portal ID changed (member added/removed), re-key it in the DB.
	finalPortalKey := oldPortalKey
	if newPortalIDStr != oldPortalIDStr {
		ctx := context.Background()
		newPortalKey := networkid.PortalKey{
			ID:       networkid.PortalID(newPortalIDStr),
			Receiver: c.UserLogin.ID,
		}
		result, _, err := c.reIDPortalWithCacheUpdate(ctx, oldPortalKey, newPortalKey)
		if err != nil {
			log.Err(err).
				Str("old_portal_id", oldPortalIDStr).
				Str("new_portal_id", newPortalIDStr).
				Msg("Failed to ReID portal for participant change")
			return
		}
		log.Info().
			Str("old_portal_id", oldPortalIDStr).
			Str("new_portal_id", newPortalIDStr).
			Int("result", int(result)).
			Msg("ReID portal for participant change")
		finalPortalKey = newPortalKey
	}

	// Cache sender_guid and group_name under the (possibly new) portal ID.
	if msg.SenderGuid != nil && *msg.SenderGuid != "" {
		c.imGroupGuidsMu.Lock()
		c.imGroupGuids[string(finalPortalKey.ID)] = *msg.SenderGuid
		c.imGroupGuidsMu.Unlock()
	}
	if msg.GroupName != nil && *msg.GroupName != "" {
		c.imGroupNamesMu.Lock()
		c.imGroupNames[string(finalPortalKey.ID)] = *msg.GroupName
		c.imGroupNamesMu.Unlock()
	}

	// Build the full new member list for Matrix room sync.
	memberMap := make(map[networkid.UserID]bridgev2.ChatMember, len(msg.NewParticipants))
	for _, p := range msg.NewParticipants {
		normalized := normalizeIdentifierForPortalID(p)
		if normalized == "" {
			continue
		}
		userID := makeUserID(normalized)
		if c.isMyHandle(normalized) {
			memberMap[userID] = bridgev2.ChatMember{
				EventSender: bridgev2.EventSender{
					IsFromMe:    true,
					SenderLogin: c.UserLogin.ID,
					Sender:      userID,
				},
				Membership: event.MembershipJoin,
			}
		} else {
			memberMap[userID] = bridgev2.ChatMember{
				EventSender: bridgev2.EventSender{Sender: userID},
				Membership:  event.MembershipJoin,
			}
		}
	}

	// Queue a ChatInfoChange with the full member list so bridgev2 syncs
	// the Matrix room membership (invites new members, kicks removed ones).
	c.Main.Bridge.QueueRemoteEvent(c.UserLogin, &simplevent.ChatInfoChange{
		EventMeta: simplevent.EventMeta{
			Type:      bridgev2.RemoteEventChatInfoChange,
			PortalKey: finalPortalKey,
			Sender:    c.makeEventSender(msg.Sender),
			Timestamp: time.UnixMilli(int64(msg.TimestampMs)),
		},
		ChatInfoChange: &bridgev2.ChatInfoChange{
			MemberChanges: &bridgev2.ChatMemberList{
				IsFull:    true,
				MemberMap: memberMap,
			},
		},
	})
}

func (c *IMClient) handleReadReceipt(log zerolog.Logger, msg rustpushgo.WrappedMessage) {
	portalKey := c.makeReceiptPortalKey(msg.Participants, msg.GroupName, msg.Sender, msg.SenderGuid)
	ctx := context.Background()

	// UUID lookup FIRST — most reliable for both DM and group receipts.
	// Group read receipts (command 102) arrive without conversation data
	// (aps_client.rs passes None), so makeReceiptPortalKey resolves to a
	// DM portal. The UUID lookup finds the actual portal from the DB.
	if msg.Uuid != "" {
		msgID := makeMessageID(msg.Uuid)
		dbMessages, err := c.Main.Bridge.DB.Message.GetAllPartsByID(ctx, c.UserLogin.ID, msgID)
		if err == nil && len(dbMessages) > 0 {
			portalKey = dbMessages[0].Room
			log.Debug().
				Str("msg_uuid", msg.Uuid).
				Str("resolved_portal", string(portalKey.ID)).
				Msg("Resolved read receipt portal via message UUID lookup")
			goto resolved
		}
	}

	// Try sender_guid lookup — first check gid: portal ID, then cache
	if msg.SenderGuid != nil && *msg.SenderGuid != "" {
		gidPortalKey := networkid.PortalKey{ID: networkid.PortalID("gid:" + *msg.SenderGuid), Receiver: c.UserLogin.ID}
		if gidPortal, _ := c.Main.Bridge.GetExistingPortalByKey(ctx, gidPortalKey); gidPortal != nil && gidPortal.MXID != "" {
			portalKey = gidPortalKey
			log.Debug().
				Str("sender_guid", *msg.SenderGuid).
				Str("resolved_portal", string(portalKey.ID)).
				Msg("Resolved read receipt portal via gid: lookup")
			goto resolved
		}
		c.imGroupGuidsMu.RLock()
		for portalIDStr, guid := range c.imGroupGuids {
			if guid == *msg.SenderGuid {
				portalKey = networkid.PortalKey{ID: networkid.PortalID(portalIDStr), Receiver: c.UserLogin.ID}
				c.imGroupGuidsMu.RUnlock()
				log.Debug().
					Str("sender_guid", *msg.SenderGuid).
					Str("resolved_portal", string(portalKey.ID)).
					Msg("Resolved read receipt portal via sender_guid cache lookup")
				goto resolved
			}
		}
		c.imGroupGuidsMu.RUnlock()
	}

	// Fall back to group member tracking
	if msg.Sender != nil {
		if groupKey, ok := c.findGroupPortalForMember(*msg.Sender); ok {
			portalKey = groupKey
			log.Debug().
				Str("sender", *msg.Sender).
				Str("resolved_portal", string(portalKey.ID)).
				Msg("Resolved read receipt portal via group member lookup")
			goto resolved
		}
	}

	// Last resort: use the initial portal key if it resolves to a valid portal.
	// For DM receipts (no conversation data), makeReceiptPortalKey already
	// resolved to the correct DM portal. For group receipts, this is a wrong
	// guess but we've exhausted all group-specific lookups above.
	{
		portal, _ := c.Main.Bridge.GetExistingPortalByKey(ctx, portalKey)
		if portal != nil && portal.MXID != "" {
			goto resolved
		}
	}
resolved:

	c.Main.Bridge.QueueRemoteEvent(c.UserLogin, &simplevent.Receipt{
		EventMeta: simplevent.EventMeta{
			Type:      bridgev2.RemoteEventReadReceipt,
			PortalKey: portalKey,
			Sender:    c.makeEventSender(msg.Sender),
			Timestamp: time.UnixMilli(int64(msg.TimestampMs)),
		},
		LastTarget: makeMessageID(msg.Uuid),
	})
}

func (c *IMClient) handleDeliveryReceipt(log zerolog.Logger, msg rustpushgo.WrappedMessage) {
	portalKey := c.makeReceiptPortalKey(msg.Participants, msg.GroupName, msg.Sender, msg.SenderGuid)
	ctx := context.Background()

	portal, err := c.Main.Bridge.GetExistingPortalByKey(ctx, portalKey)
	if (err != nil || portal == nil || portal.MXID == "") && msg.Uuid != "" {
		// Group delivery receipts may lack conversation data. Try message UUID lookup.
		msgID := makeMessageID(msg.Uuid)
		if dbMsgs, err2 := c.Main.Bridge.DB.Message.GetAllPartsByID(ctx, c.UserLogin.ID, msgID); err2 == nil && len(dbMsgs) > 0 {
			portalKey = dbMsgs[0].Room
			portal, err = c.Main.Bridge.GetExistingPortalByKey(ctx, portalKey)
		}
	}
	if err != nil || portal == nil || portal.MXID == "" {
		return
	}

	msgID := makeMessageID(msg.Uuid)
	dbMessages, err := c.Main.Bridge.DB.Message.GetAllPartsByID(ctx, portal.Receiver, msgID)
	if err != nil || len(dbMessages) == 0 {
		return
	}

	normalizedSender := normalizeIdentifierForPortalID(ptrStringOr(msg.Sender, ""))
	senderUserID := makeUserID(normalizedSender)
	ghost, err := c.Main.Bridge.GetGhostByID(ctx, senderUserID)
	if err != nil || ghost == nil {
		return
	}

	for _, dbMsg := range dbMessages {
		c.Main.Bridge.Matrix.SendMessageStatus(ctx, &bridgev2.MessageStatus{
			Status:      event.MessageStatusSuccess,
			DeliveredTo: []id.UserID{ghost.Intent.GetMXID()},
		}, &bridgev2.MessageStatusEventInfo{
			RoomID:        portal.MXID,
			SourceEventID: dbMsg.MXID,
			Sender:        dbMsg.SenderMXID,
		})
	}
}

func (c *IMClient) handleTyping(log zerolog.Logger, msg rustpushgo.WrappedMessage) {
	portalKey := c.makePortalKey(msg.Participants, msg.GroupName, msg.Sender, msg.SenderGuid)

	// For group typing indicators, iMessage may only include [sender, target]
	// without the full participant list. If the portal key resolves to a
	// non-existent portal (DM-style key), try sender_guid lookup first.
	ctx := context.Background()
	portal, _ := c.Main.Bridge.GetExistingPortalByKey(ctx, portalKey)
	if (portal == nil || portal.MXID == "") && msg.SenderGuid != nil && *msg.SenderGuid != "" {
		// Try gid: portal ID first
		gidKey := networkid.PortalKey{ID: networkid.PortalID("gid:" + *msg.SenderGuid), Receiver: c.UserLogin.ID}
		if gidPortal, _ := c.Main.Bridge.GetExistingPortalByKey(ctx, gidKey); gidPortal != nil && gidPortal.MXID != "" {
			portalKey = gidKey
			log.Debug().
				Str("sender_guid", *msg.SenderGuid).
				Str("resolved_portal", string(portalKey.ID)).
				Msg("Resolved typing portal via gid: lookup")
			goto found
		}
		// Fall back to cache lookup for legacy portals
		c.imGroupGuidsMu.RLock()
		for portalIDStr, guid := range c.imGroupGuids {
			if guid == *msg.SenderGuid {
				portalKey = networkid.PortalKey{ID: networkid.PortalID(portalIDStr), Receiver: c.UserLogin.ID}
				c.imGroupGuidsMu.RUnlock()
				log.Debug().
					Str("sender_guid", *msg.SenderGuid).
					Str("resolved_portal", string(portalKey.ID)).
					Msg("Resolved typing portal via sender_guid cache lookup")
				goto found
			}
		}
		c.imGroupGuidsMu.RUnlock()
	}
	// Fall back to member tracking
	if (portal == nil || portal.MXID == "") && msg.Sender != nil {
		if groupKey, ok := c.findGroupPortalForMember(*msg.Sender); ok {
			portalKey = groupKey
			log.Debug().
				Str("sender", *msg.Sender).
				Str("resolved_portal", string(portalKey.ID)).
				Msg("Resolved typing portal via group member lookup")
		}
	}
found:

	c.Main.Bridge.QueueRemoteEvent(c.UserLogin, &simplevent.Typing{
		EventMeta: simplevent.EventMeta{
			Type:      bridgev2.RemoteEventTyping,
			PortalKey: portalKey,
			Sender:    c.makeEventSender(msg.Sender),
			Timestamp: time.UnixMilli(int64(msg.TimestampMs)),
		},
		Timeout: 60 * time.Second,
	})
}

// ============================================================================
// Matrix → iMessage
// ============================================================================

// convertURLPreviewToIMessage encodes a Beeper link preview (or auto-detected
// URL) into the sideband text prefix that Rust parses for rich link sending.
// Follows the pattern from mautrix-whatsapp's urlpreview.go.
func (c *IMClient) convertURLPreviewToIMessage(ctx context.Context, content *event.MessageEventContent) string {
	log := zerolog.Ctx(ctx)
	body := content.Body

	// Priority 1: Explicit BeeperLinkPreviews from Matrix
	if len(content.BeeperLinkPreviews) > 0 {
		lp := content.BeeperLinkPreviews[0]
		canonical := lp.CanonicalURL
		if canonical == "" {
			canonical = lp.MatchedURL
		}
		log.Debug().
			Str("matched_url", lp.MatchedURL).
			Str("canonical_url", canonical).
			Str("title", lp.Title).
			Msg("Encoding Beeper link preview for iMessage")
		return "\x00RL\x01" + lp.MatchedURL + "\x01" + canonical + "\x01" + lp.Title + "\x01" + lp.Description + "\x00" + body
	}

	// Priority 2: Auto-detect URL and fetch preview from homeserver
	if detectedURL := urlRegex.FindString(body); detectedURL != "" {
		fetchURL := normalizeURL(detectedURL)
		log.Debug().Str("detected_url", detectedURL).Msg("Auto-detected URL in outbound message, fetching preview")
		title, desc := "", ""
		if mc, ok := c.Main.Bridge.Matrix.(bridgev2.MatrixConnectorWithURLPreviews); ok {
			if lp, err := mc.GetURLPreview(ctx, fetchURL); err == nil && lp != nil {
				title = lp.Title
				desc = lp.Description
				log.Debug().Str("title", title).Str("description", desc).Msg("Got URL preview from homeserver for outbound")
			} else if err != nil {
				log.Debug().Err(err).Msg("Failed to fetch URL preview from homeserver for outbound")
			}
		}
		return "\x00RL\x01" + detectedURL + "\x01" + fetchURL + "\x01" + title + "\x01" + desc + "\x00" + body
	}

	return body
}

func (c *IMClient) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (*bridgev2.MatrixMessageResponse, error) {
	if c.client == nil {
		return nil, bridgev2.ErrNotLoggedIn
	}

	conv := c.portalToConversation(msg.Portal)

	// File/image messages
	if msg.Content.URL != "" || msg.Content.File != nil {
		return c.handleMatrixFile(ctx, msg, conv)
	}

	textToSend := c.convertURLPreviewToIMessage(ctx, msg.Content)

	replyGuid, replyPart := extractReplyInfo(msg.ReplyTo)
	uuid, err := c.client.SendMessage(conv, textToSend, c.handle, replyGuid, replyPart)
	if err != nil {
		return nil, fmt.Errorf("failed to send iMessage: %w", err)
	}

	// If the outbound message has a URL but no link previews from the client,
	// edit the Matrix event to add com.beeper.linkpreviews so Beeper renders them.
	if len(msg.Content.BeeperLinkPreviews) == 0 {
		if detectedURL := urlRegex.FindString(msg.Content.Body); detectedURL != "" {
			go c.addOutboundURLPreview(msg.Event.ID, msg.Portal.MXID, msg.Content.Body, msg.Content.MsgType, detectedURL)
		}
	}

	return &bridgev2.MatrixMessageResponse{
		DB: &database.Message{
			ID:        makeMessageID(uuid),
			SenderID:  makeUserID(c.handle),
			Timestamp: time.Now(),
			Metadata:  &MessageMetadata{},
		},
	}, nil
}

// addOutboundURLPreview edits an outbound Matrix event to add com.beeper.linkpreviews
// so Beeper displays a URL preview for messages sent from the client.
func (c *IMClient) addOutboundURLPreview(eventID id.EventID, roomID id.RoomID, body string, msgType event.MessageType, detectedURL string) {
	log := c.UserLogin.Log.With().
		Str("component", "url_preview").
		Stringer("event_id", eventID).
		Str("detected_url", detectedURL).
		Logger()
	ctx := log.WithContext(context.Background())

	intent := c.UserLogin.User.DoublePuppet(ctx)
	if intent == nil {
		log.Debug().Msg("No double puppet available, skipping outbound URL preview edit")
		return
	}

	preview := fetchURLPreview(ctx, c.Main.Bridge, intent, detectedURL)

	editContent := &event.MessageEventContent{
		MsgType:            msgType,
		Body:               body,
		BeeperLinkPreviews: []*event.BeeperLinkPreview{preview},
	}
	editContent.SetEdit(eventID)

	wrappedContent := &event.Content{Parsed: editContent}
	_, err := intent.SendMessage(ctx, roomID, event.EventMessage, wrappedContent, nil)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to send outbound URL preview edit")
	} else {
		log.Debug().Str("title", preview.Title).Msg("Sent outbound URL preview edit")
	}
}

// fixOutboundImage re-uploads a corrected image to Matrix and edits the
// original event so all Beeper clients (desktop, Android, etc.) see the
// image with the right format, MIME type, and dimensions.
func (c *IMClient) fixOutboundImage(msg *bridgev2.MatrixMessage, data []byte, mimeType, fileName string, width, height int) {
	log := c.UserLogin.Log.With().
		Str("component", "image_fix").
		Stringer("event_id", msg.Event.ID).
		Logger()
	ctx := log.WithContext(context.Background())

	intent := c.UserLogin.User.DoublePuppet(ctx)
	if intent == nil {
		log.Debug().Msg("No double puppet available, skipping outbound image fix")
		return
	}

	url, encFile, err := intent.UploadMedia(ctx, "", data, fileName, mimeType)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to upload corrected image")
		return
	}

	editContent := &event.MessageEventContent{
		MsgType: event.MsgImage,
		Body:    fileName,
		Info: &event.FileInfo{
			MimeType: mimeType,
			Size:     len(data),
			Width:    width,
			Height:   height,
		},
	}
	if encFile != nil {
		editContent.File = encFile
	} else {
		editContent.URL = url
	}
	editContent.SetEdit(msg.Event.ID)

	wrappedContent := &event.Content{Parsed: editContent}
	_, err = intent.SendMessage(ctx, msg.Portal.MXID, event.EventMessage, wrappedContent, nil)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to edit outbound image event")
	} else {
		log.Debug().Str("mime", mimeType).Int("size", len(data)).Msg("Fixed outbound image on Matrix")
	}
}

func (c *IMClient) handleMatrixFile(ctx context.Context, msg *bridgev2.MatrixMessage, conv rustpushgo.WrappedConversation) (*bridgev2.MatrixMessageResponse, error) {
	var data []byte
	var err error
	if msg.Content.File != nil {
		data, err = c.Main.Bridge.Bot.DownloadMedia(ctx, msg.Content.File.URL, msg.Content.File)
	} else {
		data, err = c.Main.Bridge.Bot.DownloadMedia(ctx, msg.Content.URL, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to download media: %w", err)
	}

	fileName := msg.Content.Body
	if fileName == "" {
		fileName = "file"
	}

	mimeType := "application/octet-stream"
	if msg.Content.Info != nil && msg.Content.Info.MimeType != "" {
		mimeType = msg.Content.Info.MimeType
	}

	// Convert OGG Opus voice recordings to CAF Opus for native iMessage playback
	data, mimeType, fileName = convertAudioForIMessage(data, mimeType, fileName)

	// Process outbound images: detect actual format, convert non-JPEG to JPEG,
	// correct MIME type, and edit the Matrix event so all clients see it right.
	var matrixEdited bool
	if looksLikeImage(data) {
		origMime := mimeType
		if mimeType == "image/gif" {
			// GIFs are fine as-is, just detect correct MIME
			if detected := detectImageMIME(data); detected != "" && detected != mimeType {
				mimeType = detected
				fileName = strings.TrimSuffix(fileName, filepath.Ext(fileName)) + ".gif"
			}
		} else if img, _, isJPEG := decodeImageData(data); img != nil {
			if !isJPEG {
				var buf bytes.Buffer
				if encErr := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 95}); encErr == nil {
					data = buf.Bytes()
					mimeType = "image/jpeg"
					fileName = strings.TrimSuffix(fileName, filepath.Ext(fileName)) + ".jpg"
				}
			} else if detected := detectImageMIME(data); detected != "" && detected != mimeType {
				mimeType = detected
				fileName = strings.TrimSuffix(fileName, filepath.Ext(fileName)) + ".jpg"
			}
			// Edit the Matrix event with corrected image so other Beeper clients see it right
			if mimeType != origMime {
				b := img.Bounds()
				go c.fixOutboundImage(msg, data, mimeType, fileName, b.Dx(), b.Dy())
				matrixEdited = true
			}
		} else {
			// Can't decode but fix MIME type at least
			if detected := detectImageMIME(data); detected != "" && detected != mimeType {
				mimeType = detected
				ext := ".bin"
				switch detected {
				case "image/jpeg":
					ext = ".jpg"
				case "image/png":
					ext = ".png"
				case "image/tiff":
					ext = ".tiff"
				}
				fileName = strings.TrimSuffix(fileName, filepath.Ext(fileName)) + ext
			}
		}
	}
	_ = matrixEdited

	replyGuid, replyPart := extractReplyInfo(msg.ReplyTo)
	uuid, err := c.client.SendAttachment(conv, data, mimeType, mimeToUTI(mimeType), fileName, c.handle, replyGuid, replyPart)
	if err != nil {
		return nil, fmt.Errorf("failed to send attachment: %w", err)
	}

	return &bridgev2.MatrixMessageResponse{
		DB: &database.Message{
			ID:        makeMessageID(uuid),
			SenderID:  makeUserID(c.handle),
			Timestamp: time.Now(),
			Metadata:  &MessageMetadata{HasAttachments: true},
		},
	}, nil
}

func (c *IMClient) HandleMatrixTyping(ctx context.Context, msg *bridgev2.MatrixTyping) error {
	if c.client == nil {
		return nil
	}
	conv := c.portalToConversation(msg.Portal)
	return c.client.SendTyping(conv, msg.IsTyping, c.handle)
}

func (c *IMClient) HandleMatrixReadReceipt(ctx context.Context, receipt *bridgev2.MatrixReadReceipt) error {
	if c.client == nil {
		return nil
	}
	conv := c.portalToConversation(receipt.Portal)
	var forUuid *string
	if receipt.ExactMessage != nil {
		uuid := string(receipt.ExactMessage.ID)
		// Strip attachment suffixes like _att0, _att1 — Rust expects a pure UUID
		if idx := strings.Index(uuid, "_att"); idx > 0 {
			uuid = uuid[:idx]
		}
		forUuid = &uuid
	}
	return c.client.SendReadReceipt(conv, c.handle, forUuid)
}

func (c *IMClient) HandleMatrixEdit(ctx context.Context, msg *bridgev2.MatrixEdit) error {
	if c.client == nil {
		return bridgev2.ErrNotLoggedIn
	}

	conv := c.portalToConversation(msg.Portal)
	targetGUID := string(msg.EditTarget.ID)

	_, err := c.client.SendEdit(conv, targetGUID, 0, msg.Content.Body, c.handle)
	if err == nil {
		// Work around mautrix-go bridgev2 not incrementing EditCount before saving.
		msg.EditTarget.EditCount++
	}
	return err
}

func (c *IMClient) HandleMatrixMessageRemove(ctx context.Context, msg *bridgev2.MatrixMessageRemove) error {
	if c.client == nil {
		return bridgev2.ErrNotLoggedIn
	}

	conv := c.portalToConversation(msg.Portal)
	_, err := c.client.SendUnsend(conv, string(msg.TargetMessage.ID), 0, c.handle)
	return err
}

func (c *IMClient) PreHandleMatrixReaction(ctx context.Context, msg *bridgev2.MatrixReaction) (bridgev2.MatrixReactionPreResponse, error) {
	return bridgev2.MatrixReactionPreResponse{
		SenderID: makeUserID(c.handle),
		Emoji:    msg.Content.RelatesTo.Key,
	}, nil
}

func (c *IMClient) HandleMatrixReaction(ctx context.Context, msg *bridgev2.MatrixReaction) (*database.Reaction, error) {
	if c.client == nil {
		return nil, bridgev2.ErrNotLoggedIn
	}

	conv := c.portalToConversation(msg.Portal)
	reaction, emoji := emojiToTapbackType(msg.Content.RelatesTo.Key)

	_, err := c.client.SendTapback(conv, string(msg.TargetMessage.ID), 0, reaction, emoji, false, c.handle)
	if err != nil {
		return nil, fmt.Errorf("failed to send tapback: %w", err)
	}

	return &database.Reaction{
		MessageID: msg.TargetMessage.ID,
		SenderID:  makeUserID(c.handle),
		Emoji:     msg.Content.RelatesTo.Key,
		Metadata:  &MessageMetadata{},
		MXID:      msg.Event.ID,
	}, nil
}

func (c *IMClient) HandleMatrixReactionRemove(ctx context.Context, msg *bridgev2.MatrixReactionRemove) error {
	if c.client == nil {
		return bridgev2.ErrNotLoggedIn
	}

	conv := c.portalToConversation(msg.Portal)
	reaction, emoji := emojiToTapbackType(msg.TargetReaction.Emoji)
	_, err := c.client.SendTapback(conv, string(msg.TargetReaction.MessageID), 0, reaction, emoji, true, c.handle)
	return err
}

// ============================================================================
// Chat & user info
// ============================================================================

func (c *IMClient) GetChatInfo(ctx context.Context, portal *bridgev2.Portal) (*bridgev2.ChatInfo, error) {
	portalID := string(portal.ID)
	// Groups use "gid:<UUID>" portal IDs, or legacy comma-separated participant IDs
	isGroup := strings.HasPrefix(portalID, "gid:") || strings.Contains(portalID, ",")

	chatInfo := &bridgev2.ChatInfo{}

	if isGroup {
		chatInfo.Type = ptr.Ptr(database.RoomTypeDefault)

		// For gid: portals, look up members from cloud_chat table;
		// for legacy comma-separated IDs, parse from the portal ID.
		memberList := c.resolveGroupMembers(ctx, portalID)

		memberMap := make(map[networkid.UserID]bridgev2.ChatMember)
		for _, member := range memberList {
			userID := makeUserID(member)
			if c.isMyHandle(member) {
				memberMap[userID] = bridgev2.ChatMember{
					EventSender: bridgev2.EventSender{
						IsFromMe:    true,
						SenderLogin: c.UserLogin.ID,
						Sender:      userID,
					},
					Membership: event.MembershipJoin,
				}
			} else {
				memberMap[userID] = bridgev2.ChatMember{
					EventSender: bridgev2.EventSender{Sender: userID},
					Membership:  event.MembershipJoin,
				}
			}
		}

		// CloudKit doesn't include the owner in the participant list (it's
		// implied). Always ensure we're in the member map so Beeper knows
		// we belong to this conversation.
		myUserID := makeUserID(c.handle)
		if _, hasSelf := memberMap[myUserID]; !hasSelf {
			memberMap[myUserID] = bridgev2.ChatMember{
				EventSender: bridgev2.EventSender{
					IsFromMe:    true,
					SenderLogin: c.UserLogin.ID,
					Sender:      myUserID,
				},
				Membership: event.MembershipJoin,
			}
		}
		chatInfo.Members = &bridgev2.ChatMemberList{
			IsFull:    true,
			MemberMap: memberMap,
			PowerLevels: &bridgev2.PowerLevelOverrides{
				Invite: ptr.Ptr(95), // Prevent Matrix users from inviting — the bridge manages membership
			},
		}

		groupName := c.resolveGroupName(ctx, portalID)
		chatInfo.Name = &groupName

		// Persist sender_guid to portal metadata for gid: portals.
		// Only persist iMessage protocol-level group names (cv_name) to
		// metadata — NOT auto-generated contact-resolved names — since
		// the metadata GroupName is used for outbound message routing.
		if strings.HasPrefix(portalID, "gid:") {
			gid := strings.TrimPrefix(portalID, "gid:")
			c.imGroupNamesMu.RLock()
			protocolName := c.imGroupNames[portalID]
			c.imGroupNamesMu.RUnlock()
			chatInfo.ExtraUpdates = func(ctx context.Context, p *bridgev2.Portal) bool {
				meta, ok := p.Metadata.(*PortalMetadata)
				if !ok {
					meta = &PortalMetadata{}
				}
				changed := false
				if meta.SenderGuid != gid {
					meta.SenderGuid = gid
					changed = true
				}
				if protocolName != "" && meta.GroupName != protocolName {
					meta.GroupName = protocolName
					changed = true
				}
				if changed {
					p.Metadata = meta
				}
				return changed
			}
		}
	} else {
		chatInfo.Type = ptr.Ptr(database.RoomTypeDM)
		otherUser := makeUserID(portalID)
		members := &bridgev2.ChatMemberList{
			IsFull:      true,
			OtherUserID: otherUser,
			MemberMap: map[networkid.UserID]bridgev2.ChatMember{
				makeUserID(c.handle): {
					EventSender: bridgev2.EventSender{
						IsFromMe:    true,
						SenderLogin: c.UserLogin.ID,
						Sender:      makeUserID(c.handle),
					},
					Membership: event.MembershipJoin,
				},
				otherUser: {
					EventSender: bridgev2.EventSender{Sender: otherUser},
					Membership:  event.MembershipJoin,
				},
			},
		}

		// Don't set an explicit room name for DMs. With private_chat_portal_meta
		// enabled, the framework derives the room name from the ghost's profile
		// display name, which means it auto-updates when contacts are edited.
		chatInfo.Members = members
	}

	return chatInfo, nil
}

func (c *IMClient) GetUserInfo(ctx context.Context, ghost *bridgev2.Ghost) (*bridgev2.UserInfo, error) {
	identifier := string(ghost.ID)
	if identifier == "" {
		return nil, nil
	}

	isBot := false
	ui := &bridgev2.UserInfo{
		IsBot:       &isBot,
		Identifiers: []string{identifier},
	}

	// Try contact info from cloud contacts (iCloud CardDAV)
	localID := stripIdentifierPrefix(identifier)
	var contact *imessage.Contact
	if c.cloudContacts != nil {
		contact, _ = c.cloudContacts.GetContactInfo(localID)
	}

	if contact != nil && contact.HasName() {
		name := c.Main.Config.FormatDisplayname(DisplaynameParams{
			FirstName: contact.FirstName,
			LastName:  contact.LastName,
			Nickname:  contact.Nickname,
			ID:        localID,
		})
		ui.Name = &name
		for _, phone := range contact.Phones {
			ui.Identifiers = append(ui.Identifiers, "tel:"+phone)
		}
		for _, email := range contact.Emails {
			ui.Identifiers = append(ui.Identifiers, "mailto:"+email)
		}
		if len(contact.Avatar) > 0 {
			avatarHash := sha256.Sum256(contact.Avatar)
			avatarData := contact.Avatar // capture for closure
			ui.Avatar = &bridgev2.Avatar{
				ID: networkid.AvatarID(fmt.Sprintf("contact:%s:%s", identifier, hex.EncodeToString(avatarHash[:8]))),
				Get: func(ctx context.Context) ([]byte, error) {
					return avatarData, nil
				},
			}
		}
		return ui, nil
	}

	// Fallback: format from identifier
	name := c.Main.Config.FormatDisplayname(identifierToDisplaynameParams(identifier))
	ui.Name = &name
	return ui, nil
}

func (c *IMClient) ResolveIdentifier(ctx context.Context, identifier string, createChat bool) (*bridgev2.ResolveIdentifierResponse, error) {
	if c.client == nil {
		return nil, bridgev2.ErrNotLoggedIn
	}

	valid := c.client.ValidateTargets([]string{identifier}, c.handle)
	if len(valid) == 0 {
		return nil, fmt.Errorf("user not found on iMessage: %s", identifier)
	}

	userID := makeUserID(identifier)
	portalID := networkid.PortalKey{
		ID:       networkid.PortalID(identifier),
		Receiver: c.UserLogin.ID,
	}

	ghost, err := c.Main.Bridge.GetGhostByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get ghost: %w", err)
	}
	portal, err := c.Main.Bridge.GetPortalByKey(ctx, portalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get portal: %w", err)
	}
	ghostInfo, err := c.GetUserInfo(ctx, ghost)
	if err != nil {
		return nil, err
	}

	return &bridgev2.ResolveIdentifierResponse{
		Ghost:    ghost,
		UserID:   userID,
		UserInfo: ghostInfo,
		Chat: &bridgev2.CreateChatResponse{
			Portal:    portal,
			PortalKey: portalID,
		},
	}, nil
}



// ============================================================================
// State persistence
// ============================================================================

func (c *IMClient) persistState(log zerolog.Logger) {
	meta := c.UserLogin.Metadata.(*UserLoginMetadata)
	if c.connection != nil {
		meta.APSState = c.connection.State().ToString()
	}
	if c.users != nil {
		meta.IDSUsers = c.users.ToString()
	}
	if c.identity != nil {
		meta.IDSIdentity = c.identity.ToString()
	}
	if c.config != nil {
		meta.DeviceID = c.config.GetDeviceId()
	}
	if err := c.UserLogin.Save(context.Background()); err != nil {
		log.Err(err).Msg("Failed to persist state")
	}
}

func (c *IMClient) periodicStateSave(log zerolog.Logger) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.persistState(log)
			log.Debug().Msg("Periodic state save completed")
		case <-c.stopChan:
			c.persistState(log)
			log.Debug().Msg("Final state save on disconnect")
			return
		}
	}
}

// periodicCloudContactSync re-fetches contacts from iCloud CardDAV every 15 minutes.
func (c *IMClient) periodicCloudContactSync(log zerolog.Logger) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := c.cloudContacts.SyncContacts(log); err != nil {
				log.Warn().Err(err).Msg("Periodic CardDAV sync failed")
			} else {
				c.setContactsReady(log)
				c.persistMmeDelegate(log)
			}
		case <-c.stopChan:
			return
		}
	}
}

// persistMmeDelegate saves the current MobileMe delegate to user_login metadata
// so it can be seeded on restore without needing a fresh PET-based auth.
func (c *IMClient) persistMmeDelegate(log zerolog.Logger) {
	if c.tokenProvider == nil || *c.tokenProvider == nil {
		return
	}
	tp := *c.tokenProvider
	delegateJSON, err := tp.GetMmeDelegateJson()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get MobileMe delegate for persistence")
		return
	}
	if delegateJSON == nil || *delegateJSON == "" {
		return
	}
	meta := c.UserLogin.Metadata.(*UserLoginMetadata)
	if meta.MmeDelegateJSON == *delegateJSON {
		return // unchanged
	}
	meta.MmeDelegateJSON = *delegateJSON
	if err = c.UserLogin.Save(context.Background()); err != nil {
		log.Warn().Err(err).Msg("Failed to persist MobileMe delegate")
	} else {
		log.Info().Msg("Persisted MobileMe delegate to user_login metadata")
	}
}

// retryCloudContacts retries the cloud contacts initialization periodically
// when it fails on startup (e.g., expired MobileMe delegate). Once contacts
// succeed, the readiness gate opens and cloud sync begins.
func (c *IMClient) retryCloudContacts(log zerolog.Logger) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			log.Info().Msg("Retrying cloud contacts initialization...")
			c.cloudContacts = newCloudContactsClient(c.client, log)
			if c.cloudContacts != nil {
				if syncErr := c.cloudContacts.SyncContacts(log); syncErr != nil {
					log.Warn().Err(syncErr).Msg("Cloud contacts retry: sync failed")
				} else {
					c.setContactsReady(log)
					c.persistMmeDelegate(log)
					log.Info().Msg("Cloud contacts retry succeeded, starting periodic sync")
					go c.periodicCloudContactSync(log)
					return
				}
			} else {
				log.Warn().Msg("Cloud contacts retry: still unavailable")
			}
		case <-c.stopChan:
			return
		}
	}
}

// ============================================================================
// Contact change watcher
// ============================================================================

// refreshAllGhosts re-resolves contact info for every known ghost and pushes
// any changes (name, avatar, identifiers) to Matrix.
func (c *IMClient) refreshAllGhosts(log zerolog.Logger) {
	ctx := log.WithContext(context.Background())

	// Query all ghost IDs from the bridge database.
	rows, err := c.Main.Bridge.DB.Database.Query(ctx,
		"SELECT id FROM ghost WHERE bridge_id=$1",
		c.Main.Bridge.ID,
	)
	if err != nil {
		log.Err(err).Msg("Contact refresh: failed to query ghost IDs")
		return
	}
	defer rows.Close()
	var ghostIDs []networkid.UserID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			log.Err(err).Msg("Contact refresh: failed to scan ghost ID")
			continue
		}
		ghostIDs = append(ghostIDs, networkid.UserID(id))
	}
	if err := rows.Err(); err != nil {
		log.Err(err).Msg("Contact refresh: row iteration error")
	}

	updated := 0
	for _, ghostID := range ghostIDs {
		ghost, err := c.Main.Bridge.GetGhostByID(ctx, ghostID)
		if err != nil {
			log.Warn().Err(err).Str("ghost_id", string(ghostID)).Msg("Contact refresh: failed to load ghost")
			continue
		}
		info, err := c.GetUserInfo(ctx, ghost)
		if err != nil || info == nil {
			continue
		}
		ghost.UpdateInfo(ctx, info)
		updated++
	}

	log.Info().Int("ghosts_checked", len(ghostIDs)).Int("updated", updated).
		Msg("Contact change detected — refreshed ghost profiles")
}

// ============================================================================
// Helpers
// ============================================================================

func (c *IMClient) isMyHandle(handle string) bool {
	normalizedHandle := normalizeIdentifierForPortalID(handle)
	for _, h := range c.allHandles {
		if normalizedHandle == normalizeIdentifierForPortalID(h) {
			return true
		}
	}
	return false
}

// normalizeIdentifierForPortalID canonicalizes user/chat identifiers so portal
// routing is stable across formatting variants (notably SMS numbers with and
// without leading "+1").
func normalizeIdentifierForPortalID(identifier string) string {
	id := strings.TrimSpace(identifier)
	if id == "" {
		return ""
	}

	if strings.HasPrefix(id, "mailto:") {
		return "mailto:" + strings.ToLower(strings.TrimPrefix(id, "mailto:"))
	}
	if strings.Contains(id, "@") && !strings.HasPrefix(id, "tel:") {
		return "mailto:" + strings.ToLower(strings.TrimPrefix(id, "mailto:"))
	}

	if strings.HasPrefix(id, "tel:") || strings.HasPrefix(id, "+") || isNumeric(id) {
		local := stripIdentifierPrefix(id)
		normalized := normalizePhoneIdentifierForPortalID(local)
		if normalized != "" {
			return "tel:" + normalized
		}
		return addIdentifierPrefix(local)
	}

	return id
}

// normalizePhoneIdentifierForPortalID canonicalizes phone-like identifiers while
// preserving short-code semantics (e.g. "242733" stays "242733", not "+242733").
func normalizePhoneIdentifierForPortalID(local string) string {
	cleaned := normalizePhone(local)
	if cleaned == "" {
		return ""
	}
	if strings.HasPrefix(cleaned, "+") {
		return cleaned
	}
	if len(cleaned) == 10 {
		return "+1" + cleaned
	}
	if len(cleaned) == 11 && cleaned[0] == '1' {
		return "+" + cleaned
	}
	if len(cleaned) >= 11 {
		return "+" + cleaned
	}
	return cleaned
}

func (c *IMClient) makeEventSender(sender *string) bridgev2.EventSender {
	if sender == nil || *sender == "" || c.isMyHandle(*sender) {
		c.ensureDoublePuppet()
		return bridgev2.EventSender{
			IsFromMe:    true,
			SenderLogin: c.UserLogin.ID,
			Sender:      makeUserID(c.handle),
		}
	}
	normalizedSender := normalizeIdentifierForPortalID(*sender)
	return bridgev2.EventSender{
		IsFromMe: false,
		Sender:   makeUserID(normalizedSender),
	}
}

// ensureDoublePuppet retries double puppet setup if it previously failed.
//
// The mautrix bridgev2 framework permanently caches a nil DoublePuppet() on
// first failure (user.go sets doublePuppetInitialized=true BEFORE calling
// NewUserIntent). On macOS Ventura, transient IDS registration issues can
// cause the initial setup to fail, and without a retry the nil is cached
// forever — making all IsFromMe messages fall through to the ghost intent,
// which flips their direction (sent appears as received).
//
// This workaround detects the cached nil and re-attempts login using the
// saved access token, which succeeds once IDS registration stabilizes.
func (c *IMClient) ensureDoublePuppet() {
	ctx := context.Background()
	user := c.UserLogin.User
	if user.DoublePuppet(ctx) != nil {
		return // already working
	}
	token := user.AccessToken
	if token == "" {
		return // no token to retry with
	}
	user.LogoutDoublePuppet(ctx)
	if err := user.LoginDoublePuppet(ctx, token); err != nil {
		c.UserLogin.Log.Warn().Err(err).Msg("Failed to re-establish double puppet")
	} else {
		c.UserLogin.Log.Info().Msg("Re-established double puppet after previous failure")
	}
}

// resolveExistingDMPortalID prefers an already-created DM portal key variant
// (e.g. legacy tel:1415... vs canonical tel:+1415...) to avoid splitting rooms
// when normalization rules change.
func (c *IMClient) resolveExistingDMPortalID(identifier string) networkid.PortalID {
	defaultID := networkid.PortalID(identifier)
	if identifier == "" || strings.Contains(identifier, ",") || !strings.HasPrefix(identifier, "tel:") {
		return defaultID
	}

	local := strings.TrimPrefix(identifier, "tel:")
	candidates := make([]string, 0, 3)
	seen := map[string]bool{identifier: true}
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		candidates = append(candidates, id)
	}

	if strings.HasPrefix(local, "+") {
		withoutPlus := strings.TrimPrefix(local, "+")
		add("tel:" + withoutPlus)
		if strings.HasPrefix(local, "+1") && len(local) == 12 {
			add("tel:" + strings.TrimPrefix(local, "+1"))
		}
	} else if isNumeric(local) {
		if len(local) == 10 {
			add("tel:1" + local)
		}
		if len(local) == 11 && strings.HasPrefix(local, "1") {
			add("tel:" + local[1:])
		}
	}

	ctx := context.Background()
	for _, candidate := range candidates {
		portal, err := c.Main.Bridge.GetExistingPortalByKey(ctx, networkid.PortalKey{
			ID:       networkid.PortalID(candidate),
			Receiver: c.UserLogin.ID,
		})
		if err == nil && portal != nil && portal.MXID != "" {
			c.UserLogin.Log.Debug().
				Str("normalized", identifier).
				Str("resolved", candidate).
				Msg("Resolved DM portal to existing legacy identifier")
			return networkid.PortalID(candidate)
		}
	}

	return defaultID
}

// ensureGroupPortalIndex lazily loads all existing group portals from the DB
// and builds an in-memory index mapping each member to its group portal IDs.
func (c *IMClient) ensureGroupPortalIndex() {
	c.groupPortalMu.Lock()
	defer c.groupPortalMu.Unlock()
	if c.groupPortalIndex != nil {
		return // already loaded
	}

	idx := make(map[string]map[string]bool)
	ctx := context.Background()
	portals, err := c.Main.Bridge.DB.Portal.GetAllWithMXID(ctx)
	if err != nil {
		c.UserLogin.Log.Err(err).Msg("Failed to load portals for group index")
		return // leave c.groupPortalIndex nil so next call retries
	}
	for _, p := range portals {
		portalID := string(p.ID)
		if !strings.Contains(portalID, ",") {
			continue // skip DMs
		}
		if p.Receiver != c.UserLogin.ID {
			continue // skip other users' portals
		}
		for _, member := range strings.Split(portalID, ",") {
			if idx[member] == nil {
				idx[member] = make(map[string]bool)
			}
			idx[member][portalID] = true
		}
	}
	c.groupPortalIndex = idx
	c.UserLogin.Log.Debug().
		Int("portals_indexed", len(c.groupPortalIndex)).
		Msg("Built group portal fuzzy-match index")
}

// indexGroupPortalLocked adds a group portal ID to the in-memory index.
// Caller must hold groupPortalMu write lock.
func (c *IMClient) indexGroupPortalLocked(portalID string) {
	for _, member := range strings.Split(portalID, ",") {
		if c.groupPortalIndex[member] == nil {
			c.groupPortalIndex[member] = make(map[string]bool)
		}
		c.groupPortalIndex[member][portalID] = true
	}
}

// registerGroupPortal thread-safely indexes a new group portal.
func (c *IMClient) registerGroupPortal(portalID string) {
	c.groupPortalMu.Lock()
	defer c.groupPortalMu.Unlock()
	c.indexGroupPortalLocked(portalID)
}

// reIDPortalWithCacheUpdate atomically re-keys a portal in the DB and updates
// all in-memory caches. Holding all group cache write locks during the entire
// operation prevents concurrent handlers (read receipts, typing indicators)
// from observing a state where the DB key changed but caches still reference
// the old portal ID.
func (c *IMClient) reIDPortalWithCacheUpdate(ctx context.Context, oldKey, newKey networkid.PortalKey) (bridgev2.ReIDResult, *bridgev2.Portal, error) {
	oldID := string(oldKey.ID)
	newID := string(newKey.ID)

	c.imGroupNamesMu.Lock()
	c.imGroupGuidsMu.Lock()
	c.groupPortalMu.Lock()
	c.lastGroupForMemberMu.Lock()
	defer c.lastGroupForMemberMu.Unlock()
	defer c.groupPortalMu.Unlock()
	defer c.imGroupGuidsMu.Unlock()
	defer c.imGroupNamesMu.Unlock()

	result, portal, err := c.Main.Bridge.ReIDPortal(ctx, oldKey, newKey)
	if err != nil {
		return result, portal, err
	}

	// Move group name cache
	if name, ok := c.imGroupNames[oldID]; ok {
		c.imGroupNames[newID] = name
		delete(c.imGroupNames, oldID)
	}
	// Move group guid cache
	if guid, ok := c.imGroupGuids[oldID]; ok {
		c.imGroupGuids[newID] = guid
		delete(c.imGroupGuids, oldID)
	}
	// Update group portal index: remove old members, add new
	for _, member := range strings.Split(oldID, ",") {
		if portals, ok := c.groupPortalIndex[member]; ok {
			delete(portals, oldID)
			if len(portals) == 0 {
				delete(c.groupPortalIndex, member)
			}
		}
	}
	c.indexGroupPortalLocked(newID)
	// Update lastGroupForMember entries pointing to old portal
	for member, key := range c.lastGroupForMember {
		if key == oldKey {
			c.lastGroupForMember[member] = newKey
		}
	}

	return result, portal, nil
}

// resolveExistingGroupPortalID checks whether an existing group portal matches
// the computed portal ID via fuzzy matching (differs by at most 1 member).
// If senderGuid is provided, fuzzy matches are validated against the cached
// sender_guid — a mismatch means a different group even if members overlap.
// If a match is found, returns the existing portal ID; otherwise registers the
// new ID and returns it as-is.
func (c *IMClient) resolveExistingGroupPortalID(computedID string, senderGuid *string) networkid.PortalID {
	c.ensureGroupPortalIndex()

	// Fast path: exact match in DB
	ctx := context.Background()
	portal, err := c.Main.Bridge.GetExistingPortalByKey(ctx, networkid.PortalKey{
		ID:       networkid.PortalID(computedID),
		Receiver: c.UserLogin.ID,
	})
	if err == nil && portal != nil && portal.MXID != "" {
		return networkid.PortalID(computedID)
	}

	// Fuzzy match: find existing portals that share members with the candidate.
	candidateMembers := strings.Split(computedID, ",")
	candidateSize := len(candidateMembers)

	// Count how many members each existing portal shares with the candidate.
	overlap := make(map[string]int) // existing portal ID -> shared member count
	c.groupPortalMu.RLock()
	for _, member := range candidateMembers {
		for existingID := range c.groupPortalIndex[member] {
			overlap[existingID]++
		}
	}
	c.groupPortalMu.RUnlock()

	for existingID, sharedCount := range overlap {
		existingSize := len(strings.Split(existingID, ","))
		diff := (candidateSize - sharedCount) + (existingSize - sharedCount)
		if diff > 1 {
			continue
		}

		// If we have a sender_guid, reject fuzzy matches with a different
		// sender_guid — they are genuinely different group conversations
		// that happen to share most members.
		if senderGuid != nil && *senderGuid != "" {
			c.imGroupGuidsMu.RLock()
			existingGuid := c.imGroupGuids[existingID]
			c.imGroupGuidsMu.RUnlock()
			if existingGuid != "" && existingGuid != *senderGuid {
				continue
			}
		}

		// Verify the match actually exists in DB with a Matrix room.
		existing, err := c.Main.Bridge.GetExistingPortalByKey(ctx, networkid.PortalKey{
			ID:       networkid.PortalID(existingID),
			Receiver: c.UserLogin.ID,
		})
		if err != nil || existing == nil || existing.MXID == "" {
			continue
		}

		c.UserLogin.Log.Info().
			Str("computed", computedID).
			Str("resolved", existingID).
			Int("diff", diff).
			Msg("Fuzzy-matched group portal to existing room")
		return networkid.PortalID(existingID)
	}

	// No match — register this as a new group portal.
	c.registerGroupPortal(computedID)
	return networkid.PortalID(computedID)
}

// findGroupPortalForMember returns the most likely group portal for a member.
// Prefers the group where the member last sent a message; falls back to the
// sole group containing them. Used when typing/read receipts lack full
// participant lists.
func (c *IMClient) findGroupPortalForMember(member string) (networkid.PortalKey, bool) {
	normalized := normalizeIdentifierForPortalID(member)
	if normalized == "" {
		return networkid.PortalKey{}, false
	}

	// Prefer last active group for this member.
	c.lastGroupForMemberMu.RLock()
	lastGroup, ok := c.lastGroupForMember[normalized]
	c.lastGroupForMemberMu.RUnlock()
	if ok {
		return lastGroup, true
	}

	// Fall back to group portal index — works if they're in exactly one group.
	c.ensureGroupPortalIndex()
	c.groupPortalMu.RLock()
	portals := c.groupPortalIndex[normalized]
	c.groupPortalMu.RUnlock()

	if len(portals) != 1 {
		return networkid.PortalKey{}, false
	}

	for portalID := range portals {
		return networkid.PortalKey{
			ID:       networkid.PortalID(portalID),
			Receiver: c.UserLogin.ID,
		}, true
	}
	return networkid.PortalKey{}, false
}

func (c *IMClient) makePortalKey(participants []string, groupName *string, sender *string, senderGuid *string) networkid.PortalKey {
	isGroup := len(participants) > 2 || groupName != nil

	if isGroup {
		// When a persistent group UUID (sender_guid / gid) is available,
		// use "gid:<UUID>" as the stable portal ID. This avoids the
		// fragility of participant-based IDs that break when membership
		// changes or participants normalize differently.
		var portalID networkid.PortalID
		if senderGuid != nil && *senderGuid != "" {
			portalID = networkid.PortalID("gid:" + strings.ToLower(*senderGuid))
		} else {
			// Fallback: build a participant-based ID for groups without a UUID.
			sorted := make([]string, 0, len(participants))
			for _, p := range participants {
				normalized := normalizeIdentifierForPortalID(p)
				if normalized == "" || c.isMyHandle(normalized) {
					continue
				}
				sorted = append(sorted, normalized)
			}
			sorted = append(sorted, normalizeIdentifierForPortalID(c.handle))
			sort.Strings(sorted)
			deduped := sorted[:0]
			for i, s := range sorted {
				if i == 0 || s != sorted[i-1] {
					deduped = append(deduped, s)
				}
			}
			sorted = deduped
			computedID := strings.Join(sorted, ",")
			portalID = c.resolveExistingGroupPortalID(computedID, senderGuid)
		}
		// Cache the actual iMessage group name (cv_name) so outbound
		// messages can route to the correct conversation.
		if groupName != nil && *groupName != "" {
			c.imGroupNamesMu.Lock()
			c.imGroupNames[string(portalID)] = *groupName
			c.imGroupNamesMu.Unlock()
		}
		portalKey := networkid.PortalKey{ID: portalID, Receiver: c.UserLogin.ID}

		// Cache the persistent group UUID (sender_guid/gid) so outbound
		// messages reuse the same UUID and Apple Messages recipients match
		// them to the existing group thread. Only for multi-member groups.
		if senderGuid != nil && *senderGuid != "" && strings.Contains(string(portalID), ",") {
			c.imGroupGuidsMu.Lock()
			c.imGroupGuids[string(portalID)] = *senderGuid
			c.imGroupGuidsMu.Unlock()
		}

		// Persist sender_guid and group name to database so they survive restarts
		persistGuid := ""
		if senderGuid != nil {
			persistGuid = *senderGuid
		}
		persistName := ""
		if groupName != nil {
			persistName = *groupName
		}
		if persistGuid != "" || persistName != "" {
			go func(pk networkid.PortalKey, guid, gname string) {
				ctx := context.Background()
				portal, err := c.Main.Bridge.GetExistingPortalByKey(ctx, pk)
				if err == nil && portal != nil {
					meta := &PortalMetadata{}
					if existing, ok := portal.Metadata.(*PortalMetadata); ok {
						*meta = *existing
					}
					changed := false
					if guid != "" && meta.SenderGuid != guid {
						meta.SenderGuid = guid
						changed = true
					}
					if gname != "" && meta.GroupName != gname {
						meta.GroupName = gname
						changed = true
					}
					if changed {
						portal.Metadata = meta
						_ = portal.Save(ctx)
					}
				}
			}(portalKey, persistGuid, persistName)
		}
		// Track which group each member last sent a message in, so typing
		// indicators (which lack full participant lists) can be routed.
		if sender != nil && *sender != "" {
			normalized := normalizeIdentifierForPortalID(*sender)
			if normalized != "" && !c.isMyHandle(normalized) {
				c.lastGroupForMemberMu.Lock()
				c.lastGroupForMember[normalized] = portalKey
				c.lastGroupForMemberMu.Unlock()
			}
		}
		return portalKey
	}

	for _, p := range participants {
		normalized := normalizeIdentifierForPortalID(p)
		if normalized != "" && !c.isMyHandle(normalized) {
			// Resolve to an existing portal if the contact has multiple phone numbers.
			// This ensures messages from any of a contact's numbers land in one room.
			portalID := c.resolveContactPortalID(normalized)
			portalID = c.resolveExistingDMPortalID(string(portalID))
			return networkid.PortalKey{
				ID:       portalID,
				Receiver: c.UserLogin.ID,
			}
		}
	}

	// SMS edge case: some payloads include only the local forwarding number in
	// participants. When that happens, use sender as the DM portal identifier.
	if sender != nil && *sender != "" {
		normalizedSender := normalizeIdentifierForPortalID(*sender)
		if normalizedSender != "" && !c.isMyHandle(normalizedSender) {
			portalID := c.resolveContactPortalID(normalizedSender)
			portalID = c.resolveExistingDMPortalID(string(portalID))
			return networkid.PortalKey{
				ID:       portalID,
				Receiver: c.UserLogin.ID,
			}
		}
	}

	if len(participants) > 0 {
		normalized := normalizeIdentifierForPortalID(participants[0])
		if normalized == "" {
			normalized = participants[0]
		}
		portalID := c.resolveExistingDMPortalID(normalized)
		return networkid.PortalKey{
			ID:       portalID,
			Receiver: c.UserLogin.ID,
		}
	}

	return networkid.PortalKey{ID: "unknown", Receiver: c.UserLogin.ID}
}

// makeReceiptPortalKey handles receipt messages where participants may be empty.
// When participants is empty (rustpush sets conversation: None for receipts),
// use the sender field to identify the DM portal.
func (c *IMClient) makeReceiptPortalKey(participants []string, groupName *string, sender *string, senderGuid *string) networkid.PortalKey {
	if len(participants) > 0 {
		return c.makePortalKey(participants, groupName, sender, senderGuid)
	}
	if sender != nil && *sender != "" {
		// Resolve to existing portal for contacts with multiple numbers
		normalizedSender := normalizeIdentifierForPortalID(*sender)
		if normalizedSender == "" {
			return networkid.PortalKey{ID: "unknown", Receiver: c.UserLogin.ID}
		}
		portalID := c.resolveContactPortalID(normalizedSender)
		portalID = c.resolveExistingDMPortalID(string(portalID))
		return networkid.PortalKey{
			ID:       portalID,
			Receiver: c.UserLogin.ID,
		}
	}
	return networkid.PortalKey{ID: "unknown", Receiver: c.UserLogin.ID}
}

func (c *IMClient) makeConversation(participants []string, groupName *string) rustpushgo.WrappedConversation {
	return rustpushgo.WrappedConversation{
		Participants: participants,
		GroupName:    groupName,
	}
}

func (c *IMClient) portalToConversation(portal *bridgev2.Portal) rustpushgo.WrappedConversation {
	portalID := string(portal.ID)
	isSms := c.isPortalSMS(portalID)

	isGroup := strings.HasPrefix(portalID, "gid:") || strings.Contains(portalID, ",")
	if isGroup {
		// For gid: portals, get the sender_guid from the portal ID itself
		// and look up participants from the cloud store or portal metadata.
		var participants []string
		var guid string
		if strings.HasPrefix(portalID, "gid:") {
			guid = strings.TrimPrefix(portalID, "gid:")
		} else {
			participants = strings.Split(portalID, ",")
		}

		// Use the actual iMessage group name (cv_name) from the protocol,
		// NOT the bridge-generated display name (portal.Name). Using the
		// bridge display name causes Messages.app to split conversations.
		c.imGroupNamesMu.RLock()
		name := c.imGroupNames[portalID]
		c.imGroupNamesMu.RUnlock()
		if name == "" {
			// Not in memory cache - try loading from portal metadata
			if meta, ok := portal.Metadata.(*PortalMetadata); ok && meta.GroupName != "" {
				name = meta.GroupName
				c.imGroupNamesMu.Lock()
				c.imGroupNames[portalID] = name
				c.imGroupNamesMu.Unlock()
			}
		}
		var groupName *string
		if name != "" {
			groupName = &name
		}

		// For gid: portals, guid is already set from portal ID.
		// For legacy comma-separated portals, look up from cache/metadata.
		if guid == "" {
			c.imGroupGuidsMu.RLock()
			guid = c.imGroupGuids[portalID]
			c.imGroupGuidsMu.RUnlock()
			if guid == "" {
				if meta, ok := portal.Metadata.(*PortalMetadata); ok && meta.SenderGuid != "" {
					guid = meta.SenderGuid
					c.imGroupGuidsMu.Lock()
					c.imGroupGuids[portalID] = guid
					c.imGroupGuidsMu.Unlock()
				}
			}
		}
		var senderGuid *string
		if guid != "" {
			senderGuid = &guid
		}
		return rustpushgo.WrappedConversation{
			Participants: participants,
			GroupName:    groupName,
			SenderGuid:   senderGuid,
			IsSms:        isSms,
		}
	}

	// For DMs, resolve the best sendable identifier. For merged contacts,
	// the portal ID might be an inactive number that rustpush can't send to.
	sendTo := c.resolveSendTarget(portalID)

	return rustpushgo.WrappedConversation{
		Participants: []string{c.handle, sendTo},
		IsSms:        isSms,
	}
}

// resolveGroupMembers returns the participant list for a group portal.
// For legacy comma-separated portal IDs it splits the ID string.
// For gid: portals, returns nil (participants come from real-time messages).
func (c *IMClient) resolveGroupMembers(ctx context.Context, portalID string) []string {
	if strings.HasPrefix(portalID, "gid:") {
		return nil
	}
	return strings.Split(portalID, ",")
}

// resolveGroupName determines the best display name for a group portal.
// Priority: 1) in-memory cache (user-set iMessage group name from real-time
//              protocol cv_name, e.g. when someone explicitly renames a group)
//
//	2) contact-resolved member names via buildGroupName
//
// Note: CloudKit's display_name field is NOT used — it contains Apple's
// auto-generated label (raw emails/phone numbers) rather than user-set names.
// The nice contact-resolved names shown in Messages.app are generated locally.
func (c *IMClient) resolveGroupName(ctx context.Context, portalID string) string {
	// 1) In-memory cache (populated from real-time iMessage rename messages)
	c.imGroupNamesMu.RLock()
	name := c.imGroupNames[portalID]
	c.imGroupNamesMu.RUnlock()
	if name != "" {
		return name
	}

	// 2) Build from contact-resolved member names
	members := c.resolveGroupMembers(ctx, portalID)
	if len(members) == 0 {
		return "Group Chat"
	}
	return c.buildGroupName(members)
}

// buildGroupName creates a human-readable group name from member identifiers
// by resolving contact names where possible, falling back to phone/email.
func (c *IMClient) buildGroupName(members []string) string {
	var names []string
	for _, memberID := range members {
		if c.isMyHandle(memberID) {
			continue // skip self
		}
		// Strip tel:/mailto: prefix for contact lookup
		lookupID := stripIdentifierPrefix(memberID)
		name := ""
		var contact *imessage.Contact
		if c.cloudContacts != nil {
			contact, _ = c.cloudContacts.GetContactInfo(lookupID)
		}

		if contact != nil && contact.HasName() {
			name = c.Main.Config.FormatDisplayname(DisplaynameParams{
				FirstName: contact.FirstName,
				LastName:  contact.LastName,
				Nickname:  contact.Nickname,
				ID:        lookupID,
			})
		}
		if name == "" {
			name = lookupID // raw phone/email without prefix
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return "Group Chat"
	}
	if len(names) <= 4 {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s, %s, %s +%d more", names[0], names[1], names[2], len(names)-3)
}

// ============================================================================
// Message conversion
// ============================================================================

type attachmentMessage struct {
	*rustpushgo.WrappedMessage
	Attachment *rustpushgo.WrappedAttachment
	Index      int
}

// convertURLPreviewToBeeper parses rich link sideband attachments from an
// inbound iMessage and returns Beeper link previews. Follows the pattern
// from mautrix-whatsapp's urlpreview.go.
func convertURLPreviewToBeeper(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, msg *rustpushgo.WrappedMessage, bodyText string) []*event.BeeperLinkPreview {
	log := zerolog.Ctx(ctx)

	// Find sideband attachments encoded by Rust
	var rlMeta, rlImage *rustpushgo.WrappedAttachment
	for i := range msg.Attachments {
		switch msg.Attachments[i].MimeType {
		case "x-richlink/meta":
			rlMeta = &msg.Attachments[i]
		case "x-richlink/image":
			rlImage = &msg.Attachments[i]
		}
	}

	if rlMeta != nil && rlMeta.InlineData != nil {
		fields := bytes.SplitN(*rlMeta.InlineData, []byte{0x01}, 5)
		originalURL := string(fields[0])
		canonicalURL := originalURL
		if len(fields) > 1 && len(fields[1]) > 0 {
			canonicalURL = string(fields[1])
		}
		title := ""
		if len(fields) > 2 && len(fields[2]) > 0 {
			title = string(fields[2])
		}
		description := ""
		if len(fields) > 3 && len(fields[3]) > 0 {
			description = string(fields[3])
		}
		imageMime := ""
		if len(fields) > 4 && len(fields[4]) > 0 {
			imageMime = string(fields[4])
		}

		log.Debug().
			Str("original_url", originalURL).
			Str("canonical_url", canonicalURL).
			Str("title", title).
			Str("description", description).
			Str("image_mime", imageMime).
			Msg("Parsed rich link sideband data from iMessage")

		// MatchedURL must exactly match a URL in the body text so Beeper
		// can associate the preview with the inline URL. Use regex to find
		// the URL in the body rather than trusting the NSURL-converted value.
		matchedURL := originalURL
		if bodyURL := urlRegex.FindString(bodyText); bodyURL != "" {
			matchedURL = bodyURL
		}

		preview := &event.BeeperLinkPreview{
			MatchedURL: matchedURL,
			LinkPreview: event.LinkPreview{
				CanonicalURL: canonicalURL,
				Title:        title,
				Description:  description,
			},
		}

		// Upload preview image if available
		if rlImage != nil && rlImage.InlineData != nil && intent != nil {
			if imageMime == "" {
				imageMime = "image/jpeg"
			}
			log.Debug().Int("image_bytes", len(*rlImage.InlineData)).Str("mime", imageMime).Msg("Uploading rich link preview image")
			url, encFile, err := intent.UploadMedia(ctx, "", *rlImage.InlineData, "preview", imageMime)
			if err == nil {
				if encFile != nil {
					preview.ImageEncryption = encFile
					preview.ImageURL = encFile.URL
				} else {
					preview.ImageURL = url
				}
				preview.ImageType = imageMime
			} else {
				log.Warn().Err(err).Msg("Failed to upload rich link preview image")
			}
		}

		log.Debug().Str("matched_url", matchedURL).Str("title", title).Msg("Inbound rich link preview ready")
		return []*event.BeeperLinkPreview{preview}
	}

	// No rich link from iMessage — auto-detect URL and fetch og: metadata + image
	if detectedURL := urlRegex.FindString(bodyText); detectedURL != "" {
		log.Debug().Str("detected_url", detectedURL).Msg("No iMessage rich link, fetching URL preview")
		return []*event.BeeperLinkPreview{fetchURLPreview(ctx, portal.Bridge, intent, detectedURL)}
	}

	return nil
}

func convertMessage(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, msg *rustpushgo.WrappedMessage) (*bridgev2.ConvertedMessage, error) {
	text := ptrStringOr(msg.Text, "")
	content := &event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    text,
	}
	if msg.Subject != nil && *msg.Subject != "" {
		if text != "" {
			content.Body = fmt.Sprintf("**%s**\n%s", *msg.Subject, text)
			content.Format = event.FormatHTML
			content.FormattedBody = fmt.Sprintf("<strong>%s</strong><br/>%s", *msg.Subject, text)
		} else {
			content.Body = *msg.Subject
		}
	}

	content.BeeperLinkPreviews = convertURLPreviewToBeeper(ctx, portal, intent, msg, text)

	cm := &bridgev2.ConvertedMessage{
		Parts: []*bridgev2.ConvertedMessagePart{{
			Type:    event.EventMessage,
			Content: content,
		}},
	}

	if msg.ReplyGuid != nil && *msg.ReplyGuid != "" {
		replyToID := makeMessageID(*msg.ReplyGuid)
		cm.ReplyTo = &networkid.MessageOptionalPartID{MessageID: replyToID}
	}

	return cm, nil
}

func convertAttachment(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, attMsg *attachmentMessage) (*bridgev2.ConvertedMessage, error) {
	att := attMsg.Attachment
	mimeType := att.MimeType
	fileName := att.Filename
	var durationMs int

	// Convert CAF Opus voice messages to OGG Opus for Matrix clients
	var inlineData []byte
	zerolog.Ctx(ctx).Debug().Bool("is_inline", att.IsInline).Bool("has_data", att.InlineData != nil).Str("mime", mimeType).Str("file", fileName).Uint64("size", att.Size).Msg("convertAttachment called")
	if att.IsInline && att.InlineData != nil {
		inlineData = *att.InlineData
		if att.UtiType == "com.apple.coreaudio-format" || mimeType == "audio/x-caf" {
			inlineData, mimeType, fileName, durationMs = convertAudioForMatrix(inlineData, mimeType, fileName)
		}
	}

	// Process images: extract dimensions, convert non-JPEG to JPEG, generate thumbnail
	var imgWidth, imgHeight int
	var thumbData []byte
	var thumbW, thumbH int
	if inlineData != nil && (strings.HasPrefix(mimeType, "image/") || looksLikeImage(inlineData)) {
		log := zerolog.Ctx(ctx)
		log.Debug().Str("mime_type", mimeType).Str("file_name", fileName).Int("data_len", len(inlineData)).Msg("Processing image attachment")
		if mimeType == "image/gif" {
			cfg, _, err := image.DecodeConfig(bytes.NewReader(inlineData))
			if err == nil {
				imgWidth, imgHeight = cfg.Width, cfg.Height
			}
		} else if img, fmtName, isJPEG := decodeImageData(inlineData); img != nil {
			b := img.Bounds()
			imgWidth, imgHeight = b.Dx(), b.Dy()
			log.Debug().Str("decoded_format", fmtName).Int("width", imgWidth).Int("height", imgHeight).Bool("is_jpeg", isJPEG).Msg("Image decoded successfully")
			// Re-encode non-JPEG images (PNG, TIFF, etc.) as JPEG for compatibility
			if !isJPEG {
				var buf bytes.Buffer
				if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 95}); err == nil {
					inlineData = buf.Bytes()
					mimeType = "image/jpeg"
					fileName = strings.TrimSuffix(fileName, filepath.Ext(fileName)) + ".jpg"
					log.Debug().Int("jpeg_size", len(inlineData)).Msg("Re-encoded image as JPEG")
				} else {
					log.Warn().Err(err).Msg("Failed to re-encode image as JPEG")
				}
			}
			if imgWidth > 800 || imgHeight > 800 {
				thumbData, thumbW, thumbH = scaleAndEncodeThumb(img, imgWidth, imgHeight)
			}
		} else {
			log.Warn().Str("mime_type", mimeType).Msg("Failed to decode image data")
			// Log first few bytes for debugging
			if len(inlineData) >= 4 {
				log.Debug().Hex("magic_bytes", inlineData[:4]).Msg("Image magic bytes")
			}
		}
	}

	msgType := mimeToMsgType(mimeType)

	fileSize := int(att.Size)
	if inlineData != nil {
		fileSize = len(inlineData)
	}
	content := &event.MessageEventContent{
		MsgType: msgType,
		Body:    fileName,
		Info: &event.FileInfo{
			MimeType: mimeType,
			Size:     fileSize,
			Width:    imgWidth,
			Height:   imgHeight,
		},
	}

	// Mark as voice message if this was a CAF voice recording
	if durationMs > 0 {
		content.MSC3245Voice = &event.MSC3245Voice{}
		content.MSC1767Audio = &event.MSC1767Audio{
			Duration: durationMs,
		}
		content.Info.Size = len(inlineData)
	}

	if inlineData != nil && intent != nil {
		url, encFile, err := intent.UploadMedia(ctx, "", inlineData, fileName, mimeType)
		if err != nil {
			return nil, fmt.Errorf("failed to upload attachment: %w", err)
		}
		if encFile != nil {
			content.File = encFile
		} else {
			content.URL = url
		}

		// Upload image thumbnail
		if thumbData != nil {
			thumbURL, thumbEnc, err := intent.UploadMedia(ctx, "", thumbData, "thumbnail.jpg", "image/jpeg")
			if err == nil {
				if thumbEnc != nil {
					content.Info.ThumbnailFile = thumbEnc
				} else {
					content.Info.ThumbnailURL = thumbURL
				}
				content.Info.ThumbnailInfo = &event.FileInfo{
					MimeType: "image/jpeg",
					Size:     len(thumbData),
					Width:    thumbW,
					Height:   thumbH,
				}
			} else {
				zerolog.Ctx(ctx).Warn().Err(err).Msg("Failed to upload image thumbnail")
			}
		}
	}

	cm := &bridgev2.ConvertedMessage{
		Parts: []*bridgev2.ConvertedMessagePart{{
			ID:      networkid.PartID(fmt.Sprintf("att%d", attMsg.Index)),
			Type:    event.EventMessage,
			Content: content,
		}},
	}

	if attMsg.WrappedMessage.ReplyGuid != nil && *attMsg.WrappedMessage.ReplyGuid != "" {
		replyToID := makeMessageID(*attMsg.WrappedMessage.ReplyGuid)
		cm.ReplyTo = &networkid.MessageOptionalPartID{MessageID: replyToID}
	}

	return cm, nil
}

// ============================================================================
// Static helpers
// ============================================================================

// extractReplyInfo converts a bridgev2 reply-to database message into the
// iMessage reply_guid and reply_part strings expected by rustpush.
// reply_guid is the message UUID; reply_part uses the iMessage format "bp:type:length".
// We don't have the original text length, so we use 0 as a placeholder.
func extractReplyInfo(replyTo *database.Message) (*string, *string) {
	if replyTo == nil {
		return nil, nil
	}
	guid := string(replyTo.ID)
	// Strip attachment suffixes like _att0, _att1 — iMessage expects a pure UUID
	if idx := strings.Index(guid, "_att"); idx > 0 {
		guid = guid[:idx]
	}
	// iMessage thread_originator_part format is "bp:type:length" where:
	//   bp = balloon part index (0 for normal messages)
	//   type = part type (0 for text)
	//   length = character count of the original message text
	// We use 0 as the length since we don't have the original text available.
	part := "0:0:0"
	return &guid, &part
}

// scaleAndEncodeThumb generates a JPEG thumbnail capped at 800px on the
// longest side using nearest-neighbor scaling (no external dependencies).
func scaleAndEncodeThumb(img image.Image, origW, origH int) ([]byte, int, int) {
	scale := min(800.0/float64(origW), 800.0/float64(origH))
	thumbW := int(float64(origW) * scale)
	thumbH := int(float64(origH) * scale)
	if thumbW < 1 {
		thumbW = 1
	}
	if thumbH < 1 {
		thumbH = 1
	}

	srcBounds := img.Bounds()
	dst := image.NewRGBA(image.Rect(0, 0, thumbW, thumbH))
	for y := range thumbH {
		srcY := srcBounds.Min.Y + y*srcBounds.Dy()/thumbH
		for x := range thumbW {
			srcX := srcBounds.Min.X + x*srcBounds.Dx()/thumbW
			dst.Set(x, y, img.At(srcX, srcY))
		}
	}

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, dst, &jpeg.Options{Quality: 75}); err != nil {
		return nil, 0, 0
	}
	return buf.Bytes(), thumbW, thumbH
}

// detectImageMIME returns the correct MIME type based on magic bytes.
func detectImageMIME(data []byte) string {
	if len(data) < 8 {
		return ""
	}
	if data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
		return "image/jpeg"
	}
	if data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 {
		return "image/png"
	}
	if string(data[:4]) == "GIF8" {
		return "image/gif"
	}
	if (data[0] == 'I' && data[1] == 'I' && data[2] == 0x2a && data[3] == 0x00) ||
		(data[0] == 'M' && data[1] == 'M' && data[2] == 0x00 && data[3] == 0x2a) {
		return "image/tiff"
	}
	return ""
}

// looksLikeImage checks magic bytes to detect images even when MIME type is wrong.
func looksLikeImage(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	// JPEG: FF D8 FF
	if data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
		return true
	}
	// PNG: 89 50 4E 47
	if data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 {
		return true
	}
	// GIF: GIF8
	if string(data[:4]) == "GIF8" {
		return true
	}
	// TIFF: II*\0 or MM\0*
	if (data[0] == 'I' && data[1] == 'I' && data[2] == 0x2a && data[3] == 0x00) ||
		(data[0] == 'M' && data[1] == 'M' && data[2] == 0x00 && data[3] == 0x2a) {
		return true
	}
	return false
}

// decodeImageData tries to decode image bytes using stdlib decoders (PNG,
// JPEG, GIF) and falls back to a minimal TIFF parser. Returns the decoded
// image, detected format name, and whether the data is already JPEG (so
// callers can skip re-encoding).
func decodeImageData(data []byte) (image.Image, string, bool) {
	// Handles PNG, JPEG, GIF (stdlib) and TIFF (golang.org/x/image/tiff)
	if img, fmtName, err := image.Decode(bytes.NewReader(data)); err == nil {
		return img, fmtName, fmtName == "jpeg"
	}
	return nil, "", false
}

func tapbackTypeToEmoji(tapbackType *uint32, tapbackEmoji *string) string {
	if tapbackType == nil {
		return "❤️"
	}
	switch *tapbackType {
	case 0:
		return "❤️"
	case 1:
		return "👍"
	case 2:
		return "👎"
	case 3:
		return "😂"
	case 4:
		return "❗"
	case 5:
		return "❓"
	case 6:
		if tapbackEmoji != nil {
			return *tapbackEmoji
		}
		return "👍"
	default:
		return "❤️"
	}
}

func emojiToTapbackType(emoji string) (uint32, *string) {
	switch emoji {
	case "❤️", "♥️":
		return 0, nil
	case "👍":
		return 1, nil
	case "👎":
		return 2, nil
	case "😂":
		return 3, nil
	case "❗", "‼️":
		return 4, nil
	case "❓":
		return 5, nil
	default:
		return 6, &emoji
	}
}

func mimeToUTI(mime string) string {
	switch {
	case mime == "image/jpeg":
		return "public.jpeg"
	case mime == "image/png":
		return "public.png"
	case mime == "image/gif":
		return "com.compuserve.gif"
	case mime == "image/heic":
		return "public.heic"
	case mime == "video/mp4":
		return "public.mpeg-4"
	case mime == "video/quicktime":
		return "com.apple.quicktime-movie"
	case mime == "audio/mpeg", mime == "audio/mp3":
		return "public.mp3"
	case mime == "audio/aac", mime == "audio/mp4":
		return "public.aac-audio"
	case mime == "audio/x-caf":
		return "com.apple.coreaudio-format"
	case strings.HasPrefix(mime, "image/"):
		return "public.image"
	case strings.HasPrefix(mime, "video/"):
		return "public.movie"
	case strings.HasPrefix(mime, "audio/"):
		return "public.audio"
	default:
		return "public.data"
	}
}

func mimeToMsgType(mime string) event.MessageType {
	switch {
	case strings.HasPrefix(mime, "image/"):
		return event.MsgImage
	case strings.HasPrefix(mime, "video/"):
		return event.MsgVideo
	case strings.HasPrefix(mime, "audio/"):
		return event.MsgAudio
	default:
		return event.MsgFile
	}
}

func (c *IMClient) markPortalSMS(portalID string) {
	c.smsPortalsLock.Lock()
	defer c.smsPortalsLock.Unlock()
	c.smsPortals[portalID] = true
}

func (c *IMClient) isPortalSMS(portalID string) bool {
	c.smsPortalsLock.RLock()
	defer c.smsPortalsLock.RUnlock()
	return c.smsPortals[portalID]
}

func (c *IMClient) trackUnsend(uuid string) {
	c.recentUnsendsLock.Lock()
	defer c.recentUnsendsLock.Unlock()
	c.recentUnsends[uuid] = time.Now()
	for k, t := range c.recentUnsends {
		if time.Since(t) > 5*time.Minute {
			delete(c.recentUnsends, k)
		}
	}
}

func (c *IMClient) wasUnsent(uuid string) bool {
	c.recentUnsendsLock.Lock()
	defer c.recentUnsendsLock.Unlock()
	if t, ok := c.recentUnsends[uuid]; ok {
		return time.Since(t) < 5*time.Minute
	}
	return false
}

// urlRegex matches URLs in message text for rich link matching.
// Matches explicit schemes (https://...) and bare domains (example.com, example.com/path).
var urlRegex = regexp.MustCompile(`(?:https?://\S+|(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:/\S*)?)`)

// normalizeURL ensures a URL has a scheme for HTTP fetching.
func normalizeURL(u string) string {
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return "https://" + u
	}
	return u
}

func ptrStringOr(s *string, def string) string {
	if s != nil {
		return *s
	}
	return def
}

func ptrUint64Or(v *uint64, def uint64) uint64 {
	if v != nil {
		return *v
	}
	return def
}
