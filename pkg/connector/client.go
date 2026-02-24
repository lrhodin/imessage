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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"image"
	"math"
	"image/jpeg"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "image/gif"
	_ "image/png"

	_ "golang.org/x/image/tiff"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.mau.fi/util/ptr"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	matrixfmt "maunium.net/go/mautrix/bridgev2/matrix"
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

// deletedPortalEntry tracks why a portal was marked as deleted.
// Entries in recentlyDeletedPortals serve two purposes:
//  1. Echo suppression: APNs messages with known UUIDs are dropped;
//     fresh UUIDs are allowed through for new conversations.
//  2. Re-import guard: ingestCloudMessages marks messages as deleted=TRUE
//     for portals in this map, preventing periodic re-syncs from re-importing
//     messages with deleted=FALSE and triggering backfill resurrection.
type deletedPortalEntry struct {
	deletedAt   time.Time
	isTombstone bool
}

// failedAttachmentEntry tracks a CloudKit attachment download/upload failure
// with a retry count. After maxAttachmentRetries attempts the attachment is
// abandoned to avoid infinite retries on permanently corrupted records.
type failedAttachmentEntry struct {
	lastError string
	retries   int
}

const maxAttachmentRetries = 3


// recordAttachmentFailure increments the retry count for a failed attachment.
// Returns the updated entry so callers can log the retry count.
func (c *IMClient) recordAttachmentFailure(recordName, errMsg string) *failedAttachmentEntry {
	entry := &failedAttachmentEntry{lastError: errMsg, retries: 1}
	if prev, loaded := c.failedAttachments.Load(recordName); loaded {
		old := prev.(*failedAttachmentEntry)
		entry.retries = old.retries + 1
	}
	c.failedAttachments.Store(recordName, entry)
	return entry
}

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

	// Contact source for name resolution (iCloud or external CardDAV)
	contacts contactSource

	// Contacts readiness gate for CloudKit message sync.
	contactsReady     bool
	contactsReadyLock sync.RWMutex
	contactsReadyCh   chan struct{}

	// CloudKit sync gate: prevents APNs messages from creating new portals
	// until the initial CloudKit sync establishes the authoritative set of
	// portals. Without this, is_from_me echoes arriving on reconnect can
	// resurrect deleted portals before CloudKit sync confirms they're gone.
	cloudSyncDone     bool
	cloudSyncDoneLock sync.RWMutex

	// Cloud backfill local cache store.
	cloudStore *cloudBackfillStore

	// Background goroutine lifecycle
	stopChan chan struct{}

	// Unsend re-delivery suppression
	recentUnsends     map[string]time.Time
	recentUnsendsLock sync.Mutex

	// Outbound unsend echo suppression: tracks target UUIDs of unsends
	// initiated from Matrix so the APNs echo doesn't get double-processed.
	recentOutboundUnsends     map[string]time.Time
	recentOutboundUnsendsLock sync.Mutex

	// Outbound delete echo suppression: tracks portal IDs where a chat delete
	// SMS portal tracking: portal IDs known to be SMS-only contacts
	smsPortals     map[string]bool
	smsPortalsLock sync.RWMutex

	// Initial sync gate: closed once initial sync completes (or is skipped),
	// so real-time messages don't race ahead of backfill.

	// Group portal fuzzy-matching index: maps each member to the set of
	// group portal IDs containing that member. Lazily populated from DB.
	groupPortalIndex map[string]map[string]bool
	groupPortalMu    sync.RWMutex

	// Actual iMessage group names (cv_name) keyed by portal ID.
	// Populated from incoming messages; used for outbound routing.
	imGroupNames   map[string]string
	imGroupNamesMu sync.RWMutex

	// In-memory group participants cache keyed by portal ID.
	// Populated synchronously in makePortalKey so resolveGroupMembers
	// can find participants before the async cloud_chat DB write completes.
	imGroupParticipants   map[string][]string
	imGroupParticipantsMu sync.RWMutex

	// Persistent iMessage group UUIDs (sender_guid/gid) keyed by portal ID.
	// Populated from incoming messages; used for outbound routing so that
	// Apple Messages recipients match messages to the correct group thread.
	imGroupGuids   map[string]string
	imGroupGuidsMu sync.RWMutex

	// gidAliases maps unknown gid-based portal IDs (e.g. "gid:uuid-b") to the
	// resolved existing portal ID (e.g. "gid:uuid-a"). Populated when another
	// rustpush client (like OpenBubbles) uses a different gid for the same
	// group conversation. Avoids repeated participant-matching on each message.
	gidAliases   map[string]string
	gidAliasesMu sync.RWMutex

	// Last active group portal per member. Updated on every incoming group
	// message so typing indicators route to the correct group.
	lastGroupForMember   map[string]networkid.PortalKey
	lastGroupForMemberMu sync.RWMutex

	// queuedPortals tracks portal_id → newest_ts for portals already queued
	// this session. Prevents re-queuing on periodic syncs unless CloudKit
	// has newer messages.
	queuedPortals map[string]int64

	// recentlyDeletedPortals tracks portal IDs that were deleted this
	// session. Populated by:
	// - CloudKit tombstones (ingestCloudChats, during sync before cloudSyncDone)
	// All paths use hasMessageUUID for echo detection: known UUIDs are
	// dropped, fresh UUIDs are allowed through for new conversations.
	recentlyDeletedPortals   map[string]deletedPortalEntry
	recentlyDeletedPortalsMu sync.RWMutex

	// forwardBackfillSem limits concurrent forward backfills to avoid
	// overwhelming CloudKit/Matrix with simultaneous attachment downloads.
	forwardBackfillSem chan struct{}

	// attachmentContentCache maps CloudKit record_name → *event.MessageEventContent.
	// Populated by preUploadCloudAttachments, which runs in the cloud sync
	// goroutine BEFORE createPortalsFromCloudSync. Checked first by
	// downloadAndUploadAttachment so that FetchMessages (portal event loop)
	// never blocks on a CloudKit download — it just reads the pre-built content.
	attachmentContentCache sync.Map

	// failedAttachments tracks CloudKit record_name → *failedAttachmentEntry
	// for attachments that failed to download or upload. preUploadCloudAttachments
	// retries these on delayed re-syncs (15s/60s/3min) even for portals with
	// fwd_backfill_done=1, ensuring transient failures don't cause permanent
	// attachment loss. Capped at maxAttachmentRetries to avoid infinite retries
	// on permanently corrupted CloudKit records.
	failedAttachments sync.Map

	// startupTime records when this session connected. Used to suppress
	// read receipts for messages that pre-date this session: re-delivered
	// APNs receipts arrive with TimestampMs = delivery time (now), not the
	// actual read time, so they always show the wrong "Seen at" timestamp.
	startupTime time.Time

	// msgBuffer reorders incoming APNs messages by timestamp before dispatch.
	// APNs delivers messages grouped by sender rather than interleaved
	// chronologically, which causes out-of-order chat history in Matrix
	// (since Matrix stores events in insertion order). The buffer collects
	// messages, tapbacks, and edits, then flushes them sorted by timestamp
	// after a quiet window or when a size limit is reached.
	msgBuffer *messageBuffer

	// pendingPortalMsgs holds messages that need portal creation but arrived
	// before CloudKit sync established the authoritative set of portals.
	// Without this, the framework drops events where CreatePortal=false and
	// portal.MXID="", and the UUIDs are already persisted so CloudKit won't
	// re-deliver them. Flushed by setCloudSyncDone with CreatePortal=true.
	pendingPortalMsgs   []rustpushgo.WrappedMessage
	pendingPortalMsgsMu sync.Mutex

	// pendingInitialBackfills counts how many forward FetchMessages calls are
	// still outstanding from the bootstrap createPortalsFromCloudSync pass.
	// The APNs message buffer is held until this counter reaches 0, ensuring
	// buffered APNs messages are delivered to Matrix AFTER the CloudKit backfill
	// (not interleaved with it). Set by createPortalsFromCloudSync before the
	// first setCloudSyncDone; decremented by onForwardBackfillDone.
	pendingInitialBackfills int64

	// apnsBufferFlushedAt is the unix-millisecond time when the APNs buffer
	// was flushed after all forward backfills completed. Zero until that event.
	// Used to enforce a grace window: stale read receipts that were queued in
	// the APNs buffer are delivered immediately on flush, so we suppress all
	// read receipts for receiptGraceMs after the flush.
	apnsBufferFlushedAt int64 // atomic
}

var _ bridgev2.NetworkAPI = (*IMClient)(nil)
var _ bridgev2.EditHandlingNetworkAPI = (*IMClient)(nil)
var _ bridgev2.ReactionHandlingNetworkAPI = (*IMClient)(nil)
var _ bridgev2.ReadReceiptHandlingNetworkAPI = (*IMClient)(nil)
var _ bridgev2.TypingHandlingNetworkAPI = (*IMClient)(nil)
var _ bridgev2.IdentifierResolvingNetworkAPI = (*IMClient)(nil)
var _ bridgev2.BackfillingNetworkAPI = (*IMClient)(nil)
var _ bridgev2.BackfillingNetworkAPIWithLimits = (*IMClient)(nil)
var _ bridgev2.DeleteChatHandlingNetworkAPI = (*IMClient)(nil)
var _ rustpushgo.MessageCallback = (*IMClient)(nil)
var _ rustpushgo.UpdateUsersCallback = (*IMClient)(nil)

// ============================================================================
// APNs message reorder buffer
// ============================================================================

const (
	// messageBufferQuietWindow is how long to wait after the last message
	// before flushing the buffer. Balances latency vs. reordering accuracy.
	messageBufferQuietWindow = 500 * time.Millisecond

	// messageBufferMaxSize is the maximum number of messages to hold before
	// force-flushing, even if the quiet window hasn't elapsed.
	messageBufferMaxSize = 50
)

// bufferedMessage is a message waiting in the reorder buffer.
type bufferedMessage struct {
	msg       rustpushgo.WrappedMessage
	timestamp uint64
}

// messageBuffer collects incoming APNs messages and dispatches them in
// chronological (timestamp) order. While CloudKit sync is in progress
// (!cloudSyncDone), messages accumulate without flushing — this prevents
// APNs messages from being dispatched before CloudKit backfill completes,
// which would cause older CloudKit messages to appear after newer APNs
// messages in Matrix. Once cloudSyncDone fires, setCloudSyncDone triggers
// a flush. After sync, normal quiet-window / max-size flushing resumes.
//
// Only regular messages, tapbacks, and edits are buffered; time-sensitive
// events (typing, read/delivery receipts) and control events (unsends,
// renames, participant changes) bypass the buffer entirely.
type messageBuffer struct {
	mu      sync.Mutex
	entries []bufferedMessage
	timer   *time.Timer
	client  *IMClient
}

// add inserts a message into the buffer. While CloudKit sync is in progress,
// or while initial forward backfills are pending, messages accumulate without
// flushing. After both conditions clear, the buffer flushes on a quiet window
// (500ms) or when the max size (50) is reached.
func (b *messageBuffer) add(msg rustpushgo.WrappedMessage) {
	b.mu.Lock()
	b.entries = append(b.entries, bufferedMessage{
		msg:       msg,
		timestamp: msg.TimestampMs,
	})

	// Hold only while CloudKit data is being downloaded (!isCloudSyncDone).
	// Once the data download is done, messages flow immediately so real-time
	// messages are never silently swallowed. The initial buffer is flushed
	// by setCloudSyncDone / onForwardBackfillDone with ordering preserved.
	if !b.client.isCloudSyncDone() {
		b.mu.Unlock()
		return
	}

	if len(b.entries) >= messageBufferMaxSize {
		if b.timer != nil {
			b.timer.Stop()
			b.timer = nil
		}
		b.mu.Unlock()
		go b.flush() // background, consistent with the time.AfterFunc quiet-window path
		return
	}

	if b.timer != nil {
		b.timer.Stop()
	}
	b.timer = time.AfterFunc(messageBufferQuietWindow, b.flush)
	b.mu.Unlock()
}

// flush sorts all buffered messages by timestamp and dispatches them.
func (b *messageBuffer) flush() {
	b.mu.Lock()
	if len(b.entries) == 0 {
		b.mu.Unlock()
		return
	}
	entries := b.entries
	b.entries = nil
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	b.mu.Unlock()

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].timestamp < entries[j].timestamp
	})

	for _, e := range entries {
		b.client.dispatchBuffered(e.msg)
	}
}

// stop cancels the flush timer and discards pending messages.
// Called during Disconnect — remaining messages will be re-delivered
// by CloudKit on next sync.
func (b *messageBuffer) stop() {
	b.mu.Lock()
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	b.entries = nil
	b.mu.Unlock()
}

// sendGhostReadReceipt sends a "they read my message" receipt from the ghost
// user with the correct timestamp. The standard framework path
// (QueueRemoteEvent → MarkRead → SetReadMarkers) doesn't work because the
// ghost isn't double-puppeted, so the homeserver ignores BeeperReadExtra["ts"]
// and uses server time instead. This method bypasses the framework by calling
// SetBeeperInboxState directly on the ghost's underlying Matrix client, which
// the homeserver honors for BeeperReadExtra["ts"] regardless of puppet status.
// Falls back to QueueRemoteEvent if the direct path fails.
func (c *IMClient) sendGhostReadReceipt(
	log *zerolog.Logger,
	ghostUserID networkid.UserID,
	portalKey networkid.PortalKey,
	guid string,
	readTime time.Time,
) {
	ctx := context.Background()

	// Step 1: Get the ghost user.
	ghost, err := c.Main.Bridge.GetGhostByID(ctx, ghostUserID)
	if err != nil || ghost == nil || ghost.Intent == nil {
		log.Warn().Err(err).Str("ghost_user_id", string(ghostUserID)).
			Msg("Ghost not found for read receipt, falling back to QueueRemoteEvent")
		c.queueGhostReceiptFallback(ghostUserID, portalKey, guid, readTime)
		return
	}

	// Step 2: Look up the portal to get its Matrix room ID.
	portal, err := c.Main.Bridge.GetExistingPortalByKey(ctx, portalKey)
	if err != nil || portal == nil || portal.MXID == "" {
		log.Debug().Err(err).Str("portal_id", string(portalKey.ID)).
			Msg("Portal not found for ghost read receipt, falling back to QueueRemoteEvent")
		c.queueGhostReceiptFallback(ghostUserID, portalKey, guid, readTime)
		return
	}

	// Step 3: Look up the target message's Matrix event ID in the bridge DB.
	msg, err := c.Main.Bridge.DB.Message.GetLastPartByID(ctx, portalKey.Receiver, makeMessageID(guid))
	if err != nil || msg == nil || msg.HasFakeMXID() {
		log.Debug().Err(err).Str("portal_id", string(portalKey.ID)).Str("guid", guid).
			Msg("Target message not in bridge DB, falling back to QueueRemoteEvent with ReadUpTo")
		c.queueGhostReceiptFallback(ghostUserID, portalKey, guid, readTime)
		return
	}

	// Step 4: Type-assert to access the ghost's underlying Matrix client
	// and call SetBeeperInboxState directly (bypasses IsCustomPuppet check).
	asIntent, ok := ghost.Intent.(*matrixfmt.ASIntent)
	if !ok {
		log.Warn().Str("portal_id", string(portalKey.ID)).
			Msg("Ghost intent is not *matrix.ASIntent, falling back to QueueRemoteEvent")
		c.queueGhostReceiptFallback(ghostUserID, portalKey, guid, readTime)
		return
	}

	extraData := map[string]any{
		"ts": readTime.UnixMilli(),
	}
	req := &mautrix.ReqSetReadMarkers{
		Read:            msg.MXID,
		FullyRead:       msg.MXID,
		BeeperReadExtra: extraData,
		BeeperFullyReadExtra: extraData,
	}
	err = asIntent.Matrix.SetBeeperInboxState(ctx, portal.MXID, &mautrix.ReqSetBeeperInboxState{
		ReadMarkers: req,
	})
	if err != nil {
		log.Warn().Err(err).Str("portal_id", string(portalKey.ID)).
			Stringer("event_id", msg.MXID).
			Msg("SetBeeperInboxState failed for ghost, falling back to QueueRemoteEvent")
		c.queueGhostReceiptFallback(ghostUserID, portalKey, guid, readTime)
		return
	}

	log.Info().
		Str("portal_id", string(portalKey.ID)).
		Str("guid", guid).
		Stringer("event_id", msg.MXID).
		Int64("read_time_ms", readTime.UnixMilli()).
		Str("read_time", readTime.UTC().Format(time.RFC3339)).
		Msg("Set ghost read receipt via SetBeeperInboxState with correct timestamp")
}

// queueGhostReceiptFallback sends a ghost read receipt via the standard
// QueueRemoteEvent path. The homeserver may ignore BeeperReadExtra["ts"]
// (showing server time instead), but the receipt itself will still be created.
func (c *IMClient) queueGhostReceiptFallback(
	ghostUserID networkid.UserID,
	portalKey networkid.PortalKey,
	guid string,
	readTime time.Time,
) {
	c.Main.Bridge.QueueRemoteEvent(c.UserLogin, &simplevent.Receipt{
		EventMeta: simplevent.EventMeta{
			Type:      bridgev2.RemoteEventReadReceipt,
			PortalKey: portalKey,
			Sender: bridgev2.EventSender{
				IsFromMe: false,
				Sender:   ghostUserID,
			},
			Timestamp: readTime,
		},
		LastTarget: makeMessageID(guid),
		ReadUpTo:   readTime,
	})
}

// onForwardBackfillDone is called when a single forward FetchMessages call
// completes (either returning early with no messages, or via CompleteCallback
// after bridgev2 delivers the batch to Matrix). It decrements the bootstrap
// pending counter and, when it reaches exactly 0, flushes the APNs buffer.
//
// Using == 0 (not <= 0) means the flush fires exactly once: the portal whose
// decrement lands at 0. Portals that cause the counter to go negative (e.g.
// a re-sync FetchMessages that we didn't account for) do not trigger a flush.
func (c *IMClient) onForwardBackfillDone() {
	remaining := atomic.AddInt64(&c.pendingInitialBackfills, -1)
	if remaining == 0 {
		log.Info().Msg("All initial forward backfills complete — flushing APNs buffer")
		atomic.StoreInt64(&c.apnsBufferFlushedAt, time.Now().UnixMilli())
		if c.msgBuffer != nil {
			c.msgBuffer.flush()
		}
		c.flushPendingPortalMsgs()
	}
}

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
			// NOTE: Do NOT pre-populate imGroupNames from portal metadata.
			// The metadata GroupName can be stale (polluted by previous CloudKit
			// sync cycles). Loading it on startup would cause resolveGroupName
			// and refreshGroupPortalNamesFromContacts to revert correct room
			// names back to stale values. Instead, let imGroupNames be populated
			// only by real-time APNs messages (makePortalKey / handleRename).
			// Outbound routing (portalToConversation) has its own metadata fallback.
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
	c.startupTime = time.Now()
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

	// Get our handle (precedence: login metadata > first handle)
	handles := client.GetHandles()
	c.allHandles = handles
	if len(handles) > 0 {
		c.handle = handles[0]
		var preferred string
		if meta, ok := c.UserLogin.Metadata.(*UserLoginMetadata); ok {
			preferred = meta.PreferredHandle
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
	c.msgBuffer = &messageBuffer{client: c}
	go c.periodicStateSave(log)

	// Ensure CloudKit backfill schema/storage is available.
	cloudStoreReady := true
	if err = c.ensureCloudSyncStore(context.Background()); err != nil {
		cloudStoreReady = false
		log.Error().Err(err).Msg("Failed to initialize cloud backfill store")
	}

	c.UserLogin.BridgeState.Send(status.BridgeState{StateEvent: status.StateConnected})

	// Set up contact source: per-user external CardDAV if configured, else iCloud
	meta := c.UserLogin.Metadata.(*UserLoginMetadata)
	if meta.CardDAVIsConfigured() {
		key := DeriveCardDAVKey(c.Main.BridgeSecret, string(c.UserLogin.ID))
		c.contacts = newExternalCardDAVClient(meta.GetCardDAVConfig(), key, log)
		if c.contacts != nil {
			log.Info().Str("email", meta.CardDAVEmail).Msg("Using external CardDAV for contacts")
			if syncErr := c.contacts.SyncContacts(log); syncErr != nil {
				log.Warn().Err(syncErr).Msg("Initial external CardDAV sync failed")
			} else {
				c.setContactsReady(log)
			}
			go c.periodicCloudContactSync(log)
		} else {
			log.Warn().Msg("External CardDAV configured but failed to initialize")
		}
	} else {
		c.contacts = newCloudContactsClient(c.client, log)
		if c.contacts != nil {
			if cc, ok := c.contacts.(*cloudContactsClient); ok {
				log.Info().Str("url", cc.baseURL).Msg("Cloud contacts available (iCloud CardDAV)")
			}
			if syncErr := c.contacts.SyncContacts(log); syncErr != nil {
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

	if cloudStoreReady && c.cloudKitBackfillEnabled() {
		c.startCloudSyncController(log)
	} else {
		if !c.cloudKitBackfillEnabled() {
			log.Info().Msg("CloudKit backfill not enabled for this user — skipping cloud sync")
		}
		// No CloudKit — open the APNs portal-creation gate immediately
		// so real-time messages can create portals without waiting.
		c.setCloudSyncDone()
	}

}

// cloudKitBackfillEnabled returns true when both the server and this specific
// user login have CloudKit backfill enabled. The server flag gates global
// bridge backfill settings; the per-user flag records the user's choice at
// login time and is paired to their stored hardware key / session state.
func (c *IMClient) cloudKitBackfillEnabled() bool {
	if !c.Main.Config.CloudKitBackfill {
		return false
	}
	if meta, ok := c.UserLogin.Metadata.(*UserLoginMetadata); ok {
		return meta.CloudKitBackfill
	}
	return false
}

func (c *IMClient) Disconnect() {
	if c.msgBuffer != nil {
		c.msgBuffer.stop()
	}
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
	if msg.IsMoveToRecycleBin || msg.IsPermanentDelete {
		c.handleChatDelete(log, msg)
		return
	}
	// Unsends bypass the buffer — they need to apply immediately and
	// don't contribute to chat ordering.
	if msg.IsUnsend {
		c.handleUnsend(log, msg)
		return
	}
	// Rename, participant changes, and group photo changes bypass the buffer
	// — they're control events, not content messages.
	if msg.IsRename {
		c.handleRename(log, msg)
		return
	}
	if msg.IsParticipantChange {
		c.handleParticipantChange(log, msg)
		return
	}
	if msg.IsIconChange {
		go c.handleIconChange(log, msg)
		return
	}

	// Buffer regular messages, tapbacks, and edits for timestamp-based
	// reordering. APNs delivers messages grouped by sender rather than
	// interleaved chronologically; the buffer sorts them before dispatch.
	if c.msgBuffer != nil {
		c.msgBuffer.add(msg)
	} else {
		c.dispatchBuffered(msg)
	}
}

// dispatchBuffered routes a message that has been through the reorder buffer
// to its appropriate handler.
func (c *IMClient) dispatchBuffered(msg rustpushgo.WrappedMessage) {
	log := c.UserLogin.Log.With().
		Str("component", "imessage").
		Str("msg_uuid", msg.Uuid).
		Logger()

	if msg.IsTapback {
		c.handleTapback(log, msg)
		return
	}
	if msg.IsEdit {
		c.handleEdit(log, msg)
		return
	}

	c.handleMessage(log, msg)
}

// flushPendingPortalMsgs replays messages that were held during the CloudKit
// sync window because their portals didn't exist yet. Called by setCloudSyncDone
// after the sync gate opens, so handleMessage will see createPortal=true.
func (c *IMClient) flushPendingPortalMsgs() {
	c.pendingPortalMsgsMu.Lock()
	held := c.pendingPortalMsgs
	c.pendingPortalMsgs = nil
	c.pendingPortalMsgsMu.Unlock()

	if len(held) == 0 {
		return
	}

	log := c.UserLogin.Log.With().Str("component", "imessage").Logger()
	log.Info().Int("count", len(held)).Msg("Replaying held messages after CloudKit sync completion")

	// Sort held messages by timestamp so they replay in chronological order.
	sort.Slice(held, func(i, j int) bool {
		return held[i].TimestampMs < held[j].TimestampMs
	})

	for _, msg := range held {
		msgLog := log.With().Str("msg_uuid", msg.Uuid).Logger()
		c.handleMessage(msgLog, msg)
	}
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

	// Skip stored (re-delivered) APNs messages that were already bridged in a
	// previous session. IsStoredMessage=true marks messages Apple buffered while
	// the bridge was offline; if their UUID is already in the Bridge DB they've
	// been processed before (or were sent by us and echo-suppressed). Re-delivering
	// them would create duplicate or resurrected Matrix events, especially for
	// messages whose portals were subsequently deleted.
	if msg.IsStoredMessage && msg.Uuid != "" {
		if dbMsgs, err := c.Main.Bridge.DB.Message.GetAllPartsByID(
			context.Background(), c.UserLogin.ID, makeMessageID(msg.Uuid),
		); err == nil && len(dbMsgs) > 0 {
			log.Debug().Str("uuid", msg.Uuid).Msg("Skipping stored message already in bridge DB")
			return
		}
	}

	sender := c.makeEventSender(msg.Sender)
	portalKey := c.makePortalKey(msg.Participants, msg.GroupName, msg.Sender, msg.SenderGuid)

	// Drop messages that couldn't be resolved to a real portal.
	// makePortalKey returns ID:"unknown" when participants and sender are both
	// empty/unresolvable. Letting these through creates a junk "unknown" room.
	if portalKey.ID == "unknown" {
		log.Warn().
			Str("msg_uuid", msg.Uuid).
			Strs("participants", msg.Participants).
			Msg("Dropping message: could not resolve portal key (no participants/sender)")
		return
	}

	// Track SMS portals so outbound replies use the correct service type
	if msg.IsSms {
		c.markPortalSMS(string(portalKey.ID))
	}

	// Only create new portals after CloudKit sync is done.
	cloudSyncDone := c.isCloudSyncDone()
	createPortal := cloudSyncDone

	// Suppress stale echoes that would resurrect deleted portals.
	// Two cases:
	// 1. Portal is mid-deletion (still has MXID, but in recentlyDeletedPortals):
	//    Drop known UUIDs — they're echoes of messages we already bridged.
	//    Fresh UUIDs pass through (genuinely new conversation).
	// 2. Portal is fully gone (no MXID): Drop known UUIDs — CloudKit sync
	//    knew about this message but chose not to create a portal.
	portalID := string(portalKey.ID)
	c.recentlyDeletedPortalsMu.RLock()
	deletedEntry, isDeletedPortal := c.recentlyDeletedPortals[portalID]
	c.recentlyDeletedPortalsMu.RUnlock()

	// Suppress stale echoes that would resurrect deleted portals.
	if isDeletedPortal && createPortal {
		existing, _ := c.Main.Bridge.GetExistingPortalByKey(context.Background(), portalKey)
		if existing == nil || existing.MXID == "" {
			// Portal is fully gone. Use startupTime as a fast first filter:
			// APNs replays pre-deletion messages with their original send timestamp,
			// so stale echoes have msg.TimestampMs < startupTime. Post-startup
			// messages fall through; the hasMessageUUID check below provides a
			// second layer (soft-deleted UUIDs are still found in cloud_message).
			if uint64(c.startupTime.UnixMilli()) > msg.TimestampMs {
				log.Info().
					Str("portal_id", portalID).
					Str("msg_uuid", msg.Uuid).
					Bool("is_tombstone", deletedEntry.isTombstone).
					Uint64("msg_ts", msg.TimestampMs).
					Int64("startup_ts", c.startupTime.UnixMilli()).
					Msg("Dropped message: pre-startup message for deleted portal (stale echo)")
				return
			}
			// Post-startup message → genuinely new conversation with this contact.
			// Flush the APNs buffer now so any held pre-sync messages are
			// dispatched before this new message creates a portal.
			log.Info().
				Str("portal_id", portalID).
				Str("msg_uuid", msg.Uuid).
				Bool("is_tombstone", deletedEntry.isTombstone).
				Msg("Post-startup message for deleted portal — flushing buffer and allowing new conversation")
			if c.msgBuffer != nil {
				c.msgBuffer.flush()
			}
			c.flushPendingPortalMsgs()
			// Fall through with createPortal=true to create the new portal.
		} else {
			// Portal still has an MXID (mid-deletion): route to existing room
			// but don't create a fresh one.
			createPortal = false
		}
	}

	if c.cloudStore != nil {
		if known, _ := c.cloudStore.hasMessageUUID(context.Background(), msg.Uuid); known {
			if isDeletedPortal {
				// Portal mid-deletion with a known UUID — stale echo.
				log.Info().
					Str("portal_id", portalID).
					Str("msg_uuid", msg.Uuid).
					Msg("Dropped message: known UUID for recently-deleted portal (mid-deletion echo)")
				return
			}
			if createPortal {
				// Portal fully deleted. No bridge portal exists.
				existing, _ := c.Main.Bridge.GetExistingPortalByKey(context.Background(), portalKey)
				if existing == nil || existing.MXID == "" {
					log.Info().
						Str("portal_id", portalID).
						Str("msg_uuid", msg.Uuid).
						Msg("Dropped message: known UUID with no portal (stale echo of deleted chat)")
					return
				}
			}
		}
	}
	// Hold messages for portals that don't exist yet while CloudKit sync
	// is in progress. Without this, the framework drops events where
	// CreatePortal=false and portal.MXID="". We intentionally skip UUID
	// persistence here so that replayed messages aren't mistakenly treated
	// as known echoes by hasMessageUUID on the second pass.
	if !createPortal {
		existing, _ := c.Main.Bridge.GetExistingPortalByKey(context.Background(), portalKey)
		if existing == nil || existing.MXID == "" {
			c.pendingPortalMsgsMu.Lock()
			c.pendingPortalMsgs = append(c.pendingPortalMsgs, msg)
			c.pendingPortalMsgsMu.Unlock()
			log.Info().
				Str("portal_id", portalID).
				Str("msg_uuid", msg.Uuid).
				Msg("Held message pending CloudKit sync completion (portal doesn't exist yet)")
			return
		}
	}

	// Persist this message UUID so cross-restart echoes are detected.
	// hasMessageUUID checks cloud_message regardless of the deleted flag,
	// so soft-deleted UUIDs from prior portal deletions still match.
	if c.cloudStore != nil {
		_ = c.cloudStore.persistMessageUUID(context.Background(), msg.Uuid, string(portalKey.ID), int64(msg.TimestampMs), sender.IsFromMe)
	}
	if createPortal || sender.IsFromMe {
		log.Info().
			Bool("create_portal", createPortal).
			Bool("cloud_sync_done", cloudSyncDone).
			Bool("is_stored_message", msg.IsStoredMessage).
			Bool("is_from_me", sender.IsFromMe).
			Str("portal_id", string(portalKey.ID)).
			Msg("Portal creation decision for message")
	}

	if msg.Text != nil && *msg.Text != "" && strings.TrimRight(*msg.Text, "\ufffc \n") != "" {
		c.Main.Bridge.QueueRemoteEvent(c.UserLogin, &simplevent.Message[*rustpushgo.WrappedMessage]{
			EventMeta: simplevent.EventMeta{
				Type:         bridgev2.RemoteEventMessage,
				PortalKey:    portalKey,
				CreatePortal: createPortal,
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
				CreatePortal: createPortal,
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
	targetGUID := ptrStringOr(msg.TapbackTargetUuid, "")

	// Resolve portal by target message UUID first as a safety net.
	// Tapbacks usually have correct participants from the payload, but
	// self-reflections can still have participants=[self, self].
	portalKey := c.resolvePortalByTargetMessage(log, targetGUID)
	if portalKey.ID == "" {
		portalKey = c.makePortalKey(msg.Participants, msg.GroupName, msg.Sender, msg.SenderGuid)
	}
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
	targetGUID := ptrStringOr(msg.EditTargetUuid, "")

	// Resolve portal by target message UUID first. Edit reflections from the
	// user's own devices have participants=[self, self], so makePortalKey can't
	// determine the correct DM portal.
	portalKey := c.resolvePortalByTargetMessage(log, targetGUID)
	if portalKey.ID == "" {
		portalKey = c.makePortalKey(msg.Participants, msg.GroupName, msg.Sender, msg.SenderGuid)
	}
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
	targetGUID := ptrStringOr(msg.UnsendTargetUuid, "")

	// Suppress echo of unsends initiated from Matrix.
	if c.wasOutboundUnsend(targetGUID) {
		log.Debug().Str("target_uuid", targetGUID).Msg("Suppressing echo of outbound unsend")
		return
	}

	c.trackUnsend(targetGUID)

	// Resolve portal by target message UUID first. Unsend reflections from the
	// user's own devices have participants=[self, self], so makePortalKey can't
	// determine the correct DM portal.
	portalKey := c.resolvePortalByTargetMessage(log, targetGUID)
	if portalKey.ID == "" {
		portalKey = c.makePortalKey(msg.Participants, msg.GroupName, msg.Sender, msg.SenderGuid)
	}

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
	// Skip stored (backfilled) rename messages to prevent spurious
	// room name change events from historical renames delivered on reconnect.
	if msg.IsStoredMessage {
		log.Debug().Str("uuid", msg.Uuid).Msg("Skipping stored rename message")
		return
	}
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
			// Also correct the stale CloudKit display_name in cloud_chat
			// so resolveGroupName doesn't fall back to the old name.
			if c.cloudStore != nil {
				if err := c.cloudStore.updateDisplayNameByPortalID(ctx, portalID, newName); err != nil {
					log.Warn().Err(err).Str("portal_id", portalID).Msg("Failed to update cloud_chat display_name after rename")
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
	// Skip stored (backfilled) participant change messages to prevent spurious
	// member change events from historical changes delivered on reconnect.
	if msg.IsStoredMessage {
		log.Debug().Str("uuid", msg.Uuid).Msg("Skipping stored participant change message")
		return
	}
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

// handleIconChange processes a group photo (icon) change from APNs.
// When a participant changes or clears the group photo from their iMessage
// client, Apple delivers an IconChange message with MMCS transfer data.
// The Rust layer downloads the photo inline; we apply it directly to the room.
//
// Stored (IsStoredMessage) icon changes are NOT skipped: when the bridge
// reconnects after being offline, Apple may deliver a queued IconChange with
// valid MMCS data, letting us catch up on changes that occurred while offline.
// If the MMCS URL has expired Rust returns nil bytes and we warn harmlessly.
func (c *IMClient) handleIconChange(log zerolog.Logger, msg rustpushgo.WrappedMessage) {
	portalKey := c.makePortalKey(msg.Participants, msg.GroupName, msg.Sender, msg.SenderGuid)
	portalID := string(portalKey.ID)
	log = log.With().Str("portal_id", portalID).Bool("stored", msg.IsStoredMessage).Logger()

	if msg.GroupPhotoCleared {
		// Photo was removed — clear the avatar and wipe the local cache so
		// GetChatInfo won't re-apply a stale photo after a restart.
		log.Info().Msg("Group photo cleared via APNs IconChange")
		if c.cloudStore != nil {
			if err := c.cloudStore.clearGroupPhoto(context.Background(), portalID); err != nil {
				log.Warn().Err(err).Msg("Failed to clear cached group photo in DB")
			}
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
					Avatar: &bridgev2.Avatar{
						ID:  networkid.AvatarID(""),
						Get: func(ctx context.Context) ([]byte, error) { return nil, nil },
					},
				},
			},
		})
		return
	}

	// New photo set — Rust already downloaded the MMCS bytes inline.
	// Apple delivers group photos via MMCS in IconChange messages (not CloudKit).
	if msg.IconChangePhotoData == nil || len(*msg.IconChangePhotoData) == 0 {
		log.Warn().Msg("IconChange received but photo data is empty (MMCS download may have failed)")
		return
	}
	photoData := *msg.IconChangePhotoData
	// Timestamp-based avatar ID — changes when the photo changes, so bridgev2
	// always re-applies the new avatar even if the portal already has one.
	avatarID := networkid.AvatarID(fmt.Sprintf("icon-change:%d", msg.TimestampMs))
	log.Info().Int("size", len(photoData)).Msg("Group photo changed via APNs IconChange — applying MMCS photo")

	// Persist bytes to DB so GetChatInfo can apply the correct avatar after a
	// restart without a CloudKit round-trip.  Apple's native clients never write
	// to the CloudKit gp asset field — MMCS is the only delivery mechanism.
	if c.cloudStore != nil {
		if err := c.cloudStore.saveGroupPhoto(context.Background(), portalID, int64(msg.TimestampMs), photoData); err != nil {
			log.Warn().Err(err).Msg("Failed to persist group photo bytes to DB")
		}
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
				Avatar: &bridgev2.Avatar{
					ID:  avatarID,
					Get: func(ctx context.Context) ([]byte, error) { return photoData, nil },
				},
			},
		},
	})
}

func (c *IMClient) handleChatDelete(log zerolog.Logger, msg rustpushgo.WrappedMessage) {
	deleteType := "MoveToRecycleBin"
	if msg.IsPermanentDelete {
		deleteType = "PermanentDelete"
	}
	// Apple-initiated chat deletes are intentionally ignored. The Beeper
	// portal is not touched — only local Beeper deletes remove portals.
	log.Info().Str("delete_type", deleteType).Msg("Ignoring incoming Apple chat delete (bidirectional delete disabled)")
}

func (c *IMClient) handleReadReceipt(log zerolog.Logger, msg rustpushgo.WrappedMessage) {
	if msg.IsStoredMessage {
		log.Debug().Str("uuid", msg.Uuid).Msg("Skipping stored read receipt")
		return
	}
	// Drop read receipts while CloudKit sync is in progress or the APNs buffer
	// hasn't been flushed yet (forward backfills still pending, or the 10-second
	// safety net hasn't fired). Once flushedAt is stamped, backfill is done and
	// any arriving receipt is a genuine live event.
	flushedAt := atomic.LoadInt64(&c.apnsBufferFlushedAt)
	syncDone := c.isCloudSyncDone()
	if !syncDone || flushedAt == 0 {
		log.Debug().
			Str("uuid", msg.Uuid).
			Bool("sync_done", syncDone).
			Int64("flushed_at", flushedAt).
			Msg("Skipping read receipt during CloudKit sync/backfill")
		return
	}

	// Suppress duplicate receipts in the post-backfill grace window (60s).
	// After the APNs buffer flushes, stale receipts that arrived between the
	// 30s IsStoredMessage window and backfill completion can leak through.
	// If CloudKit already has a valid date_read_ms for this message, a
	// synthetic receipt with the correct historical timestamp was already
	// queued — drop the duplicate to prevent overwriting with time.Now().
	const postBackfillGraceMS = 60_000
	if c.cloudStore != nil && (time.Now().UnixMilli()-flushedAt) < postBackfillGraceMS {
		if hasReceipt, err := c.cloudStore.hasCloudReadReceipt(context.Background(), msg.Uuid); err == nil && hasReceipt {
			log.Debug().
				Str("uuid", msg.Uuid).
				Msg("Skipping duplicate read receipt — CloudKit already has date_read_ms (post-backfill grace)")
			return
		}
	}

	portalKey := c.makeReceiptPortalKey(msg.Participants, msg.GroupName, msg.Sender, msg.SenderGuid)
	ctx := context.Background()

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
	{
		portal, _ := c.Main.Bridge.GetExistingPortalByKey(ctx, portalKey)
		if portal != nil && portal.MXID != "" {
			goto resolved
		}
	}
resolved:

	readTime := time.UnixMilli(int64(msg.TimestampMs))
	sender := c.makeEventSender(msg.Sender)

	if !sender.IsFromMe {
		// Skip ghost receipts for messages that were backfilled from CloudKit.
		// APNs read receipts for group chats lack participants/senderGuid, so
		// the portal key often resolves to a DM rather than a gid: portal.
		// Check cloud_message regardless of portal type — any message that was
		// synced from CloudKit is a backfilled message whose ghost receipt
		// would incorrectly show "Seen by [person]" on outgoing messages.
		// Real-time messages (not in cloud_message) are unaffected.
		if c.cloudStore != nil {
			if backfilled, err := c.cloudStore.isCloudBackfilledMessage(context.Background(), msg.Uuid); err == nil && backfilled {
				log.Debug().
					Str("uuid", msg.Uuid).
					Str("portal_id", string(portalKey.ID)).
					Msg("Skipping ghost read receipt for backfilled message")
				return
			}
		}
		// Ghost receipt ("they read my message"): bypass the framework and call
		// SetBeeperInboxState directly. The standard framework path (QueueRemoteEvent
		// → MarkRead → SetReadMarkers) ignores BeeperReadExtra["ts"] for ghost
		// users, causing the homeserver to use server time instead of the actual
		// read time from the APNs receipt.
		c.sendGhostReadReceipt(&log, sender.Sender, portalKey, msg.Uuid, readTime)
	} else {
		// Self-receipt (unlikely for APNs read receipts, but handle gracefully).
		c.Main.Bridge.QueueRemoteEvent(c.UserLogin, &simplevent.Receipt{
			EventMeta: simplevent.EventMeta{
				Type:      bridgev2.RemoteEventReadReceipt,
				PortalKey: portalKey,
				Sender:    sender,
				Timestamp: readTime,
			},
			LastTarget: makeMessageID(msg.Uuid),
		})
	}
}

func (c *IMClient) handleDeliveryReceipt(log zerolog.Logger, msg rustpushgo.WrappedMessage) {
	if msg.IsStoredMessage {
		log.Debug().Str("uuid", msg.Uuid).Msg("Skipping stored delivery receipt")
		return
	}
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
	// Persist UUID immediately so echo detection works even if the portal
	// is deleted before the APNs echo arrives.
	if c.cloudStore != nil {
		_ = c.cloudStore.persistMessageUUID(ctx, uuid, string(msg.Portal.ID), time.Now().UnixMilli(), true)
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
	// Persist UUID immediately so echo detection works even if the portal
	// is deleted before the APNs echo arrives.
	if c.cloudStore != nil {
		_ = c.cloudStore.persistMessageUUID(ctx, uuid, string(msg.Portal.ID), time.Now().UnixMilli(), true)
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

	// Track outbound unsend so we can suppress the APNs echo.
	c.trackOutboundUnsend(string(msg.TargetMessage.ID))

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

// HandleMatrixDeleteChat is called when the user deletes a chat in Matrix/Beeper.
// It cleans up local state (echo detection, local DB) but does NOT touch Apple:
// no MoveToRecycleBin APNs message, no CloudKit record deletion. The chat stays
// on the user's Apple devices; only the Beeper portal is removed.
func (c *IMClient) HandleMatrixDeleteChat(ctx context.Context, msg *bridgev2.MatrixDeleteChat) error {
	if c.client == nil {
		return bridgev2.ErrNotLoggedIn
	}

	// Flush the APNs reorder buffer before processing the delete. Any messages
	// currently buffered (including echoes for this portal) are dispatched now
	// while the portal still exists, so they don't float around and try to
	// resurrect the portal after it's deleted.
	if c.msgBuffer != nil {
		c.msgBuffer.flush()
	}
	c.flushPendingPortalMsgs()

	log := zerolog.Ctx(ctx)
	portalID := string(msg.Portal.ID)

	// Mark as deleted in memory — NOT a tombstone, just echo protection.
	// New messages from this contact should still create fresh portals.
	c.recentlyDeletedPortalsMu.Lock()
	if c.recentlyDeletedPortals == nil {
		c.recentlyDeletedPortals = make(map[string]deletedPortalEntry)
	}
	c.recentlyDeletedPortals[portalID] = deletedPortalEntry{
		deletedAt: time.Now(),
	}
	c.recentlyDeletedPortalsMu.Unlock()

	// Clean up local DB — soft-deletes cloud_message rows (preserves UUIDs for
	// echo detection) and hard-deletes cloud_chat rows. This prevents stale APNs
	// echoes from resurrecting the portal even after a bridge restart.
	if c.cloudStore != nil {
		groupID := ""
		if strings.HasPrefix(portalID, "gid:") {
			groupID = strings.TrimPrefix(portalID, "gid:")
		}
		if err := c.cloudStore.deleteLocalChatByPortalID(ctx, portalID); err != nil {
			log.Warn().Err(err).Str("portal_id", portalID).Msg("Failed to soft-delete local cloud records")
		} else {
			log.Info().Str("portal_id", portalID).Msg("Soft-deleted local cloud_chat and cloud_message records")
		}
		if groupID != "" {
			if err := c.cloudStore.deleteLocalChatByGroupID(ctx, groupID); err != nil {
				log.Warn().Err(err).Str("group_id", groupID).Msg("Failed to soft-delete local cloud records by group_id")
			}
		}
	}

	return nil
}

// findAndDeleteCloudChatByIdentifier syncs all chat records from CloudKit,
// finds ones matching the given chat_identifier (e.g. "iMessage;-;user@example.com"),
// and deletes them. Used as a fallback when local DB doesn't have record_names.
//
// Note: This uses the same CloudSyncChats API starting from nil token (full scan).
// CloudKit change tokens are client-side state — this does NOT advance the main
// sync controller's server-side watermark or cause it to miss changes.
func (c *IMClient) findAndDeleteCloudChatByIdentifier(log zerolog.Logger, chatIdentifier string) {
	log.Info().Str("chat_identifier", chatIdentifier).Msg("Querying CloudKit for chat records to delete")

	var matchingRecordNames []string
	var token *string

	for page := 0; page < 256; page++ {
		resp, err := safeCloudSyncChats(c.client, token)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to sync chats from CloudKit for delete lookup")
			return
		}
		for _, chat := range resp.Chats {
			if chat.CloudChatId == chatIdentifier && chat.RecordName != "" {
				matchingRecordNames = append(matchingRecordNames, chat.RecordName)
			}
		}
		prev := ptrStringOr(token, "")
		token = resp.ContinuationToken
		if resp.Done || (page > 0 && prev == ptrStringOr(token, "")) {
			break
		}
	}

	if len(matchingRecordNames) == 0 {
		log.Info().Str("chat_identifier", chatIdentifier).Msg("No matching chat records found in CloudKit")
	} else if err := c.client.DeleteCloudChats(matchingRecordNames); err != nil {
		log.Warn().Err(err).Strs("record_names", matchingRecordNames).Msg("Failed to delete chat records found via CloudKit query")
	} else {
		log.Info().Int("count", len(matchingRecordNames)).Str("chat_identifier", chatIdentifier).Msg("Deleted chat records found via CloudKit query")
	}
}

// findAndDeleteCloudMessagesByChatIdentifier syncs all message records from CloudKit,
// finds ones belonging to the given chat_identifier (matched via cloud_chat_id),
// and deletes them. This prevents deleted chat portals from reappearing on fresh sync.
//
// Note: Same as findAndDeleteCloudChatByIdentifier — uses full scan from nil token.
// Does not interfere with the main sync controller's change tokens.
func (c *IMClient) findAndDeleteCloudMessagesByChatIdentifier(log zerolog.Logger, chatIdentifier string) {
	log.Info().Str("chat_identifier", chatIdentifier).Msg("Querying CloudKit for message records to delete")

	var matchingRecordNames []string
	var token *string

	for page := 0; page < 256; page++ {
		resp, err := safeCloudSyncMessages(c.client, token)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to sync messages from CloudKit for delete lookup")
			return
		}
		for _, msg := range resp.Messages {
			if msg.CloudChatId == chatIdentifier && msg.RecordName != "" {
				matchingRecordNames = append(matchingRecordNames, msg.RecordName)
			}
		}
		prev := ptrStringOr(token, "")
		token = resp.ContinuationToken
		if resp.Done || (page > 0 && prev == ptrStringOr(token, "")) {
			break
		}
	}

	if len(matchingRecordNames) == 0 {
		log.Info().Str("chat_identifier", chatIdentifier).Msg("No matching message records found in CloudKit")
		return
	}

	if err := c.client.DeleteCloudMessages(matchingRecordNames); err != nil {
		log.Warn().Err(err).Int("count", len(matchingRecordNames)).Msg("Failed to delete message records found via CloudKit query")
	} else {
		log.Info().Int("count", len(matchingRecordNames)).Str("chat_identifier", chatIdentifier).Msg("Deleted message records found via CloudKit query")
	}
}

// ============================================================================
// Chat & user info
// ============================================================================

func (c *IMClient) GetChatInfo(ctx context.Context, portal *bridgev2.Portal) (*bridgev2.ChatInfo, error) {
	portalID := string(portal.ID)
	// Groups use "gid:<UUID>" portal IDs, or legacy comma-separated participant IDs
	isGroup := strings.HasPrefix(portalID, "gid:") || strings.Contains(portalID, ",")

	canBackfill := false
	if c.cloudStore != nil {
		if hasMessages, err := c.cloudStore.hasPortalMessages(ctx, portalID); err == nil {
			canBackfill = hasMessages
		}
	}

	chatInfo := &bridgev2.ChatInfo{
		CanBackfill: canBackfill,
		// Suppress bridge bot timeline messages for name/member changes
		// during ChatResync. Real-time renames go through handleRename
		// which sends its own ChatInfoChange event (with timeline visibility).
		ExcludeChangesFromTimeline: true,
	}

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

		// Only set the group name for NEW portals (no Matrix room yet).
		// For existing portals, skip — the name is managed by handleRename
		// (explicit renames) and makePortalKey's envelope-change detection.
		// Setting the name here for existing portals would revert correct
		// names to stale values from CloudKit or metadata, and produce
		// unwanted bridge bot "name changed" events.
		if portal.MXID == "" || portal.Name == "" {
			groupName := c.resolveGroupName(ctx, portalID)
			chatInfo.Name = &groupName
		}

		// Set group photo from locally cached MMCS bytes.
		// Apple's native iMessage clients deliver group photos via MMCS inside
		// APNs IconChange messages — they never write to the CloudKit gp asset
		// field, so a CloudKit round-trip would always fail with MissingGroupPhoto.
		// handleIconChange persists the MMCS bytes to the DB, so we can apply
		// the correct avatar here on portal creation or resync after a restart.
		if c.cloudStore != nil {
			photoLog := c.Main.Bridge.Log.With().Str("portal_id", portalID).Logger()
			photoTS, photoData, gpErr := c.cloudStore.getGroupPhoto(ctx, portalID)
			if gpErr != nil {
				photoLog.Warn().Err(gpErr).Msg("group_photo: DB lookup error")
			} else if len(photoData) == 0 {
				photoLog.Debug().Msg("group_photo: no cached photo in DB")
			} else {
				avatarID := networkid.AvatarID(fmt.Sprintf("icon-change:%d", photoTS))
				photoLog.Info().Int64("ts", photoTS).Int("bytes", len(photoData)).Msg("group_photo: setting avatar from local cache")
				cachedData := photoData
				chatInfo.Avatar = &bridgev2.Avatar{
					ID:  avatarID,
					Get: func(ctx context.Context) ([]byte, error) { return cachedData, nil },
				}
			}
		}

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
		isSelfChat := c.isMyHandle(portalID)

		memberMap := map[networkid.UserID]bridgev2.ChatMember{
			makeUserID(c.handle): {
				EventSender: bridgev2.EventSender{
					IsFromMe:    true,
					SenderLogin: c.UserLogin.ID,
					Sender:      makeUserID(c.handle),
				},
				Membership: event.MembershipJoin,
			},
		}
		// Only add the other user if it's not a self-chat, to avoid
		// overwriting the IsFromMe entry with a duplicate map key.
		if !isSelfChat {
			memberMap[otherUser] = bridgev2.ChatMember{
				EventSender: bridgev2.EventSender{Sender: otherUser},
				Membership:  event.MembershipJoin,
			}
		}

		members := &bridgev2.ChatMemberList{
			IsFull:      true,
			OtherUserID: otherUser,
			MemberMap:   memberMap,
		}

		// For self-chats, set an explicit name and avatar from contacts since
		// the framework can't derive them from the ghost when the "other user"
		// is the logged-in user. Setting Name causes NameIsCustom=true in the
		// framework, which blocks UpdateInfoFromGhost (it returns early when
		// NameIsCustom is set), so we must also set the avatar explicitly here.
		if isSelfChat {
			selfName := c.resolveContactDisplayname(portalID)
			chatInfo.Name = &selfName

			// Pull contact photo for self-chat room avatar.
			localID := stripIdentifierPrefix(portalID)
			if c.contacts != nil {
				if contact, _ := c.contacts.GetContactInfo(localID); contact != nil && len(contact.Avatar) > 0 {
					avatarHash := sha256.Sum256(contact.Avatar)
					avatarData := contact.Avatar
					chatInfo.Avatar = &bridgev2.Avatar{
						ID: networkid.AvatarID(fmt.Sprintf("contact:%s:%s", portalID, hex.EncodeToString(avatarHash[:8]))),
						Get: func(ctx context.Context) ([]byte, error) {
							return avatarData, nil
						},
					}
				}
			}
		}
		// For regular DMs, don't set an explicit room name. With
		// private_chat_portal_meta, the framework derives it from the ghost's
		// display name, which auto-updates when contacts are edited.
		chatInfo.Members = members
	}

	return chatInfo, nil
}

// resolveContactDisplayname returns a contact-resolved display name for the
// given identifier (e.g. "tel:+1234567890"). Falls back to formatting the
// raw identifier if no contact is found.
func (c *IMClient) resolveContactDisplayname(identifier string) string {
	localID := stripIdentifierPrefix(identifier)
	if c.contacts != nil {
		if contact, _ := c.contacts.GetContactInfo(localID); contact != nil && contact.HasName() {
			return c.Main.Config.FormatDisplayname(DisplaynameParams{
				FirstName: contact.FirstName,
				LastName:  contact.LastName,
				Nickname:  contact.Nickname,
				ID:        localID,
			})
		}
	}
	return c.Main.Config.FormatDisplayname(identifierToDisplaynameParams(identifier))
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
	if c.contacts != nil {
		contact, _ = c.contacts.GetContactInfo(localID)
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
// Backfill (CloudKit cache-backed)
// ============================================================================

// GetBackfillMaxBatchCount returns -1 (unlimited) so backward backfill
// processes all available messages in cloud_message without a batch cap.
// When the user caps max_initial_messages, FetchMessages short-circuits
// backward requests to return empty immediately.
func (c *IMClient) GetBackfillMaxBatchCount(_ context.Context, _ *bridgev2.Portal, _ *database.BackfillTask) int {
	return -1
}

type cloudBackfillCursor struct {
	TimestampMS int64  `json:"ts"`
	GUID        string `json:"g"`
}

func (c *IMClient) FetchMessages(ctx context.Context, params bridgev2.FetchMessagesParams) (*bridgev2.FetchMessagesResponse, error) {
	fetchStart := time.Now()
	log := zerolog.Ctx(ctx)

	// For forward backfill calls: ensure the bootstrap pending counter is
	// decremented on every return path. The normal path (with messages) sets
	// forwardDone=true and uses CompleteCallback to decrement AFTER bridgev2
	// delivers the batch to Matrix. All other paths (early return, empty
	// result, error) decrement here via defer — there is nothing to wait for.
	var forwardDone bool
	if params.Forward {
		defer func() {
			if !forwardDone {
				c.onForwardBackfillDone()
			}
		}()
	}

	if !c.cloudKitBackfillEnabled() || c.cloudStore == nil {
		log.Debug().Bool("forward", params.Forward).Bool("backfill_enabled", c.cloudKitBackfillEnabled()).
			Msg("FetchMessages: backfill not enabled for this user or no cloud store, returning empty")
		return &bridgev2.FetchMessagesResponse{HasMore: false, Forward: params.Forward}, nil
	}

	// When the user has capped max_initial_messages, skip backward backfill
	// entirely. Forward backfill already delivered the capped N messages;
	// returning empty here marks the backward task as done immediately.
	if !params.Forward && c.Main.Bridge.Config.Backfill.MaxInitialMessages < math.MaxInt32 {
		return &bridgev2.FetchMessagesResponse{HasMore: false, Forward: false}, nil
	}

	count := params.Count
	if count <= 0 {
		count = 50
	}

	if params.Portal == nil || params.ThreadRoot != "" {
		log.Debug().Bool("forward", params.Forward).Msg("FetchMessages: nil portal or thread root, returning empty")
		return &bridgev2.FetchMessagesResponse{HasMore: false, Forward: params.Forward}, nil
	}
	portalID := string(params.Portal.ID)
	if portalID == "" {
		log.Debug().Bool("forward", params.Forward).Msg("FetchMessages: empty portal ID, returning empty")
		return &bridgev2.FetchMessagesResponse{HasMore: false, Forward: params.Forward}, nil
	}

	// Guard: if this portal was recently deleted, only backfill if there are
	// live (non-deleted) messages. Prevents backfilling old messages into
	// portals recreated by a genuinely new message.
	c.recentlyDeletedPortalsMu.RLock()
	_, isDeletedPortal := c.recentlyDeletedPortals[portalID]
	c.recentlyDeletedPortalsMu.RUnlock()
	if isDeletedPortal && c.cloudStore != nil {
		rows, err := c.cloudStore.listLatestMessages(context.Background(), portalID, 1)
		if err == nil && len(rows) == 0 {
			log.Info().Str("portal_id", portalID).Msg("FetchMessages: deleted portal with no live messages, returning empty")
			return &bridgev2.FetchMessagesResponse{HasMore: false, Forward: params.Forward}, nil
		}
	}

	// Look up the group display name for system message filtering.
	// Group rename system messages have text == display name but no attributedBody;
	// this lets cloudRowToBackfillMessages filter them with an AND condition.
	var groupDisplayName string
	if c.cloudStore != nil {
		groupDisplayName, _ = c.cloudStore.getDisplayNameByPortalID(ctx, portalID)
	}

	// Forward backfill: return messages for this portal in chronological order.
	// bridgev2 doForwardBackfill calls FetchMessages exactly once (no external
	// pagination), so we loop internally — fetching and converting in chunks of
	// forwardChunkSize to bound per-iteration memory. All messages are
	// accumulated and returned in a single response.
	const forwardChunkSize = 5000
	if params.Forward {
		// Acquire semaphore to limit concurrent forward backfills.
		// This prevents overwhelming CloudKit/Matrix with simultaneous
		// attachment downloads and uploads across many portals.
		// Use a select with ctx.Done() so we don't block the portal event
		// loop indefinitely when all slots are taken — that causes "Portal
		// event channel is still full" errors and dropped events.
		select {
		case c.forwardBackfillSem <- struct{}{}:
		case <-ctx.Done():
			log.Warn().Str("portal_id", portalID).Msg("Forward backfill: context cancelled while waiting for semaphore")
			return &bridgev2.FetchMessagesResponse{HasMore: false, Forward: true}, nil
		}
		defer func() { <-c.forwardBackfillSem }()
		log.Info().
			Str("portal_id", portalID).
			Int("count", count).
			Int("chunk_size", forwardChunkSize).
			Str("trigger", "portal_creation").
			Bool("has_anchor", params.AnchorMessage != nil).
			Msg("Forward backfill START")

		// Determine the starting anchor for the internal pagination loop.
		var cursorTS int64
		var cursorGUID string
		hasCursor := false
		if params.AnchorMessage != nil {
			cursorTS = params.AnchorMessage.Timestamp.UnixMilli()
			cursorGUID = string(params.AnchorMessage.ID)
			hasCursor = true
			log.Debug().
				Str("portal_id", portalID).
				Int64("anchor_ts", cursorTS).
				Str("anchor_guid", cursorGUID).
				Msg("Forward backfill: using anchor — fetching only newer messages")
		}

		var allRows []cloudMessageRow
		totalRows := 0
		chunk := 0
		remaining := count

		if !hasCursor {
			// No anchor: fetch the N most recent messages. listLatestMessages
			// selects the newest N (crash resilience — if interrupted, the
			// delivered messages are recent, not ancient). We reverse to
			// chronological (ASC) order before sending so the Matrix timeline
			// displays correctly.
			queryStart := time.Now()
			rows, queryErr := c.cloudStore.listLatestMessages(ctx, portalID, count)
			if queryErr != nil {
				log.Err(queryErr).Str("portal_id", portalID).Msg("Forward backfill: listLatestMessages FAILED")
				return nil, queryErr
			}
			for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
				rows[i], rows[j] = rows[j], rows[i]
			}
			c.preUploadChunkAttachments(ctx, rows, *log)
			allRows = rows
			totalRows = len(rows)
			chunk = 1
			log.Debug().
				Str("portal_id", portalID).
				Int("rows", totalRows).
				Dur("query_ms", time.Since(queryStart)).
				Msg("Forward backfill: fetched most recent messages")
		} else {
			// Anchor path (catchup): page forward from the anchor message.
			for remaining > 0 {
				chunkLimit := forwardChunkSize
				if chunkLimit > remaining {
					chunkLimit = remaining
				}

				queryStart := time.Now()
				rows, queryErr := c.cloudStore.listForwardMessages(ctx, portalID, cursorTS, cursorGUID, chunkLimit)
				if queryErr != nil {
					log.Err(queryErr).Str("portal_id", portalID).Int("chunk", chunk).Msg("Forward backfill: query FAILED")
					return nil, queryErr
				}
				if len(rows) == 0 {
					break
				}

				// Pre-upload any uncached attachments in this chunk in parallel
				// before conversion. This prevents the sequential conversion loop
				// from doing live CloudKit downloads (90s timeout each), which
				// would hang the portal event loop for hours on large portals.
				c.preUploadChunkAttachments(ctx, rows, *log)

				allRows = append(allRows, rows...)
				totalRows += len(rows)
				chunk++

				log.Debug().
					Str("portal_id", portalID).
					Int("chunk", chunk).
					Int("chunk_rows", len(rows)).
					Int("total_rows", totalRows).
					Dur("chunk_query_ms", time.Since(queryStart)).
					Msg("Forward backfill: chunk fetched")

				// Advance cursor to the last row in this chunk for the next iteration.
				lastRow := rows[len(rows)-1]
				cursorTS = lastRow.TimestampMS
				cursorGUID = lastRow.GUID
				hasCursor = true
				remaining -= len(rows)

				// If we got fewer rows than requested, there are no more.
				if len(rows) < chunkLimit {
					break
				}
			}
		}

		// Convert all rows with two-pass tapback resolution: reactions
		// targeting messages in this batch go into BackfillMessage.Reactions
		// (correct DAG ordering) instead of QueueRemoteEvent (end of DAG).
		allMessages := c.cloudRowsToBackfillMessages(ctx, allRows, groupDisplayName)

		if len(allMessages) == 0 {
			log.Debug().Str("portal_id", portalID).Msg("Forward backfill: no rows to process")
			c.cloudStore.markForwardBackfillDone(ctx, portalID)
			return &bridgev2.FetchMessagesResponse{HasMore: false, Forward: true}, nil
		}

		log.Info().
			Str("portal_id", portalID).
			Int("db_rows", totalRows).
			Int("backfill_msgs", len(allMessages)).
			Int("chunks", chunk).
			Dur("total_ms", time.Since(fetchStart)).
			Msg("Forward backfill COMPLETE — all messages returned for portal creation")

		// Mark done so the outer defer doesn't double-decrement; the
		// CompleteCallback will call onForwardBackfillDone after bridgev2
		// delivers the messages to Matrix (preserving ordering: CloudKit
		// backfill is fully in Matrix before APNs buffer is flushed).
		forwardDone = true
		cloudStoreDone := c.cloudStore
		portalKey := params.Portal.PortalKey

		// Capture latest backfilled message for Receipt 2 target.
		// This ensures we mark the conversation as read up to the very
		// latest message, not just the most recently read outgoing message.
		lastMsg := allMessages[len(allMessages)-1]
		lastMsgID := lastMsg.ID
		lastMsgTS := lastMsg.Timestamp

		return &bridgev2.FetchMessagesResponse{
			Messages: allMessages,
			HasMore:  false,
			Forward:  true,
			// Don't set MarkRead here — MarkReadBy on the batch send creates
			// a homeserver-side read receipt with server time (≈now), which
			// Beeper clients display as "Read at [now]". Instead, rely on
			// the synthetic receipts below for correct timestamps.
			CompleteCallback: func() {
				cloudStoreDone.markForwardBackfillDone(context.Background(), portalID)

				// NOTE: Receipt 1 (ghost "they read my message") is intentionally
				// NOT sent during backfill. CloudKit's date_read_ms is unreliable:
				// real iPhone users have no data (shows "Sent" correctly), but
				// bridge users get wrong timestamps (shows "Seen at [wrong time]").
				// Real-time read receipts via APNs still work after backfill.

				// --- Receipt 2: Double puppet receipt ("I read their message") ---
				// Works for both DMs and group chats. Uses getConversationReadByMe
				// heuristic (last message is from_me → user has read everything).
				// Independent of date_read_ms — covers conversations where the
				// recipient hasn't sent read receipts (SMS, disabled receipts, etc.).
				// Targets the latest backfilled message to mark the entire
				// conversation as read, overwriting forceMarkRead's server-time
				// receipt via SetBeeperInboxState with correct BeeperReadExtra["ts"].
				if readByMe, err := cloudStoreDone.getConversationReadByMe(context.Background(), portalID); err == nil && readByMe {
					c.Main.Bridge.QueueRemoteEvent(c.UserLogin, &simplevent.Receipt{
						EventMeta: simplevent.EventMeta{
							Type:      bridgev2.RemoteEventReadReceipt,
							PortalKey: portalKey,
							Sender: bridgev2.EventSender{
								IsFromMe:    true,
								SenderLogin: c.UserLogin.ID,
								Sender:      makeUserID(c.handle),
							},
							Timestamp: lastMsgTS,
						},
						LastTarget: lastMsgID,
						ReadUpTo:   lastMsgTS,
					})
					log.Info().
						Str("portal_id", portalID).
						Str("last_msg_id", string(lastMsgID)).
						Str("last_msg_ts", lastMsgTS.UTC().Format(time.RFC3339)).
						Msg("Queued double puppet read receipt (I read their message)")
				} else if err != nil {
					log.Warn().Err(err).Str("portal_id", portalID).Msg("Failed to check if conversation is read by me")
				}

				c.onForwardBackfillDone()
			},
		}, nil
	}

	// Backward backfill: triggered by the mautrix bridgev2 backfill queue
	// for portals with CanBackfill=true (set in GetChatInfo when cloud store
	// has messages for this portal). Paginates through older messages.
	cursorDesc := "none (initial page)"
	fetchCount := count + 1
	beforeTS := int64(0)
	beforeGUID := ""
	if params.Cursor != "" {
		cursor, err := decodeCloudBackfillCursor(params.Cursor)
		if err != nil {
			return nil, fmt.Errorf("invalid backfill cursor: %w", err)
		}
		beforeTS = cursor.TimestampMS
		beforeGUID = cursor.GUID
		cursorDesc = fmt.Sprintf("before ts=%d guid=%s", beforeTS, beforeGUID)
	} else if params.AnchorMessage != nil {
		beforeTS = params.AnchorMessage.Timestamp.UnixMilli()
		beforeGUID = string(params.AnchorMessage.ID)
		cursorDesc = fmt.Sprintf("anchor ts=%d id=%s", beforeTS, beforeGUID)
	}

	if beforeTS == 0 && beforeGUID == "" {
		// If forward backfill hasn't completed yet, don't permanently mark backward
		// as done — the anchor will appear once sendBatch finishes.
		if !c.cloudStore.isForwardBackfillDone(ctx, portalID) {
			log.Info().Str("portal_id", portalID).
				Msg("Backward backfill: no anchor yet, forward backfill still in progress — deferring")
			return &bridgev2.FetchMessagesResponse{HasMore: true, Forward: false}, nil
		}
		log.Debug().Str("portal_id", portalID).
			Msg("Backward backfill: no anchor or cursor, nothing to paginate from")
		return &bridgev2.FetchMessagesResponse{HasMore: false, Forward: false}, nil
	}

	log.Info().
		Str("portal_id", portalID).
		Int("count", count).
		Str("cursor", cursorDesc).
		Str("trigger", "backfill_queue").
		Msg("Backward backfill START — paginating older messages")

	queryStart := time.Now()
	rows, err := c.cloudStore.listBackwardMessages(ctx, portalID, beforeTS, beforeGUID, fetchCount)
	if err != nil {
		log.Err(err).Str("portal_id", portalID).Dur("query_ms", time.Since(queryStart)).Msg("Backward backfill: query FAILED")
		return nil, err
	}
	queryElapsed := time.Since(queryStart)

	hasMore := false
	if len(rows) > count {
		hasMore = true
		rows = rows[:count]
	}
	reverseCloudMessageRows(rows)

	convertStart := time.Now()
	messages := c.cloudRowsToBackfillMessages(ctx, rows, groupDisplayName)
	convertElapsed := time.Since(convertStart)

	var nextCursor networkid.PaginationCursor
	if hasMore && len(rows) > 0 {
		cursor, cursorErr := encodeCloudBackfillCursor(cloudBackfillCursor{
			TimestampMS: rows[0].TimestampMS,
			GUID:        rows[0].GUID,
		})
		if cursorErr != nil {
			return nil, cursorErr
		}
		nextCursor = cursor
	}

	log.Info().
		Str("portal_id", portalID).
		Int("db_rows", len(rows)).
		Int("backfill_msgs", len(messages)).
		Bool("has_more", hasMore).
		Dur("query_ms", queryElapsed).
		Dur("convert_ms", convertElapsed).
		Dur("total_ms", time.Since(fetchStart)).
		Msg("Backward backfill COMPLETE — older messages returned")

	return &bridgev2.FetchMessagesResponse{
		Messages: messages,
		Cursor:   nextCursor,
		HasMore:  hasMore,
		Forward:  false,
	}, nil
}

// cloudRowsToBackfillMessages converts a batch of CloudKit rows into backfill
// messages, attaching tapback reactions to their target messages when possible.
// This two-pass approach ensures reactions appear in BackfillMessage.Reactions
// (correct DAG ordering) instead of being queued via QueueRemoteEvent (which
// places them at the end of the DAG, making the sidebar show old reactions).
// Tapback removes and tapbacks targeting messages outside this batch still
// fall back to QueueRemoteEvent.
func (c *IMClient) cloudRowsToBackfillMessages(ctx context.Context, rows []cloudMessageRow, groupDisplayName string) []*bridgev2.BackfillMessage {
	// Pass 1: convert regular messages, defer tapback rows.
	var messages []*bridgev2.BackfillMessage
	var tapbackRows []cloudMessageRow
	messageByGUID := make(map[string]*bridgev2.BackfillMessage)

	for _, row := range rows {
		if row.TapbackType != nil && *row.TapbackType >= 2000 {
			tapbackRows = append(tapbackRows, row)
			continue
		}
		converted := c.cloudRowToBackfillMessages(ctx, row, groupDisplayName)
		messages = append(messages, converted...)
		// Key by row GUID so tapbacks can find their target. A row may
		// produce multiple BackfillMessages (text + attachments); attach
		// the reaction to the first one (text, or first attachment).
		if len(converted) > 0 {
			messageByGUID[row.GUID] = converted[0]
		}
	}

	// Pass 2: resolve tapbacks — attach to target if in this batch,
	// otherwise fall back to QueueRemoteEvent.
	for _, row := range tapbackRows {
		sender := c.makeCloudSender(row)
		if sender.Sender == "" && !sender.IsFromMe {
			continue
		}

		tapbackType := *row.TapbackType
		isRemove := tapbackType >= 3000

		// Parse target GUID from "p:0/GUID" format.
		targetGUID := row.TapbackTargetGUID
		if parts := strings.SplitN(targetGUID, "/", 2); len(parts) == 2 {
			targetGUID = parts[1]
		}
		if targetGUID == "" {
			continue
		}

		// Removes can't use BackfillReaction (framework only supports add).
		// Tapbacks targeting messages outside this batch also fall back.
		targetMsg, inBatch := messageByGUID[targetGUID]
		if !isRemove && inBatch {
			ts := time.UnixMilli(row.TimestampMS)
			idx := tapbackType - 2000
			emoji := tapbackTypeToEmoji(&idx, &row.TapbackEmoji)
			targetMsg.Reactions = append(targetMsg.Reactions, &bridgev2.BackfillReaction{
				Sender:    sender,
				Emoji:     emoji,
				Timestamp: ts,
			})
		} else {
			// Fall back to QueueRemoteEvent for removes and out-of-batch targets.
			c.cloudTapbackToBackfill(row, sender, time.UnixMilli(row.TimestampMS))
		}
	}

	return messages
}

func (c *IMClient) cloudRowToBackfillMessages(ctx context.Context, row cloudMessageRow, groupDisplayName string) []*bridgev2.BackfillMessage {
	sender := c.makeCloudSender(row)
	ts := time.UnixMilli(row.TimestampMS)

	// Skip messages with no resolvable sender. These are typically iMessage
	// system/notification records (group renames, participant changes, etc.)
	// stored in CloudKit without a sender field. Without this check, bridgev2
	// falls back to the bridge bot as the sender, producing spurious bot
	// messages in the backfilled timeline.
	if sender.Sender == "" && !sender.IsFromMe {
		return nil
	}

	// Skip system/service messages (group renames, participant changes, etc.).
	// Two complementary signals — either is sufficient:
	//   !HasBody: rows stored after the has_body column was added have
	//     has_body=FALSE when there is no attributedBody (i.e. system
	//     messages). All real user messages always carry an attributedBody.
	//   text==groupDisplayName: for older rows whose has_body defaulted to
	//     TRUE, the rename-notification text exactly matches the group name.
	// The startup DB cleanup (ensureSchema) hard-deletes matching rows so
	// this filter is a second line of defence for any that slipped through.
	isSystemByHasBody := !row.HasBody && row.AttachmentsJSON == "" && row.TapbackType == nil
	isSystemByName := row.Text != "" && groupDisplayName != "" && row.Text == groupDisplayName && row.AttachmentsJSON == "" && row.TapbackType == nil
	if isSystemByHasBody || isSystemByName {
		return nil
	}

	// Tapback/reaction: return as a reaction event, not a text message.
	if row.TapbackType != nil && *row.TapbackType >= 2000 {
		return c.cloudTapbackToBackfill(row, sender, ts)
	}

	var messages []*bridgev2.BackfillMessage

	// Text message — trim OBJ placeholders before building body.
	body := strings.Trim(row.Text, "\ufffc \n")
	var formattedBody string
	if row.Subject != "" {
		if body != "" {
			formattedBody = fmt.Sprintf("<strong>%s</strong><br>%s", html.EscapeString(row.Subject), html.EscapeString(body))
			body = fmt.Sprintf("**%s**\n%s", row.Subject, body)
		} else {
			body = row.Subject
		}
	}
	hasText := strings.TrimSpace(body) != ""
	if hasText {
		textContent := &event.MessageEventContent{
			MsgType: event.MsgText,
			Body:    body,
		}
		if formattedBody != "" {
			textContent.Format = event.FormatHTML
			textContent.FormattedBody = formattedBody
		}
		if detectedURL := urlRegex.FindString(row.Text); detectedURL != "" {
			textContent.BeeperLinkPreviews = []*event.BeeperLinkPreview{
				fetchURLPreview(ctx, c.Main.Bridge, c.Main.Bridge.Bot, detectedURL),
			}
		}
		messages = append(messages, &bridgev2.BackfillMessage{
			Sender:    sender,
			ID:        makeMessageID(row.GUID),
			Timestamp: ts,
			ConvertedMessage: &bridgev2.ConvertedMessage{
				Parts: []*bridgev2.ConvertedMessagePart{{
					Type:    event.EventMessage,
					Content: textContent,
				}},
			},
		})
	}

	// Attachments: downloadAndUploadAttachment checks attachmentContentCache first,
	// so this is a cheap cache lookup when preUploadCloudAttachments has run.
	attMessages := c.cloudAttachmentsToBackfill(ctx, row, sender, ts, hasText)
	messages = append(messages, attMessages...)

	// No text, no attachments, no tapback → likely a deleted/unsent message
	// whose content was wiped from CloudKit.  Skip silently.

	return messages
}

func (c *IMClient) makeCloudSender(row cloudMessageRow) bridgev2.EventSender {
	if row.IsFromMe {
		return bridgev2.EventSender{
			IsFromMe:    true,
			SenderLogin: c.UserLogin.ID,
			Sender:      makeUserID(c.handle),
		}
	}
	normalizedSender := normalizeIdentifierForPortalID(row.Sender)
	if normalizedSender == "" {
		normalizedSender = row.Sender
	}
	return bridgev2.EventSender{Sender: makeUserID(normalizedSender)}
}

// cloudTapbackToBackfill converts a CloudKit reaction record to a backfill reaction event.
func (c *IMClient) cloudTapbackToBackfill(row cloudMessageRow, sender bridgev2.EventSender, ts time.Time) []*bridgev2.BackfillMessage {
	tapbackType := *row.TapbackType
	isRemove := tapbackType >= 3000
	idx := tapbackType - 2000
	if isRemove {
		idx = tapbackType - 3000
	}
	emoji := tapbackTypeToEmoji(&idx, &row.TapbackEmoji)

	// Parse target GUID from "p:0/GUID" format
	targetGUID := row.TapbackTargetGUID
	if parts := strings.SplitN(targetGUID, "/", 2); len(parts) == 2 {
		targetGUID = parts[1]
	}
	if targetGUID == "" {
		return nil
	}

	evtType := bridgev2.RemoteEventReaction
	if isRemove {
		evtType = bridgev2.RemoteEventReactionRemove
	}

	// Reactions are sent as remote events, not backfill messages.
	// We queue them so the bridge handles dedup and target resolution.
	portalKey := networkid.PortalKey{
		ID:       networkid.PortalID(row.PortalID),
		Receiver: c.UserLogin.ID,
	}
	c.UserLogin.QueueRemoteEvent(&simplevent.Reaction{
		EventMeta: simplevent.EventMeta{
			Type:      evtType,
			PortalKey: portalKey,
			Sender:    sender,
			Timestamp: ts,
		},
		TargetMessage: makeMessageID(targetGUID),
		Emoji:         emoji,
	})
	return nil
}

// cloudAttachmentResult holds the result of a concurrent attachment download+upload.
type cloudAttachmentResult struct {
	Index   int
	Message *bridgev2.BackfillMessage
}

// cloudAttachmentsToBackfill downloads CloudKit attachments, uploads them to
// the Matrix media repo, and returns backfill messages with media URLs set.
// Downloads and uploads run concurrently (up to 4 at a time) for speed.
func (c *IMClient) cloudAttachmentsToBackfill(ctx context.Context, row cloudMessageRow, sender bridgev2.EventSender, ts time.Time, hasText bool) []*bridgev2.BackfillMessage {
	if row.AttachmentsJSON == "" {
		return nil
	}
	var atts []cloudAttachmentRow
	if err := json.Unmarshal([]byte(row.AttachmentsJSON), &atts); err != nil {
		return nil
	}

	// Filter to downloadable attachments.
	type indexedAtt struct {
		index int
		att   cloudAttachmentRow
	}
	var downloadable []indexedAtt
	for i, att := range atts {
		if att.RecordName != "" {
			downloadable = append(downloadable, indexedAtt{index: i, att: att})
		}
	}
	if len(downloadable) == 0 {
		return nil
	}
	// For a single attachment, skip goroutine overhead.
	if len(downloadable) == 1 {
		return c.downloadAndUploadAttachment(ctx, row, sender, ts, hasText, downloadable[0].index, downloadable[0].att)
	}

	// Concurrent download+upload with bounded parallelism.
	const maxParallel = 4
	sem := make(chan struct{}, maxParallel)
	results := make(chan cloudAttachmentResult, len(downloadable))
	var wg sync.WaitGroup

	for _, da := range downloadable {
		wg.Add(1)
		go func(idx int, att cloudAttachmentRow) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Error().Any("panic", r).Str("stack", string(debug.Stack())).Msg("Recovered panic in attachment download goroutine")
				}
			}()
			sem <- struct{}{}
			defer func() { <-sem }()
			msgs := c.downloadAndUploadAttachment(ctx, row, sender, ts, hasText, idx, att)
			for _, m := range msgs {
				results <- cloudAttachmentResult{Index: idx, Message: m}
			}
		}(da.index, da.att)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results and sort by original index for deterministic ordering.
	var collected []cloudAttachmentResult
	for r := range results {
		collected = append(collected, r)
	}
	sort.Slice(collected, func(i, j int) bool {
		return collected[i].Index < collected[j].Index
	})

	messages := make([]*bridgev2.BackfillMessage, 0, len(collected))
	for _, r := range collected {
		messages = append(messages, r.Message)
	}
	return messages
}

// safeCloudDownloadAttachment wraps the FFI call with panic recovery and a
// 90-second timeout. When Rust stalls on a network hang or an unrecognised
// attachment format the goroutine would otherwise block forever; the timeout
// frees the semaphore slot so other downloads can proceed. The inner goroutine
// is leaked until Rust eventually unblocks, but that is bounded to at most 32
// goroutines and is temporary.
func safeCloudDownloadAttachment(client *rustpushgo.Client, recordName string) ([]byte, error) {
	type dlResult struct {
		data []byte
		err  error
	}
	ch := make(chan dlResult, 1)
	go func() {
		var res dlResult
		defer func() {
			if r := recover(); r != nil {
				stack := string(debug.Stack())
				log.Error().Str("ffi_method", "CloudDownloadAttachment").
					Str("record_name", recordName).
					Str("stack", stack).
					Msgf("FFI panic recovered: %v", r)
				res = dlResult{err: fmt.Errorf("FFI panic in CloudDownloadAttachment: %v", r)}
			}
			ch <- res
		}()
		d, e := client.CloudDownloadAttachment(recordName)
		res = dlResult{data: d, err: e}
	}()
	select {
	case res := <-ch:
		return res.data, res.err
	case <-time.After(90 * time.Second):
		log.Error().Str("ffi_method", "CloudDownloadAttachment").
			Str("record_name", recordName).
			Msg("CloudDownloadAttachment timed out after 90s — inner goroutine leaked until FFI unblocks")
		return nil, fmt.Errorf("CloudDownloadAttachment timed out after 90s")
	}
}

// downloadAndUploadAttachment handles a single attachment: download from CloudKit,
// upload to Matrix, return as a backfill message.
func (c *IMClient) downloadAndUploadAttachment(
	ctx context.Context,
	row cloudMessageRow,
	sender bridgev2.EventSender,
	ts time.Time,
	hasText bool,
	i int,
	att cloudAttachmentRow,
) []*bridgev2.BackfillMessage {
	log := c.Main.Bridge.Log.With().Str("component", "cloud_backfill").Logger()
	intent := c.Main.Bridge.Bot

	attID := row.GUID
	if i > 0 || hasText {
		attID = fmt.Sprintf("%s_att%d", row.GUID, i)
	}

	// Cache hit: preUploadCloudAttachments already downloaded and uploaded this
	// attachment in the cloud sync goroutine. Return immediately without touching
	// CloudKit, keeping the portal event loop unblocked.
	if cached, ok := c.attachmentContentCache.Load(att.RecordName); ok {
		return []*bridgev2.BackfillMessage{{
			Sender:    sender,
			ID:        makeMessageID(attID),
			Timestamp: ts,
			ConvertedMessage: &bridgev2.ConvertedMessage{
				Parts: []*bridgev2.ConvertedMessagePart{{
					Type:    event.EventMessage,
					Content: cached.(*event.MessageEventContent),
				}},
			},
		}}
	}

	data, err := safeCloudDownloadAttachment(c.client, att.RecordName)
	if err != nil {
		fe := c.recordAttachmentFailure(att.RecordName, err.Error())
		log.Warn().Err(err).
			Str("guid", row.GUID).
			Str("att_guid", att.GUID).
			Str("record_name", att.RecordName).
			Int("attempt", fe.retries).
			Msg("Failed to download CloudKit attachment, skipping")
		return nil
	}
	if len(data) == 0 {
		fe := c.recordAttachmentFailure(att.RecordName, "empty data")
		log.Debug().Str("guid", row.GUID).Str("record_name", att.RecordName).
			Int("attempt", fe.retries).
			Msg("CloudKit attachment returned empty data")
		return nil
	}

	mimeType := att.MimeType
	if mimeType == "" {
		mimeType = utiToMIME(att.UTIType)
	}
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	fileName := att.Filename
	if fileName == "" {
		fileName = "attachment"
	}

	// Convert CAF Opus voice messages to OGG Opus for Matrix clients
	var durationMs int
	if att.UTIType == "com.apple.coreaudio-format" || mimeType == "audio/x-caf" {
		data, mimeType, fileName, durationMs = convertAudioForMatrix(data, mimeType, fileName)
	}

	// Convert non-JPEG images to JPEG and extract dimensions/thumbnail
	var imgWidth, imgHeight int
	var thumbData []byte
	var thumbW, thumbH int
	if strings.HasPrefix(mimeType, "image/") || looksLikeImage(data) {
		if mimeType == "image/gif" {
			if cfg, _, err := image.DecodeConfig(bytes.NewReader(data)); err == nil {
				imgWidth, imgHeight = cfg.Width, cfg.Height
			}
		} else if img, _, isJPEG := decodeImageData(data); img != nil {
			b := img.Bounds()
			imgWidth, imgHeight = b.Dx(), b.Dy()
			if !isJPEG {
				var buf bytes.Buffer
				if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 95}); err == nil {
					data = buf.Bytes()
					mimeType = "image/jpeg"
					fileName = strings.TrimSuffix(fileName, filepath.Ext(fileName)) + ".jpg"
				}
			}
			if imgWidth > 800 || imgHeight > 800 {
				thumbData, thumbW, thumbH = scaleAndEncodeThumb(img, imgWidth, imgHeight)
			}
		}
	}

	msgType := mimeToMsgType(mimeType)
	content := &event.MessageEventContent{
		MsgType: msgType,
		Body:    fileName,
		Info: &event.FileInfo{
			MimeType: mimeType,
			Size:     len(data),
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
	}

	url, encFile, uploadErr := intent.UploadMedia(ctx, "", data, fileName, mimeType)
	if uploadErr != nil {
		fe := c.recordAttachmentFailure(att.RecordName, uploadErr.Error())
		log.Warn().Err(uploadErr).
			Str("guid", row.GUID).
			Str("att_guid", att.GUID).
			Int("attempt", fe.retries).
			Msg("Failed to upload attachment to Matrix, skipping")
		return nil
	}
	if encFile != nil {
		content.File = encFile
	} else {
		content.URL = url
	}

	if thumbData != nil {
		thumbURL, thumbEnc, thumbErr := intent.UploadMedia(ctx, "", thumbData, "thumbnail.jpg", "image/jpeg")
		if thumbErr == nil {
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
		}
	}

	// Populate the in-memory cache so any future backfill call for the same
	// attachment returns instantly without re-downloading from CloudKit.
	c.attachmentContentCache.Store(att.RecordName, content)
	// Clear any prior failure tracking — this attachment succeeded.
	c.failedAttachments.Delete(att.RecordName)
	// Persist the mxc URI to SQLite so the cache survives bridge restarts.
	// Future pre-upload passes load this at startup and skip re-downloading.
	if c.cloudStore != nil {
		if jsonBytes, err := json.Marshal(content); err == nil {
			c.cloudStore.saveAttachmentCacheEntry(ctx, att.RecordName, jsonBytes)
		}
	}

	return []*bridgev2.BackfillMessage{{
		Sender:    sender,
		ID:        makeMessageID(attID),
		Timestamp: ts,
		ConvertedMessage: &bridgev2.ConvertedMessage{
			Parts: []*bridgev2.ConvertedMessagePart{{
				Type:    event.EventMessage,
				Content: content,
			}},
		},
	}}
}

// preUploadCloudAttachments downloads every CloudKit attachment recorded in the
// cloud message store and uploads it to Matrix, caching the resulting
// *event.MessageEventContent in attachmentContentCache keyed by record_name.
//
// Call this in the cloud sync goroutine BEFORE createPortalsFromCloudSync.
// When bridgev2 subsequently calls FetchMessages inside the portal event loop,
// every downloadAndUploadAttachment invocation becomes an instant cache lookup
// instead of a multi-second CloudKit download — eliminating the 30+ minute
// portal event loop stall caused by image-heavy conversations (e.g. 486 pics).
func (c *IMClient) preUploadCloudAttachments(ctx context.Context) {
	if c.cloudStore == nil {
		return
	}
	// When the user has capped max_initial_messages, skip the bulk startup
	// pre-upload. The per-chunk preUploadChunkAttachments in FetchMessages
	// already handles attachments for the rows actually being backfilled.
	// The startup pre-upload is an optimization for the unlimited case where
	// thousands of attachments need warming before portal creation.
	if c.Main.Bridge.Config.Backfill.MaxInitialMessages < math.MaxInt32 {
		return
	}
	log := c.Main.Bridge.Log.With().Str("component", "cloud_preupload").Logger()

	rows, err := c.cloudStore.listAllAttachmentMessages(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Pre-upload: failed to list attachment messages, skipping")
		return
	}

	// Load previously persisted mxc URIs into the in-memory cache.
	// This means attachments uploaded in any prior run are instant cache hits
	// in the pending-list filter below — zero CloudKit downloads needed.
	if cachedJSON, err := c.cloudStore.loadAttachmentCacheJSON(ctx); err != nil {
		log.Warn().Err(err).Msg("Pre-upload: failed to load persistent attachment cache, will re-download")
	} else {
		loaded := 0
		for recordName, jsonBytes := range cachedJSON {
			var content event.MessageEventContent
			if err := json.Unmarshal(jsonBytes, &content); err == nil {
				c.attachmentContentCache.Store(recordName, &content)
				loaded++
			}
		}
		if loaded > 0 {
			log.Debug().Int("loaded", loaded).Msg("Pre-upload: restored attachment cache from SQLite")
		}
	}

	// Build the set of portal IDs whose forward FetchMessages has already
	// completed successfully. These portals don't need pre-upload on restart:
	// - Normal restart: all portals are done → skip everything (no re-upload storm)
	// - Interrupted backfill: that portal is NOT in the done set → still pre-uploads
	// Using fwd_backfill_done (set by FetchMessages via CompleteCallback) rather than
	// MXID-existence avoids the interrupted-backfill edge case.
	donePortals, err := c.cloudStore.getForwardBackfillDonePortals(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Pre-upload: failed to query fwd_backfill_done, skipping pre-upload entirely")
		return
	}

	// Build the list of attachments that still need to be uploaded.
	type pendingUpload struct {
		row     cloudMessageRow
		idx     int
		att     cloudAttachmentRow
		sender  bridgev2.EventSender
		ts      time.Time
		hasText bool
	}
	var pending []pendingUpload
	for _, row := range rows {
		portalDone := donePortals[row.PortalID]
		var atts []cloudAttachmentRow
		if err := json.Unmarshal([]byte(row.AttachmentsJSON), &atts); err != nil {
			continue
		}
		sender := c.makeCloudSender(row)
		ts := time.UnixMilli(row.TimestampMS)
		hasText := strings.TrimSpace(strings.Trim(row.Text, "\ufffc \n")) != ""
		for i, att := range atts {
			if att.RecordName == "" {
				continue
			}
			if _, ok := c.attachmentContentCache.Load(att.RecordName); ok {
				continue // already cached from a previous pass
			}
			// Check if this attachment has failed before and whether
			// it has exceeded the retry limit.
			prev, isFailed := c.failedAttachments.Load(att.RecordName)
			if isFailed {
				fe := prev.(*failedAttachmentEntry)
				if fe.retries >= maxAttachmentRetries {
					log.Warn().
						Str("record_name", att.RecordName).
						Str("portal_id", row.PortalID).
						Str("last_error", fe.lastError).
						Int("retries", fe.retries).
						Msg("Pre-upload: abandoning attachment after max retries")
					c.failedAttachments.Delete(att.RecordName)
					continue
				}
			}
			// For done portals, only retry attachments that previously
			// failed (transient). New uncached attachments in done portals
			// were already handled by FetchMessages — no re-upload needed.
			if portalDone {
				if !isFailed {
					continue
				}
				fe := prev.(*failedAttachmentEntry)
				log.Info().
					Str("record_name", att.RecordName).
					Str("portal_id", row.PortalID).
					Int("attempt", fe.retries+1).
					Msg("Pre-upload: retrying previously failed attachment for completed portal")
			}
			pending = append(pending, pendingUpload{
				row: row, idx: i, att: att,
				sender: sender, ts: ts, hasText: hasText,
			})
		}
	}

	if len(pending) == 0 {
		log.Debug().Int("message_rows", len(rows)).Msg("Pre-upload: all attachments already cached")
		return
	}

	log.Info().
		Int("attachments", len(pending)).
		Int("message_rows", len(rows)).
		Msg("Pre-upload: starting CloudKit→Matrix attachment pre-upload before portal creation")

	start := time.Now()
	const maxParallel = 32
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	var uploaded atomic.Int64

	for _, p := range pending {
		wg.Add(1)
		go func(p pendingUpload) {
			defer wg.Done()
			// Check context before acquiring semaphore so shutdown doesn't
			// queue up behind 32 in-flight downloads (each up to 90s).
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					log.Error().Any("panic", r).
						Str("record_name", p.att.RecordName).
						Msg("Pre-upload: recovered panic in attachment goroutine")
				}
			}()
			// downloadAndUploadAttachment stores the result in attachmentContentCache
			// as a side effect; we discard the returned BackfillMessage here.
			result := c.downloadAndUploadAttachment(ctx, p.row, p.sender, p.ts, p.hasText, p.idx, p.att)
			if result != nil {
				uploaded.Add(1)
			}
		}(p)
	}

	// Wait for all uploads to finish. No overall timeout here: the 90s
	// per-download cap in safeCloudDownloadAttachment already bounds the
	// worst case, and the persistent SQLite cache means this only runs for
	// genuinely new/uncached attachments — so it completes fully every time
	// and FetchMessages always gets 100% cache hits.
	wg.Wait()
	failed := int64(len(pending)) - uploaded.Load()
	log.Info().
		Int64("uploaded", uploaded.Load()).
		Int64("failed", failed).
		Int("total", len(pending)).
		Dur("elapsed", time.Since(start)).
		Msg("Pre-upload: CloudKit→Matrix attachment pre-upload complete")
}

// preUploadChunkAttachments downloads and uploads any uncached attachments in
// the given rows in parallel (up to 32 concurrent). Called inline during
// forward backfill before the sequential conversion loop, so that
// downloadAndUploadAttachment gets instant cache hits instead of doing
// sequential 90s CloudKit downloads that hang the portal event loop.
func (c *IMClient) preUploadChunkAttachments(ctx context.Context, rows []cloudMessageRow, log zerolog.Logger) {
	type pendingAtt struct {
		row     cloudMessageRow
		idx     int
		att     cloudAttachmentRow
		sender  bridgev2.EventSender
		ts      time.Time
		hasText bool
	}
	var pending []pendingAtt
	for _, row := range rows {
		if row.AttachmentsJSON == "" {
			continue
		}
		var atts []cloudAttachmentRow
		if err := json.Unmarshal([]byte(row.AttachmentsJSON), &atts); err != nil {
			continue
		}
		sender := c.makeCloudSender(row)
		ts := time.UnixMilli(row.TimestampMS)
		hasText := strings.TrimSpace(strings.Trim(row.Text, "\ufffc \n")) != ""
		for i, att := range atts {
			if att.RecordName == "" {
				continue
			}
			if _, ok := c.attachmentContentCache.Load(att.RecordName); ok {
				continue
			}
			pending = append(pending, pendingAtt{
				row: row, idx: i, att: att,
				sender: sender, ts: ts, hasText: hasText,
			})
		}
	}
	if len(pending) == 0 {
		return
	}
	log.Info().Int("uncached", len(pending)).Msg("Forward backfill: pre-uploading uncached attachments in parallel")
	const maxParallel = 32
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	for _, p := range pending {
		wg.Add(1)
		go func(p pendingAtt) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					log.Error().Any("panic", r).
						Str("record_name", p.att.RecordName).
						Msg("Forward backfill pre-upload: recovered panic")
				}
			}()
			c.downloadAndUploadAttachment(ctx, p.row, p.sender, p.ts, p.hasText, p.idx, p.att)
		}(p)
	}
	wg.Wait()
	log.Info().Int("processed", len(pending)).Msg("Forward backfill: pre-upload complete")
}

func reverseCloudMessageRows(rows []cloudMessageRow) {
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
}

func encodeCloudBackfillCursor(cursor cloudBackfillCursor) (networkid.PaginationCursor, error) {
	data, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(data)
	return networkid.PaginationCursor(encoded), nil
}

func decodeCloudBackfillCursor(cursor networkid.PaginationCursor) (*cloudBackfillCursor, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(string(cursor))
	if err != nil {
		return nil, err
	}
	var parsed cloudBackfillCursor
	if err = json.Unmarshal(decoded, &parsed); err != nil {
		return nil, err
	}
	if parsed.GUID == "" {
		return nil, fmt.Errorf("empty guid in cursor")
	}
	return &parsed, nil
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
			if err := c.contacts.SyncContacts(log); err != nil {
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
			c.contacts = newCloudContactsClient(c.client, log)
			if c.contacts != nil {
				if syncErr := c.contacts.SyncContacts(log); syncErr != nil {
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
	c.imGroupParticipantsMu.Lock()
	c.groupPortalMu.Lock()
	c.lastGroupForMemberMu.Lock()
	c.gidAliasesMu.Lock()
	defer c.gidAliasesMu.Unlock()
	defer c.lastGroupForMemberMu.Unlock()
	defer c.groupPortalMu.Unlock()
	defer c.imGroupParticipantsMu.Unlock()
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
	// Move group participants cache
	if parts, ok := c.imGroupParticipants[oldID]; ok {
		c.imGroupParticipants[newID] = parts
		delete(c.imGroupParticipants, oldID)
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
	// Update gidAliases entries pointing to old portal
	for alias, target := range c.gidAliases {
		if target == oldID {
			c.gidAliases[alias] = newID
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

// resolveExistingGroupByGid tries to find an existing group portal that matches
// the incoming message when the gid (sender_guid) doesn't match any known portal.
// This handles the case where another rustpush client (like OpenBubbles) uses a
// different UUID for the same group conversation.
//
// Resolution order:
//  1. imGroupGuids cache — any existing portal with a matching guid value
//  2. imGroupParticipants cache — portals with overlapping participant sets
//  3. groupPortalIndex — comma-based portals via fuzzy participant matching
//  4. cloud_chat DB — participant matching against all persisted groups
func (c *IMClient) resolveExistingGroupByGid(gidPortalID string, senderGuid string, participants []string) networkid.PortalID {
	ctx := context.Background()
	normalizedGuid := strings.ToLower(senderGuid)

	// 1. Check imGroupGuids cache: does any existing portal already have
	//    this guid cached? (covers comma-based portals that previously
	//    received messages with this same guid)
	c.imGroupGuidsMu.RLock()
	for portalIDStr, guid := range c.imGroupGuids {
		if strings.ToLower(guid) == normalizedGuid {
			c.imGroupGuidsMu.RUnlock()
			key := networkid.PortalKey{ID: networkid.PortalID(portalIDStr), Receiver: c.UserLogin.ID}
			if p, _ := c.Main.Bridge.GetExistingPortalByKey(ctx, key); p != nil && p.MXID != "" {
				c.UserLogin.Log.Info().
					Str("gid_portal_id", gidPortalID).
					Str("resolved_portal", portalIDStr).
					Msg("Resolved unknown gid to existing portal via guid cache")
				return networkid.PortalID(portalIDStr)
			}
			c.imGroupGuidsMu.RLock()
		}
	}
	c.imGroupGuidsMu.RUnlock()

	// Build normalized participant set for matching.
	if len(participants) == 0 {
		return networkid.PortalID(gidPortalID)
	}
	normalizedParts := make([]string, 0, len(participants))
	for _, p := range participants {
		n := normalizeIdentifierForPortalID(p)
		if n != "" {
			normalizedParts = append(normalizedParts, n)
		}
	}
	if len(normalizedParts) == 0 {
		return networkid.PortalID(gidPortalID)
	}

	// 2. Check imGroupParticipants cache: find portals (including other gid:
	//    portals) with matching participant sets.
	c.imGroupParticipantsMu.RLock()
	for portalIDStr, parts := range c.imGroupParticipants {
		if portalIDStr == gidPortalID {
			continue
		}
		if participantSetsMatch(parts, normalizedParts) {
			c.imGroupParticipantsMu.RUnlock()
			key := networkid.PortalKey{ID: networkid.PortalID(portalIDStr), Receiver: c.UserLogin.ID}
			if p, _ := c.Main.Bridge.GetExistingPortalByKey(ctx, key); p != nil && p.MXID != "" {
				c.UserLogin.Log.Info().
					Str("gid_portal_id", gidPortalID).
					Str("resolved_portal", portalIDStr).
					Msg("Resolved unknown gid to existing portal via participant cache")
				return networkid.PortalID(portalIDStr)
			}
			c.imGroupParticipantsMu.RLock()
		}
	}
	c.imGroupParticipantsMu.RUnlock()

	// 3. Check comma-based portals via groupPortalIndex fuzzy matching.
	//    We intentionally skip the guid mismatch rejection here because the
	//    whole point is to find portals where the guid differs (another client
	//    using a different gid for the same group).
	c.ensureGroupPortalIndex()
	sorted := make([]string, 0, len(normalizedParts))
	for _, p := range normalizedParts {
		if !c.isMyHandle(p) {
			sorted = append(sorted, p)
		}
	}
	sorted = append(sorted, normalizeIdentifierForPortalID(c.handle))
	sort.Strings(sorted)
	deduped := sorted[:0]
	for i, s := range sorted {
		if i == 0 || s != sorted[i-1] {
			deduped = append(deduped, s)
		}
	}

	overlap := make(map[string]int)
	c.groupPortalMu.RLock()
	for _, member := range deduped {
		for existingID := range c.groupPortalIndex[member] {
			overlap[existingID]++
		}
	}
	c.groupPortalMu.RUnlock()

	candidateSize := len(deduped)
	for existingID, sharedCount := range overlap {
		existingSize := len(strings.Split(existingID, ","))
		diff := (candidateSize - sharedCount) + (existingSize - sharedCount)
		if diff > 1 {
			continue
		}
		key := networkid.PortalKey{ID: networkid.PortalID(existingID), Receiver: c.UserLogin.ID}
		if p, _ := c.Main.Bridge.GetExistingPortalByKey(ctx, key); p != nil && p.MXID != "" {
			c.UserLogin.Log.Info().
				Str("gid_portal_id", gidPortalID).
				Str("resolved_portal", existingID).
				Int("participant_diff", diff).
				Msg("Resolved unknown gid to existing comma-based portal via fuzzy match")
			return networkid.PortalID(existingID)
		}
	}

	// 4. Fall back to cloud_chat DB for portals not in memory caches
	//    (e.g., gid: portals from CloudKit sync that haven't received
	//    live messages yet, so imGroupParticipants is empty).
	if c.cloudStore != nil {
		matches, err := c.cloudStore.findPortalIDsByParticipants(ctx, normalizedParts)
		if err == nil {
			for _, matchPortalID := range matches {
				if matchPortalID == gidPortalID {
					continue
				}
				key := networkid.PortalKey{ID: networkid.PortalID(matchPortalID), Receiver: c.UserLogin.ID}
				if p, _ := c.Main.Bridge.GetExistingPortalByKey(ctx, key); p != nil && p.MXID != "" {
					c.UserLogin.Log.Info().
						Str("gid_portal_id", gidPortalID).
						Str("resolved_portal", matchPortalID).
						Msg("Resolved unknown gid to existing portal via cloud_chat DB")
					return networkid.PortalID(matchPortalID)
				}
			}
		}
	}

	// No existing portal found — this is genuinely a new group.
	return networkid.PortalID(gidPortalID)
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
			gidID := "gid:" + strings.ToLower(*senderGuid)

			// Fast path: check if we've previously resolved this gid to
			// a different portal (cached from a prior resolution).
			c.gidAliasesMu.RLock()
			aliasedID, hasAlias := c.gidAliases[gidID]
			c.gidAliasesMu.RUnlock()
			if hasAlias {
				portalID = networkid.PortalID(aliasedID)
			} else {
				// Check if a portal with this exact gid already exists.
				ctx := context.Background()
				gidKey := networkid.PortalKey{ID: networkid.PortalID(gidID), Receiver: c.UserLogin.ID}
				if existing, _ := c.Main.Bridge.GetExistingPortalByKey(ctx, gidKey); existing != nil && existing.MXID != "" {
					portalID = networkid.PortalID(gidID)
				} else {
					// This gid doesn't match any existing portal. Another
					// rustpush client (like OpenBubbles) may use a different
					// gid for the same group. Try to resolve by participants.
					portalID = c.resolveExistingGroupByGid(gidID, *senderGuid, participants)
					// Cache the alias so subsequent messages with this gid
					// resolve instantly without repeated participant matching.
					if string(portalID) != gidID {
						c.gidAliasesMu.Lock()
						c.gidAliases[gidID] = string(portalID)
						c.gidAliasesMu.Unlock()
					}
				}
			}
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
		// messages can route to the correct conversation. Also push a
		// room name update when the envelope name differs from what's
		// cached OR on the first message after restart (old is empty).
		// After restart, imGroupNames is empty and the portal may have
		// a stale name from CloudKit. Pushing on first message ensures
		// the correct cv_name from APNs overrides any stale data.
		// bridgev2's updateName deduplicates — no state event if the
		// name is already correct.
		if groupName != nil && *groupName != "" {
			c.imGroupNamesMu.Lock()
			old := c.imGroupNames[string(portalID)]
			c.imGroupNames[string(portalID)] = *groupName
			c.imGroupNamesMu.Unlock()
			if old != *groupName {
				newName := *groupName
				pid := string(portalID)
				go func() {
					c.UserLogin.QueueRemoteEvent(&simplevent.ChatInfoChange{
						EventMeta: simplevent.EventMeta{
							Type: bridgev2.RemoteEventChatInfoChange,
							PortalKey: networkid.PortalKey{
								ID:       portalID,
								Receiver: c.UserLogin.ID,
							},
							LogContext: func(lc zerolog.Context) zerolog.Context {
								return lc.Str("portal_id", pid).Str("source", "envelope_name_change")
							},
						},
						ChatInfoChange: &bridgev2.ChatInfoChange{
							ChatInfo: &bridgev2.ChatInfo{
								Name:                       &newName,
								ExcludeChangesFromTimeline: true,
							},
						},
					})
				}()
			}
		}
		// Cache normalized participants in memory so resolveGroupMembers
		// can find them immediately. The cloud_chat DB write happens async
		// and may not complete before GetChatInfo is called during portal
		// creation, which would cause the group name to resolve as "Group Chat".
		if len(participants) > 0 {
			normalized := make([]string, 0, len(participants))
			for _, p := range participants {
				n := normalizeIdentifierForPortalID(p)
				if n != "" {
					normalized = append(normalized, n)
				}
			}
			if len(normalized) > 0 {
				c.imGroupParticipantsMu.Lock()
				c.imGroupParticipants[string(portalID)] = normalized
				c.imGroupParticipantsMu.Unlock()
			}
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
		// Persist participants to cloud_chat so portalToConversation can
		// find them for outbound messages (even if CloudKit never synced this group).
		if strings.HasPrefix(string(portalID), "gid:") && len(participants) > 0 {
			go func(pk networkid.PortalKey, parts []string, guid string) {
				if c.cloudStore == nil {
					return
				}
				ctx := context.Background()
				// Only insert if no cloud_chat record exists yet
				existing, err := c.cloudStore.getChatParticipantsByPortalID(ctx, string(pk.ID))
				if err == nil && len(existing) > 0 {
					return // already have participants
				}
				if upsertErr := c.cloudStore.upsertChat(ctx, guid, "", guid, string(pk.ID), "iMessage", nil, nil, parts, 0); upsertErr != nil {
					c.Main.Bridge.Log.Warn().Err(upsertErr).Str("portal_id", string(pk.ID)).Msg("Failed to persist real-time group participants")
				} else {
					c.Main.Bridge.Log.Info().Str("portal_id", string(pk.ID)).Int("participants", len(parts)).Msg("Persisted real-time group participants to cloud_chat")
				}
			}(portalKey, participants, persistGuid)
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
			// Look up participants from cloud store
			if c.cloudStore != nil {
				ctx := context.Background()
				if parts, err := c.cloudStore.getChatParticipantsByPortalID(ctx, portalID); err == nil && len(parts) > 0 {
					participants = parts
				}
			}
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
// For gid: portals it checks the in-memory cache first (populated synchronously
// by makePortalKey), then the cloud store DB; for legacy comma-separated
// portal IDs it splits the ID string.
func (c *IMClient) resolveGroupMembers(ctx context.Context, portalID string) []string {
	if strings.HasPrefix(portalID, "gid:") {
		// 1) Check cloud store DB (persisted from CloudKit sync or previous messages)
		if c.cloudStore != nil {
			if participants, err := c.cloudStore.getChatParticipantsByPortalID(ctx, portalID); err == nil && len(participants) > 0 {
				return participants
			}
		}
		// 2) Fallback to in-memory cache (populated synchronously by makePortalKey).
		// The cloud_chat DB write is async and may not have completed yet when
		// GetChatInfo is called during portal creation from a real-time message.
		c.imGroupParticipantsMu.RLock()
		cached := c.imGroupParticipants[portalID]
		c.imGroupParticipantsMu.RUnlock()
		if len(cached) > 0 {
			return cached
		}
		return nil
	}
	return strings.Split(portalID, ",")
}

// resolveGroupName determines the best display name for a group portal.
// Priority: 1) in-memory cache (user-set iMessage group name from real-time
//              protocol cv_name, e.g. when someone explicitly renames a group)
//           2) CloudKit display_name (user-set group name persisted to iCloud,
//              the "name" field on CKChatRecord = cv_name from chat.db)
//           3) contact-resolved member names via buildGroupName
func (c *IMClient) resolveGroupName(ctx context.Context, portalID string) string {
	// 1) In-memory cache (populated from real-time iMessage rename messages)
	c.imGroupNamesMu.RLock()
	name := c.imGroupNames[portalID]
	c.imGroupNamesMu.RUnlock()
	if name != "" {
		return name
	}

	// 2) CloudKit display_name (user-set group name from iCloud).
	if c.cloudStore != nil {
		if dn, err := c.cloudStore.getDisplayNameByPortalID(ctx, portalID); err == nil && dn != "" {
			return dn
		}
	}

	// 3) Build from contact-resolved member names
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
		if c.contacts != nil {
			contact, _ = c.contacts.GetContactInfo(lookupID)
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
	text := strings.Trim(ptrStringOr(msg.Text, ""), "\ufffc \n")
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

// utiToMIME converts an Apple UTI type to its MIME equivalent.
// Used as a fallback when CloudKit attachment records have a UTI but no MIME type.
func utiToMIME(uti string) string {
	switch uti {
	case "public.jpeg":
		return "image/jpeg"
	case "public.png":
		return "image/png"
	case "com.compuserve.gif":
		return "image/gif"
	case "public.tiff":
		return "image/tiff"
	case "public.heic":
		return "image/heic"
	case "public.heif":
		return "image/heif"
	case "public.webp":
		return "image/webp"
	case "public.mpeg-4":
		return "video/mp4"
	case "com.apple.quicktime-movie":
		return "video/quicktime"
	case "public.mp3":
		return "audio/mpeg"
	case "public.aac-audio":
		return "audio/aac"
	case "com.apple.coreaudio-format":
		return "audio/x-caf"
	default:
		return ""
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

// resolvePortalByTargetMessage looks up a message by UUID in the bridge database
// and returns the portal key it belongs to. This is critical for unsends and edits
// that arrive as self-reflections from the user's other Apple devices: the APNs
// envelope has participants=[self, self], so makePortalKey can't determine the
// correct DM portal. Returns an empty PortalKey if not found.
func (c *IMClient) resolvePortalByTargetMessage(log zerolog.Logger, targetUUID string) networkid.PortalKey {
	if targetUUID == "" {
		return networkid.PortalKey{}
	}
	msgID := makeMessageID(targetUUID)
	dbMessages, err := c.Main.Bridge.DB.Message.GetAllPartsByID(
		context.Background(), c.UserLogin.ID, msgID)
	if err != nil || len(dbMessages) == 0 {
		return networkid.PortalKey{}
	}
	log.Debug().
		Str("target_uuid", targetUUID).
		Str("resolved_portal", string(dbMessages[0].Room.ID)).
		Msg("Resolved portal via target message UUID lookup")
	return dbMessages[0].Room
}

func (c *IMClient) trackOutboundUnsend(uuid string) {
	c.recentOutboundUnsendsLock.Lock()
	defer c.recentOutboundUnsendsLock.Unlock()
	c.recentOutboundUnsends[uuid] = time.Now()
	for k, t := range c.recentOutboundUnsends {
		if time.Since(t) > 5*time.Minute {
			delete(c.recentOutboundUnsends, k)
		}
	}
}

func (c *IMClient) wasOutboundUnsend(uuid string) bool {
	c.recentOutboundUnsendsLock.Lock()
	defer c.recentOutboundUnsendsLock.Unlock()
	if t, ok := c.recentOutboundUnsends[uuid]; ok {
		if time.Since(t) < 5*time.Minute {
			delete(c.recentOutboundUnsends, uuid)
			return true
		}
		delete(c.recentOutboundUnsends, uuid)
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
