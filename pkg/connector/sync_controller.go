package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/simplevent"

	"github.com/lrhodin/imessage/pkg/rustpushgo"
)

// No periodic polling needed: real-time messages arrive via APNs push
// on com.apple.madrid. CloudKit sync is only used for initial backfill
// of historical messages (bootstrap).

// cloudSyncVersion is bumped when sync logic changes in a way that
// requires a one-time full re-download from CloudKit (e.g. improved PCS
// key handling that can now decrypt previously-skipped records).
// Increment this to trigger a token clear on the next bootstrap.
const cloudSyncVersion = 4

// cloudChatSyncVersion is bumped when chat-specific sync logic changes in a
// way that requires a one-time full re-download of the chatManateeZone only
// (not messages). This avoids the expensive message re-download that
// bumping cloudSyncVersion would cause.
// Current bump: 2 — populate group_photo_guid for all group chats.
const cloudChatSyncVersion = 2

type cloudSyncCounters struct {
	Imported int
	Updated  int
	Skipped  int
	Deleted  int
	Filtered int
}

func (c *cloudSyncCounters) add(other cloudSyncCounters) {
	c.Imported += other.Imported
	c.Updated += other.Updated
	c.Skipped += other.Skipped
	c.Deleted += other.Deleted
	c.Filtered += other.Filtered
}

func (c *IMClient) setCloudSyncDone() {
	c.cloudSyncDoneLock.Lock()
	c.cloudSyncDone = true
	c.cloudSyncDoneLock.Unlock()

	// Flush the APNs reorder buffer once all forward backfills are complete.
	// Messages accumulated during CloudKit sync to avoid interleaving APNs
	// messages before older CloudKit messages in Matrix.
	//
	// If there are pending initial backfills (portals queued by the bootstrap
	// createPortalsFromCloudSync pass), we wait for each FetchMessages call
	// to complete and deliver its batch to Matrix (via CompleteCallback) before
	// flushing. This ensures APNs messages appear AFTER the CloudKit history,
	// not interleaved with it.
	//
	// If no portals were queued (fresh sync with no history, or all portals
	// already up-to-date), flush immediately.
	pending := atomic.LoadInt64(&c.pendingInitialBackfills)
	if pending <= 0 {
		log.Info().Msg("No pending initial backfills — flushing APNs buffer immediately")
		atomic.StoreInt64(&c.apnsBufferFlushedAt, time.Now().UnixMilli())
		if c.msgBuffer != nil {
			c.msgBuffer.flush()
		}
		c.flushPendingPortalMsgs()
		return
	}

	log.Info().Int64("pending", pending).
		Msg("Waiting for initial forward backfills before flushing APNs buffer")

	// Safety-net goroutine: if some FetchMessages calls never complete (e.g.
	// portal deleted before bridgev2 processes the ChatResync event, or a
	// crash/panic inside FetchMessages), force-flush the buffer so APNs
	// messages are never permanently suppressed.
	//
	// Uses an activity-based deadline rather than a fixed one: the timer
	// resets every time any forward backfill completes. This lets slow
	// hardware (or large accounts) take as long as needed, while still
	// eventually force-flushing if nothing makes progress for 5 minutes
	// (i.e. a portal is genuinely stuck and will never finish).
	go func() {
		const noProgressTimeout = 5 * time.Minute
		lastCount := atomic.LoadInt64(&c.pendingInitialBackfills)
		deadline := time.Now().Add(noProgressTimeout)
		for time.Now().Before(deadline) {
			if atomic.LoadInt64(&c.pendingInitialBackfills) <= 0 {
				// onForwardBackfillDone already flushed the buffer.
				return
			}
			time.Sleep(250 * time.Millisecond)
			if current := atomic.LoadInt64(&c.pendingInitialBackfills); current < lastCount {
				// Progress was made — reset the no-progress deadline.
				lastCount = current
				deadline = time.Now().Add(noProgressTimeout)
			}
		}
		remaining := atomic.LoadInt64(&c.pendingInitialBackfills)
		log.Warn().Int64("remaining", remaining).
			Msg("APNs buffer flush timeout: no forward backfill progress in 5 minutes, forcing flush")
		// Mirror what onForwardBackfillDone does: stamp the flush time so the
		// read-receipt grace window (handleReadReceipt) knows the burst is done.
		atomic.StoreInt64(&c.apnsBufferFlushedAt, time.Now().UnixMilli())
		if c.msgBuffer != nil {
			c.msgBuffer.flush()
		}
		c.flushPendingPortalMsgs()
	}()
}

func (c *IMClient) isCloudSyncDone() bool {
	c.cloudSyncDoneLock.RLock()
	defer c.cloudSyncDoneLock.RUnlock()
	return c.cloudSyncDone
}

// recentlyDeletedPortalsTTL is how long entries stay in recentlyDeletedPortals
// before being pruned. 24 hours is generous — tombstones are re-delivered on
// every CloudKit sync so short-lived entries are repopulated anyway.
const recentlyDeletedPortalsTTL = 24 * time.Hour

// pruneRecentlyDeletedPortals removes entries older than the TTL.
// Called after bootstrap sync to prevent unbounded memory growth.
func (c *IMClient) pruneRecentlyDeletedPortals(log zerolog.Logger) {
	c.recentlyDeletedPortalsMu.Lock()
	defer c.recentlyDeletedPortalsMu.Unlock()
	if len(c.recentlyDeletedPortals) == 0 {
		return
	}
	cutoff := time.Now().Add(-recentlyDeletedPortalsTTL)
	pruned := 0
	for portalID, entry := range c.recentlyDeletedPortals {
		if entry.deletedAt.Before(cutoff) {
			delete(c.recentlyDeletedPortals, portalID)
			pruned++
		}
	}
	if pruned > 0 {
		log.Info().Int("pruned", pruned).Int("remaining", len(c.recentlyDeletedPortals)).
			Msg("Pruned stale entries from recentlyDeletedPortals")
	}
}

func (c *IMClient) setContactsReady(log zerolog.Logger) {
	firstTime := false
	c.contactsReadyLock.Lock()
	if !c.contactsReady {
		c.contactsReady = true
		firstTime = true
		readyCh := c.contactsReadyCh
		c.contactsReadyLock.Unlock()
		if readyCh != nil {
			close(readyCh)
		}
		log.Info().Msg("Contacts readiness gate satisfied")
	} else {
		c.contactsReadyLock.Unlock()
	}

	// Re-resolve ghost and group names from contacts on every sync,
	// not just the first time. Contacts may have been added/edited in iCloud.
	if firstTime {
		log.Info().Msg("Running initial contact name resolution for ghosts and group portals")
	} else {
		log.Info().Msg("Re-syncing contact names for ghosts and group portals")
	}
	go c.refreshGhostNamesFromContacts(log)
	go c.refreshGroupPortalNamesFromContacts(log)
}

func (c *IMClient) refreshGhostNamesFromContacts(log zerolog.Logger) {
	if c.contacts == nil {
		return
	}
	ctx := context.Background()

	// Get all ghost IDs from the database via the raw DB handle
	rows, err := c.Main.Bridge.DB.RawDB.QueryContext(ctx, "SELECT id, name FROM ghost")
	if err != nil {
		log.Err(err).Msg("Failed to query ghosts for contact name refresh")
		return
	}
	defer rows.Close()

	updated := 0
	total := 0
	for rows.Next() {
		var ghostID, ghostName string
		if err := rows.Scan(&ghostID, &ghostName); err != nil {
			continue
		}
		total++
		localID := stripIdentifierPrefix(ghostID)
		if localID == "" {
			continue
		}
		contact, _ := c.contacts.GetContactInfo(localID)
		if contact == nil || !contact.HasName() {
			continue
		}
		name := c.Main.Config.FormatDisplayname(DisplaynameParams{
			FirstName: contact.FirstName,
			LastName:  contact.LastName,
			Nickname:  contact.Nickname,
			ID:        localID,
		})
		if ghostName != name {
			ghost, err := c.Main.Bridge.GetGhostByID(ctx, networkid.UserID(ghostID))
			if err != nil || ghost == nil {
				continue
			}
			ghost.UpdateInfo(ctx, &bridgev2.UserInfo{Name: &name})
			updated++
		}
	}
	log.Info().Int("updated", updated).Int("total", total).Msg("Refreshed ghost names from contacts")
}

// refreshGroupPortalNamesFromContacts re-resolves group portal names using
// contact data. Portals created before contacts loaded may have raw phone
// numbers / email addresses as the room name. This also picks up contact
// edits on subsequent periodic syncs.
func (c *IMClient) refreshGroupPortalNamesFromContacts(log zerolog.Logger) {
	if c.contacts == nil {
		return
	}
	ctx := context.Background()

	portals, err := c.Main.Bridge.GetAllPortalsWithMXID(ctx)
	if err != nil {
		log.Err(err).Msg("Failed to load portals for group name refresh")
		return
	}

	updated := 0
	total := 0
	for _, portal := range portals {
		if portal.Receiver != c.UserLogin.ID {
			continue
		}
		portalID := string(portal.ID)
		isGroup := strings.HasPrefix(portalID, "gid:") || strings.Contains(portalID, ",")
		if !isGroup {
			continue
		}
		total++

		newName := c.resolveGroupName(ctx, portalID)
		if newName == "" || newName == portal.Name {
			continue
		}

		c.UserLogin.QueueRemoteEvent(&simplevent.ChatInfoChange{
			EventMeta: simplevent.EventMeta{
				Type: bridgev2.RemoteEventChatInfoChange,
				PortalKey: networkid.PortalKey{
					ID:       portal.ID,
					Receiver: c.UserLogin.ID,
				},
				LogContext: func(lc zerolog.Context) zerolog.Context {
					return lc.Str("portal_id", portalID).Str("source", "group_name_refresh")
				},
			},
			ChatInfoChange: &bridgev2.ChatInfoChange{
				ChatInfo: &bridgev2.ChatInfo{
					Name: &newName,
					// Exclude from timeline so Beeper doesn't render
					// contact-based name resolution as a bridge bot message.
					ExcludeChangesFromTimeline: true,
				},
			},
		})
		updated++
	}
	log.Info().Int("updated", updated).Int("total_groups", total).Msg("Refreshed group portal names from contacts")
}

// contactsWaitTimeout is how long CloudKit sync waits for the contacts
// readiness gate before proceeding without contacts. Contacts are nice-to-have
// for name resolution but shouldn't block backfill indefinitely.
const contactsWaitTimeout = 30 * time.Second

func (c *IMClient) waitForContactsReady(log zerolog.Logger) bool {
	c.contactsReadyLock.RLock()
	alreadyReady := c.contactsReady
	readyCh := c.contactsReadyCh
	c.contactsReadyLock.RUnlock()
	if alreadyReady {
		return true
	}

	log.Info().Dur("timeout", contactsWaitTimeout).Msg("Waiting for contacts readiness gate before CloudKit sync")
	select {
	case <-readyCh:
		log.Info().Msg("Contacts readiness gate opened")
		return true
	case <-time.After(contactsWaitTimeout):
		log.Warn().Msg("Contacts readiness timed out — proceeding with CloudKit sync without contacts")
		return true
	case <-c.stopChan:
		return false
	}
}

func (c *IMClient) startCloudSyncController(log zerolog.Logger) {
	if c.cloudStore == nil {
		log.Warn().Msg("CloudKit sync controller not started: cloud store is nil")
		return
	}
	if c.client == nil {
		log.Warn().Msg("CloudKit sync controller not started: client is nil")
		return
	}
	log.Info().Msg("Starting CloudKit sync controller goroutine")
	go c.runCloudSyncController(log.With().Str("component", "cloud_sync").Logger())
}

// cloudSyncRetryInterval is the interval used when a bootstrap sync attempt
// fails, so recovery happens quickly.
const cloudSyncRetryInterval = 1 * time.Minute

func (c *IMClient) runCloudSyncController(log zerolog.Logger) {
	// NOTE: no defer recover() here intentionally. A panic in this goroutine
	// must crash the process so the bridge restarts and re-runs CloudKit sync.
	// Swallowing the panic would leave setCloudSyncDone() uncalled, permanently
	// blocking the APNs message buffer and dropping all incoming messages.

	// Derive a cancellable context from stopChan so that preUploadCloudAttachments
	// and other long-running operations can be interrupted promptly on shutdown
	// instead of running to completion (worst case: 48 min of leaked downloads).
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-c.stopChan:
			cancel()
		case <-ctx.Done():
		}
	}()
	defer cancel()
	controllerStart := time.Now()
	if !c.waitForContactsReady(log) {
		c.setCloudSyncDone() // unblock APNs portal creation
		return
	}
	log.Info().Dur("contacts_wait", time.Since(controllerStart)).Msg("Contacts ready, proceeding with CloudKit sync")

	// Bootstrap: download CloudKit data with retries until successful.
	// IMPORTANT: Do NOT set cloudSyncDone on failure. The APNs gate must
	// stay closed until sync succeeds — otherwise APNs echoes can create
	// portals for deleted chats because cloud_message has no UUID data
	// and recentlyDeletedPortals has no tombstone entries.
	// Messages for EXISTING portals are still delivered during this time
	// (handleMessage only checks cloudSyncDone for NEW portal creation).
	for {
		err := c.runCloudSyncOnce(ctx, log, true)
		if err != nil {
			log.Error().Err(err).
				Dur("retry_in", cloudSyncRetryInterval).
				Msg("CloudKit sync failed, will retry (APNs gate stays closed)")
			select {
			case <-time.After(cloudSyncRetryInterval):
				continue
			case <-c.stopChan:
				return
			}
		}
		break
	}

	// Soft-delete cloud records for portals that should be dead:
	// Tombstoned portals — chat tombstones processed before messages,
	// so message import creates cloud_message rows for deleted chats.
	// deleteLocalChatByPortalID marks cloud_message deleted=TRUE (preserving
	// UUIDs for echo detection) and removes cloud_chat rows.
	skipPortals := make(map[string]bool)
	c.recentlyDeletedPortalsMu.RLock()
	for portalID := range c.recentlyDeletedPortals {
		skipPortals[portalID] = true
	}
	c.recentlyDeletedPortalsMu.RUnlock()
	for portalID := range skipPortals {
		if err := c.cloudStore.deleteLocalChatByPortalID(ctx, portalID); err != nil {
			log.Warn().Err(err).Str("portal_id", portalID).Msg("Failed to soft-delete records for dead portal")
		}
	}
	if len(skipPortals) > 0 {
		log.Info().Int("count", len(skipPortals)).
			Msg("Soft-deleted re-imported records for dead portals")
	}

	// Pre-upload all CloudKit attachments to Matrix before triggering portal
	// creation. This populates attachmentContentCache so that FetchMessages
	// (which runs inside the portal event loop goroutine) gets instant cache
	// hits instead of blocking on CloudKit for 30+ minutes.
	c.preUploadCloudAttachments(ctx)

	// Create portals and queue forward backfill for all of them.
	// Skip portals that are tombstoned or recently deleted this session.
	portalStart := time.Now()
	c.createPortalsFromCloudSync(ctx, log, skipPortals)
	c.setCloudSyncDone()

	log.Info().
		Dur("portal_creation_elapsed", time.Since(portalStart)).
		Dur("total_elapsed", time.Since(controllerStart)).
		Msg("CloudKit bootstrap complete — all portals queued, APNs portal creation enabled")

	// Clean up stale entries in recentlyDeletedPortals to prevent unbounded
	// memory growth over long-running sessions.
	c.pruneRecentlyDeletedPortals(log)

	// Housekeeping: prune orphaned data that accumulates over time.
	// Run after bootstrap so the cleanup doesn't delay portal creation.
	c.runPostSyncHousekeeping(ctx, log)

	// Delayed incremental re-syncs: catch CloudKit messages that propagated
	// after the bootstrap sync completed. Messages sent in the last few minutes
	// may not be in the CloudKit changes feed yet (propagation delay). APNs
	// delivers them with CreatePortal=false (gate closed), so bridgev2 drops
	// them for non-existent portals. Multiple re-sync passes at increasing
	// intervals ensure we catch them as CloudKit propagates.
	//
	// IMPORTANT: These run inline (not in a goroutine) so that the defer
	// cancel() on the parent context doesn't fire until all re-syncs are
	// done. Previously these ran in a goroutine, but runCloudSyncController
	// returned immediately after launching it — the defer cancel() killed
	// the context, causing every re-sync to fail with "context canceled".
	delays := []time.Duration{15 * time.Second, 60 * time.Second, 3 * time.Minute}
	for i, delay := range delays {
		select {
		case <-time.After(delay):
		case <-c.stopChan:
			return
		}
		resyncLog := log.With().
			Str("source", "delayed_resync").
			Int("pass", i+1).
			Int("total_passes", len(delays)).
			Logger()
		resyncLog.Info().Msg("Running delayed incremental CloudKit re-sync")
		if err := c.runCloudSyncOnce(ctx, resyncLog, false); err != nil {
			resyncLog.Warn().Err(err).Msg("Delayed incremental re-sync failed")
			continue
		}
		// Extend skipPortals with any portals deleted since bootstrap.
		// The delayed re-sync may have imported new cloud_message records
		// for these portals (deleted=FALSE). Soft-delete them now so they
		// don't persist in the DB and resurrect the portal on next restart.
		c.recentlyDeletedPortalsMu.RLock()
		for portalID := range c.recentlyDeletedPortals {
			if !skipPortals[portalID] {
				skipPortals[portalID] = true
				if err := c.cloudStore.deleteLocalChatByPortalID(ctx, portalID); err != nil {
					resyncLog.Warn().Err(err).Str("portal_id", portalID).
						Msg("Failed to soft-delete re-imported records for recently deleted portal")
				} else {
					resyncLog.Debug().Str("portal_id", portalID).
						Msg("Soft-deleted re-imported records for portal deleted after bootstrap")
				}
			}
		}
		c.recentlyDeletedPortalsMu.RUnlock()
		// Pre-upload any new attachments discovered by this re-sync;
		// already-cached record_names are skipped instantly.
		c.preUploadCloudAttachments(ctx)
		c.createPortalsFromCloudSync(ctx, resyncLog, skipPortals)
	}
}

// runPostSyncHousekeeping cleans up accumulated dead data after a successful
// CloudKit sync. Each operation is independent and best-effort — failures are
// logged but don't block the bridge.
func (c *IMClient) runPostSyncHousekeeping(ctx context.Context, log zerolog.Logger) {
	if c.cloudStore == nil {
		return
	}
	log = log.With().Str("component", "housekeeping").Logger()

	// Prune cloud_attachment_cache entries not referenced by any live message.
	if pruned, err := c.cloudStore.pruneOrphanedAttachmentCache(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to prune orphaned attachment cache")
	} else if pruned > 0 {
		log.Info().Int64("pruned", pruned).Msg("Pruned orphaned attachment cache entries")
	}

	// Delete cloud_message rows whose portal_id has no cloud_chat entry.
	if deleted, err := c.cloudStore.deleteOrphanedMessages(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to delete orphaned cloud messages")
	} else if deleted > 0 {
		log.Info().Int64("deleted", deleted).Msg("Deleted orphaned cloud_message rows (no matching cloud_chat)")
	}
}

// runCloudSyncOnce performs a single CloudKit sync pass. On the first run
// (isBootstrap=true) it detects fresh vs. interrupted state and clears stale
// data if needed. On subsequent runs it's purely incremental — the saved
// continuation tokens mean CloudKit only returns changes since last sync.
func (c *IMClient) runCloudSyncOnce(ctx context.Context, log zerolog.Logger, isBootstrap bool) error {
	if isBootstrap {
		isFresh := false
		hasOwnPortal := false
		if portals, err := c.Main.Bridge.GetAllPortalsWithMXID(ctx); err == nil {
			for _, p := range portals {
				if p.Receiver == c.UserLogin.ID {
					hasOwnPortal = true
					break
				}
			}
		}

		if !hasOwnPortal {
			hasSyncState := false
			if has, err := c.cloudStore.hasAnySyncState(ctx); err == nil {
				hasSyncState = has
			}
			if !hasSyncState {
				// No portals AND no sync state — truly fresh. Clear everything.
				if err := c.cloudStore.clearAllData(ctx); err != nil {
					log.Warn().Err(err).Msg("Failed to clear stale cloud data")
				} else {
					log.Info().Msg("Fresh database detected, cleared cloud cache for full bootstrap")
				}
				isFresh = true
			} else {
				// Sync state exists but no portals. Two sub-cases:
				// (a) CloudKit data download was interrupted → resume from saved tokens
				// (b) Data download completed but portal creation was interrupted
				//     → backfill returns ~0 new records, portal creation re-runs
				// Both cases are handled correctly: backfill resumes or no-ops,
				// then createPortalsFromCloudSync reads from the DB tables.
				chatTok, _ := c.cloudStore.getSyncState(ctx, cloudZoneChats)
				msgTok, _ := c.cloudStore.getSyncState(ctx, cloudZoneMessages)
				log.Info().
					Bool("has_chat_token", chatTok != nil).
					Bool("has_msg_token", msgTok != nil).
					Msg("Resuming interrupted CloudKit sync (sync state exists but no portals yet)")
			}
		} else {
			// Existing portals — check sync version. If the sync logic has
			// been upgraded (e.g. better PCS key handling), do a one-time
			// full re-sync to pick up previously-undecryptable records.
			// Subsequent restarts use incremental sync (cheap).
			savedVersion, _ := c.cloudStore.getSyncVersion(ctx)
			if savedVersion < cloudSyncVersion {
				if err := c.cloudStore.clearSyncTokens(ctx); err != nil {
					log.Warn().Err(err).Msg("Failed to clear sync tokens for version upgrade re-sync")
				} else {
					log.Info().
						Int("old_version", savedVersion).
						Int("new_version", cloudSyncVersion).
						Msg("Sync version upgraded — cleared tokens for one-time full re-sync")
				}
			} else {
				log.Info().Int("sync_version", savedVersion).Msg("Sync version current — using incremental CloudKit sync")

				// Check chat-specific sync version. A bump here only clears
				// the chatManateeZone token, leaving the (expensive) message
				// token intact. Used for changes that only require re-fetching
				// chat metadata (e.g. populating group_photo_guid).
				savedChatVersion, _ := c.cloudStore.getChatSyncVersion(ctx)
				if savedChatVersion < cloudChatSyncVersion {
					if err := c.cloudStore.clearZoneToken(ctx, cloudZoneChats); err != nil {
						log.Warn().Err(err).Msg("Failed to clear chat zone token for chat sync version upgrade")
					} else {
						log.Info().
							Int("old_version", savedChatVersion).
							Int("new_version", cloudChatSyncVersion).
							Msg("Chat sync version upgraded — cleared chat zone token for one-time full chat re-sync")
					}
				}
			}
		}

		log.Info().Bool("fresh", isFresh).Msg("CloudKit sync start")
	}

	backfillStart := time.Now()
	counts, err := c.runCloudKitBackfill(ctx, log)
	if err != nil {
		return fmt.Errorf("CloudKit sync failed after %s: %w", time.Since(backfillStart).Round(time.Second), err)
	}

	log.Info().
		Int("imported", counts.Imported).
		Int("updated", counts.Updated).
		Int("skipped", counts.Skipped).
		Int("deleted", counts.Deleted).
		Bool("bootstrap", isBootstrap).
		Dur("elapsed", time.Since(backfillStart)).
		Msg("CloudKit sync pass complete")

	// Only persist sync version if the sync actually received data.
	// If the re-sync returned 0 records (e.g. CloudKit changes feed
	// considers records already delivered), leave the version unsaved
	// so the next restart will clear tokens and try again.
	totalRecords := counts.Imported + counts.Updated + counts.Deleted
	if isBootstrap && totalRecords > 0 {
		if err := c.cloudStore.setSyncVersion(ctx, cloudSyncVersion); err != nil {
			log.Warn().Err(err).Msg("Failed to persist sync version")
		}
		if err := c.cloudStore.setChatSyncVersion(ctx, cloudChatSyncVersion); err != nil {
			log.Warn().Err(err).Msg("Failed to persist chat sync version")
		}
	} else if !isBootstrap {
		// For existing portals, always persist the chat sync version so that
		// a targeted chat re-sync (cloudChatSyncVersion bump) is only done once.
		if err := c.cloudStore.setChatSyncVersion(ctx, cloudChatSyncVersion); err != nil {
			log.Warn().Err(err).Msg("Failed to persist chat sync version")
		}
	} else if isBootstrap && totalRecords == 0 {
		log.Warn().
			Int("sync_version", cloudSyncVersion).
			Msg("CloudKit sync returned 0 records — NOT saving version (will retry on next restart)")
		// Diagnostic: run a separate full-count sync to check if CloudKit
		// actually has records. This paginates from scratch independently
		// and helps identify whether the changes feed is empty vs. data exists.
		go func() {
			if diagResult, diagErr := c.client.CloudDiagFullCount(); diagErr != nil {
				log.Warn().Err(diagErr).Msg("CloudKit diagnostic full count failed")
			} else {
				log.Info().Str("diag_result", diagResult).Msg("CloudKit diagnostic full count (post-sync check)")
			}
		}()
	}

	return nil
}

func (c *IMClient) runCloudKitBackfill(ctx context.Context, log zerolog.Logger) (cloudSyncCounters, error) {
	var total cloudSyncCounters
	backfillStart := time.Now()

	// Always restart attachment sync from scratch. The attachment map
	// (attMap) is built in-memory during sync and used to enrich messages.
	// On crash/restart the map is lost, so resuming from a saved token
	// would produce an incomplete map — messages referencing pre-crash
	// attachments would lose their metadata. Attachment zones are small
	// relative to messages, so the overhead is minimal.
	if err := c.cloudStore.clearZoneToken(ctx, cloudZoneAttachments); err != nil {
		log.Warn().Err(err).Msg("Failed to clear attachment zone token for fresh sync")
	}

	// Check which zones have saved continuation tokens (for diagnostic logging).
	savedChatTok, _ := c.cloudStore.getSyncState(ctx, cloudZoneChats)
	savedMsgTok, _ := c.cloudStore.getSyncState(ctx, cloudZoneMessages)
	log.Info().
		Bool("chat_token_saved", savedChatTok != nil).
		Bool("msg_token_saved", savedMsgTok != nil).
		Msg("CloudKit backfill starting (attachment zone always fresh)")

	// Phase 0: Sync attachments first (with ALL_ASSETS) to populate the
	// Ford key cache before any downloads happen. MMCS deduplication can
	// serve Ford blobs encrypted with a different record's key, so the
	// cache must be fully populated before downloads start.
	phase0Start := time.Now()
	var attMap map[string]cloudAttachmentRow
	var attToken *string
	var attErr error
	{
		attMap, attToken, attErr = c.syncCloudAttachments(ctx)
		attCount := 0
		if attMap != nil {
			attCount = len(attMap)
		}
		log.Info().
			Dur("elapsed", time.Since(phase0Start)).
			Int("attachments", attCount).
			Err(attErr).
			Msg("CloudKit attachment sync complete (Ford key cache populated)")
	}

	// Phase 1: Sync chats. Messages depend on chats (portal ID resolution)
	// and attachments (GUID→record_name mapping), so they must wait.
	phase1Start := time.Now()

	var chatCounts cloudSyncCounters
	var chatToken *string
	var chatErr error
	{
		chatStart := time.Now()
		chatCounts, chatToken, chatErr = c.syncCloudChats(ctx)
		log.Info().
			Dur("elapsed", time.Since(chatStart)).
			Int("imported", chatCounts.Imported).
			Int("updated", chatCounts.Updated).
			Int("skipped", chatCounts.Skipped).
			Err(chatErr).
			Msg("CloudKit chat sync complete")
	}
	log.Info().Dur("phase1_elapsed", time.Since(phase1Start)).Msg("CloudKit phase 1 (chats) complete")

	if chatErr != nil {
		_ = c.cloudStore.setSyncStateError(ctx, cloudZoneChats, chatErr.Error())
		return total, chatErr
	}
	// Only persist the chat token if non-nil — a nil token from a "no changes"
	// response would overwrite the saved watermark and force a full re-download
	// on the next restart.
	if chatToken != nil {
		if err := c.cloudStore.setSyncStateSuccess(ctx, cloudZoneChats, chatToken); err != nil {
			log.Warn().Err(err).Msg("Failed to persist chat sync token")
		}
	}
	total.add(chatCounts)

	if attErr != nil {
		log.Warn().Err(attErr).Msg("Failed to sync CloudKit attachments (continuing without)")
	} else if attToken != nil {
		if err := c.cloudStore.setSyncStateSuccess(ctx, cloudZoneAttachments, attToken); err != nil {
			log.Warn().Err(err).Msg("Failed to persist attachment sync token")
		}
	}

	// Phase 2: Sync messages (depends on chats + attachments).
	phase2Start := time.Now()
	msgCounts, msgToken, err := c.syncCloudMessages(ctx, attMap)
	if err != nil {
		_ = c.cloudStore.setSyncStateError(ctx, cloudZoneMessages, err.Error())
		return total, err
	}
	if msgToken != nil {
		if err = c.cloudStore.setSyncStateSuccess(ctx, cloudZoneMessages, msgToken); err != nil {
			log.Warn().Err(err).Msg("Failed to persist message sync token")
		}
	}
	total.add(msgCounts)

	log.Info().
		Dur("phase2_elapsed", time.Since(phase2Start)).
		Int("imported", msgCounts.Imported).
		Int("updated", msgCounts.Updated).
		Int("skipped", msgCounts.Skipped).
		Dur("total_elapsed", time.Since(backfillStart)).
		Msg("CloudKit phase 2 (messages) complete")

	return total, nil
}

// syncCloudAttachments syncs the attachment zone and builds a GUID→attachment info map.
func (c *IMClient) syncCloudAttachments(ctx context.Context) (map[string]cloudAttachmentRow, *string, error) {
	attMap := make(map[string]cloudAttachmentRow)
	token, err := c.cloudStore.getSyncState(ctx, cloudZoneAttachments)
	if err != nil {
		return attMap, nil, err
	}

	log := c.Main.Bridge.Log.With().Str("component", "cloud_sync").Logger()
	consecutiveErrors := 0
	const maxConsecutiveAttErrors = 3
	for page := 0; page < 10000; page++ {
		resp, syncErr := safeCloudSyncAttachments(c.client, token)
		if syncErr != nil {
			consecutiveErrors++
			log.Warn().Err(syncErr).
				Int("page", page).
				Int("imported_so_far", len(attMap)).
				Int("consecutive_errors", consecutiveErrors).
				Msg("CloudKit attachment sync page failed (FFI error)")
			if consecutiveErrors >= maxConsecutiveAttErrors {
				log.Error().
					Int("page", page).
					Int("imported_so_far", len(attMap)).
					Msg("CloudKit attachment sync: too many consecutive FFI errors, stopping pagination")
				break
			}
			continue
		}
		consecutiveErrors = 0

		for _, att := range resp.Attachments {
			mime := ""
			if att.MimeType != nil {
				mime = *att.MimeType
			}
			uti := ""
			if att.UtiType != nil {
				uti = *att.UtiType
			}
			filename := ""
			if att.Filename != nil {
				filename = *att.Filename
			}
			attMap[att.Guid] = cloudAttachmentRow{
				GUID:           att.Guid,
				MimeType:       mime,
				UTIType:        uti,
				Filename:       filename,
				FileSize:       att.FileSize,
				RecordName:     att.RecordName,
				HideAttachment: att.HideAttachment,
				HasAvid:        att.HasAvid,
			}
		}

		prev := ptrStringOr(token, "")
		token = resp.ContinuationToken

		// Persist token after each page for crash-safe resume.
		if token != nil {
			if saveErr := c.cloudStore.setSyncStateSuccess(ctx, cloudZoneAttachments, token); saveErr != nil {
				log.Warn().Err(saveErr).Int("page", page).Msg("Failed to persist attachment sync token mid-page")
			}
		}

		if resp.Done || (page > 0 && prev == ptrStringOr(token, "")) {
			break
		}
	}

	return attMap, token, nil
}

func (c *IMClient) syncCloudChats(ctx context.Context) (cloudSyncCounters, *string, error) {
	var counts cloudSyncCounters
	token, err := c.cloudStore.getSyncState(ctx, cloudZoneChats)
	if err != nil {
		return counts, nil, err
	}

	log := c.Main.Bridge.Log.With().Str("component", "cloud_sync").Logger()
	totalPages := 0
	consecutiveErrors := 0
	const maxConsecutiveChatErrors = 3
	for page := 0; page < 10000; page++ {
		resp, syncErr := safeCloudSyncChats(c.client, token)
		if syncErr != nil {
			consecutiveErrors++
			log.Warn().Err(syncErr).
				Int("page", page).
				Int("imported_so_far", counts.Imported).
				Int("consecutive_errors", consecutiveErrors).
				Msg("CloudKit chat sync page failed (FFI error)")
			if consecutiveErrors >= maxConsecutiveChatErrors {
				log.Error().
					Int("page", page).
					Int("imported_so_far", counts.Imported).
					Msg("CloudKit chat sync: too many consecutive FFI errors, stopping pagination")
				break
			}
			time.Sleep(500 * time.Millisecond)
			continue
		}
		consecutiveErrors = 0

		log.Info().
			Int("page", page).
			Int("chats_on_page", len(resp.Chats)).
			Int32("status", resp.Status).
			Bool("done", resp.Done).
			Msg("CloudKit chat sync page")

		ingestCounts, ingestErr := c.ingestCloudChats(ctx, resp.Chats)
		if ingestErr != nil {
			return counts, token, ingestErr
		}
		counts.add(ingestCounts)
		totalPages = page + 1

		prev := ptrStringOr(token, "")
		token = resp.ContinuationToken

		// Persist token after each page for crash-safe resume.
		if token != nil {
			if saveErr := c.cloudStore.setSyncStateSuccess(ctx, cloudZoneChats, token); saveErr != nil {
				log.Warn().Err(saveErr).Int("page", page).Msg("Failed to persist chat sync token mid-page")
			}
		}

		if resp.Done || (page > 0 && prev == ptrStringOr(token, "")) {
			log.Info().Int("page", page).Bool("api_done", resp.Done).Bool("token_unchanged", prev == ptrStringOr(token, "")).
				Msg("CloudKit chat sync pagination stopped")
			break
		}
	}

	log.Info().Int("total_pages", totalPages).Int("imported", counts.Imported).Int("updated", counts.Updated).
		Int("skipped", counts.Skipped).Int("deleted", counts.Deleted).Int("filtered", counts.Filtered).
		Msg("CloudKit chat sync finished")

	return counts, token, nil
}

// safeCloudSyncMessages wraps the FFI call with panic recovery.
// UniFFI deserialization panics on malformed buffers; this prevents bridge crashes.
func safeCloudSyncMessages(client *rustpushgo.Client, token *string) (resp rustpushgo.WrappedCloudSyncMessagesPage, err error) {
	defer func() {
		if r := recover(); r != nil {
			stack := string(debug.Stack())
			log.Error().Str("ffi_method", "CloudSyncMessages").Str("stack", stack).Msgf("FFI panic recovered: %v", r)
			err = fmt.Errorf("FFI panic in CloudSyncMessages: %v", r)
		}
	}()
	return client.CloudSyncMessages(token)
}

// safeCloudSyncChats wraps the FFI call with panic recovery.
func safeCloudSyncChats(client *rustpushgo.Client, token *string) (resp rustpushgo.WrappedCloudSyncChatsPage, err error) {
	defer func() {
		if r := recover(); r != nil {
			stack := string(debug.Stack())
			log.Error().Str("ffi_method", "CloudSyncChats").Str("stack", stack).Msgf("FFI panic recovered: %v", r)
			err = fmt.Errorf("FFI panic in CloudSyncChats: %v", r)
		}
	}()
	return client.CloudSyncChats(token)
}

// safeCloudSyncAttachments wraps the FFI call with panic recovery.
func safeCloudSyncAttachments(client *rustpushgo.Client, token *string) (resp rustpushgo.WrappedCloudSyncAttachmentsPage, err error) {
	defer func() {
		if r := recover(); r != nil {
			stack := string(debug.Stack())
			log.Error().Str("ffi_method", "CloudSyncAttachments").Str("stack", stack).Msgf("FFI panic recovered: %v", r)
			err = fmt.Errorf("FFI panic in CloudSyncAttachments: %v", r)
		}
	}()
	return client.CloudSyncAttachments(token)
}

func (c *IMClient) syncCloudMessages(ctx context.Context, attMap map[string]cloudAttachmentRow) (cloudSyncCounters, *string, error) {
	var counts cloudSyncCounters
	token, err := c.cloudStore.getSyncState(ctx, cloudZoneMessages)
	if err != nil {
		return counts, nil, err
	}

	log := c.Main.Bridge.Log.With().Str("component", "cloud_sync").Logger()
	log.Info().
		Bool("token_nil", token == nil).
		Msg("CloudKit message sync starting")

	consecutiveErrors := 0
	const maxConsecutiveErrors = 3
	totalPages := 0
	for page := 0; page < 10000; page++ {
		resp, syncErr := safeCloudSyncMessages(c.client, token)
		if syncErr != nil {
			consecutiveErrors++
			log.Warn().Err(syncErr).
				Int("page", page).
				Int("imported_so_far", counts.Imported).
				Int("consecutive_errors", consecutiveErrors).
				Msg("CloudKit message sync page failed (FFI error)")
			if consecutiveErrors >= maxConsecutiveErrors {
				log.Error().
					Int("page", page).
					Int("imported_so_far", counts.Imported).
					Msg("CloudKit message sync: too many consecutive FFI errors, stopping pagination")
				break
			}
			// Skip this page and retry with the same token on next iteration.
			// The server may return different records on retry.
			time.Sleep(500 * time.Millisecond)
			continue
		}
		consecutiveErrors = 0

		log.Info().
			Int("page", page).
			Int("messages", len(resp.Messages)).
			Int32("status", resp.Status).
			Bool("done", resp.Done).
			Bool("has_token", resp.ContinuationToken != nil).
			Msg("CloudKit message sync page")

		if err = c.ingestCloudMessages(ctx, resp.Messages, "", &counts, attMap); err != nil {
			return counts, token, err
		}

		prev := ptrStringOr(token, "")
		token = resp.ContinuationToken
		totalPages = page + 1

		// Only persist the continuation token if records were received.
		// Persisting an empty-page token on a 0-record re-sync would
		// prevent future retries from starting fresh.
		if token != nil && len(resp.Messages) > 0 {
			if saveErr := c.cloudStore.setSyncStateSuccess(ctx, cloudZoneMessages, token); saveErr != nil {
				log.Warn().Err(saveErr).Int("page", page).Msg("Failed to persist message sync token mid-page")
			}
		}

		if resp.Done || (page > 0 && prev == ptrStringOr(token, "")) {
			log.Info().
				Int("page", page).
				Bool("api_done", resp.Done).
				Bool("token_unchanged", prev == ptrStringOr(token, "")).
				Msg("CloudKit message sync pagination stopped")
			break
		}
	}

	log.Info().
		Int("total_pages", totalPages).
		Int("imported", counts.Imported).
		Int("updated", counts.Updated).
		Int("skipped", counts.Skipped).
		Int("deleted", counts.Deleted).
		Int("filtered", counts.Filtered).
		Msg("CloudKit message sync finished")

	return counts, token, nil
}

func (c *IMClient) ingestCloudChats(ctx context.Context, chats []rustpushgo.WrappedCloudSyncChat) (cloudSyncCounters, error) {
	var counts cloudSyncCounters
	log := c.Main.Bridge.Log.With().Str("component", "cloud_sync").Logger()

	// Batch existence check for all non-deleted chat IDs.
	chatIDs := make([]string, 0, len(chats))
	for _, chat := range chats {
		if !chat.Deleted {
			chatIDs = append(chatIDs, chat.CloudChatId)
		}
	}
	existingSet, err := c.cloudStore.hasChatBatch(ctx, chatIDs)
	if err != nil {
		return counts, fmt.Errorf("batch chat existence check failed: %w", err)
	}

	// Collect deleted record_names for tombstone handling.
	// Tombstones only carry the record_name (CloudChatId is set to
	// record_name by the FFI layer since there's no data to extract
	// the real chat identifier). We must look up by record_name.
	var deletedRecordNames []string

	// Build batch of rows.
	batch := make([]cloudChatUpsertRow, 0, len(chats))
	for _, chat := range chats {
		if chat.Deleted {
			counts.Deleted++
			deletedRecordNames = append(deletedRecordNames, chat.RecordName)
			continue
		}

		portalID := c.resolvePortalIDForCloudChat(chat.Participants, chat.DisplayName, chat.GroupId, chat.Style)
		if portalID == "" {
			counts.Skipped++
			continue
		}

		participantsJSON, jsonErr := json.Marshal(chat.Participants)
		if jsonErr != nil {
			return counts, jsonErr
		}

		if chat.GroupPhotoGuid != nil && *chat.GroupPhotoGuid != "" {
			log.Info().
				Str("portal_id", portalID).
				Str("record_name", chat.RecordName).
				Str("group_photo_guid", *chat.GroupPhotoGuid).
				Msg("CloudKit chat sync: group photo GUID found")
		}

		batch = append(batch, cloudChatUpsertRow{
			CloudChatID:      chat.CloudChatId,
			RecordName:       chat.RecordName,
			GroupID:          chat.GroupId,
			PortalID:         portalID,
			Service:          chat.Service,
			DisplayName:      nullableString(chat.DisplayName),
			GroupPhotoGuid:   nullableString(chat.GroupPhotoGuid),
			ParticipantsJSON: string(participantsJSON),
			UpdatedTS:        int64(chat.UpdatedTimestampMs),
			IsFiltered:       chat.IsFiltered,
		})

		if chat.IsFiltered != 0 {
			counts.Filtered++
			log.Debug().
				Str("cloud_chat_id", chat.CloudChatId).
				Str("portal_id", portalID).
				Int64("is_filtered", chat.IsFiltered).
				Msg("Stored filtered/junk chat from CloudKit (will skip messages)")
		} else if existingSet[chat.CloudChatId] {
			counts.Updated++
		} else {
			counts.Imported++
		}
	}

	// Batch insert all non-deleted chats.
	if err := c.cloudStore.upsertChatBatch(ctx, batch); err != nil {
		return counts, err
	}

	// Handle tombstoned (deleted) chats. Tombstones only carry the
	// record_name, so we look up portal_ids from the local cloud_chat
	// table, then:
	// 1. Hard-delete cloud_chat and cloud_message rows for the portal
	// 2. Queue bridge portal deletion for any existing portal
	// 3. Mark in recentlyDeletedPortals to block APNs echo resurrection
	//    and to ensure ingestCloudMessages marks any re-imported messages
	//    as deleted=TRUE (cloudSyncDone gate ensures tombstones are always
	//    processed before APNs can create portals — no DB table needed)
	if len(deletedRecordNames) > 0 {
		// Resolve record_names → portal_ids before deleting the rows.
		portalMap, lookupErr := c.cloudStore.lookupPortalIDsByRecordNames(ctx, deletedRecordNames)
		if lookupErr != nil {
			log.Warn().Err(lookupErr).Msg("Failed to look up portal IDs for tombstoned chats")
		}

		// Delete cloud_chat entries by record_name (correct for tombstones).
		if err := c.cloudStore.deleteChatsByRecordNames(ctx, deletedRecordNames); err != nil {
			return counts, fmt.Errorf("failed to delete tombstoned chats by record_name: %w", err)
		}

		// Hard-delete cloud_chat and cloud_message rows for resolved portal_ids.
		// Echo detection is handled by recentlyDeletedPortals (set below) and by
		// ingestCloudMessages marking re-imported messages as deleted=TRUE for
		// portals in recentlyDeletedPortals.
		for recordName, portalID := range portalMap {
			if err := c.cloudStore.deleteLocalChatByPortalID(ctx, portalID); err != nil {
				log.Warn().Err(err).Str("portal_id", portalID).Msg("Failed to hard-delete messages for tombstoned chat")
			}

			// Mark as deleted in memory so createPortalsFromCloudSync skips
			// this portal and FetchMessages returns empty.
			c.recentlyDeletedPortalsMu.Lock()
			if c.recentlyDeletedPortals == nil {
				c.recentlyDeletedPortals = make(map[string]deletedPortalEntry)
			}
			c.recentlyDeletedPortals[portalID] = deletedPortalEntry{
				deletedAt:   time.Now(),
				isTombstone: true,
			}
			c.recentlyDeletedPortalsMu.Unlock()

			// Queue bridge portal deletion if it exists.
			portalKey := networkid.PortalKey{
				ID:       networkid.PortalID(portalID),
				Receiver: c.UserLogin.ID,
			}
			existing, _ := c.Main.Bridge.GetExistingPortalByKey(ctx, portalKey)
			if existing != nil && existing.MXID != "" {
				log.Info().
					Str("portal_id", portalID).
					Str("record_name", recordName).
					Msg("CloudKit tombstone: deleting bridge portal for chat in recycle bin")
				c.Main.Bridge.QueueRemoteEvent(c.UserLogin, &simplevent.ChatDelete{
					EventMeta: simplevent.EventMeta{
						Type:      bridgev2.RemoteEventChatDelete,
						PortalKey: portalKey,
						Timestamp: time.Now(),
						LogContext: func(lc zerolog.Context) zerolog.Context {
							return lc.Str("source", "cloudkit_tombstone").Str("record_name", recordName)
						},
					},
					OnlyForMe: true,
				})
			}
		}
	}

	return counts, nil
}

// uuidPattern matches a UUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// resolveConversationID determines the canonical portal ID for a cloud message.
//
// Rule 1: If chat_id is a UUID → it's a group conversation → "gid:<lowercase-uuid>"
// Rule 2: Otherwise derive from sender (DM) → "tel:+..." or "mailto:..."
// Rule 3: Messages create conversations. Never discard a message because
//         we haven't seen the chat record yet.
func (c *IMClient) resolveConversationID(ctx context.Context, msg rustpushgo.WrappedCloudSyncMessage) string {
	// Check if chat_id is a UUID (= group conversation)
	if msg.CloudChatId != "" && uuidPattern.MatchString(msg.CloudChatId) {
		return "gid:" + strings.ToLower(msg.CloudChatId)
	}

	// Try to look up the chat record for non-UUID chat_ids
	// (e.g., "iMessage;-;+16692858317" or "chat12345...")
	if msg.CloudChatId != "" {
		if portalID, err := c.cloudStore.getChatPortalID(ctx, msg.CloudChatId); err == nil && portalID != "" {
			return portalID
		}
	}

	// DM: derive from sender
	if msg.Sender != "" && !msg.IsFromMe {
		normalized := normalizeIdentifierForPortalID(msg.Sender)
		if normalized != "" {
			resolved := c.resolveContactPortalID(normalized)
			resolved = c.resolveExistingDMPortalID(string(resolved))
			return string(resolved)
		}
	}

	// is_from_me DMs: derive from destination
	if msg.IsFromMe && msg.CloudChatId != "" {
		// chat_id for DMs is like "iMessage;-;+16692858317"
		parts := strings.Split(msg.CloudChatId, ";")
		if len(parts) == 3 {
			normalized := normalizeIdentifierForPortalID(parts[2])
			if normalized != "" {
				resolved := c.resolveContactPortalID(normalized)
				resolved = c.resolveExistingDMPortalID(string(resolved))
				return string(resolved)
			}
		}
	}

	return ""
}

func (c *IMClient) ingestCloudMessages(
	ctx context.Context,
	messages []rustpushgo.WrappedCloudSyncMessage,
	preferredPortalID string,
	counts *cloudSyncCounters,
	attMap map[string]cloudAttachmentRow,
) error {
	log := c.Main.Bridge.Log.With().Str("component", "cloud_sync").Logger()

	// Separate deleted messages from live messages up front.
	// Deleted messages are removed from the DB (they may have been stored
	// in a previous sync before the user deleted them in iCloud).
	var deletedGUIDs []string
	var liveMessages []rustpushgo.WrappedCloudSyncMessage
	for _, msg := range messages {
		if msg.Deleted {
			counts.Deleted++
			if msg.Guid != "" {
				deletedGUIDs = append(deletedGUIDs, msg.Guid)
			}
			continue
		}
		liveMessages = append(liveMessages, msg)
	}

	// Remove deleted messages from DB.
	if err := c.cloudStore.deleteMessageBatch(ctx, deletedGUIDs); err != nil {
		return fmt.Errorf("failed to delete messages: %w", err)
	}

	// Snapshot recentlyDeletedPortals so we can mark re-imported messages for
	// deleted portals as deleted=TRUE. This closes the race where a periodic
	// re-sync downloads messages for a portal that was just deleted: without
	// this check, those messages would be inserted with deleted=FALSE and could
	// trigger portal resurrection or spurious backfill on a future restart.
	c.recentlyDeletedPortalsMu.RLock()
	deletedPortalsSnapshot := make(map[string]bool, len(c.recentlyDeletedPortals))
	for id := range c.recentlyDeletedPortals {
		deletedPortalsSnapshot[id] = true
	}
	c.recentlyDeletedPortalsMu.RUnlock()

	// Phase 1: Resolve portal IDs and build rows for live messages (no DB writes yet).
	guids := make([]string, 0, len(liveMessages))
	for _, msg := range liveMessages {
		if msg.Guid != "" {
			guids = append(guids, msg.Guid)
		}
	}
	existingSet, err := c.cloudStore.hasMessageBatch(ctx, guids)
	if err != nil {
		return fmt.Errorf("batch existence check failed: %w", err)
	}

	batch := make([]cloudMessageRow, 0, len(liveMessages))
	for _, msg := range liveMessages {
		if msg.Guid == "" {
			log.Warn().
				Str("cloud_chat_id", msg.CloudChatId).
				Str("sender", msg.Sender).
				Bool("is_from_me", msg.IsFromMe).
				Int64("timestamp_ms", msg.TimestampMs).
				Msg("Skipping message with empty GUID")
			counts.Skipped++
			continue
		}

		// Skip system/service records (group renames, participant changes, etc.)
		// that slipped past the Rust-side IS_SYSTEM_MESSAGE / IS_SERVICE_MESSAGE
		// flag filter. In CloudKit, regular user messages have msgType=1;
		// msgType=0 indicates non-user-content system records.
		if msg.MsgType == 0 {
			log.Debug().
				Str("guid", msg.Guid).
				Str("cloud_chat_id", msg.CloudChatId).
				Msg("Skipping system/service message (msgType=0)")
			counts.Skipped++
			continue
		}

		portalID := c.resolveConversationID(ctx, msg)
		if portalID == "" {
			portalID = preferredPortalID
		}
		if portalID == "" {
			log.Warn().
				Str("guid", msg.Guid).
				Str("cloud_chat_id", msg.CloudChatId).
				Str("sender", msg.Sender).
				Bool("is_from_me", msg.IsFromMe).
				Int64("timestamp_ms", msg.TimestampMs).
				Str("service", msg.Service).
				Msg("Skipping message: could not resolve portal ID")
			counts.Skipped++
			continue
		}

		// Skip orphaned messages: no chat_id AND no cloud_chat record for the
		// resolved portal. Apple omits filtered/junk chats from the chat zone
		// entirely, so these messages have no chat association and represent
		// spam or unknown-sender conversations the user never sees in iMessage.
		if msg.CloudChatId == "" && c.cloudStore != nil {
			if hasChat, err := c.cloudStore.portalHasChat(ctx, portalID); err == nil && !hasChat {
				log.Debug().
					Str("guid", msg.Guid).
					Str("portal_id", portalID).
					Str("sender", msg.Sender).
					Msg("Skipping orphaned message (no chat_id, no chat record)")
				counts.Filtered++
				continue
			}
		}

		text := ""
		if msg.Text != nil {
			text = *msg.Text
		}
		subject := ""
		if msg.Subject != nil {
			subject = *msg.Subject
		}
		timestampMS := msg.TimestampMs
		if timestampMS <= 0 {
			timestampMS = time.Now().UnixMilli()
		}

		tapbackTargetGUID := ""
		if msg.TapbackTargetGuid != nil {
			tapbackTargetGUID = *msg.TapbackTargetGuid
		}
		tapbackEmoji := ""
		if msg.TapbackEmoji != nil {
			tapbackEmoji = *msg.TapbackEmoji
		}

		// Enrich and serialize attachment metadata.
		attachmentsJSON := ""
		if len(msg.AttachmentGuids) > 0 && attMap != nil {
			var attRows []cloudAttachmentRow
			for _, guid := range msg.AttachmentGuids {
				if guid == "" {
					continue
				}
				if enriched, ok := attMap[guid]; ok {
					attRows = append(attRows, enriched)
				} else {
					log.Warn().Str("msg_guid", msg.Guid).Str("att_guid", guid).
						Msg("Attachment GUID not found in attachment zone")
				}
			}
			// Live Photo companion discovery: if a message has an HEIC still,
			// search the attachment zone for a MOV video with the same base
			// filename (e.g., IMG_5551.HEIC → IMG_5551.MOV). CloudKit doesn't
			// reference the MOV GUID from the message, but the record exists
			// in the attachment zone. We inject it with HideAttachment=true so
			// cloudAttachmentsToBackfill skips the HEIC and bridges the video.
			attRows = injectLivePhotoCompanion(attRows, attMap, log, msg.Guid)
			if len(attRows) > 0 {
				if attJSON, jsonErr := json.Marshal(attRows); jsonErr == nil {
					attachmentsJSON = string(attJSON)
				}
			}
		}

		// Mark as deleted if the portal is currently being deleted, so
		// concurrent or future re-syncs don't resurrect the portal.
		isDeleted := deletedPortalsSnapshot[portalID]

		batch = append(batch, cloudMessageRow{
			GUID:              msg.Guid,
			RecordName:        msg.RecordName,
			CloudChatID:       msg.CloudChatId,
			PortalID:          portalID,
			TimestampMS:       timestampMS,
			Sender:            msg.Sender,
			IsFromMe:          msg.IsFromMe,
			Text:              text,
			Subject:           subject,
			Service:           msg.Service,
			Deleted:           isDeleted,
			TapbackType:       msg.TapbackType,
			TapbackTargetGUID: tapbackTargetGUID,
			TapbackEmoji:      tapbackEmoji,
			AttachmentsJSON:   attachmentsJSON,
			DateReadMS:        msg.DateReadMs,
			HasBody:           msg.HasBody,
		})

		if existingSet[msg.Guid] {
			counts.Updated++
		} else {
			counts.Imported++
		}
	}

	// Phase 2: Batch insert all live rows in a single transaction.
	if err := c.cloudStore.upsertMessageBatch(ctx, batch); err != nil {
		return err
	}

	return nil
}

func (c *IMClient) resolvePortalIDForCloudChat(participants []string, displayName *string, groupID string, style int64) string {
	normalizedParticipants := make([]string, 0, len(participants))
	for _, participant := range participants {
		normalized := normalizeIdentifierForPortalID(participant)
		if normalized == "" {
			continue
		}
		normalizedParticipants = append(normalizedParticipants, normalized)
	}
	if len(normalizedParticipants) == 0 {
		return ""
	}

	// CloudKit chat style: 43 = group, 45 = DM.
	// Use style as the authoritative group/DM signal. The group_id (gid)
	// field is set for ALL CloudKit chats, even DMs, so we can't use its
	// presence alone.
	isGroup := style == 43

	// For groups with a persistent group UUID, use gid:<UUID> as portal ID
	if isGroup && groupID != "" {
		normalizedGID := strings.ToLower(groupID)
		return "gid:" + normalizedGID
	}

	// For DMs: use the single remote participant as the portal ID
	// (e.g., "tel:+15551234567" or "mailto:user@example.com").
	// Filter out our own handle so only the remote side remains.
	remoteParticipants := make([]string, 0, len(normalizedParticipants))
	for _, p := range normalizedParticipants {
		if !c.isMyHandle(p) {
			remoteParticipants = append(remoteParticipants, p)
		}
	}

	if len(remoteParticipants) == 1 {
		// Standard DM — portal ID is the remote participant.
		// Use contact merging so that separate CloudKit chat records for
		// the same contact (one per handle) resolve to a single portal.
		handle := remoteParticipants[0]
		resolved := c.resolveContactPortalID(handle)
		if string(resolved) == handle {
			resolved = networkid.PortalID(c.canonicalContactHandle(handle))
		}
		resolved = c.resolveExistingDMPortalID(string(resolved))
		return string(resolved)
	}

	// Self-chat (Notes to Self): all participants are our own handle.
	// Use our handle as the portal ID directly.
	if len(remoteParticipants) == 0 && len(normalizedParticipants) > 0 {
		return normalizedParticipants[0]
	}

	// Fallback for edge cases (unknown style, multi-participant without group style)
	groupName := displayName
	var senderGuidPtr *string
	if isGroup && groupID != "" {
		senderGuidPtr = &groupID
	}
	portalKey := c.makePortalKey(normalizedParticipants, groupName, nil, senderGuidPtr)
	return string(portalKey.ID)
}

func (c *IMClient) createPortalsFromCloudSync(ctx context.Context, log zerolog.Logger, pendingDeletePortals map[string]bool) {
	if c.cloudStore == nil {
		return
	}

	// Get portal IDs sorted by newest message timestamp (most recent first).
	// This includes both portals that have messages AND chat-only portals
	// from cloud_chat (with 0 messages). Chat-only portals are included so
	// conversations synced from CloudKit without any resolved messages still
	// get bridge portals created.
	portalInfos, err := c.cloudStore.listPortalIDsWithNewestTimestamp(ctx)
	if err != nil {
		log.Err(err).Msg("Failed to list cloud portal IDs with timestamps")
		return
	}

	if len(portalInfos) == 0 {
		return
	}

	// Tombstoned (deleted) chats are already removed from cloud_chat/cloud_message
	// during ingestCloudChats, so they won't appear in portalInfos. No separate
	// deleted_portal filter needed — CloudKit tombstones are the authoritative signal.

	// Snapshot recentlyDeletedPortals so we filter portals deleted in-session
	// even if they were deleted after the static pendingDeletePortals map was built
	// (e.g. deleted between bootstrap sync and a delayed 15s/60s/3min re-sync).
	c.recentlyDeletedPortalsMu.RLock()
	recentlyDeletedSnapshot := make(map[string]bool, len(c.recentlyDeletedPortals))
	for id := range c.recentlyDeletedPortals {
		recentlyDeletedSnapshot[id] = true
	}
	c.recentlyDeletedPortalsMu.RUnlock()

	// Count how many portals have messages vs chat-only (diagnostic).
	chatOnlyPortals := 0
	for _, p := range portalInfos {
		if p.MessageCount == 0 {
			chatOnlyPortals++
		}
	}
	log.Info().
		Int("total_portals", len(portalInfos)).
		Int("with_messages", len(portalInfos)-chatOnlyPortals).
		Int("chat_only", chatOnlyPortals).
		Msg("Portal candidates from cloud sync (messages + chat-only)")

	// Skip portals already queued this session with the same newest timestamp.
	// If CloudKit has newer messages, the timestamp changes and we re-queue.
	if c.queuedPortals == nil {
		c.queuedPortals = make(map[string]int64)
	}
	ordered := make([]string, 0, len(portalInfos))
	newestTSByPortal := make(map[string]int64, len(portalInfos))
	alreadyQueued := 0
	pendingDeleteSkipped := 0
	for _, p := range portalInfos {
		newestTSByPortal[p.PortalID] = p.NewestTS
		// Skip portals with no messages — these are cloud_chat records whose
		// messages were all deleted. Creating empty portals is pointless; if
		// new messages arrive later, APNs will create the portal on demand.
		if p.MessageCount == 0 {
			continue
		}
		// Skip portals that are tombstoned or recently deleted this session.
		// pendingDeletePortals is the skip map passed by the caller;
		// recentlyDeletedSnapshot catches portals deleted after that point.
		if pendingDeletePortals[p.PortalID] || recentlyDeletedSnapshot[p.PortalID] {
			pendingDeleteSkipped++
			continue
		}
		if lastTS, ok := c.queuedPortals[p.PortalID]; ok && lastTS >= p.NewestTS {
			alreadyQueued++
			continue
		}
		ordered = append(ordered, p.PortalID)
	}
	if pendingDeleteSkipped > 0 {
		log.Info().Int("skipped", pendingDeleteSkipped).Msg("Skipped tombstoned or recently deleted portals")
	}

	portalStart := time.Now()
	log.Info().
		Int("total_candidates", len(portalInfos)).
		Int("already_queued", alreadyQueued).
		Int("to_process", len(ordered)).
		Msg("Creating portals from cloud sync")

	// Set pendingInitialBackfills BEFORE queuing any portals.
	// bridgev2 processes ChatResync events concurrently (QueueRemoteEvent is
	// async), so FetchMessages(Forward=true) calls — and their
	// onForwardBackfillDone decrements — can fire during the queuing loop.
	// If we set the counter AFTER the loop (StoreInt64 at the end), early
	// decrements land on 0 (making it negative), then the Store overwrites
	// those decrements with N, leaving the counter stuck at the number of
	// early completions rather than reaching 0.  Setting it up-front to
	// len(ordered) ensures every decrement is counted correctly.
	if !c.isCloudSyncDone() {
		atomic.StoreInt64(&c.pendingInitialBackfills, int64(len(ordered)))
		log.Debug().Int("count", len(ordered)).Msg("Set pendingInitialBackfills for APNs buffer hold")
	}

	created := 0
	for i, portalID := range ordered {
		portalKey := networkid.PortalKey{
			ID:       networkid.PortalID(portalID),
			Receiver: c.UserLogin.ID,
		}

		newestTS := newestTSByPortal[portalID]
		var latestMessageTS time.Time
		if newestTS > 0 {
			latestMessageTS = time.UnixMilli(newestTS)
		}
		log.Debug().
			Str("portal_id", portalID).
			Int("index", i).
			Int("total", len(ordered)).
			Int64("newest_ts", newestTS).
			Msg("Queuing ChatResync for portal")
		c.UserLogin.QueueRemoteEvent(&simplevent.ChatResync{
			EventMeta: simplevent.EventMeta{
				Type:         bridgev2.RemoteEventChatResync,
				PortalKey:    portalKey,
				CreatePortal: true,
				LogContext: func(lc zerolog.Context) zerolog.Context {
					return lc.
						Str("portal_id", portalID).
						Str("source", "cloud_sync")
				},
			},
			GetChatInfoFunc: c.GetChatInfo,
			LatestMessageTS: latestMessageTS,
		})
		c.queuedPortals[portalID] = newestTS
		created++
		if (i+1)%25 == 0 {
			log.Info().
				Int("progress", i+1).
				Int("total", len(ordered)).
				Dur("elapsed", time.Since(portalStart)).
				Msg("Portal queuing progress")
		}
		// Stagger portal processing to avoid overwhelming Matrix server
		// with concurrent ghost updates and room state changes.
		if (i+1)%5 == 0 {
			time.Sleep(500 * time.Millisecond)
		}
	}

	log.Info().
		Int("queued", created).
		Int("total", len(ordered)).
		Dur("elapsed", time.Since(portalStart)).
		Msg("Finished queuing portals from cloud sync")

	// pendingInitialBackfills was already set to len(ordered) BEFORE the loop
	// so that early-completing FetchMessages(Forward=true) calls are counted
	// correctly (see comment above the loop).  Nothing more to do here.

	// Reset backward backfill tasks for portals that already have Matrix rooms.
	// This handles the version-upgrade re-sync case where rooms exist but the
	// backfill task may be marked done from a previous incomplete sync.
	//
	// For NEW portals (fresh DB, no rooms yet), we do NOT create tasks here.
	// bridgev2 automatically creates backfill tasks when it creates the Matrix
	// room during ChatResync processing (portal.go calls BackfillTask.Upsert
	// when CanBackfill=true). Creating tasks before rooms exist causes a race:
	// the backfill queue picks up the task, finds portal.MXID=="", and
	// permanently deletes it via deleteBackfillQueueTaskIfRoomDoesNotExist.
	resetCount := 0
	skippedNoRoom := 0
	for _, portalID := range ordered {
		portalKey := networkid.PortalKey{
			ID:       networkid.PortalID(portalID),
			Receiver: c.UserLogin.ID,
		}
		portal, err := c.Main.Bridge.GetExistingPortalByKey(ctx, portalKey)
		if err != nil {
			log.Warn().Err(err).Str("portal_id", portalID).Msg("Failed to look up portal for backfill task")
			continue
		}
		if portal == nil || portal.MXID == "" {
			skippedNoRoom++
			continue
		}
		if err := c.Main.Bridge.DB.BackfillTask.Upsert(ctx, &database.BackfillTask{
			PortalKey:         portalKey,
			UserLoginID:       c.UserLogin.ID,
			BatchCount:        -1,
			IsDone:            false,
			Cursor:            "",
			OldestMessageID:   "",
			NextDispatchMinTS: time.Now().Add(5 * time.Second),
		}); err != nil {
			log.Warn().Err(err).Str("portal_id", portalID).Msg("Failed to reset backfill task")
		} else {
			resetCount++
		}
	}
	if resetCount > 0 || skippedNoRoom > 0 {
		log.Info().
			Int("reset_count", resetCount).
			Int("skipped_no_room", skippedNoRoom).
			Msg("Backward backfill task setup (rooms without tasks reset, new portals deferred to ChatResync)")
		if resetCount > 0 {
			c.Main.Bridge.WakeupBackfillQueue()
		}
	}
}

func (c *IMClient) ensureCloudSyncStore(ctx context.Context) error {
	if c.cloudStore == nil {
		return fmt.Errorf("cloud store not initialized")
	}
	return c.cloudStore.ensureSchema(ctx)
}

// injectLivePhotoCompanion searches the attachment zone for a Live Photo MOV
// companion when a message has an HEIC still image. Apple Live Photos store
// two files: a still HEIC and a short MOV video with matching base filename
// (e.g., IMG_5551.HEIC + IMG_5551.MOV). In CloudKit, only the HEIC GUID is
// referenced by the message; the MOV exists in the attachment zone but is
// orphaned. This function finds the MOV by filename match and injects it into
// the attachment list with HideAttachment=true so downstream filtering
// (cloudAttachmentsToBackfill) drops the HEIC and bridges only the video.
func injectLivePhotoCompanion(attRows []cloudAttachmentRow, attMap map[string]cloudAttachmentRow, log zerolog.Logger, msgGUID string) []cloudAttachmentRow {
	// Find HEIC/image attachments with filenames we can match.
	var heicBases []string
	heicGUIDs := make(map[string]bool)
	for _, att := range attRows {
		if strings.HasPrefix(att.MimeType, "image/") && att.Filename != "" {
			base := filenameBase(att.Filename)
			if base != "" {
				heicBases = append(heicBases, base)
				heicGUIDs[att.GUID] = true
			}
		}
	}
	if len(heicBases) == 0 {
		return attRows
	}

	// Build a set of base names for quick lookup.
	baseSet := make(map[string]bool, len(heicBases))
	for _, b := range heicBases {
		baseSet[strings.ToLower(b)] = true
	}

	// Search the entire attachment zone for videos with matching base filenames.
	// Existing attachment GUIDs are skipped to avoid duplicates.
	existingGUIDs := make(map[string]bool, len(attRows))
	for _, att := range attRows {
		existingGUIDs[att.GUID] = true
	}

	for _, att := range attMap {
		if existingGUIDs[att.GUID] {
			continue
		}
		if !strings.HasPrefix(att.MimeType, "video/") || att.Filename == "" {
			continue
		}
		base := filenameBase(att.Filename)
		if base != "" && baseSet[strings.ToLower(base)] {
			// Found a Live Photo MOV companion. Mark it as hidden so
			// cloudAttachmentsToBackfill will drop the HEIC still.
			att.HideAttachment = true
			attRows = append(attRows, att)
			log.Info().Str("msg_guid", msgGUID).Str("mov_guid", att.GUID).
				Str("filename", att.Filename).
				Msg("Live Photo: injected MOV companion from attachment zone")
		}
	}

	return attRows
}

// filenameBase returns the filename without its extension.
// e.g., "IMG_5551.HEIC" → "IMG_5551", "photo.MOV" → "photo"
func filenameBase(name string) string {
	if idx := strings.LastIndex(name, "."); idx > 0 {
		return name[:idx]
	}
	return ""
}
