package connector

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/bridgev2/networkid"
)

type cloudBackfillStore struct {
	db      *dbutil.Database
	loginID networkid.UserLoginID
}

type cloudMessageRow struct {
	GUID        string
	RecordName  string
	CloudChatID string
	PortalID    string
	TimestampMS int64
	Sender      string
	IsFromMe    bool
	Text        string
	Subject     string
	Service     string
	Deleted     bool

	// Tapback/reaction fields
	TapbackType       *uint32
	TapbackTargetGUID string
	TapbackEmoji      string

	// Attachment metadata JSON (serialized []cloudAttachmentRow)
	AttachmentsJSON string

	// When the recipient read this message (Unix ms). Only for is_from_me messages.
	DateReadMS int64

	// Whether the CloudKit record has an attributedBody (rich text payload).
	// Regular user messages always have this; system messages (group renames,
	// participant changes) do not.
	HasBody bool
}

// cloudAttachmentRow holds CloudKit attachment metadata for a single attachment.
type cloudAttachmentRow struct {
	GUID       string `json:"guid"`
	MimeType   string `json:"mime_type,omitempty"`
	UTIType    string `json:"uti_type,omitempty"`
	Filename   string `json:"filename,omitempty"`
	FileSize   int64  `json:"file_size"`
	RecordName string `json:"record_name"`
}

const (
	cloudZoneChats       = "chatManateeZone"
	cloudZoneMessages    = "messageManateeZone"
	cloudZoneAttachments = "attachmentManateeZone"
)

func newCloudBackfillStore(db *dbutil.Database, loginID networkid.UserLoginID) *cloudBackfillStore {
	return &cloudBackfillStore{db: db, loginID: loginID}
}

func (s *cloudBackfillStore) ensureSchema(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS cloud_sync_state (
			login_id TEXT NOT NULL,
			zone TEXT NOT NULL,
			continuation_token TEXT,
			last_success_ts BIGINT,
			last_error TEXT,
			updated_ts BIGINT NOT NULL,
			PRIMARY KEY (login_id, zone)
		)`,
		`CREATE TABLE IF NOT EXISTS cloud_chat (
			login_id TEXT NOT NULL,
			cloud_chat_id TEXT NOT NULL,
			record_name TEXT NOT NULL DEFAULT '',
			group_id TEXT NOT NULL DEFAULT '',
			portal_id TEXT NOT NULL,
			service TEXT,
			display_name TEXT,
			group_photo_guid TEXT,
			participants_json TEXT,
			updated_ts BIGINT,
			created_ts BIGINT NOT NULL,
			PRIMARY KEY (login_id, cloud_chat_id)
		)`,
		`CREATE TABLE IF NOT EXISTS cloud_message (
			login_id TEXT NOT NULL,
			guid TEXT NOT NULL,
			chat_id TEXT,
			portal_id TEXT,
			timestamp_ms BIGINT NOT NULL,
			sender TEXT,
			is_from_me BOOLEAN NOT NULL,
			text TEXT,
			subject TEXT,
			service TEXT,
			deleted BOOLEAN NOT NULL DEFAULT FALSE,
			tapback_type INTEGER,
			tapback_target_guid TEXT,
			tapback_emoji TEXT,
			attachments_json TEXT,
			created_ts BIGINT NOT NULL,
			updated_ts BIGINT NOT NULL,
			PRIMARY KEY (login_id, guid)
		)`,
		`CREATE TABLE IF NOT EXISTS group_photo_cache (
			login_id TEXT NOT NULL,
			portal_id TEXT NOT NULL,
			ts BIGINT NOT NULL,
			data BLOB NOT NULL,
			PRIMARY KEY (login_id, portal_id)
		)`,
		`CREATE INDEX IF NOT EXISTS cloud_chat_portal_idx
			ON cloud_chat (login_id, portal_id, cloud_chat_id)`,
		`CREATE INDEX IF NOT EXISTS cloud_message_portal_ts_idx
			ON cloud_message (login_id, portal_id, timestamp_ms, guid)`,
		`CREATE INDEX IF NOT EXISTS cloud_message_chat_ts_idx
			ON cloud_message (login_id, chat_id, timestamp_ms, guid)`,
	}

	// Run table creation queries first (without indexes that depend on migrations)
	for _, query := range queries {
		if _, err := s.db.Exec(ctx, query); err != nil {
			return fmt.Errorf("failed to ensure cloud backfill schema: %w", err)
		}
	}

	// Migration: add record_name column if missing (SQLite doesn't support IF NOT EXISTS on ALTER)
	var hasRecordName int
	_ = s.db.QueryRow(ctx, `SELECT COUNT(*) FROM pragma_table_info('cloud_chat') WHERE name='record_name'`).Scan(&hasRecordName)
	if hasRecordName == 0 {
		if _, err := s.db.Exec(ctx, `ALTER TABLE cloud_chat ADD COLUMN record_name TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("failed to add record_name column: %w", err)
		}
	}

	// Migration: add group_id column if missing
	var hasGroupID int
	_ = s.db.QueryRow(ctx, `SELECT COUNT(*) FROM pragma_table_info('cloud_chat') WHERE name='group_id'`).Scan(&hasGroupID)
	if hasGroupID == 0 {
		if _, err := s.db.Exec(ctx, `ALTER TABLE cloud_chat ADD COLUMN group_id TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("failed to add group_id column: %w", err)
		}
	}

	// Migration: add group_photo_guid column if missing
	var hasGroupPhotoGuid int
	_ = s.db.QueryRow(ctx, `SELECT COUNT(*) FROM pragma_table_info('cloud_chat') WHERE name='group_photo_guid'`).Scan(&hasGroupPhotoGuid)
	if hasGroupPhotoGuid == 0 {
		if _, err := s.db.Exec(ctx, `ALTER TABLE cloud_chat ADD COLUMN group_photo_guid TEXT`); err != nil {
			return fmt.Errorf("failed to add group_photo_guid column: %w", err)
		}
	}


	// Migration: add deleted column to cloud_chat if missing.
	// Soft-deletes cloud_chat rows alongside cloud_message rows so that
	// restore-chat can recover group name and participants.
	var hasChatDeleted int
	_ = s.db.QueryRow(ctx, `SELECT COUNT(*) FROM pragma_table_info('cloud_chat') WHERE name='deleted'`).Scan(&hasChatDeleted)
	if hasChatDeleted == 0 {
		if _, err := s.db.Exec(ctx, `ALTER TABLE cloud_chat ADD COLUMN deleted BOOLEAN NOT NULL DEFAULT FALSE`); err != nil {
			return fmt.Errorf("failed to add deleted column to cloud_chat: %w", err)
		}
	}

	// Migration: add is_filtered column to cloud_chat if missing
	var hasIsFiltered int
	_ = s.db.QueryRow(ctx, `SELECT COUNT(*) FROM pragma_table_info('cloud_chat') WHERE name='is_filtered'`).Scan(&hasIsFiltered)
	if hasIsFiltered == 0 {
		if _, err := s.db.Exec(ctx, `ALTER TABLE cloud_chat ADD COLUMN is_filtered INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("failed to add is_filtered column: %w", err)
		}
	}

	// Migration: add rich content columns to cloud_message if missing
	richCols := []struct {
		name string
		def  string
	}{
		{"subject", "TEXT"},
		{"tapback_type", "INTEGER"},
		{"tapback_target_guid", "TEXT"},
		{"tapback_emoji", "TEXT"},
		{"attachments_json", "TEXT"},
	}
	for _, col := range richCols {
		var exists int
		_ = s.db.QueryRow(ctx, `SELECT COUNT(*) FROM pragma_table_info('cloud_message') WHERE name=$1`, col.name).Scan(&exists)
		if exists == 0 {
			if _, err := s.db.Exec(ctx, fmt.Sprintf(`ALTER TABLE cloud_message ADD COLUMN %s %s`, col.name, col.def)); err != nil {
				return fmt.Errorf("failed to add %s column: %w", col.name, err)
			}
		}
	}

	// Migration: add date_read_ms column to cloud_message if missing
	var hasDateReadMS int
	_ = s.db.QueryRow(ctx, `SELECT COUNT(*) FROM pragma_table_info('cloud_message') WHERE name='date_read_ms'`).Scan(&hasDateReadMS)
	if hasDateReadMS == 0 {
		if _, err := s.db.Exec(ctx, `ALTER TABLE cloud_message ADD COLUMN date_read_ms BIGINT NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("failed to add date_read_ms column: %w", err)
		}
	}

	// Migration: add record_name column to cloud_message if missing
	var hasMsgRecordName int
	_ = s.db.QueryRow(ctx, `SELECT COUNT(*) FROM pragma_table_info('cloud_message') WHERE name='record_name'`).Scan(&hasMsgRecordName)
	if hasMsgRecordName == 0 {
		if _, err := s.db.Exec(ctx, `ALTER TABLE cloud_message ADD COLUMN record_name TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("failed to add record_name column to cloud_message: %w", err)
		}
	}

	// Migration: add has_body column to cloud_message if missing
	var hasHasBody int
	_ = s.db.QueryRow(ctx, `SELECT COUNT(*) FROM pragma_table_info('cloud_message') WHERE name='has_body'`).Scan(&hasHasBody)
	if hasHasBody == 0 {
		if _, err := s.db.Exec(ctx, `ALTER TABLE cloud_message ADD COLUMN has_body BOOLEAN NOT NULL DEFAULT TRUE`); err != nil {
			return fmt.Errorf("failed to add has_body column: %w", err)
		}
	}

	// Migration: add fwd_backfill_done column to cloud_chat if missing.
	// Set to 1 when FetchMessages(forward) completes for a portal so that
	// preUploadCloudAttachments skips those portals on restart instead of
	// re-uploading every attachment. Default 0 means "not yet done".
	var hasFwdBackfillDone int
	_ = s.db.QueryRow(ctx, `SELECT COUNT(*) FROM pragma_table_info('cloud_chat') WHERE name='fwd_backfill_done'`).Scan(&hasFwdBackfillDone)
	if hasFwdBackfillDone == 0 {
		if _, err := s.db.Exec(ctx, `ALTER TABLE cloud_chat ADD COLUMN fwd_backfill_done BOOLEAN NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("failed to add fwd_backfill_done column: %w", err)
		}
	}

	// Cleanup: permanently delete system/rename message rows that slipped into
	// the DB before the MsgType==0 ingest filter was added.  Two conditions
	// catch different eras of the DB:
	//   1. has_body=FALSE + no attachments + no tapback — rows that were stored
	//      after the has_body column was added but before the MsgType filter;
	//      their has_body is correctly FALSE (no attributedBody).
	//   2. text matches the portal's display_name + no attachments + no tapback
	//      — older rows whose has_body defaulted to TRUE but whose content
	//      reveals them as group-rename notifications.
	// This runs every startup and is idempotent: after the first pass it
	// matches zero rows.
	if _, err := s.db.Exec(ctx, `
		DELETE FROM cloud_message
		WHERE login_id = $1
		  AND COALESCE(attachments_json, '') = ''
		  AND tapback_type IS NULL
		  AND (
		    has_body = FALSE
		    OR (
		      text IS NOT NULL AND text <> ''
		      AND portal_id IN (
		        SELECT portal_id FROM cloud_chat c
		        WHERE c.login_id = $1
		          AND c.display_name IS NOT NULL AND c.display_name <> ''
		          AND c.display_name = cloud_message.text
		      )
		    )
		  )
	`, s.loginID); err != nil {
		return fmt.Errorf("failed to delete system messages: %w", err)
	}

	// Migration: add cloud_attachment_cache table if missing.
	// Persists record_name → MessageEventContent JSON so mxc URIs survive
	// bridge restarts. Pre-upload loads this at startup and skips already-cached
	// attachments, so a 27k-message thread never re-downloads across restarts.
	if _, err := s.db.Exec(ctx, `CREATE TABLE IF NOT EXISTS cloud_attachment_cache (
		login_id    TEXT    NOT NULL,
		record_name TEXT    NOT NULL,
		content_json BLOB   NOT NULL,
		created_ts  BIGINT  NOT NULL,
		PRIMARY KEY (login_id, record_name)
	)`); err != nil {
		return fmt.Errorf("failed to create cloud_attachment_cache table: %w", err)
	}

	// Create index that depends on record_name column (must be after migration)
	if _, err := s.db.Exec(ctx, `CREATE INDEX IF NOT EXISTS cloud_chat_record_name_idx
		ON cloud_chat (login_id, record_name) WHERE record_name <> ''`); err != nil {
		return fmt.Errorf("failed to create record_name index: %w", err)
	}

	// Create index for group_id lookups (messages reference chats by group_id UUID)
	if _, err := s.db.Exec(ctx, `CREATE INDEX IF NOT EXISTS cloud_chat_group_id_idx
		ON cloud_chat (login_id, group_id) WHERE group_id <> ''`); err != nil {
		return fmt.Errorf("failed to create group_id index: %w", err)
	}

	return nil
}

func (s *cloudBackfillStore) getSyncState(ctx context.Context, zone string) (*string, error) {
	var token sql.NullString
	err := s.db.QueryRow(ctx,
		`SELECT continuation_token FROM cloud_sync_state WHERE login_id=$1 AND zone=$2`,
		s.loginID, zone,
	).Scan(&token)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if !token.Valid {
		return nil, nil
	}
	return &token.String, nil
}

func (s *cloudBackfillStore) setSyncStateSuccess(ctx context.Context, zone string, token *string) error {
	nowMS := time.Now().UnixMilli()
	_, err := s.db.Exec(ctx, `
		INSERT INTO cloud_sync_state (login_id, zone, continuation_token, last_success_ts, last_error, updated_ts)
		VALUES ($1, $2, $3, $4, NULL, $5)
		ON CONFLICT (login_id, zone) DO UPDATE SET
			continuation_token=excluded.continuation_token,
			last_success_ts=excluded.last_success_ts,
			last_error=NULL,
			updated_ts=excluded.updated_ts
	`, s.loginID, zone, nullableString(token), nowMS, nowMS)
	return err
}

// clearSyncTokens removes only the sync continuation tokens for this login,
// forcing the next sync to re-download all records from CloudKit.
// Preserves cloud_chat, cloud_message, and the _version row.
func (s *cloudBackfillStore) clearSyncTokens(ctx context.Context) error {
	_, err := s.db.Exec(ctx,
		`DELETE FROM cloud_sync_state WHERE login_id=$1 AND zone != '_version'`,
		s.loginID,
	)
	return err
}

// clearZoneToken removes the continuation token for a specific zone,
// forcing the next sync for that zone to start from scratch.
func (s *cloudBackfillStore) clearZoneToken(ctx context.Context, zone string) error {
	_, err := s.db.Exec(ctx,
		`DELETE FROM cloud_sync_state WHERE login_id=$1 AND zone=$2`,
		s.loginID, zone,
	)
	return err
}

// getSyncVersion returns the stored sync schema version (0 if never set).
func (s *cloudBackfillStore) getSyncVersion(ctx context.Context) (int, error) {
	var token sql.NullString
	err := s.db.QueryRow(ctx,
		`SELECT continuation_token FROM cloud_sync_state WHERE login_id=$1 AND zone='_version'`,
		s.loginID,
	).Scan(&token)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	if !token.Valid {
		return 0, nil
	}
	v := 0
	fmt.Sscanf(token.String, "%d", &v)
	return v, nil
}

// setSyncVersion stores the sync schema version.
func (s *cloudBackfillStore) setSyncVersion(ctx context.Context, version int) error {
	nowMS := time.Now().UnixMilli()
	vStr := fmt.Sprintf("%d", version)
	_, err := s.db.Exec(ctx, `
		INSERT INTO cloud_sync_state (login_id, zone, continuation_token, updated_ts)
		VALUES ($1, '_version', $2, $3)
		ON CONFLICT (login_id, zone) DO UPDATE SET
			continuation_token=excluded.continuation_token,
			updated_ts=excluded.updated_ts
	`, s.loginID, vStr, nowMS)
	return err
}

// getChatSyncVersion returns the stored chat-specific sync version (0 if never set).
// This tracks chat-zone-only re-syncs independently of the full cloudSyncVersion,
// so we can force a targeted chat re-fetch (e.g. to populate group_photo_guid)
// without also re-downloading all messages.
func (s *cloudBackfillStore) getChatSyncVersion(ctx context.Context) (int, error) {
	var token sql.NullString
	err := s.db.QueryRow(ctx,
		`SELECT continuation_token FROM cloud_sync_state WHERE login_id=$1 AND zone='_chat_version'`,
		s.loginID,
	).Scan(&token)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	if !token.Valid {
		return 0, nil
	}
	v := 0
	fmt.Sscanf(token.String, "%d", &v)
	return v, nil
}

// setChatSyncVersion stores the chat-specific sync schema version.
func (s *cloudBackfillStore) setChatSyncVersion(ctx context.Context, version int) error {
	nowMS := time.Now().UnixMilli()
	vStr := fmt.Sprintf("%d", version)
	_, err := s.db.Exec(ctx, `
		INSERT INTO cloud_sync_state (login_id, zone, continuation_token, updated_ts)
		VALUES ($1, '_chat_version', $2, $3)
		ON CONFLICT (login_id, zone) DO UPDATE SET
			continuation_token=excluded.continuation_token,
			updated_ts=excluded.updated_ts
	`, s.loginID, vStr, nowMS)
	return err
}

// clearAllData removes cloud cache data for this login: sync tokens,
// cached chats, and cached messages. Used on fresh bootstrap when the bridge
// DB was reset but the cloud tables survived.
func (s *cloudBackfillStore) clearAllData(ctx context.Context) error {
	for _, table := range []string{"cloud_sync_state", "cloud_chat", "cloud_message", "cloud_attachment_cache"} {
		if _, err := s.db.Exec(ctx,
			fmt.Sprintf(`DELETE FROM %s WHERE login_id=$1`, table),
			s.loginID,
		); err != nil {
			return fmt.Errorf("failed to clear %s: %w", table, err)
		}
	}
	return nil
}

// hasAnySyncState checks whether any sync state rows exist for this login.
// Used to detect an interrupted sync — if tokens exist but no portals were
// created yet, the sync was interrupted mid-flight and should resume, NOT restart.
func (s *cloudBackfillStore) hasAnySyncState(ctx context.Context) (bool, error) {
	var count int
	err := s.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM cloud_sync_state WHERE login_id=$1`,
		s.loginID,
	).Scan(&count)
	return count > 0, err
}

func (s *cloudBackfillStore) setSyncStateError(ctx context.Context, zone, errMsg string) error {
	nowMS := time.Now().UnixMilli()
	_, err := s.db.Exec(ctx, `
		INSERT INTO cloud_sync_state (login_id, zone, continuation_token, last_error, updated_ts)
		VALUES ($1, $2, NULL, $3, $4)
		ON CONFLICT (login_id, zone) DO UPDATE SET
			last_error=excluded.last_error,
			updated_ts=excluded.updated_ts
	`, s.loginID, zone, errMsg, nowMS)
	return err
}

func (s *cloudBackfillStore) upsertChat(
	ctx context.Context,
	cloudChatID, recordName, groupID, portalID, service string,
	displayName, groupPhotoGuid *string,
	participants []string,
	updatedTS int64,
) error {
	participantsJSON, err := json.Marshal(participants)
	if err != nil {
		return err
	}
	nowMS := time.Now().UnixMilli()
	_, err = s.db.Exec(ctx, `
		INSERT INTO cloud_chat (
			login_id, cloud_chat_id, record_name, group_id, portal_id, service, display_name,
			group_photo_guid, participants_json, updated_ts, created_ts
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (login_id, cloud_chat_id) DO UPDATE SET
			record_name=excluded.record_name,
			group_id=excluded.group_id,
			portal_id=excluded.portal_id,
			service=excluded.service,
			display_name=CASE
				WHEN excluded.updated_ts >= COALESCE(cloud_chat.updated_ts, 0)
				THEN excluded.display_name
				ELSE cloud_chat.display_name
			END,
			group_photo_guid=CASE
				WHEN excluded.updated_ts >= COALESCE(cloud_chat.updated_ts, 0)
				THEN excluded.group_photo_guid
				ELSE cloud_chat.group_photo_guid
			END,
			participants_json=excluded.participants_json,
			updated_ts=CASE
				WHEN excluded.updated_ts >= COALESCE(cloud_chat.updated_ts, 0)
				THEN excluded.updated_ts
				ELSE cloud_chat.updated_ts
			END
	`, s.loginID, cloudChatID, recordName, groupID, portalID, service, nullableString(displayName), nullableString(groupPhotoGuid), string(participantsJSON), updatedTS, nowMS)
	return err
}

// beginTx starts a database transaction for batch operations.
func (s *cloudBackfillStore) beginTx(ctx context.Context) (*sql.Tx, error) {
	return s.db.RawDB.BeginTx(ctx, nil)
}

// upsertMessageBatch inserts multiple messages in a single transaction.
func (s *cloudBackfillStore) upsertMessageBatch(ctx context.Context, rows []cloudMessageRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.beginTx(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO cloud_message (
			login_id, guid, record_name, chat_id, portal_id, timestamp_ms,
			sender, is_from_me, text, subject, service, deleted,
			tapback_type, tapback_target_guid, tapback_emoji,
			attachments_json, date_read_ms, has_body,
			created_ts, updated_ts
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (login_id, guid) DO UPDATE SET
			record_name=excluded.record_name,
			chat_id=excluded.chat_id,
			portal_id=excluded.portal_id,
			timestamp_ms=excluded.timestamp_ms,
			sender=excluded.sender,
			is_from_me=excluded.is_from_me,
			text=excluded.text,
			subject=excluded.subject,
			service=excluded.service,
			deleted=CASE WHEN cloud_message.deleted THEN cloud_message.deleted ELSE excluded.deleted END,
			tapback_type=excluded.tapback_type,
			tapback_target_guid=excluded.tapback_target_guid,
			tapback_emoji=excluded.tapback_emoji,
			attachments_json=excluded.attachments_json,
			date_read_ms=CASE WHEN excluded.date_read_ms > cloud_message.date_read_ms THEN excluded.date_read_ms ELSE cloud_message.date_read_ms END,
			has_body=excluded.has_body,
			updated_ts=excluded.updated_ts
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer stmt.Close()

	nowMS := time.Now().UnixMilli()
	for _, row := range rows {
		_, err = stmt.ExecContext(ctx,
			s.loginID, row.GUID, row.RecordName, row.CloudChatID, row.PortalID, row.TimestampMS,
			row.Sender, row.IsFromMe, row.Text, row.Subject, row.Service, row.Deleted,
			row.TapbackType, row.TapbackTargetGUID, row.TapbackEmoji,
			row.AttachmentsJSON, row.DateReadMS, row.HasBody,
			nowMS, nowMS,
		)
		if err != nil {
			return fmt.Errorf("failed to insert message %s: %w", row.GUID, err)
		}
	}

	return tx.Commit()
}

// deleteMessageBatch soft-deletes individual messages by GUID (sets deleted=TRUE).
// This is for messages that CloudKit itself marks as deleted (individual message
// deletions), NOT for portal-level deletion (see deleteLocalChatByPortalID).
//
// Soft-delete is used here because:
//  1. Echo detection: hasMessageUUID checks cloud_message without filtering
//     by deleted. Keeping the row means re-delivered APNs echoes of the same
//     UUID are still recognised as known and suppressed.
//  2. Re-sync safety: a full CloudKit re-sync would re-import the message as
//     live. With a hard delete, the upsert inserts it with deleted=FALSE.
//     With a soft delete, the upsert conflict resolution preserves deleted=TRUE.
//
// The upsert conflict resolution (`deleted=CASE WHEN cloud_message.deleted
// THEN cloud_message.deleted ELSE excluded.deleted END`) ensures that a live
// re-delivery of the same GUID can never flip a soft-deleted row back to live.
func (s *cloudBackfillStore) deleteMessageBatch(ctx context.Context, guids []string) error {
	if len(guids) == 0 {
		return nil
	}
	nowMS := time.Now().UnixMilli()
	const chunkSize = 500
	for i := 0; i < len(guids); i += chunkSize {
		end := i + chunkSize
		if end > len(guids) {
			end = len(guids)
		}
		chunk := guids[i:end]

		placeholders := make([]string, len(chunk))
		args := make([]any, 0, len(chunk)+2)
		args = append(args, s.loginID, nowMS)
		for j, g := range chunk {
			placeholders[j] = fmt.Sprintf("$%d", j+3)
			args = append(args, g)
		}

		query := fmt.Sprintf(
			`UPDATE cloud_message SET deleted=TRUE, updated_ts=$2 WHERE login_id=$1 AND guid IN (%s) AND deleted=FALSE`,
			strings.Join(placeholders, ","),
		)
		if _, err := s.db.Exec(ctx, query, args...); err != nil {
			return fmt.Errorf("failed to soft-delete message batch: %w", err)
		}
	}
	return nil
}

// deleteChatBatch removes chats by cloud_chat_id in a single transaction.
func (s *cloudBackfillStore) deleteChatBatch(ctx context.Context, chatIDs []string) error {
	if len(chatIDs) == 0 {
		return nil
	}
	const chunkSize = 500
	for i := 0; i < len(chatIDs); i += chunkSize {
		end := i + chunkSize
		if end > len(chatIDs) {
			end = len(chatIDs)
		}
		chunk := chatIDs[i:end]

		placeholders := make([]string, len(chunk))
		args := make([]any, 0, len(chunk)+1)
		args = append(args, s.loginID)
		for j, id := range chunk {
			placeholders[j] = fmt.Sprintf("$%d", j+2)
			args = append(args, id)
		}

		query := fmt.Sprintf(
			`DELETE FROM cloud_chat WHERE login_id=$1 AND cloud_chat_id IN (%s)`,
			strings.Join(placeholders, ","),
		)
		if _, err := s.db.Exec(ctx, query, args...); err != nil {
			return fmt.Errorf("failed to delete chat batch: %w", err)
		}
	}
	return nil
}

// lookupPortalIDsByRecordNames finds portal_ids for cloud_chat records matching
// the given CloudKit record_names. Used to resolve tombstoned (deleted) chats
// whose only identifier is the record_name.
func (s *cloudBackfillStore) lookupPortalIDsByRecordNames(ctx context.Context, recordNames []string) (map[string]string, error) {
	result := make(map[string]string, len(recordNames))
	if len(recordNames) == 0 {
		return result, nil
	}
	const chunkSize = 500
	for i := 0; i < len(recordNames); i += chunkSize {
		end := i + chunkSize
		if end > len(recordNames) {
			end = len(recordNames)
		}
		chunk := recordNames[i:end]

		placeholders := make([]string, len(chunk))
		args := make([]any, 0, len(chunk)+1)
		args = append(args, s.loginID)
		for j, rn := range chunk {
			placeholders[j] = fmt.Sprintf("$%d", j+2)
			args = append(args, rn)
		}

		query := fmt.Sprintf(
			`SELECT record_name, portal_id FROM cloud_chat WHERE login_id=$1 AND record_name IN (%s)`,
			strings.Join(placeholders, ","),
		)
		rows, err := s.db.Query(ctx, query, args...)
		if err != nil {
			return nil, fmt.Errorf("failed to lookup portal IDs by record names: %w", err)
		}
		for rows.Next() {
			var rn, pid string
			if err := rows.Scan(&rn, &pid); err != nil {
				rows.Close()
				return nil, err
			}
			result[rn] = pid
		}
		rows.Close()
	}
	return result, nil
}

// deleteChatsByRecordNames removes cloud_chat entries by their CloudKit
// record_name (not cloud_chat_id). Needed for tombstoned records where the
// only identifier is the record_name.
func (s *cloudBackfillStore) deleteChatsByRecordNames(ctx context.Context, recordNames []string) error {
	if len(recordNames) == 0 {
		return nil
	}
	const chunkSize = 500
	for i := 0; i < len(recordNames); i += chunkSize {
		end := i + chunkSize
		if end > len(recordNames) {
			end = len(recordNames)
		}
		chunk := recordNames[i:end]

		placeholders := make([]string, len(chunk))
		args := make([]any, 0, len(chunk)+1)
		args = append(args, s.loginID)
		for j, rn := range chunk {
			placeholders[j] = fmt.Sprintf("$%d", j+2)
			args = append(args, rn)
		}

		query := fmt.Sprintf(
			`DELETE FROM cloud_chat WHERE login_id=$1 AND record_name IN (%s)`,
			strings.Join(placeholders, ","),
		)
		if _, err := s.db.Exec(ctx, query, args...); err != nil {
			return fmt.Errorf("failed to delete chats by record name: %w", err)
		}
	}
	return nil
}

// deleteMessagesByChatIDs removes messages whose chat_id matches any of the
// given cloud_chat_ids. This prevents orphaned messages from keeping portals
// alive after their parent chat is deleted from CloudKit.
func (s *cloudBackfillStore) deleteMessagesByChatIDs(ctx context.Context, chatIDs []string) error {
	if len(chatIDs) == 0 {
		return nil
	}
	const chunkSize = 500
	for i := 0; i < len(chatIDs); i += chunkSize {
		end := i + chunkSize
		if end > len(chatIDs) {
			end = len(chatIDs)
		}
		chunk := chatIDs[i:end]

		placeholders := make([]string, len(chunk))
		args := make([]any, 0, len(chunk)+1)
		args = append(args, s.loginID)
		for j, id := range chunk {
			placeholders[j] = fmt.Sprintf("$%d", j+2)
			args = append(args, id)
		}

		query := fmt.Sprintf(
			`DELETE FROM cloud_message WHERE login_id=$1 AND chat_id IN (%s)`,
			strings.Join(placeholders, ","),
		)
		if _, err := s.db.Exec(ctx, query, args...); err != nil {
			return fmt.Errorf("failed to delete messages by chat ID: %w", err)
		}
	}
	return nil
}

// upsertChatBatch inserts multiple chats in a single transaction.
func (s *cloudBackfillStore) upsertChatBatch(ctx context.Context, chats []cloudChatUpsertRow) error {
	if len(chats) == 0 {
		return nil
	}
	tx, err := s.beginTx(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO cloud_chat (
			login_id, cloud_chat_id, record_name, group_id, portal_id, service, display_name,
			group_photo_guid, participants_json, updated_ts, created_ts, is_filtered
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (login_id, cloud_chat_id) DO UPDATE SET
			record_name=excluded.record_name,
			group_id=excluded.group_id,
			portal_id=excluded.portal_id,
			service=excluded.service,
			display_name=CASE
				WHEN excluded.updated_ts >= COALESCE(cloud_chat.updated_ts, 0)
				THEN excluded.display_name
				ELSE cloud_chat.display_name
			END,
			group_photo_guid=CASE
				WHEN excluded.updated_ts >= COALESCE(cloud_chat.updated_ts, 0)
				THEN excluded.group_photo_guid
				ELSE cloud_chat.group_photo_guid
			END,
			participants_json=excluded.participants_json,
			updated_ts=CASE
				WHEN excluded.updated_ts >= COALESCE(cloud_chat.updated_ts, 0)
				THEN excluded.updated_ts
				ELSE cloud_chat.updated_ts
			END,
			is_filtered=excluded.is_filtered
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer stmt.Close()

	nowMS := time.Now().UnixMilli()
	for _, chat := range chats {
		_, err = stmt.ExecContext(ctx,
			s.loginID, chat.CloudChatID, chat.RecordName, chat.GroupID,
			chat.PortalID, chat.Service, chat.DisplayName,
			chat.GroupPhotoGuid, chat.ParticipantsJSON, chat.UpdatedTS, nowMS, chat.IsFiltered,
		)
		if err != nil {
			return fmt.Errorf("failed to insert chat %s: %w", chat.CloudChatID, err)
		}
	}

	return tx.Commit()
}

// hasMessageBatch checks existence of multiple GUIDs in a single query and
// returns the set of GUIDs that already exist.
func (s *cloudBackfillStore) hasMessageBatch(ctx context.Context, guids []string) (map[string]bool, error) {
	if len(guids) == 0 {
		return nil, nil
	}
	existing := make(map[string]bool, len(guids))
	// SQLite has a limit on the number of variables. Process in chunks.
	const chunkSize = 500
	for i := 0; i < len(guids); i += chunkSize {
		end := i + chunkSize
		if end > len(guids) {
			end = len(guids)
		}
		chunk := guids[i:end]

		placeholders := make([]string, len(chunk))
		args := make([]any, 0, len(chunk)+1)
		args = append(args, s.loginID)
		for j, g := range chunk {
			placeholders[j] = fmt.Sprintf("$%d", j+2)
			args = append(args, g)
		}

		query := fmt.Sprintf(
			`SELECT guid FROM cloud_message WHERE login_id=$1 AND guid IN (%s)`,
			strings.Join(placeholders, ","),
		)
		rows, err := s.db.Query(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var guid string
			if err := rows.Scan(&guid); err != nil {
				rows.Close()
				return nil, err
			}
			existing[guid] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return existing, nil
}

// cloudChatUpsertRow holds the pre-serialized data for a batch chat upsert.
type cloudChatUpsertRow struct {
	CloudChatID      string
	RecordName       string
	GroupID          string
	PortalID         string
	Service          string
	DisplayName      any // nil or string
	GroupPhotoGuid   any // nil or string
	ParticipantsJSON string
	UpdatedTS        int64
	IsFiltered       int64
}

func (s *cloudBackfillStore) getChatPortalID(ctx context.Context, cloudChatID string) (string, error) {
	var portalID string
	// Try matching by cloud_chat_id, record_name, or group_id.
	// CloudKit messages reference chats by group_id UUID (the chatID field),
	// while cloud_chat stores chat_identifier as cloud_chat_id and record hash as record_name.
	// Use LOWER() on group_id because CloudKit stores it uppercase but messages reference it lowercase.
	err := s.db.QueryRow(ctx,
		`SELECT portal_id FROM cloud_chat WHERE login_id=$1 AND (cloud_chat_id=$2 OR record_name=$2 OR LOWER(group_id)=LOWER($2))`,
		s.loginID, cloudChatID,
	).Scan(&portalID)
	if err != nil {
		if err == sql.ErrNoRows {
			// Messages use chat_identifier format like "SMS;-;+14158138533" or "iMessage;-;user@example.com"
			// but cloud_chat stores just the identifier part ("+14158138533" or "user@example.com").
			// Try stripping the service prefix.
			if parts := strings.SplitN(cloudChatID, ";-;", 2); len(parts) == 2 {
				return s.getChatPortalID(ctx, parts[1])
			}
			return "", nil
		}
		return "", err
	}
	return portalID, nil
}

// portalHasChat returns true if the given portal_id has at least one
// cloud_chat record (i.e., the conversation was included in CloudKit chat
// sync). Portals with no chat record are orphaned — typically junk/spam
// that Apple filters from the chat zone.
func (s *cloudBackfillStore) portalHasChat(ctx context.Context, portalID string) (bool, error) {
	var count int
	err := s.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM cloud_chat WHERE login_id=$1 AND portal_id=$2 AND deleted=FALSE`,
		s.loginID, portalID,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *cloudBackfillStore) hasChat(ctx context.Context, cloudChatID string) (bool, error) {
	var count int
	err := s.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM cloud_chat WHERE login_id=$1 AND cloud_chat_id=$2`,
		s.loginID, cloudChatID,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// hasChatBatch checks existence of multiple cloud chat IDs in a single query
// and returns the set of IDs that already exist.
func (s *cloudBackfillStore) hasChatBatch(ctx context.Context, chatIDs []string) (map[string]bool, error) {
	if len(chatIDs) == 0 {
		return nil, nil
	}
	existing := make(map[string]bool, len(chatIDs))
	const chunkSize = 500
	for i := 0; i < len(chatIDs); i += chunkSize {
		end := i + chunkSize
		if end > len(chatIDs) {
			end = len(chatIDs)
		}
		chunk := chatIDs[i:end]

		placeholders := make([]string, len(chunk))
		args := make([]any, 0, len(chunk)+1)
		args = append(args, s.loginID)
		for j, id := range chunk {
			placeholders[j] = fmt.Sprintf("$%d", j+2)
			args = append(args, id)
		}

		query := fmt.Sprintf(
			`SELECT cloud_chat_id FROM cloud_chat WHERE login_id=$1 AND cloud_chat_id IN (%s)`,
			strings.Join(placeholders, ","),
		)
		rows, err := s.db.Query(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			existing[id] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return existing, nil
}

func (s *cloudBackfillStore) getChatParticipantsByPortalID(ctx context.Context, portalID string) ([]string, error) {
	var participantsJSON string
	err := s.db.QueryRow(ctx,
		`SELECT participants_json FROM cloud_chat WHERE login_id=$1 AND portal_id=$2 LIMIT 1`,
		s.loginID, portalID,
	).Scan(&participantsJSON)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	var participants []string
	if err = json.Unmarshal([]byte(participantsJSON), &participants); err != nil {
		return nil, err
	}
	// Normalize participants to portal ID format (e.g., tel:+14158138533)
	normalized := make([]string, 0, len(participants))
	for _, p := range participants {
		n := normalizeIdentifierForPortalID(p)
		if n != "" {
			normalized = append(normalized, n)
		}
	}
	return normalized, nil
}

// getDisplayNameByPortalID returns the CloudKit display_name for a given portal_id.
// This is the user-set group name (cv_name from the iMessage protocol), NOT an
// auto-generated label. Returns empty string if none found or if the group is unnamed.
func (s *cloudBackfillStore) getDisplayNameByPortalID(ctx context.Context, portalID string) (string, error) {
	var displayName sql.NullString
	err := s.db.QueryRow(ctx,
		`SELECT display_name FROM cloud_chat WHERE login_id=$1 AND portal_id=$2 AND display_name IS NOT NULL AND display_name <> '' ORDER BY updated_ts DESC LIMIT 1`,
		s.loginID, portalID,
	).Scan(&displayName)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	if displayName.Valid {
		return displayName.String, nil
	}
	return "", nil
}

// getGroupPhotoByPortalID returns the group_photo_guid and record_name for
// the most recently updated cloud_chat row that has a group photo set.
// Returns ("", "", nil) if no photo is set.
func (s *cloudBackfillStore) getGroupPhotoByPortalID(ctx context.Context, portalID string) (guid, recordName string, err error) {
	var g, r sql.NullString
	err = s.db.QueryRow(ctx,
		`SELECT group_photo_guid, record_name FROM cloud_chat WHERE login_id=$1 AND portal_id=$2 AND group_photo_guid IS NOT NULL AND group_photo_guid <> '' ORDER BY updated_ts DESC LIMIT 1`,
		s.loginID, portalID,
	).Scan(&g, &r)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", nil
		}
		return "", "", err
	}
	if g.Valid {
		rStr := ""
		if r.Valid {
			rStr = r.String
		}
		return g.String, rStr, nil
	}
	return "", "", nil
}

// clearGroupPhotoGuid sets group_photo_guid = NULL for all cloud_chat rows
// matching a portal_id. Called when a real-time IconChange(cleared) arrives so
// that subsequent GetChatInfo calls know there is no custom photo.
func (s *cloudBackfillStore) clearGroupPhotoGuid(ctx context.Context, portalID string) error {
	_, err := s.db.Exec(ctx,
		`UPDATE cloud_chat SET group_photo_guid = NULL WHERE login_id = $1 AND portal_id = $2`,
		s.loginID, portalID,
	)
	return err
}

// saveGroupPhoto persists MMCS-downloaded group photo bytes and the IconChange
// timestamp (used as avatar ID) to the group_photo_cache table.
// UPSERT so it works regardless of whether a cloud_chat row exists yet.
func (s *cloudBackfillStore) saveGroupPhoto(ctx context.Context, portalID string, ts int64, data []byte) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO group_photo_cache (login_id, portal_id, ts, data) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (login_id, portal_id) DO UPDATE SET ts=excluded.ts, data=excluded.data`,
		s.loginID, portalID, ts, data,
	)
	return err
}

// getGroupPhoto returns the locally cached group photo bytes and timestamp for
// the given portal. Returns (0, nil, nil) if no cached photo exists.
func (s *cloudBackfillStore) getGroupPhoto(ctx context.Context, portalID string) (ts int64, data []byte, err error) {
	err = s.db.QueryRow(ctx,
		`SELECT ts, data FROM group_photo_cache WHERE login_id=$1 AND portal_id=$2`,
		s.loginID, portalID,
	).Scan(&ts, &data)
	if err == sql.ErrNoRows {
		return 0, nil, nil
	}
	return ts, data, err
}

// clearGroupPhoto removes the cached group photo for a portal.
// Called when an IconChange(cleared) arrives so GetChatInfo won't
// re-apply a stale photo after restart.
func (s *cloudBackfillStore) clearGroupPhoto(ctx context.Context, portalID string) error {
	_, err := s.db.Exec(ctx,
		`DELETE FROM group_photo_cache WHERE login_id=$1 AND portal_id=$2`,
		s.loginID, portalID,
	)
	return err
}

// updateDisplayNameByPortalID updates the display_name for all cloud_chat
// rows matching a portal_id. Used when a real-time rename event arrives to
// correct stale CloudKit data in the local cache.
func (s *cloudBackfillStore) updateDisplayNameByPortalID(ctx context.Context, portalID, displayName string) error {
	_, err := s.db.Exec(ctx,
		`UPDATE cloud_chat SET display_name=$1 WHERE login_id=$2 AND portal_id=$3`,
		displayName, s.loginID, portalID,
	)
	return err
}

// deleteLocalChatByPortalID soft-deletes the cloud_chat and cloud_message
// records for a portal (sets deleted=TRUE, preserves the rows).
//
// cloud_chat is soft-deleted so that restore-chat can recover group name and
// participant data. Queries that drive portal creation (listPortalIDsWithNewestTimestamp,
// portalHasChat) filter on deleted=FALSE so soft-deleted rows don't resurrect portals.
//
// cloud_message is soft-deleted, NOT hard-deleted. The rows' GUIDs must survive
// so that hasMessageUUID can detect stale APNs echoes even after:
//   - pending_cloud_deletion is cleared (CloudKit deletion finished)
//   - Bridge restarts (recentlyDeletedPortals is repopulated from pending entries,
//     but once cleared there is no in-memory protection)
//
// hasMessageUUID queries cloud_message without filtering on deleted, so
// soft-deleted UUIDs still block echoes. Fresh UUIDs from genuinely new
// messages are not in cloud_message → hasMessageUUID=false → portal allowed.
//
// All other cloud_message queries (listLatestMessages, hasPortalMessages,
// getOldestMessageTimestamp, FetchMessages) filter WHERE deleted=FALSE, so
// soft-deleted rows don't trigger backfill or portal resurrection.
func (s *cloudBackfillStore) deleteLocalChatByPortalID(ctx context.Context, portalID string) error {
	if _, err := s.db.Exec(ctx,
		`UPDATE cloud_chat SET deleted=TRUE WHERE login_id=$1 AND portal_id=$2`,
		s.loginID, portalID,
	); err != nil {
		return fmt.Errorf("failed to soft-delete cloud_chat records for portal %s: %w", portalID, err)
	}
	nowMS := time.Now().UnixMilli()
	if _, err := s.db.Exec(ctx,
		`UPDATE cloud_message SET deleted=TRUE, updated_ts=$3 WHERE login_id=$1 AND portal_id=$2`,
		s.loginID, portalID, nowMS,
	); err != nil {
		return fmt.Errorf("failed to soft-delete cloud_message records for portal %s: %w", portalID, err)
	}
	return nil
}

// persistMessageUUID inserts a minimal cloud_message record for a realtime
// APNs message so the UUID survives restarts. CloudKit-synced messages are
// already stored via upsertMessageBatch; this covers the realtime path.
// Uses INSERT OR IGNORE so it's safe to call even if the message already exists.
func (s *cloudBackfillStore) persistMessageUUID(ctx context.Context, uuid, portalID string, timestampMS int64, isFromMe bool) error {
	nowMS := time.Now().UnixMilli()
	_, err := s.db.Exec(ctx, `
		INSERT OR IGNORE INTO cloud_message (login_id, guid, portal_id, timestamp_ms, is_from_me, created_ts, updated_ts)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, s.loginID, uuid, portalID, timestampMS, isFromMe, nowMS, nowMS)
	return err
}

// hasMessageUUID checks if a message UUID exists in cloud_message for this login.
// Used for echo detection: if the UUID is known, the message is an echo of a
// previously-seen message and should not create a new portal.
func (s *cloudBackfillStore) hasMessageUUID(ctx context.Context, uuid string) (bool, error) {
	var count int
	err := s.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM cloud_message WHERE login_id=$1 AND guid=$2 LIMIT 1`,
		s.loginID, uuid,
	).Scan(&count)
	return count > 0, err
}

// getMessageTimestampByGUID returns the Unix-millisecond send timestamp for a
// message UUID, and whether the row was found. Used to enforce the pre-startup
// receipt filter when the message is still being backfilled into the Matrix DB
// (so the Matrix DB lookup returns nothing but CloudKit already has the record).
func (s *cloudBackfillStore) getMessageTimestampByGUID(ctx context.Context, uuid string) (int64, bool, error) {
	var ts int64
	// UPPER() on both sides: APNs delivers UUIDs as uppercase while CloudKit
	// GUIDs may be lowercase or mixed-case, so a case-sensitive = would miss them.
	err := s.db.QueryRow(ctx,
		`SELECT timestamp_ms FROM cloud_message WHERE login_id=$1 AND UPPER(guid)=UPPER($2) LIMIT 1`,
		s.loginID, uuid,
	).Scan(&ts)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	return ts, err == nil, err
}

// portalHasPreStartupOutgoingMessages returns true if the portal has any
// is_from_me messages with timestamp_ms < beforeMS. Used to detect portals
// that were backfilled this session: if the portal has outgoing messages
// predating startup, a live APNs read receipt arriving near startup is
// almost certainly a buffered re-delivery (APNs re-delivers them with
// TimestampMs = now on reconnect) rather than a genuine new read event.
func (s *cloudBackfillStore) portalHasPreStartupOutgoingMessages(ctx context.Context, portalID string, beforeMS int64) (bool, error) {
	var count int
	err := s.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM cloud_message WHERE login_id=$1 AND portal_id=$2 AND is_from_me=TRUE AND timestamp_ms < $3 LIMIT 1`,
		s.loginID, portalID, beforeMS,
	).Scan(&count)
	return count > 0, err
}

// findPortalIDsByParticipants returns all distinct portal_ids from cloud_chat
// whose participants overlap with the given normalized participant list.
// Used to find duplicate group portals that have the same members but different
// group UUIDs. Participants are compared after normalization (tel:/mailto: prefix).
func (s *cloudBackfillStore) findPortalIDsByParticipants(ctx context.Context, normalizedTarget []string) ([]string, error) {
	rows, err := s.db.Query(ctx,
		`SELECT DISTINCT portal_id, participants_json FROM cloud_chat WHERE login_id=$1 AND portal_id <> '' AND deleted=FALSE`,
		s.loginID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Build a set of target participants for fast lookup.
	targetSet := make(map[string]bool, len(normalizedTarget))
	for _, p := range normalizedTarget {
		targetSet[p] = true
	}

	var matches []string
	seen := make(map[string]bool)
	for rows.Next() {
		var portalID, participantsJSON string
		if err = rows.Scan(&portalID, &participantsJSON); err != nil {
			return nil, err
		}
		if seen[portalID] {
			continue
		}
		var participants []string
		if err = json.Unmarshal([]byte(participantsJSON), &participants); err != nil {
			continue
		}
		// Normalize and check overlap: match if all non-self participants overlap.
		normalized := make([]string, 0, len(participants))
		for _, p := range participants {
			n := normalizeIdentifierForPortalID(p)
			if n != "" {
				normalized = append(normalized, n)
			}
		}
		if participantSetsMatch(normalized, normalizedTarget) {
			matches = append(matches, portalID)
			seen[portalID] = true
		}
	}
	return matches, rows.Err()
}

// participantSetsMatch checks if two normalized participant sets are equivalent
// (same members, ignoring order). Allows ±1 member difference to handle cases
// where self is included in one set but not the other.
func participantSetsMatch(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	setA := make(map[string]bool, len(a))
	for _, p := range a {
		setA[p] = true
	}
	setB := make(map[string]bool, len(b))
	for _, p := range b {
		setB[p] = true
	}
	// Count members in A not in B, and vice versa.
	diff := 0
	for p := range setA {
		if !setB[p] {
			diff++
		}
	}
	for p := range setB {
		if !setA[p] {
			diff++
		}
	}
	// Allow ±1 difference (self may be in one set but not the other).
	return diff <= 1
}

// deleteLocalChatByGroupID removes all local cloud_chat and cloud_message records
// for any portal_id that shares the given group_id.
func (s *cloudBackfillStore) deleteLocalChatByGroupID(ctx context.Context, groupID string) error {
	// Find all portal_ids for this group
	rows, err := s.db.Query(ctx,
		`SELECT DISTINCT portal_id FROM cloud_chat WHERE login_id=$1 AND LOWER(group_id)=LOWER($2) AND portal_id <> ''`,
		s.loginID, groupID,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	var portalIDs []string
	for rows.Next() {
		var pid string
		if err = rows.Scan(&pid); err != nil {
			return err
		}
		portalIDs = append(portalIDs, pid)
	}
	if err = rows.Err(); err != nil {
		return err
	}

	for _, pid := range portalIDs {
		if err := s.deleteLocalChatByPortalID(ctx, pid); err != nil {
			return err
		}
	}
	return nil
}

// getOldestMessageTimestamp returns the oldest non-deleted message timestamp
// for a portal, or 0 if no messages exist.
func (s *cloudBackfillStore) getOldestMessageTimestamp(ctx context.Context, portalID string) (int64, error) {
	var ts sql.NullInt64
	err := s.db.QueryRow(ctx, `
		SELECT MIN(timestamp_ms)
		FROM cloud_message
		WHERE login_id=$1 AND portal_id=$2 AND deleted=FALSE
	`, s.loginID, portalID).Scan(&ts)
	if err != nil || !ts.Valid {
		return 0, err
	}
	return ts.Int64, nil
}

func (s *cloudBackfillStore) hasPortalMessages(ctx context.Context, portalID string) (bool, error) {
	var count int
	err := s.db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM cloud_message
		WHERE login_id=$1 AND portal_id=$2 AND deleted=FALSE
	`, s.loginID, portalID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

const cloudMessageSelectCols = `guid, COALESCE(chat_id, ''), portal_id, timestamp_ms, COALESCE(sender, ''), is_from_me,
	COALESCE(text, ''), COALESCE(subject, ''), COALESCE(service, ''), deleted,
	tapback_type, COALESCE(tapback_target_guid, ''), COALESCE(tapback_emoji, ''),
	COALESCE(attachments_json, ''), COALESCE(date_read_ms, 0), COALESCE(has_body, TRUE)`

func (s *cloudBackfillStore) listBackwardMessages(
	ctx context.Context,
	portalID string,
	beforeTS int64,
	beforeGUID string,
	count int,
) ([]cloudMessageRow, error) {
	query := `SELECT ` + cloudMessageSelectCols + `
		FROM cloud_message
		WHERE login_id=$1 AND portal_id=$2 AND deleted=FALSE
	`
	args := []any{s.loginID, portalID}
	if beforeTS > 0 || beforeGUID != "" {
		query += ` AND (timestamp_ms < $3 OR (timestamp_ms = $3 AND guid < $4))`
		args = append(args, beforeTS, beforeGUID)
		query += ` ORDER BY timestamp_ms DESC, guid DESC LIMIT $5`
		args = append(args, count)
	} else {
		query += ` ORDER BY timestamp_ms DESC, guid DESC LIMIT $3`
		args = append(args, count)
	}
	return s.queryMessages(ctx, query, args...)
}

func (s *cloudBackfillStore) listForwardMessages(
	ctx context.Context,
	portalID string,
	afterTS int64,
	afterGUID string,
	count int,
) ([]cloudMessageRow, error) {
	query := `SELECT ` + cloudMessageSelectCols + `
		FROM cloud_message
		WHERE login_id=$1 AND portal_id=$2 AND deleted=FALSE
			AND (timestamp_ms > $3 OR (timestamp_ms = $3 AND guid > $4))
		ORDER BY timestamp_ms ASC, guid ASC
		LIMIT $5
	`
	return s.queryMessages(ctx, query, s.loginID, portalID, afterTS, afterGUID, count)
}

func (s *cloudBackfillStore) listLatestMessages(ctx context.Context, portalID string, count int) ([]cloudMessageRow, error) {
	query := `SELECT ` + cloudMessageSelectCols + `
		FROM cloud_message
		WHERE login_id=$1 AND portal_id=$2 AND deleted=FALSE
		ORDER BY timestamp_ms DESC, guid DESC
		LIMIT $3
	`
	return s.queryMessages(ctx, query, s.loginID, portalID, count)
}

// listOldestMessages returns the oldest `count` non-deleted messages for a
// portal in chronological order (ASC). Used by forward backfill chunking to
// deliver messages starting from the beginning of conversation history.
func (s *cloudBackfillStore) listOldestMessages(ctx context.Context, portalID string, count int) ([]cloudMessageRow, error) {
	query := `SELECT ` + cloudMessageSelectCols + `
		FROM cloud_message
		WHERE login_id=$1 AND portal_id=$2 AND deleted=FALSE
		ORDER BY timestamp_ms ASC, guid ASC
		LIMIT $3
	`
	return s.queryMessages(ctx, query, s.loginID, portalID, count)
}

// listAllAttachmentMessages returns every non-deleted cloud_message row that
// has at least one attachment. Used by preUploadCloudAttachments to drive the
// pre-upload pass before portal creation.
func (s *cloudBackfillStore) listAllAttachmentMessages(ctx context.Context) ([]cloudMessageRow, error) {
	query := `SELECT ` + cloudMessageSelectCols + `
		FROM cloud_message
		WHERE login_id=$1
		  AND deleted=FALSE
		  AND attachments_json IS NOT NULL
		  AND attachments_json <> ''
		ORDER BY timestamp_ms ASC, guid ASC
	`
	return s.queryMessages(ctx, query, s.loginID)
}

func (s *cloudBackfillStore) queryMessages(ctx context.Context, query string, args ...any) ([]cloudMessageRow, error) {
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]cloudMessageRow, 0)
	for rows.Next() {
		var row cloudMessageRow
		if err = rows.Scan(
			&row.GUID,
			&row.CloudChatID,
			&row.PortalID,
			&row.TimestampMS,
			&row.Sender,
			&row.IsFromMe,
			&row.Text,
			&row.Subject,
			&row.Service,
			&row.Deleted,
			&row.TapbackType,
			&row.TapbackTargetGUID,
			&row.TapbackEmoji,
			&row.AttachmentsJSON,
			&row.DateReadMS,
			&row.HasBody,
		); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// portalWithNewestMessage pairs a portal ID with its newest message timestamp
// and message count. Used to prioritize portal creation during initial sync.
type portalWithNewestMessage struct {
	PortalID     string
	NewestTS     int64
	MessageCount int
}

// listPortalIDsWithNewestTimestamp returns all portal IDs from both messages
// and chat records, ordered by newest message timestamp descending (most
// recent activity first). Chat-only portals (no messages) are included with
// their updated_ts from the cloud_chat table so they still get portals created.
func (s *cloudBackfillStore) listPortalIDsWithNewestTimestamp(ctx context.Context) ([]portalWithNewestMessage, error) {
	rows, err := s.db.Query(ctx, `
		SELECT sub.portal_id, MAX(sub.newest_ts) AS newest_ts, SUM(sub.msg_count) AS msg_count FROM (
			SELECT portal_id, MAX(timestamp_ms) AS newest_ts, COUNT(*) AS msg_count
			FROM cloud_message
			WHERE login_id=$1 AND portal_id IS NOT NULL AND portal_id <> '' AND deleted=FALSE
			GROUP BY portal_id

			UNION ALL

			SELECT cc.portal_id, COALESCE(cc.updated_ts, 0) AS newest_ts, 0 AS msg_count
			FROM cloud_chat cc
			WHERE cc.login_id=$1 AND cc.portal_id IS NOT NULL AND cc.portal_id <> ''
			AND COALESCE(cc.is_filtered, 0) = 0
			AND cc.deleted = FALSE
			AND cc.portal_id NOT IN (
				SELECT DISTINCT cm.portal_id FROM cloud_message cm
				WHERE cm.login_id=$1 AND cm.portal_id IS NOT NULL AND cm.portal_id <> '' AND cm.deleted=FALSE
			)
		) sub
		WHERE NOT EXISTS (
			SELECT 1 FROM cloud_chat fc
			WHERE fc.login_id=$1 AND fc.portal_id=sub.portal_id AND COALESCE(fc.is_filtered, 0) != 0
		)
		GROUP BY sub.portal_id
		ORDER BY newest_ts DESC
	`, s.loginID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []portalWithNewestMessage
	for rows.Next() {
		var p portalWithNewestMessage
		if err = rows.Scan(&p.PortalID, &p.NewestTS, &p.MessageCount); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func nullableString(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

// softDeletedPortal describes a portal whose cloud_message rows are all
// soft-deleted (deleted=TRUE), meaning it was deleted at the Beeper level.
type softDeletedPortal struct {
	PortalID string
	NewestTS int64
	Count    int
}

// listSoftDeletedPortals returns portals where every cloud_message row is
// soft-deleted (no live messages remain). These are candidates for restore.
// Results are sorted newest-first by the most recent message timestamp.
func (s *cloudBackfillStore) listSoftDeletedPortals(ctx context.Context) ([]softDeletedPortal, error) {
	rows, err := s.db.Query(ctx, `
		SELECT portal_id, MAX(timestamp_ms), COUNT(*)
		FROM cloud_message
		WHERE login_id=$1 AND portal_id IS NOT NULL AND portal_id <> ''
		GROUP BY portal_id
		HAVING MAX(CASE WHEN deleted=FALSE THEN 1 ELSE 0 END) = 0
		   AND MAX(CASE WHEN deleted=TRUE  THEN 1 ELSE 0 END) = 1
		ORDER BY MAX(timestamp_ms) DESC
	`, s.loginID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []softDeletedPortal
	for rows.Next() {
		var p softDeletedPortal
		if err = rows.Scan(&p.PortalID, &p.NewestTS, &p.Count); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// undeleteCloudMessagesByPortalID reverses a portal-level soft-delete by
// setting deleted=FALSE on all cloud_message rows for the portal.
// Returns the number of rows updated.
func (s *cloudBackfillStore) undeleteCloudMessagesByPortalID(ctx context.Context, portalID string) (int, error) {
	// Un-soft-delete cloud_chat rows so GetChatInfo can resolve group name
	// and participants during the ChatResync that follows restore.
	if _, err := s.db.Exec(ctx,
		`UPDATE cloud_chat SET deleted=FALSE WHERE login_id=$1 AND portal_id=$2 AND deleted=TRUE`,
		s.loginID, portalID,
	); err != nil {
		return 0, fmt.Errorf("failed to undelete cloud_chat for portal %s: %w", portalID, err)
	}

	result, err := s.db.Exec(ctx,
		`UPDATE cloud_message SET deleted=FALSE, updated_ts=$3
		 WHERE login_id=$1 AND portal_id=$2 AND deleted=TRUE`,
		s.loginID, portalID, time.Now().UnixMilli(),
	)
	if err != nil {
		return 0, err
	}
	n, _ := result.RowsAffected()
	return int(n), nil
}

// loadAttachmentCacheJSON returns every persisted record_name → content_json
// pair for this login. The caller deserialises the JSON into
// *event.MessageEventContent and populates the in-memory attachmentContentCache
// so pre-upload skips already-uploaded attachments without touching CloudKit.
func (s *cloudBackfillStore) loadAttachmentCacheJSON(ctx context.Context) (map[string][]byte, error) {
	rows, err := s.db.Query(ctx,
		`SELECT record_name, content_json FROM cloud_attachment_cache WHERE login_id=$1`,
		s.loginID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cache := make(map[string][]byte)
	for rows.Next() {
		var recordName string
		var contentJSON []byte
		if err := rows.Scan(&recordName, &contentJSON); err != nil {
			return nil, err
		}
		cache[recordName] = contentJSON
	}
	return cache, rows.Err()
}

// saveAttachmentCacheEntry persists a record_name → MessageEventContent JSON
// pair. Idempotent (upsert). Errors are silently ignored — the persistent cache
// is a best-effort optimisation; missing entries fall back to re-download.
func (s *cloudBackfillStore) saveAttachmentCacheEntry(ctx context.Context, recordName string, contentJSON []byte) {
	_, _ = s.db.Exec(ctx, `
		INSERT INTO cloud_attachment_cache (login_id, record_name, content_json, created_ts)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (login_id, record_name) DO UPDATE SET content_json=excluded.content_json
	`, s.loginID, recordName, contentJSON, time.Now().UnixMilli())
}

// markForwardBackfillDone marks all cloud_chat rows for portalID as having
// completed their initial forward FetchMessages call. Idempotent. Called from
// FetchMessages when the forward pass completes so that preUploadCloudAttachments
// skips this portal on the next restart instead of re-uploading every attachment.
//
// Self-healing: if the UPDATE hits 0 rows (no cloud_chat row matches this
// portal_id), a synthetic row is inserted so the flag persists. This covers
// APNs-created portals, CloudKit portal_id mismatches between cloud_message
// and cloud_chat, and any other case where a portal exists without a
// corresponding cloud_chat row.
func (s *cloudBackfillStore) markForwardBackfillDone(ctx context.Context, portalID string) {
	res, err := s.db.Exec(ctx,
		`UPDATE cloud_chat SET fwd_backfill_done=1 WHERE login_id=$1 AND portal_id=$2`,
		s.loginID, portalID,
	)

	// If the UPDATE failed (cancelled context, DB error) or matched 0 rows
	// (no cloud_chat entry for this portal), insert a synthetic row.
	// Use context.Background() — this MUST persist even during shutdown.
	needsInsert := err != nil || res == nil
	if !needsInsert {
		if rows, _ := res.RowsAffected(); rows == 0 {
			needsInsert = true
		}
	}
	if needsInsert {
		_, _ = s.db.Exec(context.Background(), `
			INSERT OR IGNORE INTO cloud_chat (login_id, cloud_chat_id, portal_id, created_ts, fwd_backfill_done)
			VALUES ($1, $2, $3, $4, 1)`,
			s.loginID, "synthetic:"+portalID, portalID, time.Now().UnixMilli(),
		)
	}
}

// isForwardBackfillDone returns true if forward backfill has completed for the
// given portal. Used by backward backfill to avoid permanently marking
// is_done=true before forward backfill has inserted the anchor message.
func (s *cloudBackfillStore) isForwardBackfillDone(ctx context.Context, portalID string) bool {
	var done bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM cloud_chat WHERE login_id=$1 AND portal_id=$2 AND fwd_backfill_done=1)`,
		s.loginID, portalID,
	).Scan(&done)
	if err != nil {
		return false
	}
	return done
}

// getForwardBackfillDonePortals returns the set of portal IDs whose forward
// FetchMessages has completed at least once. Used by preUploadCloudAttachments
// to skip portals that don't need pre-upload on restart.
func (s *cloudBackfillStore) getForwardBackfillDonePortals(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.Query(ctx,
		`SELECT DISTINCT portal_id FROM cloud_chat WHERE login_id=$1 AND fwd_backfill_done=1`,
		s.loginID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	done := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		done[id] = true
	}
	return done, rows.Err()
}

// hasCloudReadReceipt checks whether a message UUID in cloud_message already
// has a valid date_read_ms (i.e., CloudKit recorded that it was read). Used to
// suppress duplicate APNs read receipts that arrive after backfill — the
// synthetic receipt already used the correct CloudKit timestamp, so the stale
// APNs receipt (with delivery-time instead of read-time) should be dropped.
// Uses case-insensitive GUID matching (APNs delivers uppercase, CloudKit may be mixed).
func (s *cloudBackfillStore) hasCloudReadReceipt(ctx context.Context, uuid string) (bool, error) {
	var dateReadMS int64
	err := s.db.QueryRow(ctx, `
		SELECT COALESCE(date_read_ms, 0)
		FROM cloud_message
		WHERE login_id=$1 AND UPPER(guid)=UPPER($2) AND is_from_me=TRUE
		LIMIT 1
	`, s.loginID, uuid).Scan(&dateReadMS)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return dateReadMS > 978307200000, nil
}

// isCloudBackfilledMessage checks whether a message UUID exists in the
// cloud_message table as a CloudKit-synced message. CloudKit entries (from
// upsertMessageBatch) have record_name populated, while real-time entries
// (from persistMessageUUID) have record_name=''. This distinguishes
// backfilled messages whose ghost receipts should be suppressed from
// real-time messages whose ghost receipts should go through.
func (s *cloudBackfillStore) isCloudBackfilledMessage(ctx context.Context, uuid string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM cloud_message
			WHERE login_id=$1 AND UPPER(guid)=UPPER($2) AND record_name != ''
		)
	`, s.loginID, uuid).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// getConversationReadByMe returns true if the portal has no unread incoming
// messages — i.e., the user has read the entire conversation on the iMessage
// side. This is approximated by checking if any incoming messages exist that
// are newer than the latest outgoing message (if we sent a reply, we must have
// read everything before it). Returns false if there are no incoming messages.
func (s *cloudBackfillStore) getConversationReadByMe(ctx context.Context, portalID string) (bool, error) {
	// Strategy: if the newest message in the portal is from_me, the user has
	// seen the conversation. If the newest is NOT from_me, they might not have.
	// This is a heuristic — CloudKit doesn't store "I read their message".
	var isFromMe bool
	err := s.db.QueryRow(ctx, `
		SELECT is_from_me
		FROM cloud_message
		WHERE login_id=$1 AND portal_id=$2 AND deleted=FALSE
		ORDER BY timestamp_ms DESC, guid DESC
		LIMIT 1
	`, s.loginID, portalID).Scan(&isFromMe)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return isFromMe, nil
}

// pruneOrphanedAttachmentCache deletes cloud_attachment_cache entries whose
// record_name is not referenced by any live (non-deleted) cloud_message row.
// This prevents unbounded growth after portal deletions or message tombstones
// remove the messages that originally needed those cached attachments.
func (s *cloudBackfillStore) pruneOrphanedAttachmentCache(ctx context.Context) (int64, error) {
	result, err := s.db.Exec(ctx, `
		DELETE FROM cloud_attachment_cache
		WHERE login_id=$1
		  AND record_name NOT IN (
			SELECT DISTINCT json_extract(je.value, '$.record_name')
			FROM cloud_message, json_each(cloud_message.attachments_json) AS je
			WHERE cloud_message.login_id=$1
			  AND cloud_message.deleted=FALSE
			  AND cloud_message.attachments_json IS NOT NULL
			  AND cloud_message.attachments_json <> ''
			  AND json_extract(je.value, '$.record_name') IS NOT NULL
		  )
	`, s.loginID)
	if err != nil {
		return 0, fmt.Errorf("failed to prune orphaned attachment cache: %w", err)
	}
	n, _ := result.RowsAffected()
	return n, nil
}

// deleteOrphanedMessages hard-deletes cloud_message rows that are already
// soft-deleted (deleted=TRUE) AND whose portal_id has no matching cloud_chat
// entry. This is conservative: DM portals legitimately have messages without
// cloud_chat rows, so we only clean up rows that are BOTH orphaned AND already
// marked deleted (from tombstone processing or portal deletion).
func (s *cloudBackfillStore) deleteOrphanedMessages(ctx context.Context) (int64, error) {
	result, err := s.db.Exec(ctx, `
		DELETE FROM cloud_message
		WHERE login_id=$1
		  AND deleted=TRUE
		  AND portal_id NOT IN (
			SELECT DISTINCT portal_id FROM cloud_chat WHERE login_id=$1
		  )
	`, s.loginID)
	if err != nil {
		return 0, fmt.Errorf("failed to delete orphaned messages: %w", err)
	}
	n, _ := result.RowsAffected()
	return n, nil
}
