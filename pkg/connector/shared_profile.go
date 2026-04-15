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
	"database/sql"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/bridgev2/networkid"

	"github.com/lrhodin/imessage/pkg/rustpushgo"
)

// Shared iMessage profile (Name & Photo Sharing) ingestion, caching, and
// persistence. These are the "Me card" shares an iPhone sends automatically
// when its user has Name and Photo Sharing enabled — they carry a CloudKit
// record key + decryption key that point at an encrypted blob containing the
// sender's first/last name, display name, and avatar bytes.
//
// User-provided contacts (CardDAV or iCloud) always win over shared profiles
// in the GetUserInfo fallback chain; shared profiles only surface when the
// sender's identifier is unknown to the address book entirely.
//
// Design:
//   - `sharedProfileStore` persists each decrypted record plus the keys we
//     need to re-fetch it, so the photo survives bridge restarts without the
//     iPhone side re-sending a share.
//   - An in-memory `sync.Map` fronts the DB for read hot paths.
//   - `periodicSharedProfileSync` re-fetches every stored record from
//     CloudKit on a 15-minute cadence so profile edits that don't trigger a
//     fresh ShareProfile message still propagate to Matrix.

const sharedProfileSyncInterval = 15 * time.Minute

// sharedProfileStore persists decrypted iMessage shared profiles keyed by
// (login_id, identifier).
type sharedProfileStore struct {
	db      *dbutil.Database
	loginID networkid.UserLoginID
}

func newSharedProfileStore(db *dbutil.Database, loginID networkid.UserLoginID) *sharedProfileStore {
	return &sharedProfileStore{db: db, loginID: loginID}
}

func (s *sharedProfileStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `CREATE TABLE IF NOT EXISTS shared_profiles (
		login_id       TEXT    NOT NULL,
		identifier     TEXT    NOT NULL,
		display_name   TEXT    NOT NULL DEFAULT '',
		first_name     TEXT    NOT NULL DEFAULT '',
		last_name      TEXT    NOT NULL DEFAULT '',
		avatar         BLOB,
		record_key     TEXT    NOT NULL,
		decryption_key BLOB    NOT NULL,
		has_poster     BOOLEAN NOT NULL DEFAULT FALSE,
		updated_ts     BIGINT  NOT NULL,
		PRIMARY KEY (login_id, identifier)
	)`)
	if err != nil {
		return fmt.Errorf("failed to create shared_profiles table: %w", err)
	}
	return nil
}

// sharedProfileRow is the on-disk representation; also used in-memory as the
// cache value so we always have the fetch keys at hand for periodic re-sync.
type sharedProfileRow struct {
	Identifier    string
	DisplayName   string
	FirstName     string
	LastName      string
	Avatar        []byte
	RecordKey     string
	DecryptionKey []byte
	HasPoster     bool
	UpdatedTS     int64
}

func (r *sharedProfileRow) asProfileRecord() *rustpushgo.WrappedProfileRecord {
	rec := &rustpushgo.WrappedProfileRecord{
		DisplayName: r.DisplayName,
		FirstName:   r.FirstName,
		LastName:    r.LastName,
	}
	if len(r.Avatar) > 0 {
		avatar := append([]byte(nil), r.Avatar...)
		rec.Avatar = &avatar
	}
	return rec
}

func (s *sharedProfileStore) save(ctx context.Context, row *sharedProfileRow) error {
	_, err := s.db.Exec(ctx, `INSERT INTO shared_profiles
			(login_id, identifier, display_name, first_name, last_name, avatar, record_key, decryption_key, has_poster, updated_ts)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (login_id, identifier) DO UPDATE SET
			display_name   = excluded.display_name,
			first_name     = excluded.first_name,
			last_name      = excluded.last_name,
			avatar         = excluded.avatar,
			record_key     = excluded.record_key,
			decryption_key = excluded.decryption_key,
			has_poster     = excluded.has_poster,
			updated_ts     = excluded.updated_ts`,
		s.loginID, row.Identifier, row.DisplayName, row.FirstName, row.LastName,
		row.Avatar, row.RecordKey, row.DecryptionKey, row.HasPoster, row.UpdatedTS)
	if err != nil {
		return fmt.Errorf("failed to upsert shared profile: %w", err)
	}
	return nil
}

func (s *sharedProfileStore) loadAll(ctx context.Context) ([]*sharedProfileRow, error) {
	rows, err := s.db.Query(ctx, `SELECT identifier, display_name, first_name, last_name,
			avatar, record_key, decryption_key, has_poster, updated_ts
		FROM shared_profiles WHERE login_id = $1`, s.loginID)
	if err != nil {
		return nil, fmt.Errorf("failed to query shared_profiles: %w", err)
	}
	defer rows.Close()
	var out []*sharedProfileRow
	for rows.Next() {
		var r sharedProfileRow
		var avatar sql.RawBytes
		if err := rows.Scan(&r.Identifier, &r.DisplayName, &r.FirstName, &r.LastName,
			&avatar, &r.RecordKey, &r.DecryptionKey, &r.HasPoster, &r.UpdatedTS); err != nil {
			return nil, fmt.Errorf("failed to scan shared_profiles row: %w", err)
		}
		if len(avatar) > 0 {
			r.Avatar = append([]byte(nil), avatar...)
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

// -- IMClient wiring ---------------------------------------------------------

// loadSharedProfilesIntoCache hydrates the in-memory cache from the DB so a
// bridge restart doesn't lose cached names/photos until a fresh share message
// arrives. Called once from Connect after ensureSharedProfileSchema.
func (c *IMClient) loadSharedProfilesIntoCache(ctx context.Context, log zerolog.Logger) {
	if c.sharedProfileStore == nil {
		return
	}
	rows, err := c.sharedProfileStore.loadAll(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to load shared profiles from DB")
		return
	}
	for _, r := range rows {
		c.sharedProfiles.Store(r.Identifier, r)
	}
	if len(rows) > 0 {
		log.Info().Int("count", len(rows)).Msg("Loaded shared iMessage profiles from DB")
	}
}

// ensureSharedProfileSchema runs the CREATE TABLE IF NOT EXISTS so existing
// bridge instances pick up the feature on first run without requiring a
// re-login or fresh database.
func (c *IMClient) ensureSharedProfileSchema(ctx context.Context) error {
	if c.sharedProfileStore == nil {
		return nil
	}
	return c.sharedProfileStore.ensureSchema(ctx)
}

// handleSharedProfile processes an incoming ShareProfile or UpdateProfile
// message: fetch the decrypted record from CloudKit, persist it, refresh the
// in-memory cache, and push the new name/avatar to the Matrix ghost.
//
// Replaces the inline handleShareProfile that previously lived in client.go.
func (c *IMClient) handleSharedProfile(log zerolog.Logger, msg rustpushgo.WrappedMessage) {
	if msg.Sender == nil || *msg.Sender == "" {
		return
	}
	sender := *msg.Sender
	log = log.With().Str("sender", sender).Logger()

	if msg.ShareProfileRecordKey == nil || msg.ShareProfileDecryptionKey == nil {
		log.Debug().Msg("ShareProfile message has no record/decryption key, ignoring")
		return
	}
	if c.client == nil {
		return
	}

	log.Info().Msg("Fetching shared iMessage profile")
	record, err := c.client.FetchProfile(*msg.ShareProfileRecordKey, *msg.ShareProfileDecryptionKey, msg.ShareProfileHasPoster)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to fetch shared profile")
		return
	}

	row := &sharedProfileRow{
		Identifier:    sender,
		DisplayName:   record.DisplayName,
		FirstName:     record.FirstName,
		LastName:      record.LastName,
		RecordKey:     *msg.ShareProfileRecordKey,
		DecryptionKey: append([]byte(nil), *msg.ShareProfileDecryptionKey...),
		HasPoster:     msg.ShareProfileHasPoster,
		UpdatedTS:     time.Now().UnixMilli(),
	}
	if record.Avatar != nil {
		row.Avatar = append([]byte(nil), *record.Avatar...)
	}

	c.sharedProfiles.Store(sender, row)
	if c.sharedProfileStore != nil {
		if err := c.sharedProfileStore.save(context.Background(), row); err != nil {
			log.Warn().Err(err).Msg("Failed to persist shared profile")
		}
	}

	log.Info().
		Str("display_name", row.DisplayName).
		Str("first_name", row.FirstName).
		Str("last_name", row.LastName).
		Bool("has_avatar", len(row.Avatar) > 0).
		Msg("Cached shared iMessage profile")

	c.refreshGhostFromSharedProfile(log, sender)
}

// refreshGhostFromSharedProfile pushes updated name/avatar to the Matrix
// ghost for the given identifier. GetUserInfo internally enforces the
// CardDAV/iCloud > shared-profile priority rule, so this is a no-op from the
// user's perspective when they already have the contact in their address
// book.
func (c *IMClient) refreshGhostFromSharedProfile(log zerolog.Logger, sender string) {
	ctx := context.Background()
	userID := makeUserID(sender)
	ghost, err := c.Main.Bridge.GetGhostByID(ctx, userID)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get ghost for shared-profile refresh")
		return
	}
	info, err := c.GetUserInfo(ctx, ghost)
	if err != nil || info == nil {
		return
	}
	ghost.UpdateInfo(ctx, info)
}

// lookupSharedProfile returns the cached shared profile for an identifier, or
// nil if none. Falls back to the DB on cache miss so a cold GetUserInfo call
// before the bootstrap load completes still finds the row.
func (c *IMClient) lookupSharedProfile(identifier string) *rustpushgo.WrappedProfileRecord {
	if v, ok := c.sharedProfiles.Load(identifier); ok {
		switch r := v.(type) {
		case *sharedProfileRow:
			return r.asProfileRecord()
		case *rustpushgo.WrappedProfileRecord:
			// Compat path for any pre-existing cache writes.
			return r
		}
	}
	if c.sharedProfileStore == nil {
		return nil
	}
	rows, err := c.sharedProfileStore.loadAll(context.Background())
	if err != nil {
		return nil
	}
	for _, r := range rows {
		c.sharedProfiles.Store(r.Identifier, r)
		if r.Identifier == identifier {
			return r.asProfileRecord()
		}
	}
	return nil
}

// periodicSharedProfileSync re-fetches every persisted shared profile from
// CloudKit on a 15-minute cadence so profile edits that don't re-trigger a
// ShareProfile message still reach Matrix. Mirrors periodicCloudContactSync.
func (c *IMClient) periodicSharedProfileSync(log zerolog.Logger) {
	ticker := time.NewTicker(sharedProfileSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.refreshAllSharedProfiles(log)
		case <-c.stopChan:
			return
		}
	}
}

// refreshAllSharedProfiles re-fetches every persisted shared profile and
// refreshes the corresponding ghost when the record changed.
func (c *IMClient) refreshAllSharedProfiles(log zerolog.Logger) {
	if c.sharedProfileStore == nil || c.client == nil {
		return
	}
	rows, err := c.sharedProfileStore.loadAll(context.Background())
	if err != nil {
		log.Warn().Err(err).Msg("Failed to load shared profiles for periodic sync")
		return
	}
	var refreshed, changed int
	for _, r := range rows {
		record, err := c.client.FetchProfile(r.RecordKey, r.DecryptionKey, r.HasPoster)
		if err != nil {
			log.Debug().Err(err).Str("identifier", r.Identifier).
				Msg("Periodic shared-profile fetch failed")
			continue
		}
		refreshed++
		newAvatar := []byte(nil)
		if record.Avatar != nil {
			newAvatar = *record.Avatar
		}
		if record.DisplayName == r.DisplayName &&
			record.FirstName == r.FirstName &&
			record.LastName == r.LastName &&
			bytes.Equal(newAvatar, r.Avatar) {
			continue
		}
		r.DisplayName = record.DisplayName
		r.FirstName = record.FirstName
		r.LastName = record.LastName
		r.Avatar = append([]byte(nil), newAvatar...)
		r.UpdatedTS = time.Now().UnixMilli()
		if err := c.sharedProfileStore.save(context.Background(), r); err != nil {
			log.Warn().Err(err).Str("identifier", r.Identifier).
				Msg("Failed to persist refreshed shared profile")
		}
		c.sharedProfiles.Store(r.Identifier, r)
		c.refreshGhostFromSharedProfile(log, r.Identifier)
		changed++
	}
	if refreshed > 0 {
		log.Debug().Int("refreshed", refreshed).Int("changed", changed).
			Msg("Periodic shared-profile sync completed")
	}
}

