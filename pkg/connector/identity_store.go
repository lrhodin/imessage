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
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
)

// trustedPeersFilePath returns the per-user keychain trust state path:
// ~/.local/share/mautrix-imessage/trustedpeers_<dsid>.plist
func trustedPeersFilePath(dsid string) (string, error) {
	dataDir := os.Getenv("XDG_DATA_HOME")
	if dataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dataDir = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dataDir, "mautrix-imessage", "trustedpeers_"+dsid+".plist"), nil
}

// hasKeychainCliqueState returns true if the per-user trustedpeers.plist
// appears to contain a keychain user identity (i.e. trust circle has been joined).
func hasKeychainCliqueState(log zerolog.Logger, dsid string) bool {
	path, err := trustedPeersFilePath(dsid)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to determine trusted peers file path")
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	// trustedpeers.plist is written by Rust as XML plist, where a joined clique
	// includes either userIdentity or user_identity key.
	if bytes.Contains(data, []byte("<key>userIdentity</key>")) || bytes.Contains(data, []byte("<key>user_identity</key>")) {
		return true
	}
	log.Info().Str("path", path).Msg("Trusted peers state exists but has no user identity (not in clique)")
	return false
}
