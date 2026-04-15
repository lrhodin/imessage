// mautrix-imessage - A Matrix-iMessage puppeting bridge.
// Copyright (C) 2024 Ludvig Rhodin
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"maunium.net/go/mautrix/bridgev2/commands"

	"github.com/lrhodin/imessage/pkg/rustpushgo"
)

// cmdFindMy syncs Find My item positions and displays them as a list of
// accessories with their last-known coordinates. Only AirTags and other
// accessories registered to the Apple ID are shown; "Find My Friends" person
// locations are in a separate share_state structure that is not surfaced here.
//
// Usage:
//
//	!findmy
var cmdFindMy = &commands.FullHandler{
	Name: "findmy",
	Func: fnFindMy,
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionGeneral,
		Description: "Show the current locations of your Find My accessories (AirTags, etc.).",
	},
	RequiresLogin: true,
}

var cmdFindMySyncItems = &commands.FullHandler{
	Name: "findmy-sync-items",
	Func: fnFindMySyncItems,
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionGeneral,
		Description: "Sync Find My items metadata, optionally including shared items.",
		Args:        "[--fetch-shares]",
	},
	RequiresLogin: true,
}

var cmdFindMyAcceptShare = &commands.FullHandler{
	Name: "findmy-accept-share",
	Func: fnFindMyAcceptShare,
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionGeneral,
		Description: "Accept a Find My item share by circle ID.",
		Args:        "<circle-id>",
	},
	RequiresLogin: true,
}

var cmdFindMyDeleteItem = &commands.FullHandler{
	Name: "findmy-delete-item",
	Func: fnFindMyDeleteItem,
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionGeneral,
		Description: "Delete a shared Find My item by item ID.",
		Args:        "<item-id> [--remove-beacon]",
	},
	RequiresLogin: true,
}

var cmdFindMyRenameBeacon = &commands.FullHandler{
	Name: "findmy-rename-beacon",
	Func: fnFindMyRenameBeacon,
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionGeneral,
		Description: "Rename a Find My beacon by associated beacon + role ID.",
		Args:        "<associated-beacon> <role-id> <name> [emoji]",
	},
	RequiresLogin: true,
}

var cmdFindMyStateJSON = &commands.FullHandler{
	Name: "findmy-state-json",
	Func: fnFindMyStateJSON,
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionGeneral,
		Description: "Show raw Find My state JSON (debug).",
	},
	RequiresLogin: true,
}

var cmdFindMyStateBytes = &commands.FullHandler{
	Name: "findmy-state-bytes",
	Func: fnFindMyStateBytes,
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionGeneral,
		Description: "Show Find My state bytes length + hash (debug).",
	},
	RequiresLogin: true,
}

// ---- JSON schema types -------------------------------------------------------
// These mirror the serde-serialised FindMyState from rustpush/findmy.rs.
// Only fields we actually display are declared; unknown keys are ignored.

type findMyState struct {
	Accessories map[string]findMyAccessory `json:"accessories"`
}

type findMyAccessory struct {
	Naming     findMyNaming          `json:"naming"`
	LastReport *findMyLocationReport `json:"last_report"`
}

// BeaconNamingRecord in findmy.rs serialises its fields in snake_case (no
// #[serde(rename_all = "camelCase")] attribute on the struct itself).
type findMyNaming struct {
	Name  string `json:"name"`
	Emoji string `json:"emoji"`
}

// LocationReport in findmy.rs also uses snake_case field names.
type findMyLocationReport struct {
	Lat                float64 `json:"lat"`
	Long               float64 `json:"long"`
	HorizontalAccuracy uint8   `json:"horizontal_accuracy"`
	Confidence         uint8   `json:"confidence"`
}

// ---- Command handler ---------------------------------------------------------

func fnFindMy(ce *commands.Event) {
	login := ce.User.GetDefaultLogin()
	if login == nil {
		ce.Reply("No active login found.")
		return
	}
	client, ok := login.Client.(*IMClient)
	if !ok || client == nil || client.client == nil {
		ce.Reply("Bridge client not available.")
		return
	}

	var (
		stateJSON string
		syncErr   error
		exportErr error
	)
	func() {
		defer func() {
			if r := recover(); r != nil {
				syncErr = fmt.Errorf("findmy client panicked: %v", r)
			}
		}()
		fm, initErr := client.client.GetFindmyClient()
		if initErr != nil {
			syncErr = initErr
			return
		}
		if err := fm.SyncItemPositions(); err != nil {
			syncErr = err
			return
		}
		stateJSON, exportErr = fm.ExportStateJson()
	}()

	if syncErr != nil {
		ce.Reply("Failed to sync Find My positions: %v", syncErr)
		return
	}
	if exportErr != nil {
		ce.Reply("Failed to export Find My state: %v", exportErr)
		return
	}

	var state findMyState
	if err := json.Unmarshal([]byte(stateJSON), &state); err != nil {
		ce.Reply("Failed to parse Find My state: %v", err)
		return
	}

	if len(state.Accessories) == 0 {
		ce.Reply("No Find My accessories found. Make sure you have AirTags or other Find My items registered to your Apple ID.")
		return
	}

	// Sort accessor keys so output is stable across calls.
	keys := make([]string, 0, len(state.Accessories))
	for k := range state.Accessories {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("**Find My Accessories (%d)**\n\n", len(state.Accessories)))
	for _, k := range keys {
		acc := state.Accessories[k]
		name := acc.Naming.Name
		if name == "" {
			name = k
		}
		emoji := acc.Naming.Emoji
		if emoji == "" {
			emoji = "📡"
		}
		sb.WriteString(fmt.Sprintf("%s **%s**\n", emoji, name))
		if acc.LastReport != nil {
			sb.WriteString(fmt.Sprintf(
				"  📍 %.6f, %.6f (accuracy ±%dm, confidence %d%%)\n",
				acc.LastReport.Lat, acc.LastReport.Long,
				int(acc.LastReport.HorizontalAccuracy),
				int(acc.LastReport.Confidence),
			))
			sb.WriteString(fmt.Sprintf(
				"  [Open in Maps](https://maps.apple.com/?ll=%.6f,%.6f&q=%s)\n",
				acc.LastReport.Lat, acc.LastReport.Long, url.QueryEscape(name),
			))
		} else {
			sb.WriteString("  _No location reported_\n")
		}
		sb.WriteString("\n")
	}

	ce.Reply(sb.String())
}

func findMyClientFromEvent(ce *commands.Event) (*rustpushgo.WrappedFindMyClient, bool) {
	login := ce.User.GetDefaultLogin()
	if login == nil {
		ce.Reply("No active login found.")
		return nil, false
	}
	client, ok := login.Client.(*IMClient)
	if !ok || client == nil || client.client == nil {
		ce.Reply("Bridge client not available.")
		return nil, false
	}
	fm, err := client.client.GetFindmyClient()
	if err != nil {
		ce.Reply("Failed to initialize Find My client: %v", err)
		return nil, false
	}
	return fm, true
}

func fnFindMySyncItems(ce *commands.Event) {
	fm, ok := findMyClientFromEvent(ce)
	if !ok {
		return
	}
	fetchShares := len(ce.Args) > 0 && strings.EqualFold(strings.TrimSpace(ce.Args[0]), "--fetch-shares")
	if err := fm.SyncItems(fetchShares); err != nil {
		ce.Reply("Failed to sync Find My items: %v", err)
		return
	}
	ce.Reply("Find My items synced (fetch_shares=%v).", fetchShares)
}

func fnFindMyAcceptShare(ce *commands.Event) {
	if len(ce.Args) < 1 {
		ce.Reply("Usage: `!findmy-accept-share <circle-id>`")
		return
	}
	fm, ok := findMyClientFromEvent(ce)
	if !ok {
		return
	}
	circleID := strings.TrimSpace(ce.Args[0])
	if err := fm.AcceptItemShare(circleID); err != nil {
		ce.Reply("Failed to accept Find My share: %v", err)
		return
	}
	ce.Reply("Accepted Find My share `%s`.", circleID)
}

func fnFindMyDeleteItem(ce *commands.Event) {
	if len(ce.Args) < 1 {
		ce.Reply("Usage: `!findmy-delete-item <item-id> [--remove-beacon]`")
		return
	}
	fm, ok := findMyClientFromEvent(ce)
	if !ok {
		return
	}
	itemID := strings.TrimSpace(ce.Args[0])
	removeBeacon := false
	for _, arg := range ce.Args[1:] {
		if strings.EqualFold(strings.TrimSpace(arg), "--remove-beacon") {
			removeBeacon = true
		}
	}
	if err := fm.DeleteSharedItem(itemID, removeBeacon); err != nil {
		ce.Reply("Failed to delete Find My shared item: %v", err)
		return
	}
	ce.Reply("Deleted shared item `%s` (remove_beacon=%v).", itemID, removeBeacon)
}

func fnFindMyRenameBeacon(ce *commands.Event) {
	if len(ce.Args) < 3 {
		ce.Reply("Usage: `!findmy-rename-beacon <associated-beacon> <role-id> <name> [emoji]`")
		return
	}
	fm, ok := findMyClientFromEvent(ce)
	if !ok {
		return
	}
	associatedBeacon := strings.TrimSpace(ce.Args[0])
	roleID, err := strconv.ParseInt(strings.TrimSpace(ce.Args[1]), 10, 64)
	if err != nil {
		ce.Reply("Invalid role-id: %v", err)
		return
	}
	name := strings.TrimSpace(ce.Args[2])
	emoji := ""
	if len(ce.Args) > 3 {
		emoji = strings.TrimSpace(ce.Args[3])
	}
	if err := fm.UpdateBeaconName(associatedBeacon, roleID, name, emoji); err != nil {
		ce.Reply("Failed to rename beacon: %v", err)
		return
	}
	ce.Reply("Updated beacon name for `%s` (role=%d).", associatedBeacon, roleID)
}

func fnFindMyStateJSON(ce *commands.Event) {
	fm, ok := findMyClientFromEvent(ce)
	if !ok {
		return
	}
	state, err := fm.ExportStateJson()
	if err != nil {
		ce.Reply("Failed to export Find My state JSON: %v", err)
		return
	}
	if len(state) > 12000 {
		state = state[:12000] + "\n... (truncated)"
	}
	ce.Reply("```json\n%s\n```", state)
}

func fnFindMyStateBytes(ce *commands.Event) {
	fm, ok := findMyClientFromEvent(ce)
	if !ok {
		return
	}
	blob, err := fm.ExportStateBytes()
	if err != nil {
		ce.Reply("Failed to export Find My state bytes: %v", err)
		return
	}
	sum := sha256.Sum256(blob)
	ce.Reply("Find My state bytes: %d bytes, sha256 `%s`", len(blob), hex.EncodeToString(sum[:]))
}
