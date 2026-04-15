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
	"encoding/json"
	"fmt"
	"strings"

	"maunium.net/go/mautrix/bridgev2/commands"
)

// cmdFindMyFriends shows followers/following from the Find My Friends (FMF)
// service — the list of people whose location you share and who share theirs
// with you. Note: actual coordinates are not surfaced here (Apple only delivers
// them via live APNs updates, not the init snapshot).
//
// Usage:
//
//	!findmy-friends           — use app mode (default)
//	!findmy-friends --daemon  — use daemon (fmfd) mode for background-compatible requests
var cmdFindMyFriends = &commands.FullHandler{
	Name: "findmy-friends",
	Func: fnFindMyFriends,
	Help: commands.HelpMeta{
		Section:     HelpSectionFindMy,
		Description: "List your Find My Friends followers and followings; --daemon uses fmfd for background requests.",
		Args:        "[--daemon]",
	},
	RequiresLogin: true,
}

// cmdFindMyFriendsImport imports a Find My Friends location-share URL
// (e.g. from an iMessage deep-link) into the bridge's location-sharing state.
//
// Usage:
//
//	!findmy-friends-import <url>
var cmdFindMyFriendsImport = &commands.FullHandler{
	Name: "findmy-friends-import",
	Func: fnFindMyFriendsImport,
	Help: commands.HelpMeta{
		Section:     HelpSectionFindMy,
		Description: "Accept a Find My Friends location share by pasting the URL from an iMessage deep-link.",
		Args:        "<url> [--daemon]",
	},
	RequiresLogin: true,
}

// ---- JSON schema types -------------------------------------------------------
// FriendsSnapshot is the serde-serialised struct from lib.rs
// findmy_friends_refresh_json. Fields use snake_case (no rename_all).

type friendsSnapshot struct {
	SelectedFriend *string        `json:"selected_friend"`
	Followers      []friendFollow `json:"followers"`
	Following      []friendFollow `json:"following"`
}

// Follow from findmy.rs uses #[serde(rename_all = "camelCase")].
type friendFollow struct {
	ID                        string   `json:"id"`
	InvitationFromHandles     []string `json:"invitationFromHandles"`
	InvitationAcceptedHandles []string `json:"invitationAcceptedHandles"`
	IsFromMessages            bool     `json:"isFromMessages"`
	OptedNotToShare           *bool    `json:"optedNotToShare"`
	Source                    string   `json:"source"`
}

// ---- Helpers -----------------------------------------------------------------

func fmfClientFromEvent(ce *commands.Event) (*IMClient, bool) {
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
	return client, true
}

// primaryHandle returns the most useful handle string for a Follow entry:
// prefer invitation_accepted_handles (they accepted the invite) then
// invitation_from_handles (who sent it), falling back to the opaque ID.
func primaryHandle(f friendFollow) string {
	if len(f.InvitationAcceptedHandles) > 0 {
		return f.InvitationAcceptedHandles[0]
	}
	if len(f.InvitationFromHandles) > 0 {
		return f.InvitationFromHandles[0]
	}
	return f.ID
}

// ---- Command handlers --------------------------------------------------------

func fnFindMyFriends(ce *commands.Event) {
	client, ok := fmfClientFromEvent(ce)
	if !ok {
		return
	}

	daemon := false
	for _, arg := range ce.Args {
		if strings.EqualFold(strings.TrimSpace(arg), "--daemon") {
			daemon = true
		}
	}

	var (
		snapshotJSON string
		fetchErr     error
	)
	func() {
		defer func() {
			if r := recover(); r != nil {
				fetchErr = fmt.Errorf("findmy friends client panicked: %v", r)
			}
		}()
		snapshotJSON, fetchErr = client.client.FindmyFriendsRefreshJson(daemon)
	}()

	if fetchErr != nil {
		ce.Reply("Failed to fetch Find My Friends: %v", fetchErr)
		return
	}

	var snap friendsSnapshot
	if err := json.Unmarshal([]byte(snapshotJSON), &snap); err != nil {
		ce.Reply("Failed to parse Find My Friends response: %v", err)
		return
	}

	if len(snap.Followers) == 0 && len(snap.Following) == 0 {
		ce.Reply("No Find My Friends relationships found. Use `!findmy-friends-import <url>` to add one from an iMessage location-share link.")
		return
	}

	var sb strings.Builder
	sb.WriteString("**Find My Friends**\n\n")

	if len(snap.Following) > 0 {
		sb.WriteString(fmt.Sprintf("**Following** (%d — you can see their location):\n", len(snap.Following)))
		for _, f := range snap.Following {
			handle := primaryHandle(f)
			opted := ""
			if f.OptedNotToShare != nil && *f.OptedNotToShare {
				opted = " _(opted not to share location)_"
			}
			fromMsg := ""
			if f.IsFromMessages {
				fromMsg = " _(via iMessage)_"
			}
			sb.WriteString(fmt.Sprintf("  👤 %s%s%s\n", handle, opted, fromMsg))
		}
		sb.WriteString("\n")
	}

	if len(snap.Followers) > 0 {
		sb.WriteString(fmt.Sprintf("**Followers** (%d — they can see your location):\n", len(snap.Followers)))
		for _, f := range snap.Followers {
			handle := primaryHandle(f)
			fromMsg := ""
			if f.IsFromMessages {
				fromMsg = " _(via iMessage)_"
			}
			sb.WriteString(fmt.Sprintf("  👤 %s%s\n", handle, fromMsg))
		}
		sb.WriteString("\n")
	}

	if snap.SelectedFriend != nil && *snap.SelectedFriend != "" {
		sb.WriteString(fmt.Sprintf("_Currently selected friend: %s_\n", *snap.SelectedFriend))
	}

	sb.WriteString("_Note: actual coordinates are not available via this API — Apple only delivers locations via live APNs updates._")
	ce.Reply(sb.String())
}

func fnFindMyFriendsImport(ce *commands.Event) {
	if len(ce.Args) < 1 {
		ce.Reply("Usage: `!findmy-friends-import <url> [--daemon]`")
		return
	}
	client, ok := fmfClientFromEvent(ce)
	if !ok {
		return
	}

	shareURL := strings.TrimSpace(ce.Args[0])
	daemon := false
	for _, arg := range ce.Args[1:] {
		if strings.EqualFold(strings.TrimSpace(arg), "--daemon") {
			daemon = true
		}
	}

	var importErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				importErr = fmt.Errorf("findmy friends import panicked: %v", r)
			}
		}()
		importErr = client.client.FindmyFriendsImport(daemon, shareURL)
	}()

	if importErr != nil {
		ce.Reply("Failed to import Find My Friends URL: %v", importErr)
		return
	}
	ce.Reply("Location share imported. Run `!findmy-friends` to see the updated relationship list.")
}
