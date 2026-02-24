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
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/commands"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/simplevent"
)

// BridgeCommands returns the custom slash commands for the iMessage bridge.
// Register these in main.go's PostInit hook:
//
//	m.Bridge.Commands.(*commands.Processor).AddHandlers(connector.BridgeCommands()...)
func BridgeCommands() []*commands.FullHandler {
	return []*commands.FullHandler{
		cmdRestoreChat,
		cmdContacts,
		cmdCardDAV,
	}
}

// cmdRestoreChat lists deleted rooms, then waits for the user to reply with
// just a number to restore that room.
//
// Usage:
//
//	!restore-chat    — show numbered list of restorable rooms
//	3                — (bare number) restore room #3 from the list
var cmdRestoreChat = &commands.FullHandler{
	Name:    "restore-chat",
	Aliases: []string{"restore"},
	Func:    fnRestoreChat,
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionChats,
		Description: "Restore a deleted iMessage room. Run the command to see the list, then reply with just the number.",
		Args:        "",
	},
	RequiresLogin: true,
}

func fnRestoreChat(ce *commands.Event) {
	login := ce.User.GetDefaultLogin()
	if login == nil {
		ce.Reply("No active login found.")
		return
	}
	client, ok := login.Client.(*IMClient)
	if !ok || client == nil || client.cloudStore == nil {
		ce.Reply("Bridge client not available.")
		return
	}

	deleted, err := client.cloudStore.listSoftDeletedPortals(ce.Ctx)
	if err != nil {
		ce.Reply("Failed to query deleted rooms: %v", err)
		return
	}

	// Filter out portals that already have an active Matrix room.
	active := deleted[:0]
	for _, p := range deleted {
		portalKey := networkid.PortalKey{ID: networkid.PortalID(p.PortalID), Receiver: login.ID}
		existing, _ := ce.Bridge.GetExistingPortalByKey(ce.Ctx, portalKey)
		if existing != nil && existing.MXID != "" {
			continue // room is alive — not a candidate
		}
		active = append(active, p)
	}

	if len(active) == 0 {
		ce.Reply("No deleted rooms found that can be restored.")
		return
	}

	// Show the numbered list.
	var sb strings.Builder
	sb.WriteString("**Deleted iMessage rooms:**\n\n")
	for i, p := range active {
		name := friendlyPortalName(ce.Ctx, ce.Bridge, client, networkid.PortalKey{
			ID:       networkid.PortalID(p.PortalID),
			Receiver: login.ID,
		}, p.PortalID)
		ts := time.UnixMilli(p.NewestTS).Format("Jan 2, 2006")
		sb.WriteString(fmt.Sprintf("%d. **%s** — %s, last message %s\n",
			i+1, name, pluralMessages(p.Count), ts))
	}
	sb.WriteString("\nReply with a number to restore, or `$cmdprefix cancel` to cancel.")
	ce.Reply(sb.String())

	// Store the list so the next bare message from this user is treated as
	// a selection — no need to retype the command.
	commands.StoreCommandState(ce.User, &commands.CommandState{
		Action: "restore chat",
		Next: commands.MinimalCommandHandlerFunc(func(ce *commands.Event) {
			n, err := strconv.Atoi(strings.TrimSpace(ce.RawArgs))
			if err != nil || n < 1 || n > len(active) {
				ce.Reply("Please reply with a number between 1 and %d, or `$cmdprefix cancel` to cancel.", len(active))
				return
			}

			// Clear state immediately (before the slow ops below).
			commands.StoreCommandState(ce.User, nil)

			chosen := active[n-1]
			portalID := chosen.PortalID
			portalKey := networkid.PortalKey{ID: networkid.PortalID(portalID), Receiver: login.ID}
			name := friendlyPortalName(ce.Ctx, ce.Bridge, client, portalKey, portalID)

			restored, err := client.cloudStore.undeleteCloudMessagesByPortalID(ce.Ctx, portalID)
			if err != nil {
				ce.Reply("Failed to restore history for **%s**: %v", name, err)
				return
			}

			// Remove from recentlyDeletedPortals so recreation isn't blocked.
			client.recentlyDeletedPortalsMu.Lock()
			delete(client.recentlyDeletedPortals, portalID)
			client.recentlyDeletedPortalsMu.Unlock()

			client.Main.Bridge.QueueRemoteEvent(login, &simplevent.ChatResync{
				EventMeta: simplevent.EventMeta{
					Type:         bridgev2.RemoteEventChatResync,
					PortalKey:    portalKey,
					CreatePortal: true,
					Timestamp:    time.Now(),
				},
				GetChatInfoFunc: client.GetChatInfo,
			})

			if restored > 0 {
				ce.Reply("Restoring **%s** — the room will appear shortly with %s.", name, pluralMessages(restored))
			} else {
				ce.Reply("Restoring **%s** — the room will appear shortly (history will be fetched from iCloud).", name)
			}
		}),
		Cancel: func() {}, // nothing to clean up
	})
}

// friendlyPortalName returns a human-readable name for a portal.
// Tries the bridgev2 portal DB first, then the IMClient's resolveGroupName
// (which checks cloud_chat for display_name and participant contacts),
// then falls back to formatting the portal_id.
func friendlyPortalName(ctx context.Context, bridge *bridgev2.Bridge, client *IMClient, key networkid.PortalKey, portalID string) string {
	if portal, _ := bridge.GetExistingPortalByKey(ctx, key); portal != nil && portal.Name != "" {
		return portal.Name
	}
	// For group chats, resolve from cloud store (display_name / contact names).
	isGroup := strings.HasPrefix(portalID, "gid:") || strings.Contains(portalID, ",")
	if isGroup && client != nil {
		if name := client.resolveGroupName(ctx, portalID); name != "" && name != "Group Chat" {
			return name
		}
	}
	// Strip URI prefix for a cleaner display.
	id := strings.TrimPrefix(strings.TrimPrefix(portalID, "mailto:"), "tel:")
	if strings.HasPrefix(portalID, "gid:") {
		return "Group " + strings.TrimPrefix(portalID, "gid:")[:8] + "…"
	}
	return id
}

func pluralMessages(n int) string {
	if n == 1 {
		return "1 message"
	}
	return fmt.Sprintf("%d messages", n)
}

// restorePortalByID is the programmatic equivalent of the restore-chat command.
func (c *IMClient) restorePortalByID(ctx context.Context, portalID string) error {
	if c.cloudStore != nil {
		if _, err := c.cloudStore.undeleteCloudMessagesByPortalID(ctx, portalID); err != nil {
			return fmt.Errorf("undelete cloud_message: %w", err)
		}
	}
	c.recentlyDeletedPortalsMu.Lock()
	delete(c.recentlyDeletedPortals, portalID)
	c.recentlyDeletedPortalsMu.Unlock()

	portalKey := networkid.PortalKey{
		ID:       networkid.PortalID(portalID),
		Receiver: c.UserLogin.ID,
	}
	c.Main.Bridge.QueueRemoteEvent(c.UserLogin, &simplevent.ChatResync{
		EventMeta: simplevent.EventMeta{
			Type:         bridgev2.RemoteEventChatResync,
			PortalKey:    portalKey,
			CreatePortal: true,
			Timestamp:    time.Now(),
		},
		GetChatInfoFunc: c.GetChatInfo,
	})
	return nil
}
