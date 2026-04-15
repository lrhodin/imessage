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
	"fmt"
	"strings"

	"maunium.net/go/mautrix/bridgev2/commands"

	"github.com/lrhodin/imessage/pkg/rustpushgo"
)

var cmdStatuskitState = &commands.FullHandler{
	Name: "statuskit-state",
	Func: fnStatuskitState,
	Help: commands.HelpMeta{
		Section:     HelpSectionStatusKit,
		Description: "Dump raw StatusKit client state (channels, keys, interest tokens) as JSON — debugging only.",
	},
	RequiresLogin: true,
}

var cmdStatuskitShare = &commands.FullHandler{
	Name: "statuskit-share",
	Func: fnStatuskitShare,
	Help: commands.HelpMeta{
		Section:     HelpSectionStatusKit,
		Description: "Publish your StatusKit shared-status. Use `on` to mark yourself available; use `off <mode>` where <mode> is the iOS Focus UUID to publish as away in that mode.",
		Args:        "on | off <mode>",
	},
	RequiresLogin: true,
}

var cmdStatuskitResetKeys = &commands.FullHandler{
	Name: "statuskit-reset-keys",
	Func: fnStatuskitResetKeys,
	Help: commands.HelpMeta{
		Section:     HelpSectionStatusKit,
		Description: "Wipe local StatusKit keys; the next publish will mint a fresh keyset.",
	},
	RequiresLogin: true,
}

var cmdStatuskitRollKeys = &commands.FullHandler{
	Name: "statuskit-roll-keys",
	Func: fnStatuskitRollKeys,
	Help: commands.HelpMeta{
		Section:     HelpSectionStatusKit,
		Description: "Rotate local StatusKit keys and reshare them with invited handles.",
	},
	RequiresLogin: true,
}

var cmdStatuskitRequestHandles = &commands.FullHandler{
	Name: "statuskit-request-handles",
	Func: fnStatuskitRequestHandles,
	Help: commands.HelpMeta{
		Section:     HelpSectionStatusKit,
		Description: "Ask Apple to push StatusKit updates for each listed handle.",
		Args:        "<handle...>",
	},
	RequiresLogin: true,
}

var cmdStatuskitClearInterest = &commands.FullHandler{
	Name: "statuskit-clear-interest",
	Func: fnStatuskitClearInterest,
	Help: commands.HelpMeta{
		Section:     HelpSectionStatusKit,
		Description: "Drop all StatusKit interest tokens so Apple re-pushes them on the next subscribe.",
	},
	RequiresLogin: true,
}

var cmdStatuskitInviteToChannel = &commands.FullHandler{
	Name: "statuskit-invite-channel",
	Func: fnStatuskitInviteToChannel,
	Help: commands.HelpMeta{
		Section:     HelpSectionStatusKit,
		Description: "Invite handles to your StatusKit channel so they can decrypt your shared presence; optional =mode1|mode2 per handle.",
		Args:        "<sender-handle> <handle[=mode1|mode2]...>",
	},
	RequiresLogin: true,
}

func statusKitClientFromEvent(ce *commands.Event) (*rustpushgo.WrappedStatusKitClient, bool) {
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
	sk, err := client.client.GetStatuskitClient()
	if err != nil {
		ce.Reply("Failed to initialize StatusKit client: %v", err)
		return nil, false
	}
	return sk, true
}

func parseBoolish(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "on", "yes", "y", "active":
		return true, nil
	case "0", "false", "off", "no", "n", "inactive":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean %q", value)
	}
}

func fnStatuskitState(ce *commands.Event) {
	sk, ok := statusKitClientFromEvent(ce)
	if !ok {
		return
	}
	state, err := sk.ExportStateJson()
	if err != nil {
		ce.Reply("Failed to export StatusKit state: %v", err)
		return
	}
	if len(state) > 12000 {
		state = state[:12000] + "\n... (truncated)"
	}
	ce.Reply("```json\n%s\n```", state)
}

func fnStatuskitShare(ce *commands.Event) {
	if len(ce.Args) < 1 {
		ce.Reply("Usage: `!statuskit-share <on|off> [mode]`")
		return
	}
	sk, ok := statusKitClientFromEvent(ce)
	if !ok {
		return
	}
	active, err := parseBoolish(ce.Args[0])
	if err != nil {
		ce.Reply("%v", err)
		return
	}
	var mode *string
	if len(ce.Args) > 1 {
		m := strings.TrimSpace(ce.Args[1])
		if m != "" {
			mode = &m
		}
	}
	if err := sk.ShareStatus(active, mode); err != nil {
		ce.Reply("Failed to publish StatusKit share status: %v", err)
		return
	}
	if mode != nil {
		ce.Reply("Published StatusKit share state: active=%v mode=%s", active, *mode)
	} else {
		ce.Reply("Published StatusKit share state: active=%v", active)
	}
}

func fnStatuskitResetKeys(ce *commands.Event) {
	sk, ok := statusKitClientFromEvent(ce)
	if !ok {
		return
	}
	sk.ResetKeys()
	ce.Reply("Reset StatusKit keys.")
}

func fnStatuskitRollKeys(ce *commands.Event) {
	sk, ok := statusKitClientFromEvent(ce)
	if !ok {
		return
	}
	sk.RollKeys()
	ce.Reply("Rotated StatusKit keys.")
}

func fnStatuskitRequestHandles(ce *commands.Event) {
	if len(ce.Args) < 1 {
		ce.Reply("Usage: `!statuskit-request-handles <handle...>`")
		return
	}
	sk, ok := statusKitClientFromEvent(ce)
	if !ok {
		return
	}
	handles := parseListArgs(ce.Args)
	if len(handles) == 0 {
		ce.Reply("Please provide at least one handle.")
		return
	}
	sk.RequestHandles(handles)
	ce.Reply("Requested StatusKit updates for %d handle(s).", len(handles))
}

func fnStatuskitClearInterest(ce *commands.Event) {
	sk, ok := statusKitClientFromEvent(ce)
	if !ok {
		return
	}
	sk.ClearInterestTokens()
	ce.Reply("Cleared StatusKit interest tokens.")
}

func fnStatuskitInviteToChannel(ce *commands.Event) {
	if len(ce.Args) < 2 {
		ce.Reply("Usage: `!statuskit-invite-channel <sender-handle> <handle[=mode1|mode2]...>`")
		return
	}
	sk, ok := statusKitClientFromEvent(ce)
	if !ok {
		return
	}
	sender := strings.TrimSpace(ce.Args[0])
	targetParts := parseListArgs(ce.Args[1:])
	if len(targetParts) == 0 {
		ce.Reply("Please provide at least one invite handle.")
		return
	}
	invites := make([]rustpushgo.WrappedStatusKitInviteHandle, 0, len(targetParts))
	for _, part := range targetParts {
		handle := part
		allowedModes := []string{}
		if eq := strings.Index(part, "="); eq > 0 {
			handle = strings.TrimSpace(part[:eq])
			modes := strings.Split(part[eq+1:], "|")
			for _, m := range modes {
				m = strings.TrimSpace(m)
				if m != "" {
					allowedModes = append(allowedModes, m)
				}
			}
		}
		if handle == "" {
			continue
		}
		invites = append(invites, rustpushgo.WrappedStatusKitInviteHandle{Handle: handle, AllowedModes: allowedModes})
	}
	if len(invites) == 0 {
		ce.Reply("No valid invite handles provided.")
		return
	}
	if err := sk.InviteToChannel(sender, invites); err != nil {
		ce.Reply("Failed to invite handles to StatusKit channel: %v", err)
		return
	}
	ce.Reply("Invited %d handle(s) to StatusKit channel.", len(invites))
}
