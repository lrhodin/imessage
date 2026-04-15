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
