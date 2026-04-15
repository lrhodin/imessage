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
	"strings"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/bridgev2/commands"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"

	"github.com/lrhodin/imessage/pkg/rustpushgo"
)

// cmdSharedAlbums lists all iCloud Shared Streams albums the account is
// subscribed to. Album IDs can be used with !shared-photos to inspect content.
var cmdSharedAlbums = &commands.FullHandler{
	Name: "shared-albums",
	Func: fnSharedAlbums,
	Help: commands.HelpMeta{
		Section:     HelpSectionSharedStreams,
		Description: "List the iCloud Shared Streams albums you're currently subscribed to.",
	},
	RequiresLogin: true,
}

// cmdSharedPhotos lists the asset GUIDs in a specific shared album.
var cmdSharedPhotos = &commands.FullHandler{
	Name: "shared-photos",
	Func: fnSharedPhotos,
	Help: commands.HelpMeta{
		Section:     HelpSectionSharedStreams,
		Description: "List every photo and video GUID in a shared album.",
		Args:        "<album-id>",
	},
	RequiresLogin: true,
}

var cmdSharedSubscribe = &commands.FullHandler{
	Name: "shared-subscribe",
	Func: fnSharedSubscribe,
	Help: commands.HelpMeta{
		Section:     HelpSectionSharedStreams,
		Description: "Subscribe to a shared album by its album ID so the bridge watches it for new assets.",
		Args:        "<album-id>",
	},
	RequiresLogin: true,
}

var cmdSharedSubscribeToken = &commands.FullHandler{
	Name: "shared-subscribe-token",
	Func: fnSharedSubscribeToken,
	Help: commands.HelpMeta{
		Section:     HelpSectionSharedStreams,
		Description: "Subscribe to a shared album using the one-time invitation token from an iCloud share URL.",
		Args:        "<token>",
	},
	RequiresLogin: true,
}

var cmdSharedUnsubscribe = &commands.FullHandler{
	Name: "shared-unsubscribe",
	Func: fnSharedUnsubscribe,
	Help: commands.HelpMeta{
		Section:     HelpSectionSharedStreams,
		Description: "Unsubscribe from a shared album by album ID so the bridge stops watching it.",
		Args:        "<album-id>",
	},
	RequiresLogin: true,
}

var cmdSharedState = &commands.FullHandler{
	Name: "shared-state",
	Func: fnSharedState,
	Help: commands.HelpMeta{
		Section:     HelpSectionSharedStreams,
		Description: "Dump raw Shared Streams state (subscriptions, asset metadata) as JSON — debugging only.",
	},
	RequiresLogin: true,
}

var cmdSharedAssetsJSON = &commands.FullHandler{
	Name: "shared-assets-json",
	Func: fnSharedAssetsJSON,
	Help: commands.HelpMeta{
		Section:     HelpSectionSharedStreams,
		Description: "Export full asset metadata as JSON for specific assets in an album — debugging only.",
		Args:        "<album-id> <asset-guid...>",
	},
	RequiresLogin: true,
}

var cmdSharedDeleteAssets = &commands.FullHandler{
	Name: "shared-delete-assets",
	Func: fnSharedDeleteAssets,
	Help: commands.HelpMeta{
		Section:     HelpSectionSharedStreams,
		Description: "Delete specific assets from a shared album by asset GUID.",
		Args:        "<album-id> <asset-guid...>",
	},
	RequiresLogin: true,
}

func fnSharedAlbums(ce *commands.Event) {
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

	var ids []string
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("shared streams client panicked: %v", r)
			}
		}()
		ss, initErr := client.client.GetSharedstreamsClient()
		if initErr != nil {
			err = initErr
			return
		}
		ids = ss.ListAlbumIds()
	}()

	if err != nil {
		ce.Reply("Failed to get shared albums: %v", err)
		return
	}

	if len(ids) == 0 {
		ce.Reply("You are not subscribed to any shared albums.")
		return
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("**Shared Albums (%d)**\n\n", len(ids)))
	for i, id := range ids {
		sb.WriteString(fmt.Sprintf("%d. `%s`\n", i+1, id))
	}
	sb.WriteString("\nUse `!shared-photos <album-id>` to list photos in an album.")
	ce.Reply(sb.String())
}

func fnSharedPhotos(ce *commands.Event) {
	if len(ce.Args) == 0 {
		ce.Reply("Usage: `!shared-photos <album-id>`")
		return
	}
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

	albumID := strings.TrimSpace(ce.Args[0])
	var guids []string
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("shared streams client panicked: %v", r)
			}
		}()
		ss, initErr := client.client.GetSharedstreamsClient()
		if initErr != nil {
			err = initErr
			return
		}
		guids, err = ss.GetAlbumSummary(albumID)
	}()

	if err != nil {
		ce.Reply("Failed to get album summary for `%s`: %v", albumID, err)
		return
	}

	if len(guids) == 0 {
		ce.Reply("Album `%s` is empty.", albumID)
		return
	}

	shown := guids
	extra := 0
	if len(shown) > 20 {
		extra = len(shown) - 20
		shown = shown[len(shown)-20:]
	}

	var sb strings.Builder
	extraStr := ""
	if extra > 0 {
		extraStr = fmt.Sprintf(" (showing latest 20 of %d)", len(guids))
	}
	sb.WriteString(fmt.Sprintf("**Album** `%s` \u2014 %d asset(s)%s\n\n", albumID, len(guids), extraStr))
	for _, guid := range shown {
		sb.WriteString(fmt.Sprintf("- `%s`\n", guid))
	}
	ce.Reply(sb.String())
}

// startSharedStreamsWatcher polls GetChanges() every 10 minutes and posts a
// notice to the management room when subscribed albums receive new content.
// Must be called as a goroutine; exits when c.stopChan is closed.
func (c *IMClient) startSharedStreamsWatcher(log zerolog.Logger) {
	// Wait 2 minutes before first poll so the bridge finishes initialising.
	select {
	case <-c.stopChan:
		return
	case <-time.After(2 * time.Minute):
	}

	if err := c.pollSharedStreams(log); err != nil {
		log.Warn().Err(err).Msg("Initial shared streams poll failed")
	}

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			if err := c.pollSharedStreams(log); err != nil {
				log.Warn().Err(err).Msg("Shared streams poll failed")
			}
		}
	}
}

// pollSharedStreams calls GetChanges and posts a management-room notice for
// each batch of changed albums. Returns the first error encountered, if any.
func (c *IMClient) pollSharedStreams(log zerolog.Logger) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("shared streams panic: %v", r)
		}
	}()

	if c.client == nil {
		return nil
	}

	ss, err := c.client.GetSharedstreamsClient()
	if err != nil {
		return fmt.Errorf("get shared streams client: %w", err)
	}

	changedAlbums, err := ss.GetChanges()
	if err != nil {
		return fmt.Errorf("get changes: %w", err)
	}

	if len(changedAlbums) == 0 {
		return nil
	}

	notifyAlbums := make([]string, 0, len(changedAlbums))
	for _, albumID := range changedAlbums {
		assets, summaryErr := ss.GetAlbumSummary(albumID)
		if summaryErr != nil {
			return fmt.Errorf("get album summary for %s: %w", albumID, summaryErr)
		}
		if c.recordSharedStreamAssets(albumID, assets) {
			notifyAlbums = append(notifyAlbums, albumID)
		}
	}

	if len(notifyAlbums) == 0 {
		log.Debug().Strs("albums", changedAlbums).Msg("Shared albums changed, but no new visible assets were added")
		return nil
	}

	log.Info().Strs("albums", notifyAlbums).Msg("Detected new content in shared albums")

	ctx := context.Background()
	mgmtRoom, err := c.UserLogin.User.GetManagementRoom(ctx)
	if err != nil {
		return fmt.Errorf("get management room: %w", err)
	}

	var sb strings.Builder
	if len(notifyAlbums) == 1 {
		sb.WriteString(fmt.Sprintf("\U0001f4f8 New content in shared album `%s`.", notifyAlbums[0]))
	} else {
		sb.WriteString(fmt.Sprintf("\U0001f4f8 New content in %d shared albums:\n\n", len(notifyAlbums)))
		for _, id := range notifyAlbums {
			sb.WriteString(fmt.Sprintf("- `%s`\n", id))
		}
	}
	sb.WriteString("\n\nUse `!shared-photos <album-id>` to see the contents.")

	content := format.RenderMarkdown(sb.String(), true, false)
	content.MsgType = event.MsgNotice
	_, sendErr := c.Main.Bridge.Bot.SendMessage(ctx, mgmtRoom, event.EventMessage, &event.Content{
		Parsed: content,
	}, nil)
	if sendErr != nil {
		return fmt.Errorf("send shared streams notification: %w", sendErr)
	}

	return nil
}

func (c *IMClient) recordSharedStreamAssets(albumID string, assets []string) bool {
	current := make(map[string]struct{}, len(assets))
	for _, assetID := range assets {
		if assetID != "" {
			current[assetID] = struct{}{}
		}
	}

	c.sharedStreamAssetCacheMu.Lock()
	defer c.sharedStreamAssetCacheMu.Unlock()

	previous, hadBaseline := c.sharedStreamAssetCache[albumID]
	c.sharedStreamAssetCache[albumID] = current

	if !hadBaseline {
		return false
	}
	for assetID := range current {
		if _, seen := previous[assetID]; !seen {
			return true
		}
	}
	return false
}

func sharedStreamsClientFromEvent(ce *commands.Event) (*rustpushgo.WrappedSharedStreamsClient, bool) {
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
	ss, err := client.client.GetSharedstreamsClient()
	if err != nil {
		ce.Reply("Failed to initialize shared streams client: %v", err)
		return nil, false
	}
	return ss, true
}

func fnSharedSubscribe(ce *commands.Event) {
	if len(ce.Args) < 1 {
		ce.Reply("Usage: `!shared-subscribe <album-id>`")
		return
	}
	ss, ok := sharedStreamsClientFromEvent(ce)
	if !ok {
		return
	}
	albumID := strings.TrimSpace(ce.Args[0])
	if err := ss.Subscribe(albumID); err != nil {
		ce.Reply("Failed to subscribe to album `%s`: %v", albumID, err)
		return
	}
	ce.Reply("Subscribed to shared album `%s`.", albumID)
}

func fnSharedSubscribeToken(ce *commands.Event) {
	if len(ce.Args) < 1 {
		ce.Reply("Usage: `!shared-subscribe-token <token>`")
		return
	}
	ss, ok := sharedStreamsClientFromEvent(ce)
	if !ok {
		return
	}
	token := strings.TrimSpace(ce.Args[0])
	if err := ss.SubscribeToken(token); err != nil {
		ce.Reply("Failed to subscribe using token: %v", err)
		return
	}
	ce.Reply("Subscribed to shared album using token.")
}

func fnSharedUnsubscribe(ce *commands.Event) {
	if len(ce.Args) < 1 {
		ce.Reply("Usage: `!shared-unsubscribe <album-id>`")
		return
	}
	ss, ok := sharedStreamsClientFromEvent(ce)
	if !ok {
		return
	}
	albumID := strings.TrimSpace(ce.Args[0])
	if err := ss.Unsubscribe(albumID); err != nil {
		ce.Reply("Failed to unsubscribe from album `%s`: %v", albumID, err)
		return
	}
	ce.Reply("Unsubscribed from shared album `%s`.", albumID)
}

func fnSharedState(ce *commands.Event) {
	ss, ok := sharedStreamsClientFromEvent(ce)
	if !ok {
		return
	}
	state, err := ss.ExportStateJson()
	if err != nil {
		ce.Reply("Failed to export shared streams state: %v", err)
		return
	}
	if len(state) > 12000 {
		state = state[:12000] + "\n... (truncated)"
	}
	ce.Reply("```json\n%s\n```", state)
}

func fnSharedAssetsJSON(ce *commands.Event) {
	if len(ce.Args) < 2 {
		ce.Reply("Usage: `!shared-assets-json <album-id> <asset-guid...>`")
		return
	}
	ss, ok := sharedStreamsClientFromEvent(ce)
	if !ok {
		return
	}
	albumID := strings.TrimSpace(ce.Args[0])
	assets := parseListArgs(ce.Args[1:])
	if len(assets) == 0 {
		ce.Reply("Please provide at least one asset GUID.")
		return
	}
	assetsJSON, err := ss.GetAssetsJson(albumID, assets)
	if err != nil {
		ce.Reply("Failed to fetch assets JSON: %v", err)
		return
	}
	if len(assetsJSON) > 12000 {
		assetsJSON = assetsJSON[:12000] + "\n... (truncated)"
	}
	ce.Reply("```json\n%s\n```", assetsJSON)
}

func fnSharedDeleteAssets(ce *commands.Event) {
	if len(ce.Args) < 2 {
		ce.Reply("Usage: `!shared-delete-assets <album-id> <asset-guid...>`")
		return
	}
	ss, ok := sharedStreamsClientFromEvent(ce)
	if !ok {
		return
	}
	albumID := strings.TrimSpace(ce.Args[0])
	assets := parseListArgs(ce.Args[1:])
	if len(assets) == 0 {
		ce.Reply("Please provide at least one asset GUID.")
		return
	}
	if err := ss.DeleteAssets(albumID, assets); err != nil {
		ce.Reply("Failed to delete assets: %v", err)
		return
	}
	ce.Reply("Deleted %d asset(s) from `%s`.", len(assets), albumID)
}
