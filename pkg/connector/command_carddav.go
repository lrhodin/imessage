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

// carddav command — per-user external CardDAV contact sync setup.
//
// Flow for "!im carddav setup google":
//   !im carddav setup google
//   → Bot sends Google App Password instructions and prompts for Gmail address
//   their@gmail.com
//   → Bot prompts for app password
//   xxxx xxxx xxxx xxxx
//   → Bot auto-discovers URL, tests sync, saves credentials, reports contact count
//
// Other subcommands:
//   !im carddav status   — show current config and last sync time
//   !im carddav sync     — force re-sync now
//   !im carddav remove   — unlink CardDAV credentials

import (
	"fmt"
	"strings"

	"maunium.net/go/mautrix/bridgev2/commands"
)

var cmdCardDAV = &commands.FullHandler{
	Name:    "carddav",
	Aliases: []string{"contacts-sync"},
	Func:    fnCardDAV,
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionGeneral,
		Description: "Set up external CardDAV contact sync (Google, Fastmail, etc.)",
		Args:        "<setup|status|sync|remove>",
	},
	RequiresLogin: true,
}

func fnCardDAV(ce *commands.Event) {
	sub := ""
	if len(ce.Args) > 0 {
		sub = strings.ToLower(ce.Args[0])
	}
	switch sub {
	case "setup":
		fnCardDAVSetup(ce)
	case "status":
		fnCardDAVStatus(ce)
	case "sync":
		fnCardDAVSync(ce)
	case "remove", "unlink", "disconnect":
		fnCardDAVRemove(ce)
	default:
		ce.Reply("**CardDAV Contact Sync**\n\n" +
			"• `!im carddav setup` — link a CardDAV account (Google, Fastmail, etc.)\n" +
			"• `!im carddav status` — show current config and last sync time\n" +
			"• `!im carddav sync` — force re-sync contacts now\n" +
			"• `!im carddav remove` — unlink CardDAV account")
	}
}

// fnCardDAVSetup starts the interactive CardDAV setup flow.
// Accepts an optional provider name or custom URL as the second argument.
func fnCardDAVSetup(ce *commands.Event) {
	provider := ""
	if len(ce.Args) > 1 {
		provider = strings.ToLower(ce.Args[1])
	}

	if provider == "" {
		ce.Reply("**Choose a contact provider:**\n\n" +
			"1. **Google Contacts**\n" +
			"2. **Fastmail**\n" +
			"3. **Yahoo**\n" +
			"4. **Custom CardDAV URL**\n\n" +
			"Reply with a number, or run `!im carddav setup google` to go straight to Google setup.")
		commands.StoreCommandState(ce.User, &commands.CommandState{
			Action: "carddav provider",
			Next: commands.MinimalCommandHandlerFunc(func(ce *commands.Event) {
				commands.StoreCommandState(ce.User, nil)
				choice := strings.TrimSpace(ce.RawArgs)
				var resolved string
				switch choice {
				case "1", "google":
					resolved = "google"
				case "2", "fastmail":
					resolved = "fastmail"
				case "3", "yahoo":
					resolved = "yahoo"
				case "4", "custom":
					resolved = "custom"
				default:
					if strings.HasPrefix(choice, "http") {
						resolved = choice // treat as a raw custom URL
					} else {
						ce.Reply("Invalid choice. Run `!im carddav setup` again.")
						return
					}
				}
				startCardDAVSetupFlow(ce, resolved)
			}),
			Cancel: func() {},
		})
		return
	}

	startCardDAVSetupFlow(ce, provider)
}

// cardDAVProviderDisplayName returns a human-readable name for a known provider key.
func cardDAVProviderDisplayName(provider string) string {
	switch provider {
	case "google":
		return "Google Contacts"
	case "fastmail":
		return "Fastmail"
	case "yahoo":
		return "Yahoo"
	default:
		return provider
	}
}

// startCardDAVSetupFlow drives the multi-step credential collection for a given
// provider (e.g. "google", "fastmail") or a raw custom URL (starts with "http").
func startCardDAVSetupFlow(ce *commands.Event, provider string) {
	client, ok := ce.User.GetDefaultLogin().Client.(*IMClient)
	if !ok || client == nil {
		ce.Reply("No active bridge connection.")
		return
	}

	isGoogle := provider == "google"
	isCustomURL := strings.HasPrefix(provider, "http")

	// Step 1: prompt for email / username
	if isGoogle {
		ce.Reply("**Google Contacts Setup**\n\n" +
			"You need a **Google App Password** to connect.\n\n" +
			"**Steps to create one:**\n" +
			"1. Go to https://myaccount.google.com/apppasswords\n" +
			"2. Sign in to your Google account\n" +
			"3. Create a new app password — choose **Other** as the app type and give it any name\n" +
			"4. Copy the 16-character password\n\n" +
			"⚠️ **2-Step Verification must be enabled** on your Google account before app passwords are available.\n\n" +
			"Reply with your **Gmail address** to continue, or `!im cancel` to cancel.")
	} else if isCustomURL {
		ce.Reply("Reply with your **username** for `%s`, or `!im cancel` to cancel.", provider)
	} else {
		ce.Reply("Reply with your **email address** for %s, or `!im cancel` to cancel.",
			cardDAVProviderDisplayName(provider))
	}

	commands.StoreCommandState(ce.User, &commands.CommandState{
		Action: "carddav email",
		Next: commands.MinimalCommandHandlerFunc(func(ce *commands.Event) {
			commands.StoreCommandState(ce.User, nil)
			emailOrUser := strings.TrimSpace(ce.RawArgs)
			if emailOrUser == "" {
				ce.Reply("Please enter a valid email address or username.")
				return
			}

			// Step 2: prompt for password
			if isGoogle {
				ce.Reply("Reply with your **16-character Google App Password** (spaces are OK), or `!im cancel` to cancel.")
			} else {
				ce.Reply("Reply with your **app password**, or `!im cancel` to cancel.")
			}

			commands.StoreCommandState(ce.User, &commands.CommandState{
				Action: "carddav password",
				Next: commands.MinimalCommandHandlerFunc(func(ce *commands.Event) {
					commands.StoreCommandState(ce.User, nil)
					// Google app passwords have spaces — strip them
					password := strings.ReplaceAll(strings.TrimSpace(ce.RawArgs), " ", "")
					if password == "" {
						ce.Reply("Please enter a valid password.")
						return
					}

					customURL := ""
					if isCustomURL {
						customURL = provider
					}

					completeCardDAVSetup(ce, client, emailOrUser, password, customURL)
				}),
				Cancel: func() {},
			})
		}),
		Cancel: func() {},
	})
}

// completeCardDAVSetup validates credentials, discovers the CardDAV URL, syncs
// contacts, and persists everything to the user's login metadata.
func completeCardDAVSetup(ce *commands.Event, client *IMClient, emailOrUser, password, customURL string) {
	log := client.UserLogin.Log.With().Str("component", "carddav-setup").Logger()

	ce.Reply("Connecting to CardDAV server…")

	// Derive the per-user encryption key
	key := DeriveCardDAVKey(client.Main.BridgeSecret, string(client.UserLogin.ID))

	// Encrypt the password before any network I/O so we don't hold plaintext longer than needed
	encPwd, err := EncryptCardDAVPassword(key, password)
	if err != nil {
		ce.Reply("❌ Internal error encrypting password: %v", err)
		return
	}

	// Resolve CardDAV URL (provided or auto-discovered)
	url := customURL
	if url == "" {
		discovered, discoverErr := DiscoverCardDAVURL(emailOrUser, emailOrUser, password, log)
		if discoverErr != nil {
			ce.Reply("❌ Could not find a CardDAV server for that address.\n\n" +
				"Check that the email is correct, or try `!im carddav setup <url>` " +
				"with the full CardDAV URL.")
			return
		}
		url = discovered
	}

	// Build config and create client to test the connection
	cfg := CardDAVConfig{
		Email:             emailOrUser,
		URL:               url,
		PasswordEncrypted: encPwd,
	}

	testClient := newExternalCardDAVClient(cfg, key, log)
	if testClient == nil {
		ce.Reply("❌ Failed to initialize CardDAV client. Check your credentials.")
		return
	}

	// Run a full sync to verify the credentials are accepted
	if syncErr := testClient.SyncContacts(log); syncErr != nil {
		ce.Reply("❌ Failed to sync contacts: %v", syncErr)
		return
	}

	count := len(testClient.GetAllContacts())

	// Persist to UserLoginMetadata
	meta := client.UserLogin.Metadata.(*UserLoginMetadata)
	meta.CardDAVEmail = emailOrUser
	meta.CardDAVURL = url
	meta.CardDAVUsername = ""
	meta.CardDAVPasswordEncrypted = encPwd

	if saveErr := client.UserLogin.Save(ce.Ctx); saveErr != nil {
		ce.Reply("❌ Failed to save credentials: %v", saveErr)
		return
	}

	// Replace the active contacts source
	client.contacts = testClient
	client.setContactsReady(log)

	ce.Reply("✓ Connected! Found **%d contacts**. Ghost display names will update shortly.", count)
}

// fnCardDAVStatus shows the current CardDAV configuration and last sync time.
func fnCardDAVStatus(ce *commands.Event) {
	login := ce.User.GetDefaultLogin()
	meta := login.Metadata.(*UserLoginMetadata)

	if !meta.CardDAVIsConfigured() {
		ce.Reply("No external CardDAV account configured.\n\nRun `!im carddav setup` to set one up.")
		return
	}

	client, ok := login.Client.(*IMClient)
	if !ok || client == nil {
		ce.Reply("No active bridge connection.")
		return
	}

	syncLine := "Not yet synced"
	if ext, ok := client.contacts.(*externalCardDAVClient); ok {
		last := ext.LastSync()
		if !last.IsZero() {
			count := len(client.contacts.GetAllContacts())
			syncLine = fmt.Sprintf("Last synced: %s (%d contacts)", last.Format("Jan 2, 2006 at 3:04 PM"), count)
		}
	}

	ce.Reply("**CardDAV Contact Sync**\n\n"+
		"**Account:** %s\n"+
		"**URL:** %s\n"+
		"%s\n\n"+
		"Run `!im carddav sync` to force a re-sync or `!im carddav remove` to unlink.",
		meta.CardDAVEmail, meta.CardDAVURL, syncLine)
}

// fnCardDAVSync forces an immediate contact re-sync.
func fnCardDAVSync(ce *commands.Event) {
	login := ce.User.GetDefaultLogin()
	meta := login.Metadata.(*UserLoginMetadata)

	if !meta.CardDAVIsConfigured() {
		ce.Reply("No external CardDAV configured. Run `!im carddav setup` first.")
		return
	}

	client, ok := login.Client.(*IMClient)
	if !ok || client == nil || client.contacts == nil {
		ce.Reply("No active bridge connection.")
		return
	}

	log := client.UserLogin.Log
	if err := client.contacts.SyncContacts(log); err != nil {
		ce.Reply("❌ Sync failed: %v", err)
		return
	}

	count := len(client.contacts.GetAllContacts())
	ce.Reply("✓ Synced **%d contacts**.", count)
}

// fnCardDAVRemove clears the stored CardDAV credentials and falls back to iCloud.
func fnCardDAVRemove(ce *commands.Event) {
	login := ce.User.GetDefaultLogin()
	meta := login.Metadata.(*UserLoginMetadata)

	if !meta.CardDAVIsConfigured() {
		ce.Reply("No external CardDAV account is configured.")
		return
	}

	meta.CardDAVEmail = ""
	meta.CardDAVURL = ""
	meta.CardDAVUsername = ""
	meta.CardDAVPasswordEncrypted = ""

	if err := login.Save(ce.Ctx); err != nil {
		ce.Reply("❌ Failed to clear credentials: %v", err)
		return
	}

	client, ok := login.Client.(*IMClient)
	if !ok || client == nil {
		ce.Reply("✓ CardDAV account removed.")
		return
	}

	// Fall back to iCloud contacts
	log := client.UserLogin.Log
	client.contacts = newCloudContactsClient(client.client, log)
	if client.contacts != nil {
		_ = client.contacts.SyncContacts(log)
		client.setContactsReady(log)
		ce.Reply("✓ CardDAV account removed. Switched back to iCloud contacts.")
	} else {
		ce.Reply("✓ CardDAV account removed. iCloud contacts are not available on this platform.")
	}
}
