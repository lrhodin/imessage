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
	"math"
	"net/url"
	"sort"
	"strings"

	"maunium.net/go/mautrix/bridgev2/commands"
)

// cmdFindMyDevices fetches the list of iCloud-linked Apple devices via the
// Find My iPhone/Mac API and displays their location and status.
//
// Usage:
//
//	!findmy-devices
var cmdFindMyDevices = &commands.FullHandler{
	Name: "findmy-devices",
	Func: fnFindMyDevices,
	Help: commands.HelpMeta{
		Section:     HelpSectionFindMy,
		Description: "List iCloud-linked Apple devices with current location, battery, charging state, and a Maps link.",
	},
	RequiresLogin: true,
}

// ---- JSON schema types -------------------------------------------------------
// FoundDevice from rustpush findmy.rs uses #[serde(rename_all = "camelCase")].

type foundDevice struct {
	Name              *string        `json:"name"`
	DeviceDisplayName *string        `json:"deviceDisplayName"`
	ModelDisplayName  *string        `json:"modelDisplayName"`
	DeviceModel       *string        `json:"deviceModel"`
	DeviceClass       *string        `json:"deviceClass"`
	BatteryStatus     *string        `json:"batteryStatus"`
	BatteryLevel      *float64       `json:"batteryLevel"`
	Location          *foundDeviceLoc `json:"location"`
	LocationEnabled   *bool          `json:"locationEnabled"`
	LostModeEnabled   *bool          `json:"lostModeEnabled"`
	LowPowerMode      *bool          `json:"lowPowerMode"`
	IsMac             *bool          `json:"isMac"`
	ThisDevice        *bool          `json:"thisDevice"`
}

// Location fields match rustpush's Location struct (camelCase).
type foundDeviceLoc struct {
	Latitude           float64 `json:"latitude"`
	Longitude          float64 `json:"longitude"`
	HorizontalAccuracy float64 `json:"horizontalAccuracy"`
	IsOld              *bool   `json:"isOld"`
}

// ---- Command handler ---------------------------------------------------------

func fnFindMyDevices(ce *commands.Event) {
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
		devicesJSON string
		fetchErr    error
	)
	func() {
		defer func() {
			if r := recover(); r != nil {
				fetchErr = fmt.Errorf("findmy devices client panicked: %v", r)
			}
		}()
		devicesJSON, fetchErr = client.client.FindmyPhoneRefreshJson()
	}()

	if fetchErr != nil {
		ce.Reply("Failed to fetch Find My devices: %v", fetchErr)
		return
	}

	var devices []foundDevice
	if err := json.Unmarshal([]byte(devicesJSON), &devices); err != nil {
		ce.Reply("Failed to parse Find My devices response: %v", err)
		return
	}

	if len(devices) == 0 {
		ce.Reply("No iCloud devices found. Make sure your Apple ID has devices enrolled in Find My.")
		return
	}

	// Sort: this device first, then alphabetically by name.
	sort.Slice(devices, func(i, j int) bool {
		iThis := devices[i].ThisDevice != nil && *devices[i].ThisDevice
		jThis := devices[j].ThisDevice != nil && *devices[j].ThisDevice
		if iThis != jThis {
			return iThis
		}
		ni := ptrStringOr(devices[i].Name, ptrStringOr(devices[i].DeviceDisplayName, ""))
		nj := ptrStringOr(devices[j].Name, ptrStringOr(devices[j].DeviceDisplayName, ""))
		return strings.ToLower(ni) < strings.ToLower(nj)
	})

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("**Find My Devices (%d)**\n\n", len(devices)))
	for _, d := range devices {
		name := ptrStringOr(d.Name, ptrStringOr(d.DeviceDisplayName, "Unknown device"))
		model := ptrStringOr(d.ModelDisplayName, ptrStringOr(d.DeviceModel, ""))
		class := ptrStringOr(d.DeviceClass, "")
		emoji := deviceClassEmoji(class, d.IsMac)

		if d.ThisDevice != nil && *d.ThisDevice {
			sb.WriteString(fmt.Sprintf("%s **%s** _(this device)_\n", emoji, name))
		} else {
			sb.WriteString(fmt.Sprintf("%s **%s**\n", emoji, name))
		}
		if model != "" {
			sb.WriteString(fmt.Sprintf("  Model: %s\n", model))
		}
		if d.LowPowerMode != nil && *d.LowPowerMode {
			sb.WriteString("  🔋 Low Power Mode\n")
		}
		if d.BatteryLevel != nil && d.BatteryStatus != nil {
			pct := int(math.Round(*d.BatteryLevel * 100))
			bEmoji := batteryEmoji(pct, d.BatteryStatus)
			sb.WriteString(fmt.Sprintf("  %s %d%% (%s)\n", bEmoji, pct, *d.BatteryStatus))
		}
		if d.LostModeEnabled != nil && *d.LostModeEnabled {
			sb.WriteString("  ⚠️ Lost Mode enabled\n")
		}
		if d.Location != nil {
			loc := d.Location
			ageNote := ""
			if loc.IsOld != nil && *loc.IsOld {
				ageNote = " _(old)_"
			}
			accNote := ""
			if loc.HorizontalAccuracy > 0 {
				accNote = fmt.Sprintf(", ±%dm", int(math.Round(loc.HorizontalAccuracy)))
			}
			sb.WriteString(fmt.Sprintf(
				"  📍 %.6f, %.6f%s%s\n",
				loc.Latitude, loc.Longitude, accNote, ageNote,
			))
			sb.WriteString(fmt.Sprintf(
				"  [Open in Maps](https://maps.apple.com/?ll=%.6f,%.6f&q=%s)\n",
				loc.Latitude, loc.Longitude, url.QueryEscape(name),
			))
		} else if d.LocationEnabled != nil && !*d.LocationEnabled {
			sb.WriteString("  _Location sharing disabled_\n")
		} else {
			sb.WriteString("  _Location unavailable_\n")
		}
		sb.WriteString("\n")
	}

	ce.Reply(sb.String())
}

func deviceClassEmoji(class string, isMac *bool) string {
	if isMac != nil && *isMac {
		return "💻"
	}
	switch strings.ToLower(class) {
	case "iphone":
		return "📱"
	case "ipad":
		return "📲"
	case "mac":
		return "💻"
	case "watch":
		return "⌚"
	case "airpods", "beats":
		return "🎧"
	case "appletv":
		return "📺"
	case "homepod":
		return "🔊"
	default:
		return "📡"
	}
}

func batteryEmoji(pct int, status *string) string {
	if status != nil && strings.EqualFold(*status, "Charging") {
		return "🔋⚡"
	}
	if pct <= 20 {
		return "🪫"
	}
	return "🔋"
}
