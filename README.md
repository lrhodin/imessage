# mautrix-imessage (v2)

A Matrix-iMessage puppeting bridge. Send and receive iMessages from any Matrix client.

This is the **v2** rewrite using [rustpush](https://github.com/OpenBubbles/rustpush) and [bridgev2](https://mau.fi/blog/megabridge-twilio/) — it connects directly to Apple's iMessage servers without SIP bypass, Barcelona, or relay servers.

**Features**: text, images, video, audio, files, reactions/tapbacks, edits, unsends, typing indicators, read receipts, group chats, SMS forwarding, and contact name resolution.

**Platforms**: macOS (full features) and Linux (via hardware key extracted from a Mac once).

## Quick Start (macOS)

macOS 13+ required (Ventura or later). Sign into iCloud on the Mac running the bridge (Settings → Apple ID) — this lets Apple recognize the device so login works without 2FA prompts.

### With Beeper

```bash
git clone https://github.com/lrhodin/imessage.git
cd imessage
make install-beeper
```

The installer handles everything: Homebrew, dependencies, building, Beeper login, iMessage login, config, and LaunchAgent setup.

### With a Self-Hosted Homeserver

```bash
git clone https://github.com/lrhodin/imessage.git
cd imessage
make install
```

The installer auto-installs Homebrew and dependencies if needed, asks three questions (homeserver URL, domain, your Matrix ID), generates config files, handles iMessage login, and starts the bridge as a LaunchAgent. It will pause and tell you exactly what to add to your `homeserver.yaml` to register the bridge.

## Quick Start (Linux)

The bridge runs on Linux using a hardware key extracted once from a real Mac. No Mac needed at runtime for Intel keys; **Apple Silicon Macs** require the NAC relay (a small background process on the Mac).

### Prerequisites

Ubuntu 22.04+ (or equivalent). Only `git`, `make`, and `sudo` are needed — the build installs everything else:

```bash
sudo apt install -y git make
```

### Step 1: Extract hardware key (one-time, on your Mac)

**If the Mac has Go installed (macOS 13+):**

```bash
git clone https://github.com/lrhodin/imessage.git
cd imessage
go run tools/extract-key/main.go
```

**If the Mac is older (macOS 10.13 High Sierra through 12) or doesn't have Go:**

Cross-compile on any Mac that has Go, then copy the binary over:

```bash
# On your newer Mac (with Go installed):
git clone https://github.com/lrhodin/imessage.git
cd imessage
make extract-key-intel

# Copy to the older Mac:
scp extract-key-intel user@old-mac:~/

# On the older Mac:
cd ~ && ./extract-key-intel
```

This reads hardware identifiers (serial, MLB, ROM, etc.) and outputs a base64 key. The Mac is not modified and can continue to be used normally.

**Apple Silicon Macs** lack the encrypted IOKit properties needed by the x86_64 NAC emulator. You must also run the NAC relay — a small HTTP server that generates Apple validation data using the Mac's native `AAAbsintheContext` framework.

**Set up the relay:**

```bash
go build -o ~/bin/nac-relay ./tools/nac-relay/
~/bin/nac-relay --setup
```

This installs a LaunchAgent that starts on login and auto-restarts if it crashes. On first run, grant **Full Disk Access** and **Contacts** access when prompted — this enables chat history backfill (including images and attachments), contact name resolution, and SMS forwarding from the Mac.

The relay auto-generates a self-signed TLS certificate and a random bearer token on first start, stored in `~/Library/Application Support/nac-relay/`. All endpoints (except `/health`) require the token. The bridge verifies the relay's certificate fingerprint (Go side) and authenticates with the token (both Go and Rust sides).

```bash
# Check it's running
tail -f /tmp/nac-relay.log
```

**Extract the key with the relay URL:**

```bash
go run tools/extract-key/main.go -relay https://<your-mac-ip>:5001/validation-data
```

The `extract-key` tool reads the token and certificate fingerprint from `relay-info.json` (written by the relay) and embeds them in the hardware key automatically. The relay must be running before you run `extract-key`.

If the bridge runs outside your LAN (e.g., cloud VM), forward port 5001 TCP to your Mac's local IP. Lock the allowed source IPs to your bridge server's IP for defense in depth — the relay is also protected by TLS + bearer token auth.

**Intel Macs**: The NAC relay is not needed. The bridge runs the x86_64 NAC emulator locally on Linux using hardware data from the extracted key. Chat history starts from when you log in and contacts appear by phone number / email.

### Step 2: Build and install the bridge (on Linux)

#### With Beeper

```bash
git clone https://github.com/lrhodin/imessage.git
cd imessage
make install-beeper
```

#### With a Self-Hosted Homeserver

```bash
git clone https://github.com/lrhodin/imessage.git
cd imessage
make install
```

On first run expect ~3 minutes for the Rust library to compile.

### Step 3: Login

DM the bridge bot and choose the **"Apple ID (External Key)"** login flow:

1. Paste your hardware key (base64)
2. Enter your Apple ID and password
3. Enter the 2FA code sent to your trusted devices

The bridge registers with Apple's servers and starts receiving iMessages.

## Login

Follow the prompts: Apple ID → password → 2FA (if needed) → handle selection. If the Mac is signed into iCloud with the same Apple ID, login completes without 2FA.

If your Apple ID has multiple identities registered (e.g. a phone number and an email address), you'll be asked which one to use for outgoing messages. This is what recipients see your messages "from". To change it later, set `preferred_handle` in the config (see [Configuration](#configuration)) or log in again.

> **Tip:** In a DM with the bot, commands don't need a prefix. In a regular room, use `!im login`, `!im help`, etc.

### SMS Forwarding

To bridge SMS (green bubble) messages, enable forwarding on your iPhone:

**Settings → Messages → Text Message Forwarding** → toggle on the bridge device.

### Contact Sync

By default, the bridge resolves contact names and avatars from your iCloud account (the Apple ID you logged in with). To use **Google Contacts or another CardDAV provider** instead, run the setup command in a DM with the bridge bot:

```
!im carddav setup
```

This starts an interactive flow — choose your provider, enter credentials, and the bridge will auto-discover the server and sync your contacts immediately.

**Supported providers:** Google Contacts, Fastmail, Yahoo, Nextcloud, Radicale, and any standard CardDAV server.

#### Google Contacts

Google requires an **App Password** (not your regular Google password):

1. Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
2. Sign in to your Google account
3. Create a new app password — choose **Other** as the app type
4. Copy the 16-character password

⚠️ 2-Step Verification must be enabled on your Google account before app passwords are available.

Run `!im carddav setup google` and the bot will walk you through the rest.

#### Other providers

```
!im carddav setup fastmail          # Fastmail
!im carddav setup yahoo             # Yahoo
!im carddav setup https://dav.example.com/  # Custom CardDAV URL
```

#### Managing contact sync

```
!im carddav status     # Show current config and last sync time
!im carddav sync       # Force re-sync contacts now
!im carddav remove     # Unlink CardDAV account (reverts to iCloud)
```

Contacts are re-synced automatically every 15 minutes. Credentials are stored encrypted per user — each person using the bridge has their own independent contact source.

### Chatting

Incoming iMessages automatically create Matrix rooms. If Full Disk Access is granted (macOS), existing conversations from Messages.app are also synced.

To start a **new** conversation:

```
resolve +15551234567
```

This creates a portal room. Messages you send there are delivered as iMessages.

## How It Works

The bridge connects directly to Apple's iMessage servers using [rustpush](https://github.com/OpenBubbles/rustpush) with local NAC validation (no SIP bypass, no relay server). On macOS with Full Disk Access, it also reads `chat.db` for message history backfill and contact name resolution.

On Linux, NAC validation uses one of two paths:

- **Intel key**: [open-absinthe](rustpush/open-absinthe/) emulates Apple's `IMDAppleServices` x86_64 binary via unicorn-engine, hooking IOKit/CoreFoundation calls and feeding them hardware data from the extracted key
- **Apple Silicon key + relay**: The bridge fetches validation data from a NAC relay running on the Mac, which calls Apple's native `AAAbsintheContext` framework

```mermaid
flowchart TB
    subgraph macos["🖥 macOS"]
        HS1[Homeserver] -- appservice --> Bridge1[mautrix-imessage]
        Bridge1 -- FFI --> RP1[rustpush]
        RP1 -- IOKit/AAAbsinthe --> NAC1[Local NAC]
    end
    subgraph linux["🐧 Linux"]
        HS2[Homeserver] -- appservice --> Bridge2[mautrix-imessage]
        Bridge2 -- FFI --> RP2[rustpush]
        RP2 -- unicorn-engine --> NAC2[open-absinthe]
        RP2 -. "Apple Silicon key (HTTPS + token)" .-> Relay[NAC Relay on Mac]
    end
    Client1[Matrix client] <--> HS1
    Client2[Matrix client] <--> HS2
    RP1 <--> Apple[Apple IDS / APNs]
    RP2 <--> Apple

    style macos fill:#f0f4ff,stroke:#4a6fa5,stroke-width:2px,color:#1a1a2e
    style linux fill:#f0fff4,stroke:#4aa56f,stroke-width:2px,color:#1a1a2e
    style Apple fill:#1a1a2e,stroke:#1a1a2e,color:#fff
    style Client1 fill:#fff,stroke:#999,color:#333
    style Client2 fill:#fff,stroke:#999,color:#333
    style Relay fill:#ffe0b2,stroke:#e65100,color:#333
```

### Real-time and backfill

**Real-time messages** flow through Apple's push notification service (APNs) via rustpush and appear in Matrix immediately.

**CloudKit backfill** (optional, off by default) syncs your iMessage history from iCloud on first login. Enable it during `make install` or by setting `cloudkit_backfill: true` in config. When enabled, the login flow will ask for your device PIN to join the iCloud Keychain trust circle, which grants access to Messages in iCloud. The backfill window is controlled by `initial_sync_days` (default: 1 year).

## Management

### macOS

```bash
# View logs
tail -f data/bridge.stdout.log

# Restart (auto-restarts via KeepAlive)
launchctl kickstart -k gui/$(id -u)/com.lrhodin.mautrix-imessage

# Stop until next login
launchctl bootout gui/$(id -u)/com.lrhodin.mautrix-imessage

# Uninstall
make uninstall
```

### Linux

```bash
# If using systemd (from make install / make install-beeper)
systemctl --user status mautrix-imessage
journalctl --user -u mautrix-imessage -f
systemctl --user restart mautrix-imessage

# If running directly
./mautrix-imessage-v2 -c data/config.yaml
```

### NAC Relay (macOS)

```bash
# View logs
tail -f /tmp/nac-relay.log

# Restart
launchctl kickstart -k gui/$(id -u)/com.imessage.nac-relay

# Stop
launchctl bootout gui/$(id -u)/com.imessage.nac-relay
```

## Configuration

Config lives in `data/config.yaml` (generated during install). To reconfigure from scratch:

```bash
rm -rf data
make install    # or make install-beeper
```

Key options:

| Field | Default | What it does |
|-------|---------|-------------|
| `network.cloudkit_backfill` | `false` | Enable CloudKit message history backfill (requires device PIN during login) |
| `network.initial_sync_days` | `365` | How far back to backfill on first login (only when backfill is enabled) |
| `network.displayname_template` | First/Last name | How bridged contacts appear in Matrix |
| `network.preferred_handle` | *(from login)* | Outgoing identity (`tel:+15551234567` or `mailto:user@example.com`) |
| `backfill.max_initial_messages` | `50000` | Max messages to backfill per chat (auto-tuned when backfill enabled) |
| `encryption.allow` | `true` | Enable end-to-bridge encryption |
| `database.type` | `sqlite3-fk-wal` | `sqlite3-fk-wal` or `postgres` |

## Development

```bash
make build      # Build .app bundle (macOS) or binary (Linux)
make rust       # Build Rust library only
make bindings   # Regenerate Go FFI bindings (needs uniffi-bindgen-go)
make clean      # Remove build artifacts
```

### Source layout

```
cmd/mautrix-imessage/        # Entrypoint
pkg/connector/               # bridgev2 connector
  ├── connector.go           #   bridge lifecycle + platform detection
  ├── client.go              #   send/receive/reactions/edits/typing
  ├── login.go               #   Apple ID + external key login flows
  ├── chatdb.go              #   chat.db backfill + contacts (macOS)
  ├── ids.go                 #   identifier/portal ID conversion
  ├── capabilities.go        #   supported features
  └── config.go              #   bridge config schema
pkg/rustpushgo/              # Rust FFI wrapper (uniffi)
rustpush/                    # OpenBubbles/rustpush (vendored)
  └── open-absinthe/         #   NAC emulator (unicorn-engine, cross-platform)
nac-validation/              # Local NAC via AppleAccount.framework (macOS)
tools/
  ├── extract-key/           # Hardware key extraction (run on Mac)
  └── nac-relay/             # NAC validation + contacts + backfill relay (run on Mac)
imessage/                    # macOS chat.db + Contacts reader
```

## License

AGPL-3.0 — see [LICENSE](LICENSE).
