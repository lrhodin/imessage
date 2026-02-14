#!/bin/bash
set -euo pipefail

BINARY="$1"
DATA_DIR="$2"
BUNDLE_ID="$3"

BRIDGE_NAME="${BRIDGE_NAME:-sh-imessage}"

BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"
CONFIG="$DATA_DIR/config.yaml"
PLIST="$HOME/Library/LaunchAgents/$BUNDLE_ID.plist"

# Where we build/cache bbctl
BBCTL_DIR="${BBCTL_DIR:-$HOME/.local/share/mautrix-imessage/bridge-manager}"
BBCTL_REPO="${BBCTL_REPO:-https://github.com/lrhodin/bridge-manager.git}"
BBCTL_BRANCH="${BBCTL_BRANCH:-add-imessage-v2}"

echo ""
echo "═══════════════════════════════════════════════"
echo "  iMessage Bridge Setup (Beeper)"
echo "═══════════════════════════════════════════════"
echo ""

# ── Build bbctl from source ───────────────────────────────────
BBCTL="$BBCTL_DIR/bbctl"

build_bbctl() {
    echo "Building bbctl..."
    mkdir -p "$(dirname "$BBCTL_DIR")"
    if [ -d "$BBCTL_DIR" ]; then
        cd "$BBCTL_DIR"
        git fetch --quiet origin
        git checkout --quiet "$BBCTL_BRANCH"
        git reset --hard --quiet "origin/$BBCTL_BRANCH"
    else
        git clone --quiet --branch "$BBCTL_BRANCH" "$BBCTL_REPO" "$BBCTL_DIR"
        cd "$BBCTL_DIR"
    fi
    go build -o bbctl ./cmd/bbctl/ 2>&1
    cd - >/dev/null
    echo "✓ Built bbctl"
}

if [ ! -x "$BBCTL" ]; then
    build_bbctl
else
    echo "✓ Found bbctl: $BBCTL"
    # Update if repo has changes
    if [ -d "$BBCTL_DIR/.git" ]; then
        cd "$BBCTL_DIR"
        git fetch --quiet origin 2>/dev/null || true
        LOCAL=$(git rev-parse HEAD 2>/dev/null)
        REMOTE=$(git rev-parse "origin/$BBCTL_BRANCH" 2>/dev/null || echo "$LOCAL")
        cd - >/dev/null
        if [ "$LOCAL" != "$REMOTE" ]; then
            echo "  Updating bbctl..."
            build_bbctl
        fi
    fi
fi

# ── Check bbctl login ────────────────────────────────────────
if ! "$BBCTL" whoami >/dev/null 2>&1 || "$BBCTL" whoami 2>&1 | grep -qi "not logged in"; then
    echo ""
    echo "Not logged into Beeper. Running bbctl login..."
    echo ""
    "$BBCTL" login
fi
WHOAMI=$("$BBCTL" whoami 2>&1 | head -1 || true)
echo "✓ Logged in: $WHOAMI"

# ── Check for existing bridge registration ────────────────────
# If the bridge is already registered on the server but we're about to
# generate a fresh config (no local config file), the old registration's
# rooms would be orphaned.  Delete it first so the server cleans up rooms.
EXISTING_BRIDGE=$("$BBCTL" whoami 2>&1 | grep "^\s*$BRIDGE_NAME " || true)
if [ -n "$EXISTING_BRIDGE" ] && [ ! -f "$CONFIG" ]; then
    echo ""
    echo "⚠  Found existing '$BRIDGE_NAME' registration on server but no local config."
    echo "   Deleting old registration to avoid orphaned rooms..."
    "$BBCTL" delete "$BRIDGE_NAME"
    echo "✓ Old registration cleaned up"
fi

# ── Generate config via bbctl ─────────────────────────────────
mkdir -p "$DATA_DIR"
if [ -f "$CONFIG" ] && [ -z "$EXISTING_BRIDGE" ]; then
    # Config exists locally but bridge isn't registered on server (e.g. bbctl
    # delete was run manually).  The stale config has an invalid as_token and
    # the DB references rooms that no longer exist.
    #
    # Double-check by retrying bbctl whoami — a transient network error or the
    # bridge restarting can cause the first check to return empty even though
    # the registration is fine.
    echo "⚠  Bridge not found in bbctl whoami — retrying in 3s to rule out transient error..."
    sleep 3
    EXISTING_BRIDGE=$("$BBCTL" whoami 2>&1 | grep "^\s*$BRIDGE_NAME " || true)
    if [ -z "$EXISTING_BRIDGE" ]; then
        echo "⚠  Local config exists but bridge is not registered on server."
        echo "   Removing stale config and database to re-register..."
        rm -f "$CONFIG"
        DB_DIR="$(cd "$DATA_DIR" && pwd)"
        rm -f "$DB_DIR"/mautrix-imessage.db*
    else
        echo "✓ Bridge found on retry — keeping existing config and database"
    fi
fi
if [ -f "$CONFIG" ]; then
    echo "✓ Config already exists at $CONFIG"
    echo "  Delete it to regenerate from Beeper."
else
    echo "Generating Beeper config..."
    "$BBCTL" config --type imessage-v2 -o "$CONFIG" "$BRIDGE_NAME"
    # Make DB path absolute so it doesn't depend on working directory
    DATA_ABS_TMP="$(cd "$DATA_DIR" && pwd)"
    sed -i '' "s|uri: file:mautrix-imessage.db|uri: file:$DATA_ABS_TMP/mautrix-imessage.db|" "$CONFIG"
    # Enable unlimited backward backfill (default is 0 which disables it)
    sed -i '' 's/max_batches: 0$/max_batches: -1/' "$CONFIG"
    # Remove artificial delay between backfill batches (default 20s is way too slow)
    sed -i '' 's/batch_delay: [0-9]*/batch_delay: 0/' "$CONFIG"

    echo "✓ Config saved to $CONFIG"
fi

# Ensure backward backfill is enabled (default from bbctl is 0 which disables it)
if grep -q 'max_batches: 0$' "$CONFIG" 2>/dev/null; then
    sed -i '' 's/max_batches: 0$/max_batches: -1/' "$CONFIG"

    echo "✓ Enabled backward backfill (max_batches: -1)"
fi

if ! grep -q "beeper" "$CONFIG" 2>/dev/null; then
    echo ""
    echo "WARNING: Config doesn't appear to contain Beeper details."
    echo "  Try: rm $CONFIG && re-run make install-beeper"
    echo ""
    exit 1
fi

# (initial_sync_days is unused — cloud sync fetches all available history)

# ── Check for existing login / prompt if needed ──────────────
DB_URI=$(grep 'uri:' "$CONFIG" | head -1 | sed 's/.*uri: file://' | sed 's/?.*//')
NEEDS_LOGIN=false

SESSION_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/mautrix-imessage"
SESSION_FILE="$SESSION_DIR/session.json"
if [ -z "$DB_URI" ] || [ ! -f "$DB_URI" ]; then
    # DB missing — check if session.json can auto-restore (has hardware_key for Linux, or macOS)
    if [ -f "$SESSION_FILE" ] && { grep -q '"hardware_key"' "$SESSION_FILE" 2>/dev/null || [ "$(uname -s)" = "Darwin" ]; }; then
        echo "✓ No database yet, but session state found — bridge will auto-restore login"
        NEEDS_LOGIN=false
    else
        NEEDS_LOGIN=true
    fi
elif command -v sqlite3 >/dev/null 2>&1; then
    LOGIN_COUNT=$(sqlite3 "$DB_URI" "SELECT count(*) FROM user_login;" 2>/dev/null || echo "0")
    if [ "$LOGIN_COUNT" = "0" ]; then
        if [ -f "$SESSION_FILE" ] && { grep -q '"hardware_key"' "$SESSION_FILE" 2>/dev/null || [ "$(uname -s)" = "Darwin" ]; }; then
            echo "✓ No login in database, but session state found — bridge will auto-restore"
            NEEDS_LOGIN=false
        else
            NEEDS_LOGIN=true
        fi
    fi
else
    NEEDS_LOGIN=true
fi

# Require re-login if keychain trust-circle state is missing.
# This catches upgrades from pre-keychain versions where the device-passcode
# step was never run. If trustedpeers.plist exists with a user_identity, the
# keychain was joined successfully and any transient PCS errors are harmless.
TRUSTEDPEERS_FILE="$SESSION_DIR/trustedpeers.plist"
FORCE_CLEAR_STATE=false
if [ "$NEEDS_LOGIN" = "false" ]; then
    HAS_CLIQUE=false
    if [ -f "$TRUSTEDPEERS_FILE" ]; then
        if grep -q "<key>userIdentity</key>\|<key>user_identity</key>" "$TRUSTEDPEERS_FILE" 2>/dev/null; then
            HAS_CLIQUE=true
        fi
    fi

    if [ "$HAS_CLIQUE" != "true" ]; then
        echo "⚠ Existing login found, but keychain trust-circle is not initialized."
        echo "  Forcing fresh login so device-passcode step can run."
        NEEDS_LOGIN=true
        FORCE_CLEAR_STATE=true
    fi
fi

# Check if backup session state can be restored — validates that session.json
# and keystore.plist exist AND that the keystore has the referenced keys.
if [ "$NEEDS_LOGIN" = "true" ] && [ "${FORCE_CLEAR_STATE:-false}" != "true" ] && "$BINARY" check-restore 2>/dev/null; then
    echo "✓ Backup session state validated — bridge will auto-restore login"
    NEEDS_LOGIN=false
fi

# ── Restore preferred_handle from DB or session backup ────────
if [ "$NEEDS_LOGIN" = "false" ]; then
    CURRENT_HANDLE=$(grep 'preferred_handle:' "$CONFIG" 2>/dev/null | head -1 | sed "s/.*preferred_handle: *//;s/['\"]//g" || true)
    if [ -z "$CURRENT_HANDLE" ]; then
        # Try DB first
        SAVED_HANDLE=""
        if command -v sqlite3 >/dev/null 2>&1 && [ -n "$DB_URI" ] && [ -f "$DB_URI" ]; then
            SAVED_HANDLE=$(sqlite3 "$DB_URI" "SELECT json_extract(metadata, '$.preferred_handle') FROM user_login LIMIT 1;" 2>/dev/null || true)
        fi
        # Fall back to session backup file
        if [ -z "$SAVED_HANDLE" ]; then
            SESSION_FILE="${XDG_DATA_HOME:-$HOME/.local/share}/mautrix-imessage/session.json"
            if [ -f "$SESSION_FILE" ] && command -v python3 >/dev/null 2>&1; then
                SAVED_HANDLE=$(python3 -c "import json; print(json.load(open('$SESSION_FILE')).get('preferred_handle',''))" 2>/dev/null || true)
            fi
        fi
        if [ -n "$SAVED_HANDLE" ]; then
            sed -i '' "s|preferred_handle: .*|preferred_handle: '$SAVED_HANDLE'|" "$CONFIG"
            echo "✓ Restored preferred handle: $SAVED_HANDLE"
        fi
    fi
fi

if [ "$NEEDS_LOGIN" = "true" ]; then
    echo ""
    echo "┌─────────────────────────────────────────────────┐"
    echo "│  No valid iMessage login found — starting login │"
    echo "└─────────────────────────────────────────────────┘"
    echo ""
    # Stop the bridge if running (otherwise it holds the DB lock)
    GUI_DOMAIN_TMP="gui/$(id -u)"
    launchctl bootout "$GUI_DOMAIN_TMP/$BUNDLE_ID" 2>/dev/null || true

    if [ "${FORCE_CLEAR_STATE:-false}" = "true" ]; then
        echo "Clearing stale local state before login..."
        rm -f "$DB_URI" "$DB_URI-wal" "$DB_URI-shm"
        rm -f "$SESSION_DIR/session.json" "$SESSION_DIR/identity.plist" "$SESSION_DIR/trustedpeers.plist"
    fi

    # Run login from the data directory so the keystore (state/keystore.plist)
    # is written to the same location the launchd service will read from.
    (cd "$DATA_DIR" && "$BINARY" login -c "$CONFIG")
    echo ""
fi

# ── Install LaunchAgent ───────────────────────────────────────
CONFIG_ABS="$(cd "$DATA_DIR" && pwd)/config.yaml"
DATA_ABS="$(cd "$DATA_DIR" && pwd)"
LOG_OUT="$DATA_ABS/bridge.stdout.log"
LOG_ERR="$DATA_ABS/bridge.stderr.log"

mkdir -p "$(dirname "$PLIST")"
GUI_DOMAIN="gui/$(id -u)"
launchctl bootout "$GUI_DOMAIN/$BUNDLE_ID" 2>/dev/null || true
launchctl unload "$PLIST" 2>/dev/null || true

cat > "$PLIST" << PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$BUNDLE_ID</string>
    <key>ProgramArguments</key>
    <array>
        <string>$BINARY</string>
        <string>-c</string>
        <string>$CONFIG_ABS</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$DATA_ABS</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>Crashed</key>
        <true/>
    </dict>
    <key>StandardOutPath</key>
    <string>$LOG_OUT</string>
    <key>StandardErrorPath</key>
    <string>$LOG_ERR</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin</string>
        <key>CGO_CFLAGS</key>
        <string>-I/opt/homebrew/include</string>
        <key>CGO_LDFLAGS</key>
        <string>-L/opt/homebrew/lib</string>
    </dict>
</dict>
</plist>
PLIST_EOF

if ! launchctl bootstrap "$GUI_DOMAIN" "$PLIST" 2>/dev/null; then
    if ! launchctl load "$PLIST" 2>/dev/null; then
        echo ""
        echo "⚠  LaunchAgent failed to load. You can run the bridge manually:"
        echo "   $BINARY -c $CONFIG_ABS"
        echo ""
        echo "   This is a known issue on macOS 13 (Ventura). Try:"
        echo "   1. Remove and re-add the .app in Full Disk Access"
        echo "   2. Re-run: make install-beeper"
        echo ""
    fi
fi
echo "✓ Bridge started (LaunchAgent installed)"
echo ""

# ── Wait for bridge to connect ────────────────────────────────
DOMAIN=$(grep '^\s*domain:' "$CONFIG" | head -1 | awk '{print $2}' || true)
DOMAIN="${DOMAIN:-beeper.local}"

echo "Waiting for bridge to start..."
for i in $(seq 1 15); do
    if grep -q "Bridge started\|UNCONFIGURED\|Backfill queue starting" "$LOG_OUT" 2>/dev/null; then
        echo "✓ Bridge is running"
        echo ""
        echo "═══════════════════════════════════════════════"
        echo "  Setup Complete"
        echo "═══════════════════════════════════════════════"
        echo ""
        echo "  Logs:    tail -f $LOG_OUT"
        echo "  Stop:    launchctl bootout $GUI_DOMAIN/$BUNDLE_ID"
        echo "  Start:   launchctl bootstrap $GUI_DOMAIN $PLIST"
        echo "  Restart: launchctl kickstart -k $GUI_DOMAIN/$BUNDLE_ID"
        exit 0
    fi
    sleep 1
done

echo ""
echo "Bridge is starting up (check logs for status):"
echo "  tail -f $LOG_OUT"
echo ""
echo "Once running, DM @${BRIDGE_NAME}bot:$DOMAIN and send: login"
