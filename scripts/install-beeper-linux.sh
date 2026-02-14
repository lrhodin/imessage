#!/bin/bash
set -euo pipefail

BINARY="$1"
DATA_DIR="$2"

BRIDGE_NAME="${BRIDGE_NAME:-sh-imessage}"

BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"
CONFIG="$DATA_DIR/config.yaml"

# Where we build/cache bbctl
BBCTL_DIR="${BBCTL_DIR:-$HOME/.local/share/mautrix-imessage/bridge-manager}"
BBCTL_REPO="${BBCTL_REPO:-https://github.com/lrhodin/bridge-manager.git}"
BBCTL_BRANCH="${BBCTL_BRANCH:-add-imessage-v2}"

echo ""
echo "═══════════════════════════════════════════════"
echo "  iMessage Bridge Setup (Beeper · Linux)"
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
fi

# ── Check bbctl login ────────────────────────────────────────
WHOAMI_CHECK=$("$BBCTL" whoami 2>&1 || true)
if echo "$WHOAMI_CHECK" | grep -qi "not logged in" || [ -z "$WHOAMI_CHECK" ]; then
    echo ""
    echo "Not logged into Beeper. Running bbctl login..."
    echo ""
    "$BBCTL" login
fi
WHOAMI=$("$BBCTL" whoami 2>&1 || true)
WHOAMI=$(echo "$WHOAMI" | head -1)
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
    echo "⚠  Local config exists but bridge is not registered on server."
    echo "   Removing stale config and database to re-register..."
    rm -f "$CONFIG"
    rm -f "$DATA_DIR"/mautrix-imessage.db*
fi
if [ -f "$CONFIG" ]; then
    echo "✓ Config already exists at $CONFIG"
else
    echo "Generating Beeper config..."
    "$BBCTL" config --type imessage-v2 -o "$CONFIG" "$BRIDGE_NAME"
    # Make DB path absolute — everything lives in DATA_DIR
    sed -i "s|uri: file:mautrix-imessage.db|uri: file:$DATA_DIR/mautrix-imessage.db|" "$CONFIG"
    # Also catch sqlite:// URIs from newer bbctl versions
    sed -i "s|uri: sqlite:mautrix-imessage.db|uri: sqlite:$DATA_DIR/mautrix-imessage.db|" "$CONFIG"
    # Enable unlimited backward backfill (default is 0 which disables it)
    sed -i 's/max_batches: 0$/max_batches: -1/' "$CONFIG"
    # Remove artificial delay between backfill batches (default 20s is way too slow)
    sed -i 's/batch_delay: [0-9]*/batch_delay: 0/' "$CONFIG"
    echo "✓ Config saved to $CONFIG"
fi

# Ensure backward backfill is enabled (default from bbctl is 0 which disables it)
if grep -q 'max_batches: 0$' "$CONFIG" 2>/dev/null; then
    sed -i 's/max_batches: 0$/max_batches: -1/' "$CONFIG"
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
    # DB missing — check if session.json can auto-restore (has hardware_key)
    if [ -f "$SESSION_FILE" ] && grep -q '"hardware_key"' "$SESSION_FILE" 2>/dev/null; then
        echo "✓ No database yet, but session state found — bridge will auto-restore login"
        NEEDS_LOGIN=false
    else
        NEEDS_LOGIN=true
    fi
elif command -v sqlite3 >/dev/null 2>&1; then
    LOGIN_COUNT=$(sqlite3 "$DB_URI" "SELECT count(*) FROM user_login;" 2>/dev/null || echo "0")
    if [ "$LOGIN_COUNT" = "0" ]; then
        # DB exists but no logins — check if auto-restore is possible
        if [ -f "$SESSION_FILE" ] && grep -q '"hardware_key"' "$SESSION_FILE" 2>/dev/null; then
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
            sed -i "s|preferred_handle: .*|preferred_handle: '$SAVED_HANDLE'|" "$CONFIG"
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
    if systemctl --user is-active mautrix-imessage >/dev/null 2>&1; then
        systemctl --user stop mautrix-imessage
    elif systemctl is-active mautrix-imessage >/dev/null 2>&1; then
        sudo systemctl stop mautrix-imessage
    fi

    if [ "${FORCE_CLEAR_STATE:-false}" = "true" ]; then
        echo "Clearing stale local state before login..."
        rm -f "$DB_URI" "$DB_URI-wal" "$DB_URI-shm"
        rm -f "$SESSION_DIR/session.json" "$SESSION_DIR/identity.plist" "$SESSION_DIR/trustedpeers.plist"
    fi

    # Run login from DATA_DIR so that relative paths (state/anisette/)
    # resolve to the same location as when systemd runs the bridge.
    (cd "$DATA_DIR" && "$BINARY" login -c "$CONFIG")
    echo ""
fi

# ── Install / update systemd service ─────────────────────────
# Detect whether systemd user sessions work. In containers (LXC) or when
# running as root, the user instance is often unavailable — fall back to a
# system-level service in that case.
USER_SERVICE_FILE="$HOME/.config/systemd/user/mautrix-imessage.service"
SYSTEM_SERVICE_FILE="/etc/systemd/system/mautrix-imessage.service"

if command -v systemctl >/dev/null 2>&1; then
    if systemctl --user status >/dev/null 2>&1; then
        SYSTEMD_MODE="user"
        SERVICE_FILE="$USER_SERVICE_FILE"
    else
        SYSTEMD_MODE="system"
        SERVICE_FILE="$SYSTEM_SERVICE_FILE"
    fi
else
    SYSTEMD_MODE="none"
    SERVICE_FILE=""
fi

install_systemd_user() {
    # Enable lingering so user services survive SSH session closures
    if command -v loginctl >/dev/null 2>&1 && [ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null)" != "yes" ]; then
        sudo loginctl enable-linger "$USER" 2>/dev/null || true
    fi
    mkdir -p "$(dirname "$USER_SERVICE_FILE")"
    cat > "$USER_SERVICE_FILE" << EOF
[Unit]
Description=mautrix-imessage bridge (Beeper)
After=network.target

[Service]
Type=simple
WorkingDirectory=$DATA_DIR
ExecStart=$BINARY -c $CONFIG
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload
    systemctl --user enable mautrix-imessage
}

install_systemd_system() {
    cat > "$SYSTEM_SERVICE_FILE" << EOF
[Unit]
Description=mautrix-imessage bridge (Beeper)
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$DATA_DIR
ExecStart=$BINARY -c $CONFIG
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable mautrix-imessage
}

if [ "$SYSTEMD_MODE" = "user" ]; then
    if [ -f "$USER_SERVICE_FILE" ]; then
        install_systemd_user
        systemctl --user restart mautrix-imessage
        echo "✓ Bridge restarted"
    else
        echo ""
        read -p "Install as a systemd user service? [Y/n] " answer
        case "$answer" in
            [nN]*) ;;
            *)     install_systemd_user
                   systemctl --user start mautrix-imessage
                   echo "✓ Bridge started (systemd user service installed)" ;;
        esac
    fi
elif [ "$SYSTEMD_MODE" = "system" ]; then
    if [ -f "$SYSTEM_SERVICE_FILE" ]; then
        install_systemd_system
        systemctl restart mautrix-imessage
        echo "✓ Bridge restarted"
    else
        echo ""
        echo "Note: systemd user session not available (container/root)."
        read -p "Install as a system-level systemd service? [Y/n] " answer
        case "$answer" in
            [nN]*) ;;
            *)     install_systemd_system
                   systemctl start mautrix-imessage
                   echo "✓ Bridge started (system service installed)" ;;
        esac
    fi
fi

echo ""
echo "═══════════════════════════════════════════════"
echo "  Setup Complete"
echo "═══════════════════════════════════════════════"
echo ""
echo "  Binary: $BINARY"
echo "  Config: $CONFIG"
echo ""
if [ "$SYSTEMD_MODE" = "user" ] && [ -f "$USER_SERVICE_FILE" ]; then
    echo "  Status:  systemctl --user status mautrix-imessage"
    echo "  Logs:    journalctl --user -u mautrix-imessage -f"
    echo "  Stop:    systemctl --user stop mautrix-imessage"
    echo "  Restart: systemctl --user restart mautrix-imessage"
elif [ "$SYSTEMD_MODE" = "system" ] && [ -f "$SYSTEM_SERVICE_FILE" ]; then
    echo "  Status:  systemctl status mautrix-imessage"
    echo "  Logs:    journalctl -u mautrix-imessage -f"
    echo "  Stop:    systemctl stop mautrix-imessage"
    echo "  Restart: systemctl restart mautrix-imessage"
else
    echo "  Run manually:"
    echo "    cd $(dirname "$CONFIG") && $BINARY -c $CONFIG"
fi
echo ""
