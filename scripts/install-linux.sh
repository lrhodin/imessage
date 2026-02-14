#!/bin/bash
set -euo pipefail

BINARY="$1"
DATA_DIR="$2"

BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"
CONFIG="$DATA_DIR/config.yaml"
REGISTRATION="$DATA_DIR/registration.yaml"

echo ""
echo "═══════════════════════════════════════════════"
echo "  iMessage Bridge Setup (Standalone · Linux)"
echo "═══════════════════════════════════════════════"
echo ""

# ── Generate config ───────────────────────────────────────────
FIRST_RUN=false
mkdir -p "$DATA_DIR"
if [ -f "$CONFIG" ]; then
    echo "✓ Config already exists at $CONFIG"
else
    FIRST_RUN=true

    read -p "Homeserver URL [http://localhost:8008]: " HS_ADDRESS
    HS_ADDRESS="${HS_ADDRESS:-http://localhost:8008}"

    read -p "Homeserver domain (the server_name, e.g. example.com): " HS_DOMAIN
    if [ -z "$HS_DOMAIN" ]; then
        echo "ERROR: Domain is required." >&2
        exit 1
    fi

    read -p "Your Matrix ID [@you:$HS_DOMAIN]: " ADMIN_USER
    ADMIN_USER="${ADMIN_USER:-@you:$HS_DOMAIN}"

    echo ""
    echo "Database:"
    echo "  1) PostgreSQL (recommended)"
    echo "  2) SQLite"
    read -p "Choice [1]: " DB_CHOICE
    DB_CHOICE="${DB_CHOICE:-1}"

    if [ "$DB_CHOICE" = "1" ]; then
        DB_TYPE="postgres"
        read -p "PostgreSQL URI [postgres://localhost/mautrix_imessage?sslmode=disable]: " DB_URI
        DB_URI="${DB_URI:-postgres://localhost/mautrix_imessage?sslmode=disable}"
    else
        DB_TYPE="sqlite3-fk-wal"
        DB_URI="file:$DATA_DIR/mautrix-imessage.db?_txlock=immediate"
    fi

    echo ""

    # Generate example config, then patch in user values
    "$BINARY" -c "$CONFIG" -e 2>/dev/null
    echo "✓ Generated config"

    python3 -c "
import re, sys
text = open('$CONFIG').read()

def patch(text, key, val):
    return re.sub(
        r'^(\s+' + re.escape(key) + r'\s*:)\s*.*$',
        r'\1 ' + val,
        text, count=1, flags=re.MULTILINE
    )

text = patch(text, 'address', '$HS_ADDRESS')
text = patch(text, 'domain', '$HS_DOMAIN')
text = patch(text, 'type', '$DB_TYPE')
text = patch(text, 'uri', '$DB_URI')

lines = text.split('\n')
in_perms = False
for i, line in enumerate(lines):
    if 'permissions:' in line and not line.strip().startswith('#'):
        in_perms = True
        continue
    if in_perms and line.strip() and not line.strip().startswith('#'):
        indent = len(line) - len(line.lstrip())
        lines[i] = ' ' * indent + '\"$ADMIN_USER\": admin'
        break
text = '\n'.join(lines)

open('$CONFIG', 'w').write(text)
"
    echo "✓ Configured: $HS_ADDRESS, $HS_DOMAIN, $ADMIN_USER, $DB_TYPE"
fi

# ── Generate registration ────────────────────────────────────
if [ -f "$REGISTRATION" ]; then
    echo "✓ Registration already exists"
else
    "$BINARY" -c "$CONFIG" -g -r "$REGISTRATION" 2>/dev/null
    echo "✓ Generated registration"
fi

# ── Register with homeserver (first run only) ─────────────────
if [ "$FIRST_RUN" = true ]; then
    REG_PATH="$(cd "$DATA_DIR" && pwd)/registration.yaml"
    echo ""
    echo "┌─────────────────────────────────────────────────┐"
    echo "│  Register with your homeserver:                 │"
    echo "│                                                 │"
    echo "│  Add to homeserver.yaml:                        │"
    echo "│    app_service_config_files:                    │"
    echo "│      - $REG_PATH"
    echo "│                                                 │"
    echo "│  Then restart your homeserver.                  │"
    echo "└─────────────────────────────────────────────────┘"
    echo ""
    read -p "Press Enter once your homeserver is restarted..."
fi

# ── Backfill window (first install only) ──────────────────────
DB_PATH=$(grep 'uri:' "$CONFIG" | head -1 | sed 's/.*uri: file://' | sed 's/?.*//')
if [ -t 0 ] && { [ -z "$DB_PATH" ] || [ ! -f "$DB_PATH" ]; }; then
    CURRENT_DAYS=$(grep 'initial_sync_days:' "$CONFIG" | head -1 | sed 's/.*initial_sync_days: *//')
    [ -z "$CURRENT_DAYS" ] && CURRENT_DAYS=365
    printf "How many days of message history to backfill? [%s]: " "$CURRENT_DAYS"
    read BACKFILL_DAYS
    BACKFILL_DAYS=$(echo "$BACKFILL_DAYS" | tr -dc '0-9')
    [ -z "$BACKFILL_DAYS" ] && BACKFILL_DAYS="$CURRENT_DAYS"
    sed -i "s/initial_sync_days: .*/initial_sync_days: $BACKFILL_DAYS/" "$CONFIG"
    echo "✓ Backfill window set to $BACKFILL_DAYS days"
fi

# ── Check for existing login / prompt if needed ──────────────
DB_URI=$(grep 'uri:' "$CONFIG" | head -1 | sed 's/.*uri: file://' | sed 's/?.*//')
NEEDS_LOGIN=false

if [ -z "$DB_URI" ] || [ ! -f "$DB_URI" ]; then
    NEEDS_LOGIN=true
elif command -v sqlite3 >/dev/null 2>&1; then
    LOGIN_COUNT=$(sqlite3 "$DB_URI" "SELECT count(*) FROM user_login;" 2>/dev/null || echo "0")
    if [ "$LOGIN_COUNT" = "0" ]; then
        NEEDS_LOGIN=true
    fi
else
    # sqlite3 not available — can't verify DB has logins, assume login needed
    NEEDS_LOGIN=true
fi

# Require re-login if keychain trust-circle state is missing.
# This catches upgrades from pre-keychain versions where the device-passcode
# step was never run. If trustedpeers.plist exists with a user_identity, the
# keychain was joined successfully and any transient PCS errors are harmless.
SESSION_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/mautrix-imessage"
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

# ── Install systemd service (optional) ────────────────────────
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
Description=mautrix-imessage bridge
After=network.target

[Service]
Type=simple
WorkingDirectory=$(dirname "$BINARY")
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
Description=mautrix-imessage bridge
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(dirname "$BINARY")
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
echo "  Registration: $REGISTRATION"
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
