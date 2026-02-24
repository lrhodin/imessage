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
    # iMessage CloudKit chats can have tens of thousands of messages.
    # Deliver all history in one forward batch to avoid DAG fragmentation.
    sed -i 's/max_initial_messages: [0-9]*/max_initial_messages: 2147483647/' "$CONFIG"
    sed -i 's/max_catchup_messages: [0-9]*/max_catchup_messages: 5000/' "$CONFIG"
    sed -i 's/batch_size: [0-9]*/batch_size: 10000/' "$CONFIG"
    sed -i 's/max_batches: 0$/max_batches: -1/' "$CONFIG"
    # Use 1s between batches — fast enough for backfill, prevents idle hot-loop
    sed -i 's/batch_delay: [0-9]*/batch_delay: 1/' "$CONFIG"
    echo "✓ Configured: $HS_ADDRESS, $HS_DOMAIN, $ADMIN_USER, $DB_TYPE"
fi

# ── CloudKit backfill toggle (runs every time) ────────────────
CURRENT_BACKFILL=$(grep 'cloudkit_backfill:' "$CONFIG" 2>/dev/null | head -1 | sed 's/.*cloudkit_backfill: *//' || true)
if [ -t 0 ]; then
    echo ""
    echo "CloudKit Backfill:"
    echo "  When enabled, the bridge will sync your iMessage history from iCloud."
    echo "  This requires entering your device PIN during login to join the iCloud Keychain."
    echo "  When disabled, only new real-time messages are bridged (no PIN needed)."
    echo ""
    if [ "$CURRENT_BACKFILL" = "true" ]; then
        read -p "Enable CloudKit message history backfill? [Y/n]: " ENABLE_BACKFILL
        case "$ENABLE_BACKFILL" in
            [nN]*) ENABLE_BACKFILL=false ;;
            *)     ENABLE_BACKFILL=true ;;
        esac
    else
        read -p "Enable CloudKit message history backfill? [y/N]: " ENABLE_BACKFILL
        case "$ENABLE_BACKFILL" in
            [yY]*) ENABLE_BACKFILL=true ;;
            *)     ENABLE_BACKFILL=false ;;
        esac
    fi
    sed -i "s/cloudkit_backfill: .*/cloudkit_backfill: $ENABLE_BACKFILL/" "$CONFIG"
    if [ "$ENABLE_BACKFILL" = "true" ]; then
        echo "✓ CloudKit backfill enabled — you'll be asked for your device PIN during login"
        echo ""
        echo "IMPORTANT: Before starting the bridge, sync your latest messages to iCloud"
        echo "from an Apple device (iPhone, iPad, or Mac) to ensure all recent messages"
        echo "are available for backfill."
        echo ""
        read -p "Have you synced your Apple device to iCloud? [y/N]: " ICLOUD_SYNCED
        case "$ICLOUD_SYNCED" in
            [yY]*) echo "✓ Great — backfill will include your latest messages" ;;
            *)     echo "⚠ Please sync your Apple device to iCloud before starting the bridge" ;;
        esac
    else
        echo "✓ CloudKit backfill disabled — real-time messages only, no PIN needed"
    fi
fi

# ── Max initial messages (new database + CloudKit backfill + interactive) ──
CURRENT_BACKFILL=$(grep 'cloudkit_backfill:' "$CONFIG" 2>/dev/null | head -1 | sed 's/.*cloudkit_backfill: *//' || true)
if [ "$CURRENT_BACKFILL" = "true" ] && [ -t 0 ]; then
    DB_PATH=$(grep 'uri:' "$CONFIG" | head -1 | sed 's/.*uri: file://' | sed 's/?.*//')
    if [ -z "$DB_PATH" ] || [ ! -f "$DB_PATH" ]; then
        echo ""
        echo "By default, all messages per chat will be backfilled."
        echo "If you choose to limit, the minimum is 100 messages per chat."
        read -p "Would you like to limit the number of messages? [y/N]: " LIMIT_MSGS
        case "$LIMIT_MSGS" in
            [yY]*)
                while true; do
                    read -p "Max messages per chat (minimum 100): " MAX_MSGS
                    MAX_MSGS=$(echo "$MAX_MSGS" | tr -dc '0-9')
                    if [ -n "$MAX_MSGS" ] && [ "$MAX_MSGS" -ge 100 ] 2>/dev/null; then
                        break
                    fi
                    echo "Minimum is 100. Please enter a value of 100 or more."
                done
                sed -i "s/max_initial_messages: [0-9]*/max_initial_messages: $MAX_MSGS/" "$CONFIG"
                # Disable backward backfill so the cap is the final word on message count
                sed -i 's/max_batches: -1$/max_batches: 0/' "$CONFIG"
                echo "✓ Max initial messages set to $MAX_MSGS per chat"
                ;;
            *)
                echo "✓ Backfilling all messages"
                ;;
        esac
    fi
fi

# Tune backfill settings when CloudKit backfill is enabled
CURRENT_BACKFILL=$(grep 'cloudkit_backfill:' "$CONFIG" 2>/dev/null | head -1 | sed 's/.*cloudkit_backfill: *//' || true)
if [ "$CURRENT_BACKFILL" = "true" ]; then
    PATCHED_BACKFILL=false
    # Only enable unlimited backward backfill when max_initial is uncapped.
    # When the user caps max_initial_messages, max_batches stays at 0 so the
    # bridge won't backfill beyond the cap.
    if grep -q 'max_initial_messages: 2147483647' "$CONFIG" 2>/dev/null; then
        if grep -q 'max_batches: 0$' "$CONFIG" 2>/dev/null; then
            sed -i 's/max_batches: 0$/max_batches: -1/' "$CONFIG"
            PATCHED_BACKFILL=true
        fi
    fi
    if grep -q 'max_initial_messages: [0-9]\{1,2\}$' "$CONFIG" 2>/dev/null; then
        sed -i 's/max_initial_messages: [0-9]*/max_initial_messages: 2147483647/' "$CONFIG"
        PATCHED_BACKFILL=true
    fi
    if grep -q 'max_catchup_messages: [0-9]\{1,3\}$' "$CONFIG" 2>/dev/null; then
        sed -i 's/max_catchup_messages: [0-9]*/max_catchup_messages: 5000/' "$CONFIG"
        PATCHED_BACKFILL=true
    fi
    if grep -q 'batch_size: [0-9]\{1,3\}$' "$CONFIG" 2>/dev/null; then
        sed -i 's/batch_size: [0-9]*/batch_size: 10000/' "$CONFIG"
        PATCHED_BACKFILL=true
    fi
    if grep -q 'batch_delay: 0$' "$CONFIG" 2>/dev/null; then
        sed -i 's/batch_delay: 0$/batch_delay: 1/' "$CONFIG"
        PATCHED_BACKFILL=true
    fi
    if [ "$PATCHED_BACKFILL" = true ]; then
        echo "✓ Updated backfill settings (max_initial=unlimited, batch_size=10000, max_batches=-1)"
    fi
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

# ── Restore CardDAV config from backup ────────────────────────
CARDDAV_BACKUP="$DATA_DIR/.carddav-config"
if [ -f "$CARDDAV_BACKUP" ]; then
    CHECK_EMAIL=$(grep 'email:' "$CONFIG" 2>/dev/null | head -1 | sed "s/.*email: *//;s/['\"]//g" | tr -d ' ' || true)
    if [ -z "$CHECK_EMAIL" ]; then
        source "$CARDDAV_BACKUP"
        if [ -n "${SAVED_CARDDAV_EMAIL:-}" ] && [ -n "${SAVED_CARDDAV_ENC:-}" ]; then
            python3 -c "
import re
text = open('$CONFIG').read()
def patch(text, key, val):
    return re.sub(r'^(\s+' + re.escape(key) + r'\s*:)\s*.*$', r'\1 ' + val, text, count=1, flags=re.MULTILINE)
text = patch(text, 'email', '\"$SAVED_CARDDAV_EMAIL\"')
text = patch(text, 'url', '\"$SAVED_CARDDAV_URL\"')
text = patch(text, 'username', '\"$SAVED_CARDDAV_USERNAME\"')
text = patch(text, 'password_encrypted', '\"$SAVED_CARDDAV_ENC\"')
open('$CONFIG', 'w').write(text)
"
            echo "✓ Restored CardDAV config: $SAVED_CARDDAV_EMAIL"
        fi
    fi
fi

# ── Contact source (runs every time, can reconfigure) ─────────
if [ -t 0 ]; then
    CURRENT_CARDDAV_EMAIL=$(grep 'email:' "$CONFIG" 2>/dev/null | head -1 | sed "s/.*email: *//;s/['\"]//g" | tr -d ' ' || true)
    CONFIGURE_CARDDAV=false

    if [ -n "$CURRENT_CARDDAV_EMAIL" ] && [ "$CURRENT_CARDDAV_EMAIL" != '""' ]; then
        echo ""
        echo "Contact source: External CardDAV ($CURRENT_CARDDAV_EMAIL)"
        read -p "Change contact provider? [y/N]: " CHANGE_CONTACTS
        case "$CHANGE_CONTACTS" in
            [yY]*) CONFIGURE_CARDDAV=true ;;
        esac
    else
        echo ""
        echo "Contact source (for resolving names in chats):"
        echo "  1) iCloud (default — uses your Apple ID)"
        echo "  2) Google Contacts (requires app password)"
        echo "  3) Fastmail"
        echo "  4) Nextcloud"
        echo "  5) Other CardDAV server"
        read -p "Choice [1]: " CONTACT_CHOICE
        CONTACT_CHOICE="${CONTACT_CHOICE:-1}"
        if [ "$CONTACT_CHOICE" != "1" ]; then
            CONFIGURE_CARDDAV=true
        fi
    fi

    if [ "$CONFIGURE_CARDDAV" = true ]; then
        # Show menu if we're changing from an existing provider
        if [ -n "$CURRENT_CARDDAV_EMAIL" ] && [ "$CURRENT_CARDDAV_EMAIL" != '""' ]; then
            echo ""
            echo "  1) iCloud (remove external CardDAV)"
            echo "  2) Google Contacts (requires app password)"
            echo "  3) Fastmail"
            echo "  4) Nextcloud"
            echo "  5) Other CardDAV server"
            read -p "Choice: " CONTACT_CHOICE
        fi

        CARDDAV_EMAIL=""
        CARDDAV_PASSWORD=""
        CARDDAV_USERNAME=""
        CARDDAV_URL=""

        if [ "${CONTACT_CHOICE:-}" = "1" ]; then
            # Remove external CardDAV — clear the config fields
            python3 -c "
import re
text = open('$CONFIG').read()
def patch(text, key, val):
    return re.sub(r'^(\s+' + re.escape(key) + r'\s*:)\s*.*$', r'\1 ' + val, text, count=1, flags=re.MULTILINE)
text = patch(text, 'email', '\"\"')
text = patch(text, 'url', '\"\"')
text = patch(text, 'username', '\"\"')
text = patch(text, 'password_encrypted', '\"\"')
open('$CONFIG', 'w').write(text)
"
            rm -f "$CARDDAV_BACKUP"
            echo "✓ Switched to iCloud contacts"
        elif [ -n "${CONTACT_CHOICE:-}" ]; then
            read -p "Email address: " CARDDAV_EMAIL
            if [ -z "$CARDDAV_EMAIL" ]; then
                echo "ERROR: Email is required." >&2
                exit 1
            fi

            case "$CONTACT_CHOICE" in
                2)
                    CARDDAV_URL="https://www.googleapis.com/carddav/v1/principals/$CARDDAV_EMAIL/lists/default/"
                    echo "  Note: Use a Google App Password, without spaces (https://myaccount.google.com/apppasswords)"
                    ;;
                3)
                    CARDDAV_URL="https://carddav.fastmail.com/dav/addressbooks/user/$CARDDAV_EMAIL/Default/"
                    echo "  Note: Use a Fastmail App Password (Settings → Privacy & Security → App Passwords)"
                    ;;
                4)
                    read -p "Nextcloud server URL (e.g. https://cloud.example.com): " NC_SERVER
                    NC_SERVER="${NC_SERVER%/}"
                    CARDDAV_URL="$NC_SERVER/remote.php/dav"
                    ;;
                5)
                    read -p "CardDAV server URL: " CARDDAV_URL
                    if [ -z "$CARDDAV_URL" ]; then
                        echo "ERROR: URL is required." >&2
                        exit 1
                    fi
                    ;;
            esac

            read -p "Username (leave empty to use email): " CARDDAV_USERNAME
            read -s -p "App password: " CARDDAV_PASSWORD
            echo ""
            if [ -z "$CARDDAV_PASSWORD" ]; then
                echo "ERROR: Password is required." >&2
                exit 1
            fi

            # Encrypt password and patch config
            CARDDAV_ARGS="--email $CARDDAV_EMAIL --password $CARDDAV_PASSWORD --url $CARDDAV_URL"
            if [ -n "$CARDDAV_USERNAME" ]; then
                CARDDAV_ARGS="$CARDDAV_ARGS --username $CARDDAV_USERNAME"
            fi
            CARDDAV_JSON=$("$BINARY" carddav-setup $CARDDAV_ARGS 2>/dev/null) || CARDDAV_JSON=""

            if [ -z "$CARDDAV_JSON" ]; then
                echo "⚠  CardDAV setup failed. You can configure it manually in $CONFIG"
            else
                CARDDAV_RESOLVED_URL=$(echo "$CARDDAV_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['url'])")
                CARDDAV_ENC=$(echo "$CARDDAV_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['password_encrypted'])")
                EFFECTIVE_USERNAME="${CARDDAV_USERNAME:-$CARDDAV_EMAIL}"
                python3 -c "
import re
text = open('$CONFIG').read()
def patch(text, key, val):
    return re.sub(r'^(\s+' + re.escape(key) + r'\s*:)\s*.*$', r'\1 ' + val, text, count=1, flags=re.MULTILINE)
text = patch(text, 'email', '\"$CARDDAV_EMAIL\"')
text = patch(text, 'url', '\"$CARDDAV_RESOLVED_URL\"')
text = patch(text, 'username', '\"$EFFECTIVE_USERNAME\"')
text = patch(text, 'password_encrypted', '\"$CARDDAV_ENC\"')
open('$CONFIG', 'w').write(text)
"
                echo "✓ CardDAV configured: $CARDDAV_EMAIL → $CARDDAV_RESOLVED_URL"
                cat > "$CARDDAV_BACKUP" << BKEOF
SAVED_CARDDAV_EMAIL="$CARDDAV_EMAIL"
SAVED_CARDDAV_URL="$CARDDAV_RESOLVED_URL"
SAVED_CARDDAV_USERNAME="$EFFECTIVE_USERNAME"
SAVED_CARDDAV_ENC="$CARDDAV_ENC"
BKEOF
            fi
        fi
    fi
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

# Require re-login if keychain trust-circle state is missing (CloudKit only).
# This catches upgrades from pre-keychain versions where the device-passcode
# step was never run. Each user gets a per-DSID trustedpeers file; check all
# of them. Only applies when cloudkit_backfill is enabled in the config.
SESSION_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/mautrix-imessage"
FORCE_CLEAR_STATE=false
CLOUDKIT_ENABLED=$(grep 'cloudkit_backfill:' "$CONFIG" 2>/dev/null | head -1 | sed 's/.*cloudkit_backfill: *//' || true)
if [ "$NEEDS_LOGIN" = "false" ] && [ "$CLOUDKIT_ENABLED" = "true" ]; then
    HAS_CLIQUE=false
    for tp_file in "$SESSION_DIR"/trustedpeers_*.plist; do
        if [ -f "$tp_file" ] && grep -q "<key>userIdentity</key>\|<key>user_identity</key>" "$tp_file" 2>/dev/null; then
            HAS_CLIQUE=true
            break
        fi
    done

    if [ "$HAS_CLIQUE" != "true" ]; then
        echo "⚠ Existing login found, but keychain trust-circle is not initialized."
        echo "  Forcing fresh login so device-passcode step can run."
        NEEDS_LOGIN=true
        FORCE_CLEAR_STATE=true
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
        rm -f "$SESSION_DIR"/trustedpeers_*.plist
    fi

    # Run login from DATA_DIR so that relative paths (state/anisette/)
    # resolve to the same location as when systemd runs the bridge.
    (cd "$DATA_DIR" && "$BINARY" login -c "$CONFIG")
    echo ""
fi

# ── Preferred handle ──────────────────────────────────────────
# The handle is set during the login flow and stored in the database.
# To change it after login, use the !im set-handle command in Matrix.
CURRENT_HANDLE=""
if command -v sqlite3 >/dev/null 2>&1 && [ -n "${DB_URI:-}" ] && [ -f "${DB_URI:-}" ]; then
    CURRENT_HANDLE=$(sqlite3 "$DB_URI" "SELECT json_extract(metadata, '$.preferred_handle') FROM user_login LIMIT 1;" 2>/dev/null || true)
fi
if [ -n "${CURRENT_HANDLE:-}" ]; then
    echo "✓ Preferred handle: $CURRENT_HANDLE"
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
