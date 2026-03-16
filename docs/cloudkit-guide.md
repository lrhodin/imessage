# CloudKit Integration Guide

## Overview

This bridge uses Apple's CloudKit to backfill historical iMessage conversations. Real-time messages are delivered via APNs push (`com.apple.madrid`), so CloudKit is only needed for fetching message history — not for ongoing sync.

This document explains how CloudKit works, how we use it, and the design decisions behind our approach.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  Go bridge                       │
│                                                  │
│  ┌──────────────┐    ┌────────────────────────┐  │
│  │ Real-time    │    │ CloudKit backfill      │  │
│  │ APNs push    │    │ (one-shot on connect)  │  │
│  │              │    │                        │  │
│  │ com.apple.   │    │ chatManateeZone        │  │
│  │ madrid       │    │ messageManateeZone     │  │
│  └──────┬───────┘    └───────────┬────────────┘  │
│         │                        │               │
│         ▼                        ▼               │
│  ┌──────────────────────────────────────────┐    │
│  │           Matrix bridge rooms            │    │
│  └──────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
```

**Two paths, one purpose:**

| Path | Source | When | What |
|------|--------|------|------|
| **Real-time** | APNs push on `com.apple.madrid` | Always running | Incoming/outgoing messages as they happen |
| **Backfill** | CloudKit Messages in iCloud | On connect only | Historical messages from before the bridge existed |

## How CloudKit Works (Apple's Model)

Apple's CloudKit stores iMessage data in the user's **private database** under the `com.apple.messages.cloud` container. Messages in iCloud uses three record zones:

| Zone | Record Type | Contents |
|------|-------------|----------|
| `chatManateeZone` | `chatEncryptedv2` | Chat metadata: participants, group name, style, service |
| `messageManateeZone` | `MessageEncryptedV3` | Message content: text, sender, timestamp, flags |
| `attachmentManateeZone` | `attachment` | File attachments (MMCS blobs) |

All records are end-to-end encrypted using **PCS (Protected CloudStorage)** keys derived from the user's iCloud Keychain. The bridge decrypts these via the `rustpush` Rust library.

### Zone Change Tokens

CloudKit's sync model is built around **server change tokens** (Apple calls them `CKServerChangeToken`). The key API is `CKFetchRecordZoneChangesOperation`:

1. Pass `nil` token → get **all** records in the zone's history
2. Pass a stored token → get only records that **changed since** that token
3. Each response includes a new token to store for next time
4. A `status == 3` (or `moreComing == false`) signals the end of the current changeset

From Apple's docs:

> "Use this operation to fetch record changes in one or more record zones. You provide a configuration object for each record zone to query for changes. The configuration contains a server change token, which is an opaque pointer to a specific change in the zone's history. CloudKit returns only the changes that occur after that point."

Tokens are opaque, zone-specific, and safe to persist to disk.

### What Apple Says About Polling

Apple explicitly recommends **against** periodic polling:

> "It's not necessary to perform a fetch each time your app launches, or to schedule fetches at regular intervals."

The intended pattern is:
1. Fetch all changes on first launch (token = nil)
2. Subscribe to zone changes via `CKRecordZoneSubscription`
3. On receipt of a silent push notification, fetch changes using the stored token

We don't implement subscriptions because our APNs real-time path already delivers messages. CloudKit sync is redundant for ongoing operation.

## Our Implementation

### Files

| File | Purpose |
|------|---------|
| `pkg/connector/sync_controller.go` | Orchestrates CloudKit backfill on connect |
| `pkg/connector/cloud_backfill_store.go` | SQLite storage for synced chats/messages and zone tokens |
| `pkg/rustpushgo/src/lib.rs` | Go↔Rust FFI: `cloud_sync_chats`, `cloud_sync_messages` |
| `rustpush/src/imessage/cloud_messages.rs` | Rust CloudKit client: zone sync, PCS decryption |
| `rustpush/src/icloud/cloudkit.rs` | Low-level CloudKit protobuf API (`FetchRecordChangesOperation`) |

### Backfill Flow

When the bridge connects (or reconnects), `startCloudSyncController` launches a goroutine that:

```
1. Wait for contacts to be ready (needed for name resolution)
2. Check if DB has any messages
   ├── No messages → clear stored tokens (force full sync)
   └── Has messages → keep tokens (incremental catch-up)
3. Sync chats (chatManateeZone)
   - Load stored continuation token (or nil)
   - Page through CloudKit responses until status == 3
   - Upsert each chat record into cloud_chat table
   - Save new token
4. Sync messages (messageManateeZone)
   - Same token-based pagination
   - Resolve each message to a portal ID
   - Upsert into cloud_message table
   - Save new token
5. Create Matrix portals for all discovered conversations
6. Exit — real-time APNs handles everything from here
```

### Token Storage

Tokens are stored in the `cloud_sync_state` table, keyed by `(login_id, zone)`:

```sql
CREATE TABLE cloud_sync_state (
    login_id TEXT NOT NULL,
    zone TEXT NOT NULL,
    continuation_token TEXT,
    last_success_ts BIGINT,
    last_error TEXT,
    updated_ts BIGINT NOT NULL,
    PRIMARY KEY (login_id, zone)
);
```

The token is a base64-encoded opaque blob from CloudKit. We store separate tokens for `chatManateeZone` and `messageManateeZone`.

### Portal ID Resolution

CloudKit messages need to be mapped to bridge portal IDs. The resolution logic in `resolveConversationID`:

1. **UUID chat_id** → group conversation → `gid:<lowercase-uuid>`
2. **Known chat record** → look up portal ID from `cloud_chat` table
3. **DM from sender** → `tel:+...` or `mailto:...` from the sender field
4. **DM from me** → parse destination from chat_id (`iMessage;-;+16692858317`)

CloudKit chat style values:
- `43` = group conversation
- `45` = direct message (DM)

### PCS Encryption

All CloudKit records in the Manatee zones are encrypted with PCS (Protected CloudStorage). The decryption chain:

1. **iCloud Keychain** contains the PCS service key for `Messages3` (service type 55)
2. **Zone protection info** is decrypted using the service key → yields zone keys
3. **Record protection info** is decrypted using zone keys → yields per-record keys
4. **Record fields** are decrypted using the per-record key

The Rust code handles PCS key recovery with retries — if a key is missing, it refreshes the keychain/zone config and retries up to 4 times. Records that still can't be decrypted (e.g., very old records with rotated keys) are skipped with a warning.

## Why No Periodic Polling

Previous versions of the bridge polled CloudKit every 30 seconds and ran "repair tasks" that re-downloaded entire zone histories. This was removed because:

1. **Real-time APNs already delivers all messages.** The `com.apple.madrid` push topic provides incoming messages, delivery receipts, read receipts, typing indicators, and reactions in real-time. Messages sent from the user's other Apple devices are also delivered via APNs.

2. **Reconnect handles missed messages.** When the bridge reconnects after downtime, the backfill runs again using the stored continuation token. CloudKit returns only what changed while the bridge was offline. This is the same mechanism Apple uses — token-based catch-up.

3. **Full zone re-scans were wasteful.** The old "repair" system called `CloudFetchRecentMessages` which started from a nil token every time, re-downloading the entire message zone (potentially thousands of records) just to filter for recent ones client-side. This was the opposite of how Apple's API is designed to work.

4. **Apple says not to.** Their documentation explicitly states periodic polling is unnecessary when you have another mechanism for detecting changes.

## Debugging

### Inspecting Stored State

```sql
-- Check sync tokens
SELECT * FROM cloud_sync_state;

-- Count synced records
SELECT COUNT(*) FROM cloud_chat;
SELECT COUNT(*) FROM cloud_message WHERE deleted = FALSE;

-- Messages per portal
SELECT portal_id, COUNT(*) as msg_count
FROM cloud_message
WHERE deleted = FALSE
GROUP BY portal_id
ORDER BY msg_count DESC;

-- Check for unresolved messages
SELECT COUNT(*) FROM cloud_message
WHERE portal_id IS NULL OR portal_id = '';
```

### Forcing a Full Re-sync

Delete the sync tokens and restart the bridge:

```sql
DELETE FROM cloud_sync_state;
```

Or delete all cloud data to start completely fresh:

```sql
DELETE FROM cloud_sync_state;
DELETE FROM cloud_chat;
DELETE FROM cloud_message;
```

## References

- [Apple CloudKit Documentation](https://developer.apple.com/documentation/cloudkit/)
- [CKFetchRecordZoneChangesOperation](https://developer.apple.com/documentation/cloudkit/ckfetchrecordzonechangesoperation)
- [Remote Records Guide](https://developer.apple.com/documentation/cloudkit/remote-records)
- [CKRecordZoneSubscription](https://developer.apple.com/documentation/cloudkit/ckrecordzonesubscription)
- `docs/group-id-research.md` — how chat identifiers map between CloudKit and APNs
