# Research Task: iMessage Group Chat Identity Model

## Objective

Produce a comprehensive report (`docs/group-id-research.md`) mapping every identifier involved in iMessage group chat identity — across CloudKit sync, real-time APNs delivery, and the local Messages database. The goal is to understand how Apple tracks "the same conversation" across member changes, and architect the correct portal ID strategy for our Matrix-iMessage bridge.

## The Problem We're Solving

When a user sends a message to an **existing** group chat in iMessage, the bridge creates a **brand new** Matrix room in Beeper instead of routing the message to the existing room for that group. The conversation stays on the same thread in iMessage — it's only the bridge that splinters it.

Concretely: CloudKit sync created a portal with `gid:<UUID-A>` for a group. Later, a real-time APNs message arrives for the same group but with `sender_guid = <UUID-B>`. Since `UUID-B != UUID-A`, the bridge creates a new portal `gid:<UUID-B>`. The user now has two rooms in Beeper for one iMessage conversation.

We need to understand: **Why does the real-time message UUID differ from the CloudKit-synced UUID for the same group?** And what's the correct identifier to use so both paths always resolve to the same portal?

Note: There are legitimately many different group chats with the same participants (from testing). Those are separate conversations and separate portals — that's correct. The bug is specifically about a single conversation getting a different UUID in real-time vs CloudKit.

## What to Research

### 1. CloudKit Chat Records (`chatEncryptedv2` zone)

Our Rust code decodes these in `rustpush/src/imessage/cloud_messages.rs` (struct `CloudChat`, ~line 231). Examine every field:

- `cid` → `chat_identifier` — What format? (e.g., `chat368136512547052395`, `iMessage;+;chat...`, etc.) Does it stay stable across member changes?
- `gid` → `group_id` — UUID format. When exactly does it change? Is it per-member-change or something else?
- `ogid` → `original_group_id` — Points to what? The immediately previous `gid`? The very first `gid`? Something else?
- `stl` → `style` — We know 43=group, 45=DM. Any other values?
- `ptcpts` → `participants` — How are participants encoded? URIs like `tel:+1...` or `mailto:...`?
- `guid` — What is this? Same as `gid`? Different?
- `name` / `display_name` — User-set group name vs auto-generated?
- `svc` → `service_name` — Always "iMessage"? Can be "SMS"?
- Any other fields that might relate to conversation identity

**Key question**: Given 30+ CloudKit chat records that all represent the same group conversation (with different member snapshots), which field(s) are stable across all of them?

### 2. Real-Time APNs Messages (rustpush)

When a message arrives via APNs push, examine what identifiers are available:

- Look at `rustpush/src/imessage/messages.rs` for incoming message structures
- Look at `pkg/rustpushgo/src/lib.rs` for `WrappedMessage` (around line 340) — what is `sender_guid`?
- Is `sender_guid` the same as CloudKit's `gid`? Or something else?
- For group messages: what fields identify which conversation the message belongs to?
- Is there a `chat_identifier` equivalent in real-time messages?
- When group membership changes, does the real-time `sender_guid` change immediately?

### 3. Local Messages Database (chat.db on macOS)

While our bridge doesn't use chat.db directly (we use CloudKit), understanding Apple's local model helps:

- `chat` table: `ROWID`, `chat_identifier`, `group_id`, `display_name` — which stays stable?
- `chat_message_join` table: how messages link to chats
- When members change, does the `chat.ROWID` stay the same? Does `chat_identifier`?
- Is there a concept of chat "continuation" in the local DB?

### 4. The `original_group_id` Chain

This is the most critical piece to understand:

- When Apple creates a new `gid` (member change), does `ogid` on the new record point to the old `gid`?
- Is it always a direct parent link (A → B → C), or can it skip generations?
- Can `ogid` be empty on the very first version of a group?
- Can multiple records share the same `ogid`? (e.g., two member changes from the same base)
- Is the chain always linear, or can it branch/merge?

### 5. Our Current Data

Query the live database on the bridge to examine real data:

```bash
# SSH to the bridge
gcloud compute ssh imessage-bridge-32 --zone=us-west1-b

# Database location (CWD-relative, the actual DB is here):
sqlite3 ~/imessage/mautrix-imessage.db

# Cloud chat table schema
.schema cloud_chat

# Example: find all cloud_chat records for groups involving specific participants
SELECT cloud_chat_id, group_id, portal_id, display_name, participants_json
FROM cloud_chat WHERE portal_id LIKE 'gid:%' ORDER BY group_id;

# Check for the real-time message that created a duplicate portal
SELECT id, name, mxid FROM portal WHERE id LIKE 'gid:2f787cd8%';
```

Also look at the Rust source to understand what CloudKit fields are available but not yet stored:
- `rustpush/src/imessage/cloud_messages.rs` — `CloudChat` struct
- `pkg/rustpushgo/src/lib.rs` — `WrappedCloudSyncChat` FFI struct  
- `pkg/connector/cloud_backfill_store.go` — DB schema and upsert logic
- `pkg/connector/sync_controller.go` — `resolvePortalIDForCloudChat()` — current portal ID resolution logic
- `pkg/connector/client.go` — `makePortalKey()` (~line 2174) — real-time portal ID resolution

## Critical Instruction: Challenge All Assumptions

The prompt above contains assumptions made by a previous agent working on this problem. **Do not take any of them as fact.** Specifically, verify or disprove each of these through code inspection and database queries:

- **"Apple creates a new group UUID when members are added/removed"** — Is this actually true? Or do UUIDs change for other reasons? Or is the real issue something else entirely — like the real-time `sender_guid` being a fundamentally different kind of identifier than CloudKit's `gid`?
- **"`original_group_id` links to the previous UUID forming a chain"** — Does it? Or does `ogid` mean something else entirely? You'll need to expose this field first (it's in the Rust struct but not yet in the FFI/Go layer or DB). Check the actual data once exposed.
- **"30+ different group UUIDs all represent the same conversation"** — This is WRONG. The user confirmed these are legitimately different group chats created during testing. Same participants, different conversations. That's expected. Don't get distracted by this.
- **"`chat_identifier` (cid) is stable across member changes"** — Verify this. Some `cloud_chat_id` values look like `chat368136512547052395` while others look like hex hashes (`367950f3326343d1a93a4798aa98fa8e`). What determines the format? Are the `chat*` ones truly stable?
- **"`sender_guid` in real-time messages is the same as CloudKit's `gid`"** — Confirm by cross-referencing actual values.
- **"Style 43 = group, 45 = DM with no other values"** — Query for all distinct `style` values in the data.

For each assumption, state whether it is **confirmed**, **disproved**, or **uncertain**, with evidence.

## Expected Output

Produce `docs/group-id-research.md` containing:

1. **Identifier Map**: A table listing every ID field, its source (CloudKit/APNs/chatdb), format, stability characteristics, and whether it changes on member changes
2. **Chain Analysis**: Document the `original_group_id` chain behavior with examples from real data
3. **Stability Analysis**: Which identifier(s) remain constant across the lifetime of a single conversation?
4. **Architecture Recommendation**: Based on findings, what should we use as the canonical portal ID for group chats? How should we handle:
   - Initial cloud sync (bootstrap)
   - Incremental cloud sync (new chat records arriving)
   - Real-time messages (APNs push with possibly-new UUID)
   - The transition period (real-time message arrives before CloudKit syncs the new chat record)
5. **Data Model Changes**: What columns/tables/indexes need to change in our bridge DB?

## Important Context

- The bridge is a Go application with a Rust FFI layer for Apple protocol handling
- We're bridging iMessage to Matrix via the mautrix framework
- Each Matrix room = one "portal" identified by a portal ID string
- Currently using `gid:<lowercase-uuid>` for groups, `tel:+1234567890` or `mailto:user@example.com` for DMs
- The duplicate portal problem: real-time message for "Ludvig, David, & James" created `gid:2f787cd8-5e31-4ed6-802c-4e1b7ee56eff` but that UUID doesn't match ANY `group_id` in the `cloud_chat` table. The same group conversation exists in cloud_chat under a different UUID. Why?
- There are ~30 group chats with overlapping participants — these are legitimately different conversations from testing, NOT the same group. Don't try to merge them.
- We do NOT have access to the local macOS chat.db — the bridge runs on a Linux VM with only CloudKit + APNs access
