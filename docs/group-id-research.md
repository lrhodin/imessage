# iMessage Group Chat Identity Model — Research Report

## Executive Summary

The duplicate portal problem occurs because **the `sender_guid` (gid) in real-time APNs messages can differ from the `group_id` (gid) in CloudKit chat records**, even for the same conversation. This happens specifically when the bridge itself sends an outgoing message without providing the correct `sender_guid` — the Rust layer generates a brand new UUID via `Uuid::new_v4()`, which then becomes that session's `sender_guid`. When other participants reply, they parrot back this new UUID, creating a portal that doesn't match any CloudKit record.

The root cause is **not** that Apple changes the group UUID on member changes. The CloudKit `group_id` is stable across member changes. The problem is that our bridge sometimes sends messages with a freshly generated UUID instead of the established one.

---

## 1. Identifier Map

| Field | Source | Wire Name | Format | Stability | Changes on Member Change? |
|-------|--------|-----------|--------|-----------|---------------------------|
| `chat_identifier` (cid) | CloudKit `chatEncryptedv2` | `cid` | `chat<numeric>` (e.g., `chat368136512547052395`) | **Unstable** — new value per member snapshot | **Yes** — each participant change produces a new `cid` |
| `group_id` (gid) | CloudKit `chatEncryptedv2` | `gid` | UUID with dashes (e.g., `42572808-43F8-4013-AA0A-F13AD89AC210`) or hex-encoded string for SMS groups | **Stable** across member changes in CloudKit | **No** — same `gid` across all snapshots |
| `original_group_id` (ogid) | CloudKit `chatEncryptedv2` | `ogid` | UUID (same format as `gid`) | N/A — reference field | N/A — not yet exposed through FFI |
| `guid` | CloudKit `chatEncryptedv2` | `guid` | Unknown (present in struct, not yet analyzed) | Unknown | Unknown |
| `record_name` | CloudKit record metadata | (CK record name) | Hex hash (e.g., `5fe123c189fd4418a8acff4c36dacb41`) | Unique per CloudKit record | Yes — new record per snapshot |
| `sender_guid` | APNs real-time messages | `gid` | UUID without dashes, lowercase | **Should be stable** but can drift (see §3) | **No** — Apple keeps it stable; our bridge may change it |
| `style` (stl) | CloudKit `chatEncryptedv2` | `stl` | Integer: `43` = group, `45` = DM | Stable | No |
| `display_name` | CloudKit `chatEncryptedv2` | `name` | Free text or null | User-modifiable | No (unless user renames) |
| `service_name` (svc) | CloudKit `chatEncryptedv2` | `svc` | `"iMessage"` or `"SMS"` | Stable per chat | No |
| `participants` (ptcpts) | CloudKit `chatEncryptedv2` | `ptcpts` | Array of `{FZPersonID: "tel:+1..."/"mailto:..."}` | **Changes** per snapshot | **Yes** — that's what triggers new `cid` |
| `legacy_group_identifiers` | CloudKit `chatEncryptedv2` → `prop` | `prop.legacyGroupIdentifiers` | Array of strings | Unknown — not yet exposed | Unknown |

### Key Observations

1. **`group_id` (gid) IS stable across member changes in CloudKit.** Evidence: group `6265...` has 4 cloud_chat records with different `chat_identifier` values and varying participant counts (12–16), all sharing the same `group_id`.

2. **`chat_identifier` (cid) is NOT stable.** Each member-change snapshot gets a new `chat<numeric>` value. There are 70 cloud_chat records mapping to only 47 distinct group_ids.

3. **`sender_guid` in APNs is the same field as `group_id` in CloudKit** — both are serialized as `gid` in their respective plist payloads. They *should* always match for the same conversation.

4. **Two `cloud_chat_id` formats exist:**
   - `chat<numeric>` — derived from the CloudKit `chat_identifier` field when non-empty
   - 32-char hex — used when `chat_identifier` is empty; falls back to `record_name`

---

## 2. Assumption Verification

### ❌ "Apple creates a new group UUID when members are added/removed"

**DISPROVED.** CloudKit data proves the opposite. The `group_id` stays constant across member changes. What changes is the `chat_identifier` (`cid`) — Apple creates a new `chatEncryptedv2` record with a new `cid` but the same `gid` for each membership snapshot.

Evidence from the database: group `6265373930353030643536643434613362643232396630386332356665336662` has 4 records with different `cloud_chat_id` values (`chat407641904384093446`, `chat413369107146090660`, `chat894658066477092892`, `chat666379037895724839`) and varying participant counts, all sharing the same `group_id`.

### ⚠️ "`original_group_id` links to the previous UUID forming a chain"

**UNCERTAIN — cannot verify.** The `ogid` field exists in the Rust `CloudChat` struct but is **not passed through the FFI layer** (`WrappedCloudSyncChat` does not include it) and is **not stored in the database**. We cannot examine its values without first adding it to the FFI struct and DB schema.

However, since `group_id` itself appears stable, `ogid` may serve a different purpose — perhaps linking to a predecessor conversation when a group is forked or recreated, rather than tracking member-change snapshots.

### ✅ "30+ different group UUIDs all represent the same conversation" → CORRECTLY identified as WRONG

**CONFIRMED as wrong per the prompt.** The ~30 groups with overlapping participants (Ludvig, David, James) are legitimately different conversations created during testing. Each has its own unique `group_id`. This is correct behavior.

### ✅ "`chat_identifier` (cid) is stable across member changes"

**DISPROVED.** `cid` changes with each member-change snapshot. Multiple `cloud_chat_id` values (derived from `cid`) map to the same `group_id`. The `chat<numeric>` format appears to be a hash/identifier that Apple recomputes when membership changes.

### ⚠️ "`sender_guid` in real-time messages is the same as CloudKit's `gid`"

**PARTIALLY CONFIRMED, WITH A CRITICAL CAVEAT.** Both fields use the same wire name (`gid` in plist) and the same UUID format. For conversations where Apple devices are sending, the `sender_guid` in APNs messages matches the `group_id` in CloudKit. 

**However**, the bridge can introduce mismatches:
- In `messages.rs:1959-1960`: `prepare_send()` generates a new `Uuid::new_v4()` if `sender_guid` is `None`
- The Go connector (`portalToConversation`) correctly passes the sender_guid for `gid:` portals
- But for **legacy comma-separated portals** or when `sender_guid` is not cached/persisted, the Rust layer may mint a new UUID

The 3 orphaned portals (`gid:2f787cd8-...`, `gid:4b62c57d-...`, `gid:3dc13b1f-...`) with no matching cloud_chat records are evidence of this — these UUIDs were likely generated by `Uuid::new_v4()` during an outbound message, then parroted back by recipients.

### ✅ "Style 43 = group, 45 = DM with no other values"

**UNCERTAIN — cannot verify from DB** (style is not stored in `cloud_chat`). The CloudKit struct defines `style` as `i64` with comments "45 for normal chats, 43 for group". No evidence of other values, but we'd need to add style to the DB or log it during sync to verify exhaustively.

---

## 3. The Real Bug: UUID Drift on Outbound Messages

### How the Duplicate Occurs

1. **CloudKit bootstrap**: Group "Ludvig, David, & James" syncs from CloudKit with `group_id = 6BC815C2-...`. Portal `gid:6bc815c2-...` is created.

2. **Outbound message**: User sends from Beeper. The bridge calls `portalToConversation()`, which correctly resolves the `sender_guid` from the `gid:` portal ID. The Rust `prepare_send()` receives this UUID and uses it. ✅ This path works.

3. **The failure case**: At some point, a message was sent through a code path where `sender_guid` was `None` (possibly before the `gid:` portal ID scheme existed, or during a restart before caches were populated). Rust's `prepare_send()` generated `2f787cd8-...` as a new UUID. This UUID was sent to all participants.

4. **Inbound reply**: Other participants reply. Their devices now use `sender_guid = 2f787cd8-...` (the UUID from step 3). The bridge receives this, calls `makePortalKey()`, and creates a NEW portal `gid:2f787cd8-...`. The original portal `gid:6bc815c2-...` is abandoned.

5. **CloudKit never learns**: CloudKit continues to use the original `group_id = 6BC815C2-...`. The real-time UUID `2f787cd8-...` is never recorded in CloudKit.

### Evidence

- Portal `gid:2f787cd8-5e31-4ed6-802c-4e1b7ee56eff` — exists in `portal` table, has NO matching `cloud_chat` record
- Portal `gid:4b62c57d-7b73-4960-8fbd-1f5836f8feb4` — same situation
- Portal `gid:6bc815c2-f84f-4c33-9a5f-60dde285004c` — HAS a matching `cloud_chat` record (`chat838581659461115708`)

All three are named "Ludvig, David, & James" and represent the same logical conversation.

### Why Recipients Use the Bridge's UUID

When the bridge sends an outbound message with `sender_guid = <new_uuid>`, the iMessage protocol treats this as the canonical group identifier for that message. If the recipients' devices see a `gid` they don't recognize, they may:
- Create a new local chat entry with that `gid`
- Or (more likely for existing conversations) continue using the conversation but echo back whatever `gid` was in the latest message

Either way, replies come back with the bridge-generated UUID instead of the CloudKit-canonical one.

---

## 4. CloudKit Field Details

### `chat_identifier` (cid)
- Format: `chat<large_numeric>` (e.g., `chat368136512547052395`) — appears to be a hash of participant list
- For DMs: the phone number or email (e.g., `+14158138533`, `user@example.com`)
- Can be empty — in which case `record_name` is used as `cloud_chat_id`
- **NOT stable** across member changes

### `group_id` (gid)
- Format: Standard UUID with dashes for iMessage groups; hex-encoded string for SMS/MMS groups
- Present on ALL CloudKit chat records, including DMs (the code comments confirm: "The group_id (gid) field is set for ALL CloudKit chats, even DMs")
- **STABLE** across member changes for the same conversation
- Case varies between records (uppercase from CloudKit, sometimes lowercase from local operations)

### `original_group_id` (ogid)
- Declared in `CloudChat` struct but NOT passed through FFI (`WrappedCloudSyncChat` omits it)
- NOT stored in the bridge database
- Purpose unknown without data inspection. Hypotheses:
  1. Points to a predecessor group when a conversation is "forked"
  2. Always equals `gid` (redundant)
  3. Points to the very first `gid` if the group was somehow recreated
- **Action needed**: Expose through FFI and store in DB to analyze

### `legacy_group_identifiers` (in `CloudProp`)
- Array of strings inside the `prop` (properties) field
- Not exposed through FFI
- Could contain historical `gid` values or pre-migration identifiers
- **Action needed**: Expose and analyze

### `participants` (ptcpts)
- Array of `CloudParticipant` structs, each with `FZPersonID` field
- URIs like `tel:+15551234567` or `mailto:user@example.com`
- Includes the local user's handle
- Different participant snapshots across cloud_chat records for the same group

### `guid`
- Present in `CloudChat` struct but distinct from `group_id`
- Not analyzed in detail; may be a record-level GUID

---

## 5. Architecture Recommendation

### Portal ID Strategy

**Continue using `gid:<lowercase-uuid>` as the canonical portal ID for groups.** The CloudKit `group_id` is the correct stable identifier. The current approach is fundamentally sound.

### Fix: Prevent UUID Drift on Outbound Messages

The primary fix is ensuring that `sender_guid` is NEVER `None` when sending to an existing group:

1. **`portalToConversation()`** already handles `gid:` portals correctly by extracting the UUID from the portal ID. This path works.

2. **Verify all send paths**: Audit every call to `makeConversation()` and `portalToConversation()` to ensure none can produce a `nil` sender_guid for group conversations.

3. **Rust-side safety**: In `prepare_send()`, instead of silently generating a new UUID when `sender_guid` is `None`, log a warning. For group conversations (participants > 2), this should be treated as an error condition, not silently patched.

### Fix: Reconcile Orphaned Portals

For the 3 existing orphaned portals, a migration or repair step should:
1. Detect portals with `gid:` IDs that have no matching `cloud_chat.group_id`
2. Find the canonical portal for the same conversation (by matching participants + group name)
3. Merge/redirect the orphaned portal to the canonical one

### Fix: Real-Time → CloudKit Reconciliation

When a real-time message arrives with a `sender_guid` that doesn't match any existing portal:

1. **Before creating a new portal**, check if there's an existing `cloud_chat` record with a `group_id` that matches — but also check if the participants overlap with an existing portal.
2. **Expose `original_group_id`** through the FFI layer and store it. If `ogid` provides a chain linking different `gid` values, use it to map incoming real-time UUIDs to canonical CloudKit UUIDs.
3. **Expose `legacy_group_identifiers`** and check if the incoming `sender_guid` appears in any chat's legacy identifiers.

### Handling the Transition Period

When a real-time APNs message arrives with a UUID before CloudKit has synced:
- The current behavior of creating a `gid:<uuid>` portal is acceptable as a temporary measure
- When CloudKit sync later reveals the chat record with matching participants, the bridge should detect the duplicate and merge

---

## 6. Recommended Data Model Changes

### FFI Layer (`WrappedCloudSyncChat`)

Add these fields:

```rust
pub struct WrappedCloudSyncChat {
    // ... existing fields ...
    pub original_group_id: String,       // ogid — expose for chain analysis
    pub legacy_group_identifiers: Vec<String>,  // from prop field
    pub guid: String,                     // CloudKit chat guid
}
```

### Database (`cloud_chat` table)

```sql
ALTER TABLE cloud_chat ADD COLUMN original_group_id TEXT NOT NULL DEFAULT '';
ALTER TABLE cloud_chat ADD COLUMN style INTEGER NOT NULL DEFAULT 0;

-- Index for ogid lookups (chain resolution)
CREATE INDEX cloud_chat_ogid_idx 
    ON cloud_chat (login_id, original_group_id) 
    WHERE original_group_id <> '';
```

### Portal Metadata

Already includes `sender_guid` and `group_name` — no changes needed.

### New: Group UUID Alias Table

For robust reconciliation, consider a mapping table:

```sql
CREATE TABLE group_uuid_alias (
    login_id TEXT NOT NULL,
    alias_uuid TEXT NOT NULL,        -- any UUID seen for this group
    canonical_uuid TEXT NOT NULL,     -- the CloudKit group_id
    source TEXT NOT NULL,             -- 'cloudkit', 'apns', 'ogid', 'legacy'
    created_ts BIGINT NOT NULL,
    PRIMARY KEY (login_id, alias_uuid)
);

CREATE INDEX group_uuid_alias_canonical_idx 
    ON group_uuid_alias (login_id, canonical_uuid);
```

When a real-time message arrives with `sender_guid = X`:
1. Check `group_uuid_alias` for `alias_uuid = X`
2. If found, use `canonical_uuid` as the portal ID
3. If not found, create portal with `gid:X` and note it as unresolved
4. When CloudKit syncs, populate aliases from `ogid` chains and `legacy_group_identifiers`

---

## 7. Immediate Action Items

1. **Expose `original_group_id` through FFI** — Add to `WrappedCloudSyncChat`, store in DB, analyze real data to understand the chain structure.

2. **Expose `legacy_group_identifiers`** — Same treatment. These may contain the mapping we need.

3. **Add `style` to cloud_chat table** — Currently not stored; needed to distinguish groups from DMs authoritatively.

4. **Audit outbound sender_guid flow** — Verify that every code path providing a `WrappedConversation` for group sends includes the correct `sender_guid`. Add logging/assertions in `prepare_send()` for group conversations with no sender_guid.

5. **Build reconciliation logic** — After exposing `ogid` and `legacy_group_identifiers`, implement the alias table and reconciliation during CloudKit sync.

6. **Fix the 3 orphaned portals** — Manual or automated migration to redirect `gid:2f787cd8-...` and `gid:4b62c57d-...` to the canonical `gid:6bc815c2-...` portal.

---

## Appendix: Source File Reference

| File | Purpose |
|------|---------|
| `rustpush/src/imessage/cloud_messages.rs:231` | `CloudChat` struct — all CloudKit chat fields |
| `rustpush/src/imessage/messages.rs:31` | `ConversationData` struct — real-time message identity |
| `rustpush/src/imessage/messages.rs:1959` | `prepare_send()` — UUID generation when sender_guid is None |
| `rustpush/src/imessage/rawmessages.rs` | Raw APNs message structs — `gid` field mapping |
| `pkg/rustpushgo/src/lib.rs:762` | `WrappedCloudSyncChat` — FFI struct (missing `ogid`) |
| `pkg/rustpushgo/src/lib.rs:847` | `message_inst_to_wrapped()` — sender_guid propagation |
| `pkg/connector/client.go:2174` | `makePortalKey()` — portal ID resolution for real-time |
| `pkg/connector/client.go:2345` | `portalToConversation()` — outbound message routing |
| `pkg/connector/sync_controller.go:345` | `resolvePortalIDForCloudChat()` — CloudKit portal ID resolution |
| `pkg/connector/cloud_backfill_store.go:100` | DB schema — cloud_chat table |
