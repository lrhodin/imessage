# Research: Apple iCloud Authentication Tokens & Session Lifecycle

## Objective

We're building an iMessage bridge that authenticates with Apple's iCloud services (CloudKit, CardDAV contacts, iMessage). We persist credentials across process restarts but our token restoration is broken — we get 401s on CardDAV immediately after a fresh login. We clearly don't understand how Apple's auth tokens work. **Fix that.**

## What We Need to Understand

For each token/credential type below, determine:
1. **What is it?** (full name, what service issues it)
2. **How is it obtained?** (what auth flow, what inputs)
3. **What is its lifetime?** (seconds? minutes? hours? days?)
4. **Can it be refreshed without user interaction (2FA)?**
5. **What can it be used for?**
6. **What depends on it?**

### Token Types to Research

- **PET (Person/Persistent/Primary? Token)** — `com.apple.gs.idms.pet` in Apple's GSA (Grand Slam Authentication) system. We store this after login. It seems to expire quickly but we don't know the actual lifetime.

- **MobileMe delegate / mmeAuthToken** — Used for iCloud services (CardDAV contacts, etc.). Obtained by calling `login_apple_delegates()` with a PET token. Has its own expiry. We cache this as JSON.

- **SPD (Session/Security? Plist Dictionary)** — A plist dictionary containing `adsid` and other session data. Stored after login. Used in `refresh_mme()`.

- **ADSID** — Apple Directory Services ID? Appears in SPD and is used when fetching delegates.

- **DSID** — Another Apple service ID used for CardDAV auth headers.

- **Hashed password** — SRP-derived password hash stored after initial login. Can this be used to get a fresh PET without 2FA?

- **Anisette data** — Machine-specific headers (X-Apple-I-MD, X-Apple-I-MD-M, etc.). Generated locally. How does staleness affect auth?

- **CloudKit session tokens** — Are these separate from the MobileMe delegate? Do they have their own auth?

## Key Questions

1. **After a successful Apple ID login (with 2FA), what is the longest-lived credential we can store?** Can we store something that lets us get fresh tokens for weeks/months without user interaction?

2. **Can `login_email_pass()` (SRP auth with stored hashed password) obtain a fresh PET without triggering 2FA?** Our code tries this as a fallback and gets error `-22406`. Is that always the case, or is it a fixable configuration issue?

3. **What is the actual PET token lifetime?** We've seen it expire within minutes of being issued. Is that normal? Does it depend on how it was obtained?

4. **What is the MobileMe delegate token lifetime?** If we cache the delegate JSON, how long is it valid?

5. **How does a real Apple device (iPhone/Mac) maintain persistent access to iCloud services without re-prompting for 2FA?** What token chain does it use? Can we replicate that?

6. **What is the correct token refresh chain?** i.e., "Use X to refresh Y, use Y to refresh Z, Z is what you actually need for API calls." What's the dependency graph?

## Our Current (Broken) Flow

```
LOGIN (interactive, with 2FA):
  1. User enters Apple ID + password + 2FA code
  2. SRP authentication → get PET token
  3. Use PET to fetch MobileMe delegate (login_apple_delegates)
  4. Store: username, hashed_password, PET, SPD, ADSID, DSID, MobileMe delegate JSON

RESTORE (on bridge restart, no user interaction):
  1. Create fresh anisette provider
  2. Create AppleAccount with stored username + hashed_password + SPD
  3. Inject stored PET with fake 30-day expiry (!!)
  4. Seed cached MobileMe delegate JSON
  5. Try to use MobileMe delegate for CardDAV → 401
  6. refresh_mme() tries PET-based auth → UNAUTHORIZED (PET expired server-side)
  7. Fallback: login_email_pass() with hashed_password → -22406 error
  8. Everything fails. Cloud sync blocked forever.
```

## Research Approach

**DO NOT trust our codebase's assumptions.** The code injects a PET with a "30-day expiry" which is clearly wrong. Verify everything independently:

1. **Search for prior art**: Look at how other open-source Apple auth implementations handle token persistence. Key projects:
   - `apple-private-apis` / `icloud-auth` (Rust, the library we use — check its docs/issues)
   - `pypush` (Python iMessage implementation)
   - `Beeper's original mautrix-imessage` (may have solved this)
   - Any iCloud reverse-engineering research/blogs

2. **Examine the actual token data**: If possible, decode/inspect the PET token and MobileMe delegate to find embedded expiry timestamps.

3. **Test experimentally**: If you have access to the running bridge, try:
   - Call `refresh_mme()` immediately after login (before any delay) — does it work?
   - Check how long after login the PET still works
   - Check if there's a refresh token alongside the PET that we're not storing

4. **Check Apple's GSA protocol**: The SRP-based Grand Slam Authentication has been reverse-engineered. Find documentation on the full token lifecycle.

## Codebase References

- **Token restoration**: `pkg/rustpushgo/src/lib.rs` line 600 — `restore_token_provider()`
- **MobileMe refresh**: `rustpush/src/auth.rs` line 155 — `refresh_mme()`  
- **Login flow**: `pkg/connector/login.go` line 620+ — where tokens are saved after login
- **Token usage on startup**: `pkg/connector/client.go` line 190+ — where tokens are restored
- **icloud-auth library**: `rustpush/apple-private-apis/icloud-auth/src/` — the underlying Apple auth implementation
- **GSA client**: `rustpush/apple-private-apis/icloud-auth/src/client.rs` — SRP login, token fetching
- **CardDAV contacts**: `pkg/connector/cloud_contacts.go` — uses auth headers from TokenProvider

## Deliverable

Write a document at `docs/apple-auth-research.md` that:
1. Maps out every token type, its lifetime, and refresh mechanism
2. Shows the correct token dependency graph
3. Explains how a real Apple device maintains persistent auth
4. Recommends the specific changes needed so our bridge can maintain auth across restarts without 2FA
5. If persistent auth without 2FA is impossible, say so clearly and explain why

Be precise. Cite sources. Don't guess.
