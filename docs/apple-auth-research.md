# Apple iCloud Authentication: Token Lifecycle & Persistence

Research document for the iMessage bridge's iCloud authentication system.
Covers every token type, its lifetime, refresh mechanism, and the correct
strategy for maintaining persistent access across process restarts.

---

## Table of Contents

1. [Token Inventory](#1-token-inventory)
2. [Token Dependency Graph](#2-token-dependency-graph)
3. [How a Real Apple Device Maintains Persistent Auth](#3-how-a-real-apple-device-maintains-persistent-auth)
4. [Our Current (Broken) Flow Analyzed](#4-our-current-broken-flow-analyzed)
5. [Root Cause of the 401s](#5-root-cause-of-the-401s)
6. [Error -22406 Explained](#6-error--22406-explained)
7. [Recommended Fix](#7-recommended-fix)
8. [Alternative Approaches Considered](#8-alternative-approaches-considered)
9. [Sources](#9-sources)

---

## 1. Token Inventory

### 1.1 Hashed Password (SHA-256 of raw password)

| Property | Value |
|---|---|
| **Full Name** | SHA-256 pre-hash of the Apple ID password |
| **Issued By** | Computed locally: `SHA256(raw_password)` |
| **Lifetime** | Indefinite (valid as long as user doesn't change their Apple ID password) |
| **Refreshable without 2FA?** | N/A — it IS the credential |
| **Used For** | SRP-6a authentication with GSA (`login_email_pass()`) |
| **Depends On** | Nothing |

**Details:** During the initial login, the raw password is SHA-256 hashed
client-side before being used in the SRP-6a protocol. The bridge stores this
hash (hex-encoded) as `AccountHashedPasswordHex`. The hash is then further
processed through PBKDF2 with a server-provided salt and iteration count during
each SRP handshake. The protocol variant (`s2k` vs `s2k_fo`) determines whether
the hash bytes or their hex encoding are fed to PBKDF2.

**Critical insight:** This stored hash is functionally equivalent to the
plaintext password for SRP purposes. It can be used to perform `login_email_pass()`
at any time. However, on an HSA2 account, the server may still require 2FA
verification — the hash alone does not bypass 2FA.

### 1.2 SPD (Server Provided Data)

| Property | Value |
|---|---|
| **Full Name** | Server Provided Data |
| **Issued By** | GSA endpoint (`gsa.apple.com/grandslam/GsService2`) during SRP `complete` step |
| **Lifetime** | The SPD itself doesn't expire; it contains session identifiers |
| **Refreshable without 2FA?** | Only re-obtained by performing a full SRP login |
| **Used For** | Contains ADSID, DSID, GsIdmsToken, account name, and token dictionary |
| **Depends On** | Successful SRP authentication |

**Details:** The SPD is an AES-CBC encrypted plist returned in the `spd` field
of the GSA `complete` response. It is decrypted using keys derived from the
SRP session key. It contains:

- `adsid` — Alternate Directory Services ID (see 1.3)
- `DsPrsId` — Directory Services Person ID / DSID (see 1.4)
- `GsIdmsToken` — Used to build the `X-Apple-Identity-Token` header for 2FA verification
- `acname` — Account username
- `fn`, `ln` — First/last name
- `t` — Dictionary of tokens (PET, HB token, GS tokens) with their expiry/duration

The SPD is stable across sessions as long as the account hasn't changed
(password change, security upgrade, etc.). The identifiers within it (ADSID,
DSID) are permanent for the account.

### 1.3 ADSID (Alternate Directory Services ID)

| Property | Value |
|---|---|
| **Full Name** | Alternate Directory Services ID (also called AltDSID) |
| **Issued By** | Apple identity services, embedded in SPD |
| **Lifetime** | Permanent (tied to the Apple ID account) |
| **Refreshable without 2FA?** | N/A — it's an identifier, not a token |
| **Used For** | Combined with tokens (PET, HB) to form auth headers; used in `X-Apple-ADSID` header; used in delegate requests |
| **Depends On** | SPD (extracted from `spd["adsid"]`) |

**Details:** The ADSID is a UUID-like string that uniquely identifies the Apple
ID account in Apple's directory services. It is used in conjunction with various
tokens to form authorization headers (e.g., `base64(ADSID:PET)` for delegate
login, `base64(ADSID:HB_TOKEN)` for postdata/circle operations).

### 1.4 DSID (Directory Services Person ID)

| Property | Value |
|---|---|
| **Full Name** | Directory Services Person ID |
| **Issued By** | Apple identity services, embedded in SPD |
| **Lifetime** | Permanent (tied to the Apple ID account) |
| **Refreshable without 2FA?** | N/A — it's an identifier, not a token |
| **Used For** | CardDAV `Basic` auth header (`DSID:mmeAuthToken`); CloudKit operations; circle authentication |
| **Depends On** | SPD (extracted from `spd["DsPrsId"]`) |

**Details:** Numeric account identifier. Used as the "username" part of Basic
auth for MobileMe/iCloud service APIs (CardDAV, CloudKit, Quota, etc.).

### 1.5 GsIdmsToken

| Property | Value |
|---|---|
| **Full Name** | Grand Slam Identity Management Services Token |
| **Issued By** | GSA, embedded in SPD |
| **Lifetime** | Long-lived (appears to last for the duration of the SRP session, likely hours to days) |
| **Refreshable without 2FA?** | Only by performing a fresh SRP login |
| **Used For** | Building the `X-Apple-Identity-Token` header for 2FA verification and trusted device communication |
| **Depends On** | SPD (extracted from `spd["GsIdmsToken"]`) |

**Details:** This token is combined with the ADSID as `base64(ADSID:GsIdmsToken)`
to form the `X-Apple-Identity-Token` header used when sending/verifying 2FA
codes and for circle (iCloud Keychain) operations in the `is_twofa=true` path.

### 1.6 PET (Password Equivalent Token)

| Property | Value |
|---|---|
| **Full Name** | Password Equivalent Token |
| **Issued By** | GSA, via SPD token dictionary (`com.apple.gs.idms.pet`) or `X-Apple-PE-Token` header after 2FA |
| **Lifetime** | **~2 hours** (see analysis below) |
| **Refreshable without 2FA?** | **Yes, on a provisioned/trusted machine** (see Section 3) |
| **Used For** | Authenticating to Apple delegate endpoints (MobileMe, IDS) as a password substitute |
| **Depends On** | SRP login + 2FA verification (initial); SRP login only (on trusted machine) |

**Details:** The PET is the most important renewable token in the chain. Its
name literally means "Password Equivalent Token" — it acts as a short-lived
password substitute for downstream service authentication.

**Lifetime evidence from our codebase:**
- In `verify_2fa()` (device 2FA path): the PET header contains `ADSID:TOKEN` or
  `ADSID:TOKEN:DURATION`. When no duration is present, the code defaults to
  **300 seconds** (5 minutes). This is a conservative fallback.
- In `verify_sms_2fa()` (SMS path): tokens may have format
  `ADSID:TOKEN:DURATION:EXPIRY_MS`. The code parses either field.
- In `login_email_pass()` (SPD token dictionary): tokens have explicit `expiry`
  (ms since epoch) or `duration` (seconds) fields.
- From observation and community reports: PET tokens obtained after 2FA
  verification typically have a **duration of a few hours** (commonly 2-4 hours).
  The exact duration is server-controlled and varies.
- Our code in `restore_token_provider()` injects a fake **30-day expiry** which
  is completely wrong — the client-side expiry is meaningless because the server
  enforces its own expiry independently.

**Key insight:** The PET's *client-side* expiry tracking is only a hint. Even if
we set a 30-day client-side expiry, the server will reject the token after its
actual server-side lifetime (~2-4 hours). This is the primary cause of our
401 errors.

### 1.7 HB Token (Happy Birthday Token)

| Property | Value |
|---|---|
| **Full Name** | Happy Birthday Token (`com.apple.gs.idms.hb`) |
| **Issued By** | GSA, via SPD token dictionary or X-Apple-HB-Token header after 2FA |
| **Lifetime** | Similar to PET (hours) |
| **Refreshable without 2FA?** | Yes, same mechanism as PET (via SRP login on trusted machine) |
| **Used For** | `X-Apple-HB-Token` header for postdata/liveness/circle/teardown operations |
| **Depends On** | SRP login + 2FA verification |

**Details:** Used for GSA service operations (postdata, teardown, circle auth
in the non-2FA path). The code calls `get_token("com.apple.gs.idms.hb")` which
triggers automatic refresh via `login_email_pass()` if expired.

### 1.8 MobileMe Delegate / mmeAuthToken

| Property | Value |
|---|---|
| **Full Name** | MobileMe Delegate Authentication Token |
| **Issued By** | `setup.icloud.com/setup/authenticate` (login_apple_delegates endpoint) |
| **Lifetime** | **~24 hours** (server-enforced, varies) |
| **Refreshable without 2FA?** | Yes — if you have a valid PET |
| **Used For** | `X-MobileMe-AuthToken` header for iCloud services: CardDAV contacts, CloudKit, Quota, etc. |
| **Depends On** | PET + ADSID (inputs to `login_apple_delegates()`) |

**Details:** The MobileMe delegate is obtained by POSTing to the
`setup.icloud.com/setup/authenticate` endpoint with `Basic ADSID:PET`
authentication and requesting specific delegate services (`com.apple.mobileme`,
`com.apple.private.ids`).

The response is a plist containing:
- `tokens` — dict including `mmeAuthToken` (the actual bearer token for iCloud APIs)
- `com.apple.mobileme` — config dict with service URLs (CardDAV URL, Quota URL, etc.)

The `mmeAuthToken` lifetime appears to be approximately 24 hours based on
community observations, though Apple can vary this server-side.

**Our code refreshes this every 2 hours** (see `get_mme_token()` in `auth.rs`)
to stay well within the validity window. This refresh requires a valid PET.

### 1.9 IDS Delegate / auth_token

| Property | Value |
|---|---|
| **Full Name** | IDS (Identity Services) Delegate Auth Token |
| **Issued By** | Same `login_apple_delegates()` call, but for `com.apple.private.ids` |
| **Lifetime** | Used immediately for IDS certificate authentication; not cached long-term |
| **Refreshable without 2FA?** | Yes — if you have a valid PET |
| **Used For** | Authenticating with Apple's IDS certificate service to get device identity certs |
| **Depends On** | PET + ADSID |

### 1.10 Anisette Data (Machine Identity Headers)

| Property | Value |
|---|---|
| **Full Name** | Anisette Headers (X-Apple-I-MD, X-Apple-I-MD-M, X-Apple-I-MD-LU, etc.) |
| **Issued By** | Generated locally by `omnisette` library (emulates Apple's `adi` framework) |
| **Lifetime** | **~30 seconds** per OTP (X-Apple-I-MD); the machine identity (X-Apple-I-MD-M) is long-lived |
| **Refreshable without 2FA?** | Yes — generated locally, no network call needed |
| **Used For** | Required in all GSA requests. Identifies the machine to Apple's servers. |
| **Depends On** | Provisioned machine state (stored in `state/anisette/`) |

**Details:** Anisette data consists of two key components:
1. **Machine identity** (`X-Apple-I-MD-M`): A long-lived machine identifier obtained
   during initial provisioning. Persisted on disk. Valid for months/years unless
   the machine identity is revoked by Apple.
2. **One-Time Password** (`X-Apple-I-MD`): A time-based OTP derived from the
   machine identity. Valid for approximately 30 seconds.

The machine provisioning process (handled by omnisette via `midStartProvisioning`
and `midFinishProvisioning` endpoints) is what establishes the machine as a
"known device" to Apple's servers. This is analogous to installing iCloud on
a new computer — it registers the device.

**Critical for 2FA bypass:** On a real Apple device, the anisette provisioning
combined with a successful 2FA verification "trusts" the device. Subsequent
SRP logins from the same provisioned machine may not require 2FA. This is the
mechanism Blackwood-4NT documents: "Once enrolled, further GSA logins will no
longer require 2FA from the given machine."

### 1.11 CloudKit Session Tokens

| Property | Value |
|---|---|
| **Full Name** | CloudKit authentication tokens |
| **Issued By** | CloudKit service, using mmeAuthToken for initial auth |
| **Lifetime** | Session-scoped |
| **Refreshable without 2FA?** | Yes — derived from mmeAuthToken |
| **Used For** | CloudKit database operations (cloud messages, keychain sync) |
| **Depends On** | mmeAuthToken from MobileMe delegate |

**Details:** CloudKit auth piggybacks on the MobileMe delegate. The
`mmeAuthToken` is used as the authentication credential for CloudKit API calls.
There is no separate long-lived CloudKit token; if the mmeAuthToken is fresh,
CloudKit works.

---

## 2. Token Dependency Graph

```
┌──────────────────────────────────────────────────────────┐
│                  INITIAL LOGIN (with 2FA)                 │
│  Apple ID + Password (SHA-256 hash) + 2FA Code           │
│                         │                                 │
│                    SRP-6a Handshake                       │
│                    (GSA endpoint)                         │
│                         │                                 │
│                         ▼                                 │
│                    ┌─────────┐                            │
│                    │   SPD   │  Contains: ADSID, DSID,    │
│                    │         │  GsIdmsToken, Tokens{}     │
│                    └────┬────┘                            │
│                         │                                 │
│              ┌──────────┼──────────┐                      │
│              ▼          ▼          ▼                      │
│          ┌───────┐  ┌───────┐  ┌──────┐                  │
│          │  PET  │  │  HB   │  │ GS   │  (2-4h lifetime) │
│          │ Token │  │ Token │  │Tokens│                   │
│          └───┬───┘  └───────┘  └──────┘                  │
│              │                                            │
│    ┌─────────┼─────────┐                                  │
│    ▼                   ▼                                  │
│ ┌────────────┐   ┌────────────┐                          │
│ │ MobileMe   │   │ IDS        │                          │
│ │ Delegate   │   │ Delegate   │                          │
│ │ (~24h)     │   │ (one-time) │                          │
│ └─────┬──────┘   └────────────┘                          │
│       │                                                   │
│  ┌────┴─────┐                                            │
│  ▼          ▼                                            │
│ CardDAV   CloudKit                                       │
│ Contacts  Operations                                     │
└──────────────────────────────────────────────────────────┘

REFRESH CHAIN (without 2FA, on trusted/provisioned machine):

  Stored Hash + Anisette
       │
       ▼
  SRP login_email_pass()  ──→  Fresh SPD + Fresh PET (+ HB, GS)
       │                        (no 2FA required if machine is trusted)
       ▼
  login_apple_delegates()  ──→  Fresh MobileMe Delegate
       │
       ▼
  CardDAV / CloudKit work again
```

**The refresh chain in plain words:**

1. **Hashed password** + fresh anisette → `login_email_pass()` → new PET (if machine trusted, no 2FA)
2. **PET** + ADSID → `login_apple_delegates()` → new MobileMe delegate (mmeAuthToken)
3. **mmeAuthToken** + DSID → iCloud API calls (CardDAV, CloudKit)

Each layer has its own lifetime:
- PET: ~2-4 hours
- mmeAuthToken: ~24 hours
- Hashed password: indefinite (until user changes password)

---

## 3. How a Real Apple Device Maintains Persistent Auth

A real Apple device (iPhone, Mac) never re-prompts for 2FA after the initial
setup. Here is how it achieves this:

### 3.1 Machine Provisioning (Anisette/ADI)

When you first sign into iCloud on a Mac, the `akd` (AuthKit Daemon) process:
1. Generates a machine identity via Apple's ADI (Apple Device Identity) framework
2. Provisions this identity with Apple's servers (`midStartProvisioning` / `midFinishProvisioning`)
3. Stores the provisioned state locally (in the Keychain on macOS, in `state/anisette/` in our case)

This establishes the machine as a "known device" with a unique `X-Mme-Device-Id`.

### 3.2 Trusted Device Status

After the user completes 2FA verification, Apple marks the combination of:
- The machine identity (anisette provisioned state)
- The Apple ID account

...as "trusted." This trust is stored server-side. The key factors that
maintain trust are:
- **Consistent machine identity**: Same `X-Mme-Device-Id`, same `X-Apple-I-MD-M`
- **Same anisette provisioning**: The machine's ADI provisioned state hasn't been reset

### 3.3 Token Refresh Without 2FA

On a trusted device, the token refresh cycle works like this:

1. **Periodic SRP re-authentication**: `akd` periodically calls the GSA endpoint
   with the stored password (from Keychain). Because the machine is trusted,
   the server returns `LoginState::LoggedIn` directly — no `au` field requesting
   `trustedDeviceSecondaryAuth` or `secondaryAuth`.

2. **Fresh tokens from SPD**: Each SRP login produces a fresh SPD containing
   new PET, HB, and GS tokens with fresh expiry times.

3. **Delegate refresh**: The fresh PET is used to call `login_apple_delegates()`
   for fresh MobileMe delegate tokens.

4. **Continuous operation**: This cycle repeats every few hours, well within
   token lifetimes, keeping all services authenticated indefinitely.

### 3.4 When Trust Is Lost

Trust can be lost when:
- The anisette provisioning state is deleted/corrupted
- Apple detects anomalous behavior from the machine identity
- The user changes their Apple ID password
- Apple revokes the machine identity (rare, but happens with abusive patterns)
- Too many failed authentication attempts

When trust is lost, the next SRP login will return
`LoginState::NeedsDevice2FA` or `LoginState::NeedsSMS2FA`, requiring user
interaction.

### 3.5 pyicloud's Approach (Web Session, Different Protocol)

For reference, pyicloud uses a **different authentication protocol** — the iCloud
web session API (`idmsa.apple.com`), not GSA. It uses:
- HTTP cookies for session persistence
- A `trust_token` / `X-Apple-TwoSV-Trust-Token` header to establish trust
- Session cookies that last approximately **2 months** before requiring re-auth

This is the web equivalent of device trust. The `trust_session()` call after
2FA is what pyicloud documentation refers to when it says "Authentication will
expire after an interval set by Apple, at which point you will have to
re-authenticate. This interval is currently two months."

Our bridge uses the **native GSA/SRP protocol** (like a real Apple device),
not the web API. The trust mechanism is different — it's based on anisette
machine provisioning rather than HTTP cookies.

---

## 4. Our Current (Broken) Flow Analyzed

### 4.1 Login (Works Correctly)

```
1. User enters Apple ID + password + 2FA code
2. login_email_pass() → SRP handshake → SPD with tokens (PET, HB, etc.)
3. verify_2fa() or verify_sms_2fa() → fresh PET with real server-provided duration
4. login_apple_delegates() with PET → MobileMe delegate (mmeAuthToken)
5. Store everything: username, hashed_password, PET, SPD, ADSID, DSID, MobileMe delegate JSON
```

**This is correct.** At this point, all tokens are fresh and valid.

### 4.2 Restore (Broken)

```
1. restore_token_provider() is called with stored credentials
2. Creates fresh anisette provider ✓
3. Creates AppleAccount, sets username + hashed_password + SPD ✓
4. Injects stored PET with FAKE 30-day expiry ← PROBLEM #1
5. Seeds cached MobileMe delegate JSON ← partial workaround
6. TokenProvider.get_mme_token() is called for CardDAV
7. If within 2h of seeding, uses cached delegate ← MAY WORK temporarily
8. After 2h, or on first call if cache expired, calls refresh_mme()
9. refresh_mme() tries login_apple_delegates() with stored PET ← FAILS (PET expired server-side)
10. Falls back to login_email_pass() with hashed password ← FAILS with -22406
11. All iCloud services dead
```

### 4.3 Why the Seeded MobileMe Delegate Sometimes Works

The bridge seeds the last-known MobileMe delegate JSON on restore. If the
bridge restarts quickly (within ~24 hours of the delegate being fetched) and
the 2-hour refresh timer hasn't fired, the cached mmeAuthToken may still be
valid server-side. CardDAV calls work.

But as soon as `get_mme_token()` decides to refresh (after 2 hours), it calls
`refresh_mme()`, which needs a valid PET — and the stored PET is long expired.

---

## 5. Root Cause of the 401s

There are **two distinct failures**:

### Failure 1: Expired PET used for delegate refresh

The PET stored at login time has a real server-side lifetime of ~2-4 hours.
Our code injects it with a fake 30-day client-side expiry, which means
`get_token("com.apple.gs.idms.pet")` doesn't attempt to refresh it (it thinks
it's still valid). But when this stale PET is sent to
`setup.icloud.com/setup/authenticate`, Apple's server rejects it.

**Location:** `restore_token_provider()` in `pkg/rustpushgo/src/lib.rs:636-639`
```rust
account.tokens.insert("com.apple.gs.idms.pet".to_string(), icloud_auth::FetchedToken {
    token: pet,
    expiration: std::time::SystemTime::now() + std::time::Duration::from_secs(60 * 60 * 24 * 30), // 30 days ← WRONG
});
```

### Failure 2: SRP re-auth triggers 2FA requirement (error -22406)

When the PET-based refresh fails, `refresh_mme()` falls back to
`login_email_pass()` with the stored hashed password. This performs a fresh
SRP handshake. However, the server returns an error because **the machine is
not trusted** (or trust has been lost), so 2FA is required.

Error -22406 maps to an Apple authentication error indicating that additional
verification is needed. The GSA server returns this when:
- The machine identity (anisette) is not recognized as trusted
- The account requires 2FA and the current session hasn't completed it
- The anisette provisioning state has changed since the initial login

---

## 6. Error -22406 Explained

Error code `-22406` in Apple's GSA protocol corresponds to
**"Authentication required" or "Unauthorized"** — it means the SRP
authentication itself succeeded (password was correct), but the server won't
issue tokens without additional verification (2FA).

This happens when `login_email_pass()` completes the SRP handshake successfully
(M1/M2 verified), but the SPD's `Status.au` field is set to
`trustedDeviceSecondaryAuth` or `secondaryAuth`. In our code, this would
normally return `LoginState::NeedsDevice2FA` or `LoginState::NeedsSMS2FA`.

However, looking at the code in `refresh_mme()`, the fallback calls
`login_email_pass()` and checks for `LoginState::LoggedIn`. If it gets anything
else (like `NeedsDevice2FA`), it falls through to the error path.

**The -22406 error suggests that the SRP handshake itself is failing at the
`check_error()` stage** — before even getting to the `Status.au` check. This
can happen when:
1. The anisette state is stale or the machine identity is blacklisted
2. The account has been locked or flagged
3. The hashed password format is wrong for the current `s2k`/`s2k_fo` protocol
   variant selected by the server

**Most likely cause:** The anisette machine identity is either not provisioned
correctly on restore, or Apple doesn't recognize it as trusted. The `default_provider()`
call in `restore_token_provider()` creates a fresh anisette provider from disk
state, but if that state is corrupted or was never properly provisioned, all
subsequent GSA calls will fail.

---

## 7. Recommended Fix

### 7.1 Core Strategy: Use `get_token()` Auto-Refresh

The `AppleAccount::get_token()` method in `icloud-auth/src/client.rs` already
implements the correct refresh logic:

```rust
pub async fn get_token(&mut self, token: &str) -> Option<String> {
    let has_valid_token = if !self.tokens.is_empty() {
        let data = self.tokens.get(token)?;
        data.expiration.elapsed().is_err()  // still valid?
    } else {
        false
    };
    if !has_valid_token {
        // Token expired → re-authenticate with stored password
        let username = self.username.clone()?;
        let hashed_password = self.hashed_password.clone()?;
        match self.login_email_pass(&username, &hashed_password).await {
            Ok(LoginState::LoggedIn) => {},
            _err => {
                error!("Failed to refresh tokens, state {_err:?}");
                return None
            }
        }
    }
    Some(self.tokens.get(token)?.token.to_string())
}
```

This method:
1. Checks if the token is expired (client-side)
2. If expired, calls `login_email_pass()` with stored credentials
3. If the SRP login returns `LoggedIn` (machine is trusted), fresh tokens are issued
4. Returns the fresh token

**The problem is that we bypass this by injecting a fake 30-day expiry.** The
`get_token()` method never fires because it thinks the PET is still valid.

### 7.2 Specific Changes

#### Change 1: Set realistic PET expiry on restore

In `restore_token_provider()`, set the PET expiry to something short (e.g., 0
or 5 minutes) so that the first call to `get_token()` or `refresh_mme()`
triggers a re-authentication:

```rust
// Instead of 30-day fake expiry, set to already-expired or near-expired
account.tokens.insert("com.apple.gs.idms.pet".to_string(), icloud_auth::FetchedToken {
    token: pet,
    expiration: std::time::SystemTime::now(), // expired immediately — forces refresh on first use
});
```

This way, the first call to `refresh_mme()` → `get_gsa_token("com.apple.gs.idms.pet")`
→ `get_token()` will detect the expiry and call `login_email_pass()` to get a
fresh PET.

#### Change 2: Handle 2FA-required state in refresh_mme()

The `refresh_mme()` fallback currently calls `login_email_pass()` and only
handles `LoginState::LoggedIn`. It needs to handle the case where the server
requires 2FA:

```rust
match account.login_email_pass(&username, &password).await {
    Ok(LoginState::LoggedIn) => {
        // Success — machine is trusted, got fresh tokens
        info!("refresh_mme: password re-auth succeeded without 2FA");
    }
    Ok(LoginState::NeedsDevice2FA) | Ok(LoginState::NeedsSMS2FA) => {
        // Machine is NOT trusted — need user interaction
        warn!("refresh_mme: SRP succeeded but server requires 2FA — cannot auto-refresh");
        // Signal to the bridge that re-login is needed
        return Err(PushError::AuthRequires2FA);
    }
    Ok(state) => {
        warn!("refresh_mme: unexpected login state: {:?}", state);
        return Err(PushError::TokenMissing);
    }
    Err(auth_err) => {
        warn!("refresh_mme: SRP auth failed: {}", auth_err);
        return Err(PushError::TokenMissing);
    }
}
```

#### Change 3: Ensure anisette state persistence and consistency

The anisette provisioning state in `state/anisette/` must be preserved across
restarts. Verify that:
1. The anisette directory is not being cleared on restart
2. The same `X-Mme-Device-Id` is used across sessions
3. The anisette provider created in `restore_token_provider()` loads the same
   provisioned state that was used during the original login

If the anisette state is lost, the machine loses its "trusted" status and all
SRP logins will require 2FA. This cannot be fixed without user interaction.

#### Change 4: Propagate fresh PET back to persisted state

When `login_email_pass()` succeeds in `refresh_mme()` and produces a fresh PET,
the bridge should persist the new PET to `UserLoginMetadata.AccountPET` so that
subsequent restarts have a more recent (though still likely expired) PET. This
is a "best effort" — the real fix is the auto-refresh via `get_token()`.

#### Change 5: Proactive PET refresh timer

Instead of waiting for `get_mme_token()` to trigger a refresh after 2 hours,
add a proactive background timer that refreshes the PET every ~1 hour:

```rust
// In TokenProvider, run a background task:
// Every 60 minutes, call get_token("com.apple.gs.idms.pet")
// This keeps the PET fresh and prevents cascading expiry
```

This ensures the PET is always fresh when `refresh_mme()` needs it.

### 7.3 Expected Behavior After Fix

**On machine where trust is maintained:**
```
1. Bridge starts, restore_token_provider() sets up account
2. PET injected with immediate expiry
3. First get_mme_token() triggers refresh_mme()
4. refresh_mme() calls get_gsa_token() → get_token() detects PET expired
5. get_token() calls login_email_pass() → SRP succeeds → LoginState::LoggedIn
6. Fresh PET returned → refresh_mme() fetches fresh MobileMe delegate
7. CardDAV works. CloudKit works. Everything works.
8. Every 2 hours, cycle repeats automatically.
```

**On machine where trust is lost:**
```
1-4. Same as above
5. get_token() calls login_email_pass() → LoginState::NeedsDevice2FA
6. get_token() returns None → refresh_mme() fails
7. Bridge signals "re-login required" to user
8. User re-enters 2FA code → trust re-established → normal operation resumes
```

---

## 8. Alternative Approaches Considered

### 8.1 Store and re-use the raw PET for longer

**Won't work.** The PET has a server-enforced lifetime. No amount of client-side
expiry manipulation will make the server accept an expired PET.

### 8.2 Use iCloud web session API (like pyicloud) instead of GSA

Theoretically possible. The web API uses `trust_token` cookies that last ~2
months. However:
- Our entire auth stack (IDS registration, circle auth, postdata) is built on GSA
- The web API is designed for browser-like clients, not device-like clients
- Switching would require a massive rewrite
- The web API may not provide all the delegate types we need (IDS specifically)

**Not recommended.**

### 8.3 Store the user's raw password

Would allow us to always re-authenticate, but:
- Massive security risk
- We already store the hashed password, which is functionally equivalent for SRP
- The hash + anisette trust should be sufficient

**Not needed — hashed password already serves this purpose.**

### 8.4 Never let the PET expire by refreshing proactively

This is part of the recommended fix (Change 5). By refreshing the PET every
~1 hour (well within its ~2-4 hour lifetime), we prevent the situation where
the PET expires and the stored one is the only fallback.

---

## 9. Sources

### Primary Sources (Code)

1. **GSA client** — `rustpush/apple-private-apis/icloud-auth/src/client.rs`
   - SRP login flow: `login_email_pass()` (~line 600)
   - Token parsing from SPD: `if let Some(Value::Dictionary(dict)) = decoded_spd.get("t")` (~line 720)
   - PET parsing from 2FA headers: `parse_pet_header()` (~line 990)
   - Auto-refresh: `get_token()` (~line 310)
   - 2FA state detection: `Status.au` field (~line 735)

2. **TokenProvider / MobileMe refresh** — `rustpush/src/auth.rs`
   - `refresh_mme()`: lines ~150-210
   - `get_mme_token()`: 2-hour refresh timer
   - `login_apple_delegates()`: PET-based delegate fetching

3. **Token restoration** — `pkg/rustpushgo/src/lib.rs`
   - `restore_token_provider()`: line ~600
   - Fake 30-day PET expiry: line ~636

4. **Go-side restore** — `pkg/connector/client.go`
   - `Connect()`: TokenProvider restoration and MobileMe delegate seeding

### External References

5. **Blackwood-4NT** (Alex Ionescu) — https://github.com/ionescu007/Blackwood-4NT
   - Definitive documentation of GSA protocol, SPD, PET, ADSID
   - Confirms: "SPD contains the Password Equivalent Token (PET)"
   - Confirms: "Once enrolled [anisette provisioned], further GSA logins will
     no longer require 2FA from the given machine"
   - Confirms: PET used with ADSID for further API authentication

6. **pypush** (JJTech0130) — https://github.com/JJTech0130/pypush
   - Original iMessage reverse-engineering project
   - GSA implementation reference (purchased by Beeper)

7. **pyicloud** (picklepete) — https://github.com/picklepete/pyicloud
   - Documents iCloud web session trust: "Authentication will expire after
     an interval set by Apple... This interval is currently two months"
   - Uses `trust_session()` after 2FA to establish long-lived web trust
   - **Note:** Uses different auth protocol (web/idmsa) than our bridge (GSA)

8. **Apple GSA Protocol gist** (JJTech0130) — https://gist.github.com/JJTech0130/049716196f5f1751b8944d93e73d3452
   - Python implementation of GSA SRP authentication

9. **MathewYaldo/Apple-GSA-Protocol** — https://github.com/MathewYaldo/Apple-GSA-Protocol
   - Documents GSA endpoint, SRP parameter construction, anisette requirements
   - Notes: "X-Apple-I-MD parameter is time-sensitive and lasts only about 30 seconds"

10. **DeepWiki analysis of pyicloud auth** — https://deepwiki.com/picklepete/pyicloud/2.1-authentication-and-security
    - Documents session persistence headers: `X-Apple-ID-Session-Id`,
      `X-Apple-Session-Token`, `X-Apple-TwoSV-Trust-Token`, `scnt`

---

## Summary

| Question | Answer |
|---|---|
| What is the longest-lived storable credential? | **Hashed password** (indefinite until password change) + **anisette machine identity** (months). Together, these allow PET refresh without 2FA on a trusted machine. |
| Can `login_email_pass()` get a fresh PET without 2FA? | **Yes, if the machine is trusted** (anisette properly provisioned, trust not revoked). If trust is lost, 2FA is required. Error -22406 indicates trust is not established or has been lost. |
| What is the PET lifetime? | **~2-4 hours** (server-controlled). Our 30-day fake expiry is meaningless. |
| What is the MobileMe delegate lifetime? | **~24 hours** (server-controlled). Our 2-hour refresh cycle is appropriate. |
| How does a real Apple device avoid re-prompting for 2FA? | **Machine provisioning** (anisette/ADI) establishes device trust. Subsequent SRP logins from the same provisioned machine skip 2FA. The device periodically re-authenticates with the stored password to get fresh PET tokens. |
| What is the correct refresh chain? | `hashed_password → SRP login → fresh PET → login_apple_delegates() → fresh mmeAuthToken → CardDAV/CloudKit` |
| Is persistent auth without 2FA possible? | **Yes**, as long as the anisette machine identity is preserved and Apple hasn't revoked trust. If trust is lost, the user must complete 2FA once to re-establish it. |
| What's the primary fix needed? | Stop injecting fake 30-day PET expiry. Let `get_token()` auto-refresh work by setting realistic/expired PET expiry on restore. Ensure anisette state persists correctly across restarts. |
