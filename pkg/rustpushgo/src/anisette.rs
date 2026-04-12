//! Wrapper-level anisette provider for Linux.
//!
//! # Why this exists
//!
//! Upstream `omnisette::remote_anisette_v3::AnisetteClient::provision` opens
//! a WebSocket to `wss://ani.sidestore.io/v3/provisioning_session` and
//! deserializes server messages into a closed `ProvisionInput` enum:
//!
//! ```ignore
//! #[derive(Deserialize)]
//! #[serde(tag = "result")]
//! enum ProvisionInput {
//!     GiveIdentifier,
//!     GiveStartProvisioningData,
//!     GiveEndProvisioningData { cpim: String },
//!     ProvisioningSuccess { adi_pb: String },
//! }
//! ```
//!
//! If the server returns any other `result` — e.g. `EndProvisioningError`
//! after Apple rejects the end-provisioning step — serde crashes with
//! `unknown variant` and login dies with an opaque parse error. This path
//! fires on *fresh provisioning* (no `state.plist`) and *re-provisioning*
//! after mid-session state expiry.
//!
//! We can't patch upstream, and we don't want to re-implement the entire
//! provider. So this module replaces **only `provision()`** — we reuse
//! upstream's `AnisetteClient::new()` and `AnisetteClient::get_headers()`
//! verbatim and intercept provisioning in both code paths (initial and
//! retry-after-AnisetteNotProvisioned) by owning the `AnisetteProvider`
//! impl ourselves.
//!
//! Our `BridgeAnisetteProvider`:
//!   1. Owns the `state.plist` file lifecycle.
//!   2. Runs its own WebSocket provisioning dance with proper error
//!      handling for any `result` variant (not just the four upstream
//!      knows about).
//!   3. Persists state in upstream's exact on-disk format so upstream's
//!      `AnisetteClient::get_headers` consumes it without modification.
//!   4. Re-runs our provisioning in the retry path if upstream's
//!      `get_headers` returns `AnisetteNotProvisioned`.
//!
//! Net effect: upstream's broken `provision()` is never called, on any
//! code path — initial, retry, restore. The rest of omnisette is
//! unchanged.

use std::collections::HashMap;
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{SubsecRound, Utc};
use futures_util::{SinkExt, StreamExt};
use log::{debug, info, warn};
use omnisette::{AnisetteError, AnisetteProvider, LoginClientInfo};
use omnisette::remote_anisette_v3::{AnisetteClient, AnisetteState};
use plist::{Data, Dictionary, Value};
use rand::Rng;
use reqwest::{Certificate, ClientBuilder, RequestBuilder};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use uuid::Uuid;

/// Apple root cert bundled by upstream icloud-auth — we need the same
/// trust anchor to talk to `gsa.apple.com` during provisioning.
const APPLE_ROOT: &[u8] = include_bytes!(
    "../../../third_party/rustpush-upstream/apple-private-apis/icloud-auth/src/apple_root.der"
);

const ANISETTE_URL: &str = "https://ani.sidestore.io";

// ---------------------------------------------------------------------------
// On-disk state format — MUST match upstream `AnisetteState` byte-for-byte
// so `plist::from_file::<AnisetteState>` reads what we write.
// ---------------------------------------------------------------------------

fn bin_serialize<S>(x: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bytes(x)
}

fn bin_serialize_opt<S>(x: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    x.clone().map(Data::new).serialize(s)
}

fn bin_deserialize_opt<'de, D>(d: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<Data> = Deserialize::deserialize(d)?;
    Ok(s.map(|i| i.into()))
}

fn bin_deserialize_16<'de, D>(d: D) -> Result<[u8; 16], D::Error>
where
    D: Deserializer<'de>,
{
    let s: Data = Deserialize::deserialize(d)?;
    let s: Vec<u8> = s.into();
    s.try_into()
        .map_err(|v: Vec<u8>| serde::de::Error::custom(format!("expected 16 bytes, got {}", v.len())))
}

/// On-disk mirror of upstream `AnisetteState`. Plist field layout must
/// match exactly — see the `bin_serialize*` / `bin_deserialize*` helpers
/// copied from upstream `omnisette/src/remote_anisette_v3.rs`.
#[derive(Serialize, Deserialize)]
struct BridgeAnisetteState {
    #[serde(serialize_with = "bin_serialize", deserialize_with = "bin_deserialize_16")]
    keychain_identifier: [u8; 16],
    #[serde(serialize_with = "bin_serialize_opt", deserialize_with = "bin_deserialize_opt")]
    adi_pb: Option<Vec<u8>>,
}

impl BridgeAnisetteState {
    fn fresh() -> Self {
        Self {
            keychain_identifier: rand::thread_rng().gen(),
            adi_pb: None,
        }
    }

    fn md_lu(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.keychain_identifier);
        hasher.finalize().into()
    }

    fn device_id(&self) -> String {
        Uuid::from_bytes(self.keychain_identifier).to_string()
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// The provisioning dance
// ---------------------------------------------------------------------------

fn make_reqwest() -> Result<reqwest::Client, AnisetteError> {
    Ok(ClientBuilder::new()
        .http1_title_case_headers()
        .add_root_certificate(Certificate::from_der(APPLE_ROOT)?)
        .build()?)
}

fn build_apple_request(
    info: &LoginClientInfo,
    state: &BridgeAnisetteState,
    mut builder: RequestBuilder,
) -> RequestBuilder {
    let dt = Utc::now().round_subsecs(0);
    builder = builder
        .header("User-Agent", &info.akd_user_agent)
        .header("X-Apple-Baa-E", "-10000")
        .header("X-Apple-I-MD-LU", encode_hex(&state.md_lu()))
        .header("X-Mme-Device-Id", state.device_id())
        .header("X-Apple-Baa-Avail", "2")
        .header("X-Mme-Client-Info", &info.mme_client_info)
        .header("X-Apple-I-Client-Time", dt.format("%+").to_string())
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("X-Apple-Client-App-Name", "akd")
        .header("Accept", "*/*")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header(
            "X-Apple-Baa-UE",
            "AKAuthenticationError:-7066|com.apple.devicecheck.error.baa:-10000",
        )
        .header("X-Apple-Host-Baa-E", "-7066");

    for (k, v) in &info.hardware_headers {
        builder = builder.header(k, v);
    }
    builder
}

fn plist_to_string<T: Serialize>(value: &T) -> Result<String, plist::Error> {
    let mut buf: Vec<u8> = Vec::new();
    plist::to_writer_xml(Cursor::new(&mut buf), value)?;
    Ok(String::from_utf8(buf).expect("plist xml is valid utf8"))
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ProvisionBodyData {
    header: Dictionary,
    request: Dictionary,
}

/// Run the WebSocket provisioning dance against `ani.sidestore.io`,
/// populating `state.adi_pb` on success. Returns a descriptive
/// `AnisetteError` on any error — including server-reported variants
/// upstream's enum doesn't recognize (e.g. `EndProvisioningError`).
async fn run_provision(
    info: &LoginClientInfo,
    state: &mut BridgeAnisetteState,
) -> Result<(), AnisetteError> {
    info!("anisette: running bridge-level provisioning");
    let http = make_reqwest()?;

    // 1. GET lookup → Apple returns provisioning URLs
    let lookup_text = build_apple_request(
        info,
        state,
        http.get("https://gsa.apple.com/grandslam/GsService2/lookup"),
    )
    .send()
    .await?
    .text()
    .await?;
    let lookup_val = Value::from_reader(Cursor::new(lookup_text.as_str()))
        .map_err(AnisetteError::PlistError)?;
    let urls = lookup_val
        .as_dictionary()
        .and_then(|d| d.get("urls"))
        .and_then(|u| u.as_dictionary())
        .ok_or_else(|| {
            AnisetteError::InvalidArgument("lookup: no urls dict".into())
        })?;
    let start_url = urls
        .get("midStartProvisioning")
        .and_then(|v| v.as_string())
        .ok_or_else(|| {
            AnisetteError::InvalidArgument("lookup: no midStartProvisioning".into())
        })?
        .to_string();
    let end_url = urls
        .get("midFinishProvisioning")
        .and_then(|v| v.as_string())
        .ok_or_else(|| {
            AnisetteError::InvalidArgument("lookup: no midFinishProvisioning".into())
        })?
        .to_string();
    debug!("anisette: got provisioning urls");

    // 2. Open provisioning WebSocket
    let ws_url =
        format!("{}/v3/provisioning_session", ANISETTE_URL).replace("https://", "wss://");
    let (mut ws, _) = connect_async(&ws_url).await?;

    // 3. Dance. Parse `result` loosely so unknown variants become a
    //    clean error instead of a serde crash.
    loop {
        let Some(frame) = ws.next().await else {
            return Err(AnisetteError::InvalidArgument(
                "provisioning WS closed before ProvisioningSuccess".into(),
            ));
        };
        let frame = frame?;
        if frame.is_close() {
            return Err(AnisetteError::InvalidArgument(
                "provisioning WS closed before ProvisioningSuccess".into(),
            ));
        }
        if !frame.is_text() {
            continue;
        }
        let txt = frame.to_text().unwrap_or("").to_string();
        let msg_json: serde_json::Value = serde_json::from_str(&txt)?;
        let result = msg_json
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AnisetteError::InvalidArgument(format!("no result field in WS msg: {txt}"))
            })?;

        match result {
            "GiveIdentifier" => {
                #[derive(Serialize)]
                struct Identifier {
                    identifier: String,
                }
                let id = Identifier {
                    identifier: B64.encode(state.keychain_identifier),
                };
                ws.send(Message::Text(serde_json::to_string(&id)?)).await?;
            }
            "GiveStartProvisioningData" => {
                let http = make_reqwest()?;
                let body = ProvisionBodyData {
                    header: Dictionary::new(),
                    request: Dictionary::new(),
                };
                let text = build_apple_request(info, state, http.post(&start_url))
                    .body(plist_to_string(&body).map_err(AnisetteError::PlistError)?)
                    .send()
                    .await?
                    .text()
                    .await?;
                let val = Value::from_reader(Cursor::new(text.as_str()))
                    .map_err(AnisetteError::PlistError)?;
                let spim = val
                    .as_dictionary()
                    .and_then(|d| d.get("Response"))
                    .and_then(|r| r.as_dictionary())
                    .and_then(|r| r.get("spim"))
                    .and_then(|s| s.as_string())
                    .ok_or_else(|| {
                        AnisetteError::InvalidArgument(
                            "start_provisioning: no spim in response".into(),
                        )
                    })?
                    .to_string();

                #[derive(Serialize)]
                struct SpimMsg {
                    spim: String,
                }
                ws.send(Message::Text(serde_json::to_string(&SpimMsg { spim })?))
                    .await?;
            }
            "GiveEndProvisioningData" => {
                let cpim = msg_json
                    .get("cpim")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        AnisetteError::InvalidArgument(
                            "GiveEndProvisioningData without cpim".into(),
                        )
                    })?
                    .to_string();

                let http = make_reqwest()?;
                let body = ProvisionBodyData {
                    header: Dictionary::new(),
                    request: Dictionary::from_iter([("cpim", cpim)].into_iter()),
                };
                let text = build_apple_request(info, state, http.post(&end_url))
                    .body(plist_to_string(&body).map_err(AnisetteError::PlistError)?)
                    .send()
                    .await?
                    .text()
                    .await?;
                let val = Value::from_reader(Cursor::new(text.as_str()))
                    .map_err(AnisetteError::PlistError)?;
                let response = val
                    .as_dictionary()
                    .and_then(|d| d.get("Response"))
                    .and_then(|r| r.as_dictionary())
                    .ok_or_else(|| {
                        AnisetteError::InvalidArgument(
                            "end_provisioning: no Response dict".into(),
                        )
                    })?;
                let ptm = response
                    .get("ptm")
                    .and_then(|v| v.as_string())
                    .ok_or_else(|| {
                        AnisetteError::InvalidArgument("end_provisioning: no ptm".into())
                    })?
                    .to_string();
                let tk = response
                    .get("tk")
                    .and_then(|v| v.as_string())
                    .ok_or_else(|| {
                        AnisetteError::InvalidArgument("end_provisioning: no tk".into())
                    })?
                    .to_string();

                #[derive(Serialize)]
                struct EndProvisioning {
                    ptm: String,
                    tk: String,
                }
                ws.send(Message::Text(serde_json::to_string(&EndProvisioning {
                    ptm,
                    tk,
                })?))
                .await?;
            }
            "ProvisioningSuccess" => {
                let adi_pb_b64 = msg_json
                    .get("adi_pb")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        AnisetteError::InvalidArgument(
                            "ProvisioningSuccess without adi_pb".into(),
                        )
                    })?;
                let adi_pb = B64.decode(adi_pb_b64.trim()).map_err(|e| {
                    AnisetteError::InvalidArgument(format!("bad adi_pb base64: {e}"))
                })?;
                state.adi_pb = Some(adi_pb);
                let _ = ws.close(None).await;
                info!("anisette: ProvisioningSuccess");
                return Ok(());
            }
            other => {
                // EndProvisioningError (or any future variant) → clean error.
                warn!("anisette: server returned unhandled variant {other}: {txt}");
                return Err(AnisetteError::InvalidArgument(format!(
                    "anisette server rejected provisioning (result={other}). \
                     This is typically upstream rate-limiting or Apple-side refusal at \
                     ani.sidestore.io — not a bridge bug. Try again shortly, or delete \
                     state/anisette/ to get a fresh identifier."
                )));
            }
        }
    }
}

/// Persist our state to `state.plist` in upstream's exact on-disk format,
/// then read it back as upstream's `AnisetteState` (which has private
/// fields — we can't construct one directly, but `plist::from_file` works).
fn persist_and_reload(
    state_path: &PathBuf,
    state: &BridgeAnisetteState,
) -> Result<AnisetteState, AnisetteError> {
    fs::create_dir_all(state_path)?;
    let state_plist = state_path.join("state.plist");
    plist::to_file_xml(&state_plist, state).map_err(AnisetteError::PlistError)?;
    let reloaded: AnisetteState =
        plist::from_file(&state_plist).map_err(AnisetteError::PlistError)?;
    Ok(reloaded)
}

// ---------------------------------------------------------------------------
// The provider — implements `omnisette::AnisetteProvider`
// ---------------------------------------------------------------------------

/// Wrapper-level anisette provider for Linux. Uses upstream
/// `AnisetteClient::new` + `AnisetteClient::get_headers` unchanged, and
/// substitutes our own `provision()` implementation everywhere.
pub struct BridgeAnisetteProvider {
    info: LoginClientInfo,
    state_path: PathBuf,
    /// Upstream's `AnisetteState`, populated from disk (either a pre-existing
    /// `state.plist` or the one our `run_provision` wrote and we re-read).
    state: Option<AnisetteState>,
}

impl BridgeAnisetteProvider {
    pub fn new(info: LoginClientInfo, state_path: PathBuf) -> Self {
        Self {
            info,
            state_path,
            state: None,
        }
    }

    /// Make sure `self.state` contains a provisioned upstream `AnisetteState`.
    async fn ensure_state(&mut self) -> Result<(), AnisetteError> {
        // Already have in-memory provisioned state
        if let Some(s) = &self.state {
            if s.is_provisioned() {
                return Ok(());
            }
        }

        // Try to read an existing on-disk state.
        let state_plist = self.state_path.join("state.plist");
        if state_plist.exists() {
            match plist::from_file::<_, AnisetteState>(&state_plist) {
                Ok(upstream_state) if upstream_state.is_provisioned() => {
                    info!(
                        "anisette: reusing existing provisioned state at {}",
                        state_plist.display()
                    );
                    self.state = Some(upstream_state);
                    return Ok(());
                }
                Ok(_) => {
                    info!(
                        "anisette: existing state at {} is not provisioned, regenerating",
                        state_plist.display()
                    );
                }
                Err(e) => {
                    warn!(
                        "anisette: existing state at {} failed to parse ({}), regenerating",
                        state_plist.display(),
                        e
                    );
                }
            }
        }

        // Fresh provisioning via our own dance.
        let mut fresh = BridgeAnisetteState::fresh();
        run_provision(&self.info, &mut fresh).await?;
        self.state = Some(persist_and_reload(&self.state_path, &fresh)?);
        Ok(())
    }

    /// Force a re-provisioning pass, discarding any cached/on-disk state.
    /// Used when upstream `get_headers` returns `AnisetteNotProvisioned`
    /// (i.e. the server rejected our adi_pb mid-session).
    async fn force_reprovision(&mut self) -> Result<(), AnisetteError> {
        warn!("anisette: forcing re-provisioning (previous state rejected)");
        self.state = None;
        let mut fresh = BridgeAnisetteState::fresh();
        run_provision(&self.info, &mut fresh).await?;
        self.state = Some(persist_and_reload(&self.state_path, &fresh)?);
        Ok(())
    }
}

impl AnisetteProvider for BridgeAnisetteProvider {
    fn get_anisette_headers(
        &mut self,
    ) -> impl std::future::Future<Output = Result<HashMap<String, String>, AnisetteError>> + Send
    {
        async move {
            self.ensure_state().await?;

            // Construct upstream's client (trivially cheap — just holds a
            // URL and a `LoginClientInfo` clone).
            let client =
                AnisetteClient::new(ANISETTE_URL.to_string(), self.info.clone()).await?;

            // First attempt with cached state.
            let state_ref = self.state.as_ref().expect("ensure_state populated state");
            match client.get_headers(state_ref).await {
                Ok(data) => Ok(data.get_headers()),
                Err(AnisetteError::AnisetteNotProvisioned) => {
                    // Server rejected our adi_pb — re-provision and retry once.
                    self.force_reprovision().await?;
                    let state_ref = self.state.as_ref().expect("force_reprovision populated state");
                    let data = client.get_headers(state_ref).await?;
                    Ok(data.get_headers())
                }
                Err(e) => Err(e),
            }
        }
    }
}
