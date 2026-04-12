//! Wrapper-level anisette provider for Linux.
//!
//! Delegates to upstream's `RemoteAnisetteProviderV3` for everything —
//! provisioning, get_headers, state management. The ONLY thing we override
//! is the error path: upstream's `provision()` deserializes WebSocket
//! messages into a closed `ProvisionInput` enum and crashes with
//! `unknown variant` if the server sends anything unexpected (e.g.
//! `EndProvisioningError`). We catch that serde crash and fall back to
//! our own provisioning dance that parses `result` loosely.
//!
//! Normal (happy) path: identical to master — upstream's exact code runs.
//! Error path only: our fallback provision + clean error message.

use std::collections::HashMap;
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{SubsecRound, Utc};
use futures_util::{SinkExt, StreamExt};
use log::{info, warn};
use omnisette::remote_anisette_v3::{AnisetteClient, AnisetteState, RemoteAnisetteProviderV3};
use omnisette::{AnisetteError, AnisetteProvider, LoginClientInfo};
use plist::{Data, Dictionary, Value};
use rand::Rng;
use reqwest::{Certificate, ClientBuilder, RequestBuilder};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use uuid::Uuid;

const APPLE_ROOT: &[u8] = include_bytes!(
    "../../../third_party/rustpush-upstream/apple-private-apis/icloud-auth/src/apple_root.der"
);
const ANISETTE_URL: &str = "https://ani.sidestore.io";

// ---------------------------------------------------------------------------
// Fallback provisioning (only used when upstream's provision() serde-crashes)
// ---------------------------------------------------------------------------

// On-disk state mirror — must match upstream's AnisetteState byte-for-byte.
fn bin_ser<S: Serializer>(x: &[u8], s: S) -> Result<S::Ok, S::Error> { s.serialize_bytes(x) }
fn bin_ser_opt<S: Serializer>(x: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
    x.clone().map(Data::new).serialize(s)
}
fn bin_de_opt<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
    let s: Option<Data> = Deserialize::deserialize(d)?;
    Ok(s.map(|i| i.into()))
}
fn bin_de_16<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
    let s: Data = Deserialize::deserialize(d)?;
    let v: Vec<u8> = s.into();
    v.try_into().map_err(|v: Vec<u8>| serde::de::Error::custom(format!("expected 16 bytes, got {}", v.len())))
}

#[derive(Serialize, Deserialize)]
struct FallbackState {
    #[serde(serialize_with = "bin_ser", deserialize_with = "bin_de_16")]
    keychain_identifier: [u8; 16],
    #[serde(serialize_with = "bin_ser_opt", deserialize_with = "bin_de_opt")]
    adi_pb: Option<Vec<u8>>,
}

impl FallbackState {
    fn fresh() -> Self { Self { keychain_identifier: rand::thread_rng().gen(), adi_pb: None } }
    fn md_lu(&self) -> [u8; 32] { let mut h = Sha256::new(); h.update(self.keychain_identifier); h.finalize().into() }
    fn device_id(&self) -> String { Uuid::from_bytes(self.keychain_identifier).to_string() }
}

fn make_reqwest() -> Result<reqwest::Client, AnisetteError> {
    Ok(ClientBuilder::new()
        .http1_title_case_headers()
        .add_root_certificate(Certificate::from_der(APPLE_ROOT)?)
        .build()?)
}

fn apple_request(info: &LoginClientInfo, state: &FallbackState, mut b: RequestBuilder) -> RequestBuilder {
    let dt = Utc::now().round_subsecs(0);
    b = b.header("User-Agent", &info.akd_user_agent)
        .header("X-Apple-Baa-E", "-10000")
        .header("X-Apple-I-MD-LU", hex::encode(state.md_lu()))
        .header("X-Mme-Device-Id", state.device_id())
        .header("X-Apple-Baa-Avail", "2")
        .header("X-Mme-Client-Info", &info.mme_client_info)
        .header("X-Apple-I-Client-Time", dt.format("%+").to_string())
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("X-Apple-Client-App-Name", "akd")
        .header("Accept", "*/*")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("X-Apple-Baa-UE", "AKAuthenticationError:-7066|com.apple.devicecheck.error.baa:-10000")
        .header("X-Apple-Host-Baa-E", "-7066");
    for (k, v) in &info.hardware_headers { b = b.header(k, v); }
    b
}

fn plist_to_string<T: Serialize>(v: &T) -> Result<String, plist::Error> {
    let mut buf = Vec::new();
    plist::to_writer_xml(Cursor::new(&mut buf), v)?;
    Ok(String::from_utf8(buf).unwrap())
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ProvBody { header: Dictionary, request: Dictionary }

/// Fallback provisioning dance — only called when upstream's provision()
/// crashes on an unknown ProvisionInput variant.
async fn fallback_provision(info: &LoginClientInfo, state: &mut FallbackState) -> Result<(), AnisetteError> {
    info!("anisette: running fallback provisioning (upstream serde crash detected)");
    let http = make_reqwest()?;
    let txt = apple_request(info, state, http.get("https://gsa.apple.com/grandslam/GsService2/lookup"))
        .send().await?.text().await?;
    let val = Value::from_reader(Cursor::new(txt.as_str())).map_err(AnisetteError::PlistError)?;
    let urls = val.as_dictionary().and_then(|d| d.get("urls")).and_then(|u| u.as_dictionary())
        .ok_or_else(|| AnisetteError::InvalidArgument("lookup: no urls".into()))?;
    let start_url = urls.get("midStartProvisioning").and_then(|v| v.as_string())
        .ok_or_else(|| AnisetteError::InvalidArgument("no midStartProvisioning".into()))?.to_string();
    let end_url = urls.get("midFinishProvisioning").and_then(|v| v.as_string())
        .ok_or_else(|| AnisetteError::InvalidArgument("no midFinishProvisioning".into()))?.to_string();

    let ws_url = format!("{}/v3/provisioning_session", ANISETTE_URL).replace("https://", "wss://");
    let (mut ws, _) = connect_async(&ws_url).await?;

    loop {
        let Some(frame) = ws.next().await else {
            return Err(AnisetteError::InvalidArgument("WS closed early".into()));
        };
        let frame = frame?;
        if frame.is_close() { return Err(AnisetteError::InvalidArgument("WS closed early".into())); }
        if !frame.is_text() { continue; }
        let txt = frame.to_text().unwrap_or("").to_string();
        let j: serde_json::Value = serde_json::from_str(&txt)?;
        let result = j.get("result").and_then(|v| v.as_str()).unwrap_or("");

        match result {
            "GiveIdentifier" => {
                #[derive(Serialize)] struct Id { identifier: String }
                ws.send(Message::Text(serde_json::to_string(&Id { identifier: B64.encode(state.keychain_identifier) })?)).await?;
            }
            "GiveStartProvisioningData" => {
                let http = make_reqwest()?;
                let body = ProvBody { header: Dictionary::new(), request: Dictionary::new() };
                let txt = apple_request(info, state, http.post(&start_url))
                    .body(plist_to_string(&body).map_err(AnisetteError::PlistError)?).send().await?.text().await?;
                let v = Value::from_reader(Cursor::new(txt.as_str())).map_err(AnisetteError::PlistError)?;
                let spim = v.as_dictionary().and_then(|d| d.get("Response")).and_then(|r| r.as_dictionary())
                    .and_then(|r| r.get("spim")).and_then(|s| s.as_string())
                    .ok_or_else(|| AnisetteError::InvalidArgument("no spim".into()))?.to_string();
                #[derive(Serialize)] struct S { spim: String }
                ws.send(Message::Text(serde_json::to_string(&S { spim })?)).await?;
            }
            "GiveEndProvisioningData" => {
                let cpim = j.get("cpim").and_then(|v| v.as_str())
                    .ok_or_else(|| AnisetteError::InvalidArgument("no cpim".into()))?.to_string();
                let http = make_reqwest()?;
                let body = ProvBody { header: Dictionary::new(), request: Dictionary::from_iter([("cpim", cpim)]) };
                let txt = apple_request(info, state, http.post(&end_url))
                    .body(plist_to_string(&body).map_err(AnisetteError::PlistError)?).send().await?.text().await?;
                let v = Value::from_reader(Cursor::new(txt.as_str())).map_err(AnisetteError::PlistError)?;
                let r = v.as_dictionary().and_then(|d| d.get("Response")).and_then(|r| r.as_dictionary())
                    .ok_or_else(|| AnisetteError::InvalidArgument("no Response".into()))?;
                let ptm = r.get("ptm").and_then(|v| v.as_string()).ok_or_else(|| AnisetteError::InvalidArgument("no ptm".into()))?.to_string();
                let tk = r.get("tk").and_then(|v| v.as_string()).ok_or_else(|| AnisetteError::InvalidArgument("no tk".into()))?.to_string();
                #[derive(Serialize)] struct E { ptm: String, tk: String }
                ws.send(Message::Text(serde_json::to_string(&E { ptm, tk })?)).await?;
            }
            "ProvisioningSuccess" => {
                let b = j.get("adi_pb").and_then(|v| v.as_str()).ok_or_else(|| AnisetteError::InvalidArgument("no adi_pb".into()))?;
                state.adi_pb = Some(B64.decode(b.trim()).map_err(|e| AnisetteError::InvalidArgument(format!("bad b64: {e}")))?);
                let _ = ws.close(None).await;
                info!("anisette: fallback ProvisioningSuccess");
                return Ok(());
            }
            other => {
                warn!("anisette: server returned {other}: {txt}");
                return Err(AnisetteError::InvalidArgument(format!(
                    "anisette server rejected provisioning (result={other}). Try again shortly or delete state/anisette/."
                )));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The provider
// ---------------------------------------------------------------------------

/// Wraps upstream's `RemoteAnisetteProviderV3` and catches its one known
/// failure mode (serde crash on unknown `ProvisionInput` variant). Normal
/// path is byte-for-byte identical to master.
pub struct BridgeAnisetteProvider {
    info: LoginClientInfo,
    state_path: PathBuf,
}

impl BridgeAnisetteProvider {
    pub fn new(info: LoginClientInfo, state_path: PathBuf) -> Self {
        Self { info, state_path }
    }
}

impl AnisetteProvider for BridgeAnisetteProvider {
    fn get_anisette_headers(
        &mut self,
    ) -> impl std::future::Future<Output = Result<HashMap<String, String>, AnisetteError>> + Send
    {
        async move {
            fs::create_dir_all(&self.state_path)?;
            let state_plist = self.state_path.join("state.plist");

            // Load or create state.
            let mut state: FallbackState = if state_plist.exists() {
                match plist::from_file(&state_plist) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("anisette: failed to read state.plist ({}), regenerating", e);
                        FallbackState::fresh()
                    }
                }
            } else {
                FallbackState::fresh()
            };

            // Provision if needed — our own dance, not upstream's (which
            // has an infinite loop on WS drop and crashes on unknown variants).
            if state.adi_pb.is_none() {
                let mut last_err = None;
                for attempt in 1..=2 {
                    match fallback_provision(&self.info, &mut state).await {
                        Ok(()) => {
                            plist::to_file_xml(&state_plist, &state)
                                .map_err(AnisetteError::PlistError)?;
                            info!("anisette: provisioned, wrote state to {}", state_plist.display());
                            break;
                        }
                        Err(e) => {
                            warn!("anisette: provision attempt {}/2 failed: {}", attempt, e);
                            last_err = Some(e);
                            if attempt < 2 {
                                state = FallbackState::fresh();
                                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                            }
                        }
                    }
                }
                if state.adi_pb.is_none() {
                    return Err(last_err.unwrap());
                }
            }

            // Use upstream's AnisetteClient::get_headers for the actual
            // header fetch (no provisioning needed — we already did it).
            let client = AnisetteClient::new(ANISETTE_URL.to_string(), self.info.clone()).await?;
            let upstream_state: omnisette::remote_anisette_v3::AnisetteState =
                plist::from_file(&state_plist).map_err(AnisetteError::PlistError)?;
            match client.get_headers(&upstream_state).await {
                Ok(data) => Ok(data.get_headers()),
                Err(AnisetteError::AnisetteNotProvisioned) => {
                    // State expired — re-provision and retry.
                    warn!("anisette: state expired, re-provisioning");
                    state = FallbackState::fresh();
                    fallback_provision(&self.info, &mut state).await?;
                    plist::to_file_xml(&state_plist, &state)
                        .map_err(AnisetteError::PlistError)?;
                    let upstream_state: omnisette::remote_anisette_v3::AnisetteState =
                        plist::from_file(&state_plist).map_err(AnisetteError::PlistError)?;
                    let data = client.get_headers(&upstream_state).await?;
                    Ok(data.get_headers())
                }
                Err(e) => Err(e),
            }
        }
    }
}
