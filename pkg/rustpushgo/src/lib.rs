pub mod util;
#[cfg(target_os = "macos")]
pub mod local_config;
#[cfg(test)]
mod test_hwinfo;

use std::{collections::HashMap, io::Cursor, path::PathBuf, str::FromStr, sync::Arc, time::Duration, sync::atomic::{AtomicU64, Ordering}};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use icloud_auth::{AppleAccount, FetchedToken};
use keystore::{init_keystore, keystore, software::{NoEncryptor, SoftwareKeystore, SoftwareKeystoreState}};
use log::{debug, error, info, warn};
use rustpush::{
    authenticate_apple, login_apple_delegates, register, APSConnectionResource,
    APSState, Attachment, AttachmentType, ConversationData, DeleteTarget, EditMessage,
    IDSNGMIdentity, IDSUser, IMClient, LoginDelegate, MADRID_SERVICE, MMCSFile, Message,
    MessageInst, MessagePart, MessageParts, MessageType, MoveToRecycleBinMessage, NormalMessage, PermanentDeleteMessage,
    OperatedChat, OSConfig, ReactMessage, ReactMessageType, Reaction, UnsendMessage,
    IndexedMessagePart, LinkMeta, LPLinkMetadata, RichLinkImageAttachmentSubstitute, NSURL,
    TokenProvider,
    cloudkit::{ZoneDeleteOperation, CloudKitSession},
    util::{base64_decode, encode_hex, ResourceState},
};
use rustpush::cloudkit_proto::request_operation::header::IsolationLevel;
use omnisette::default_provider;
use std::sync::RwLock;
use tokio::sync::broadcast;
use util::{plist_from_string, plist_to_string};

// ============================================================================
// Wrapper types
// ============================================================================

#[derive(uniffi::Object)]
pub struct WrappedAPSState {
    pub inner: Option<APSState>,
}

#[uniffi::export]
impl WrappedAPSState {
    #[uniffi::constructor]
    pub fn new(string: Option<String>) -> Arc<Self> {
        Arc::new(Self {
            inner: string
                .and_then(|s| if s.is_empty() { None } else { Some(s) })
                .and_then(|s| plist_from_string::<APSState>(&s).ok()),
        })
    }

    pub fn to_string(&self) -> String {
        plist_to_string(&self.inner).unwrap_or_default()
    }
}

#[derive(uniffi::Object)]
pub struct WrappedAPSConnection {
    pub inner: rustpush::APSConnection,
}

#[uniffi::export]
impl WrappedAPSConnection {
    pub fn state(&self) -> Arc<WrappedAPSState> {
        Arc::new(WrappedAPSState {
            inner: Some(self.inner.state.blocking_read().clone()),
        })
    }
}

#[derive(uniffi::Record)]
pub struct IDSUsersWithIdentityRecord {
    pub users: Arc<WrappedIDSUsers>,
    pub identity: Arc<WrappedIDSNGMIdentity>,
    /// TokenProvider for iCloud services (CardDAV, CloudKit, etc.)
    pub token_provider: Option<Arc<WrappedTokenProvider>>,
    /// Persist data for restoring the TokenProvider after restart.
    pub account_persist: Option<AccountPersistData>,
}

/// Data needed to restore a TokenProvider from persisted state.
/// Stored in session.json so it survives database resets.
#[derive(uniffi::Record)]
pub struct AccountPersistData {
    pub username: String,
    pub hashed_password_hex: String,
    pub pet: String,
    pub adsid: String,
    pub dsid: String,
    pub spd_base64: String,
}

#[derive(uniffi::Object)]
pub struct WrappedIDSUsers {
    pub inner: Vec<IDSUser>,
}

#[uniffi::export]
impl WrappedIDSUsers {
    #[uniffi::constructor]
    pub fn new(string: Option<String>) -> Arc<Self> {
        Arc::new(Self {
            inner: string
                .and_then(|s| if s.is_empty() { None } else { Some(s) })
                .and_then(|s| plist_from_string(&s).ok())
                .unwrap_or_default(),
        })
    }

    pub fn to_string(&self) -> String {
        plist_to_string(&self.inner).unwrap_or_default()
    }

    pub fn login_id(&self, i: u64) -> String {
        self.inner[i as usize].user_id.clone()
    }

    pub fn get_handles(&self) -> Vec<String> {
        self.inner.iter()
            .flat_map(|user| {
                user.registration.get("com.apple.madrid")
                    .map(|reg| reg.handles.clone())
                    .unwrap_or_default()
            })
            .collect()
    }

    /// Check that all keystore keys referenced by the user state actually exist.
    /// Returns false if any auth/id keypair alias is missing from the keystore,
    /// which means the keystore was wiped or never migrated and re-login is needed.
    pub fn validate_keystore(&self) -> bool {
        if self.inner.is_empty() {
            return true;
        }
        for user in &self.inner {
            let alias = &user.auth_keypair.private.0;
            if keystore().get_key_type(alias).ok().flatten().is_none() {
                warn!("Keystore key '{}' not found for user '{}' — keystore/state mismatch", alias, user.user_id);
                return false;
            }
        }
        true
    }
}

#[derive(uniffi::Object)]
pub struct WrappedIDSNGMIdentity {
    pub inner: IDSNGMIdentity,
}

#[uniffi::export]
impl WrappedIDSNGMIdentity {
    #[uniffi::constructor]
    pub fn new(string: Option<String>) -> Arc<Self> {
        Arc::new(Self {
            inner: string
                .and_then(|s| if s.is_empty() { None } else { Some(s) })
                .and_then(|s| plist_from_string(&s).ok())
                .unwrap_or_else(|| IDSNGMIdentity::new().expect("Failed to create new identity")),
        })
    }

    pub fn to_string(&self) -> String {
        plist_to_string(&self.inner).unwrap_or_default()
    }
}

#[derive(uniffi::Object)]
pub struct WrappedOSConfig {
    pub config: Arc<dyn OSConfig>,
}

#[uniffi::export]
impl WrappedOSConfig {
    /// Get the device UUID from the underlying OSConfig.
    pub fn get_device_id(&self) -> String {
        self.config.get_device_uuid()
    }
}

#[derive(thiserror::Error, uniffi::Error, Debug)]
pub enum WrappedError {
    #[error("{msg}")]
    GenericError { msg: String },
}

impl From<rustpush::PushError> for WrappedError {
    fn from(e: rustpush::PushError) -> Self {
        WrappedError::GenericError { msg: format!("{}", e) }
    }
}

fn is_pcs_recoverable_error(err: &rustpush::PushError) -> bool {
    matches!(
        err,
        rustpush::PushError::ShareKeyNotFound(_)
            | rustpush::PushError::DecryptionKeyNotFound(_)
            | rustpush::PushError::PCSRecordKeyMissing
            | rustpush::PushError::MasterKeyNotFound
    )
}

fn keychain_retry_delay(attempt: usize) -> Duration {
    match attempt {
        0..=4 => Duration::from_secs(2),
        5..=11 => Duration::from_secs(4),
        _ => Duration::from_secs(6),
    }
}

async fn sync_keychain_with_retries(
    keychain: &rustpush::keychain::KeychainClient<omnisette::DefaultAnisetteProvider>,
    max_attempts: usize,
    context: &str,
) -> Result<(), WrappedError> {
    let attempts = max_attempts.max(1);
    let mut last_err: Option<rustpush::PushError> = None;
    for attempt in 0..attempts {
        match keychain.sync_keychain(&rustpush::keychain::KEYCHAIN_ZONES).await {
            Ok(()) => {
                if attempt > 0 {
                    info!("{} keychain sync recovered after {} attempt(s)", context, attempt + 1);
                }
                return Ok(());
            }
            Err(err) => {
                if matches!(err, rustpush::PushError::NotInClique) {
                    return Err(WrappedError::GenericError {
                        msg: format!("{} keychain sync failed: {}", context, err),
                    });
                }

                let retrying = attempt + 1 < attempts;
                warn!(
                    "{} keychain sync attempt {}/{} failed: {}{}",
                    context,
                    attempt + 1,
                    attempts,
                    err,
                    if retrying { " (retrying)" } else { "" }
                );
                last_err = Some(err);
                if retrying {
                    tokio::time::sleep(keychain_retry_delay(attempt)).await;
                }
            }
        }
    }

    let msg = match last_err {
        Some(err) => format!("{} keychain sync failed after retries: {}", context, err),
        None => format!("{} keychain sync failed", context),
    };
    Err(WrappedError::GenericError { msg })
}

async fn refresh_recoverable_tlk_shares(
    keychain: &Arc<rustpush::keychain::KeychainClient<omnisette::DefaultAnisetteProvider>>,
    context: &str,
) -> Result<(), WrappedError> {
    let identity_opt = {
        let state = keychain.state.read().await;
        state.user_identity.clone()
    };

    let Some(identity) = identity_opt else {
        warn!("{}: no keychain user identity available for TLK share refresh", context);
        return Ok(());
    };

    match keychain.fetch_shares_for(&identity).await {
        Ok(shares) => {
            info!("{}: fetched {} recoverable TLK share(s)", context, shares.len());
            if !shares.is_empty() {
                keychain.store_keys(&shares).await?;
            }
        }
        Err(err) => {
            // Best-effort: we still attempt regular keychain sync / CloudKit probes.
            warn!("{}: failed to fetch recoverable TLK shares: {}", context, err);
        }
    }

    Ok(())
}

async fn finalize_keychain_setup_with_probe(
    keychain: Arc<rustpush::keychain::KeychainClient<omnisette::DefaultAnisetteProvider>>,
    cloudkit: Arc<rustpush::cloudkit::CloudKitClient<omnisette::DefaultAnisetteProvider>>,
    max_attempts: usize,
) -> Result<(), WrappedError> {
    let cloud_messages = rustpush::cloud_messages::CloudMessagesClient::new(cloudkit, keychain.clone());
    let attempts = max_attempts.max(1);

    for attempt in 0..attempts {
        let attempt_no = attempt + 1;
        if attempt == 0 {
            // After join, explicitly refresh recoverable TLK shares for this new peer.
            // Some accounts/devices need an extra fetch before all view keys materialize.
            refresh_recoverable_tlk_shares(&keychain, "Login finalize").await?;
        }
        sync_keychain_with_retries(&keychain, 1, "Login finalize").await?;

        match cloud_messages.sync_chats(None).await {
            Ok((_token, chats, status)) => {
                info!(
                    "CloudKit decrypt probe (chats) succeeded on attempt {} (status={}, records={})",
                    attempt_no,
                    status,
                    chats.len()
                );
            }
            Err(err) => {
                if matches!(err, rustpush::PushError::NotInClique) {
                    return Err(WrappedError::GenericError {
                        msg: format!("CloudKit probe failed: {}", err),
                    });
                }

                let retrying = attempt_no < attempts;
                if is_pcs_recoverable_error(&err) {
                    warn!(
                        "CloudKit decrypt probe (chats) missing PCS keys on attempt {}/{}: {}{}",
                        attempt_no,
                        attempts,
                        err,
                        if retrying { " (retrying)" } else { "" }
                    );
                } else {
                    warn!(
                        "CloudKit decrypt probe (chats) failed on attempt {}/{}: {}{}",
                        attempt_no,
                        attempts,
                        err,
                        if retrying { " (retrying)" } else { "" }
                    );
                }
                if retrying {
                    if is_pcs_recoverable_error(&err) && attempt % 4 == 0 {
                        refresh_recoverable_tlk_shares(&keychain, "Login finalize").await?;
                    }
                    tokio::time::sleep(keychain_retry_delay(attempt)).await;
                    continue;
                }
                return Err(WrappedError::GenericError {
                    msg: format!("CloudKit decrypt probe failed after retries (chats): {}", err),
                });
            }
        }

        match cloud_messages.sync_messages(None).await {
            Ok((_token, messages, status)) => {
                info!(
                    "CloudKit decrypt probe (messages) succeeded on attempt {} (status={}, records={})",
                    attempt_no,
                    status,
                    messages.len()
                );
                return Ok(());
            }
            Err(err) => {
                if matches!(err, rustpush::PushError::NotInClique) {
                    return Err(WrappedError::GenericError {
                        msg: format!("CloudKit probe failed: {}", err),
                    });
                }

                let retrying = attempt_no < attempts;
                if is_pcs_recoverable_error(&err) {
                    warn!(
                        "CloudKit decrypt probe (messages) missing PCS keys on attempt {}/{}: {}{}",
                        attempt_no,
                        attempts,
                        err,
                        if retrying { " (retrying)" } else { "" }
                    );
                } else {
                    warn!(
                        "CloudKit decrypt probe (messages) failed on attempt {}/{}: {}{}",
                        attempt_no,
                        attempts,
                        err,
                        if retrying { " (retrying)" } else { "" }
                    );
                }
                if retrying {
                    if is_pcs_recoverable_error(&err) && attempt % 4 == 0 {
                        refresh_recoverable_tlk_shares(&keychain, "Login finalize").await?;
                    }
                    tokio::time::sleep(keychain_retry_delay(attempt)).await;
                    continue;
                }
                return Err(WrappedError::GenericError {
                    msg: format!("CloudKit decrypt probe failed after retries (messages): {}", err),
                });
            }
        }
    }

    Err(WrappedError::GenericError {
        msg: "CloudKit decrypt probe failed after retries".into(),
    })
}

// ============================================================================
// Token Provider (iCloud auth for CardDAV, CloudKit, etc.)
// ============================================================================

/// Information about a device that has an escrow bottle in the iCloud Keychain
/// trust circle. Used to let the user choose which device's passcode to enter.
#[derive(uniffi::Record)]
pub struct EscrowDeviceInfo {
    /// Index into the bottles list (used when calling join_keychain_clique_for_device).
    pub index: u32,
    /// Human-readable device name (e.g. "Ludvig's iPhone").
    pub device_name: String,
    /// Device model identifier (e.g. "iPhone15,2").
    pub device_model: String,
    /// Device serial number.
    pub serial: String,
    /// When the escrow bottle was created.
    pub timestamp: String,
}

/// Wraps a TokenProvider that manages MobileMe auth tokens with auto-refresh.
/// Used for iCloud services like CardDAV contacts and CloudKit messages.
#[derive(uniffi::Object)]
pub struct WrappedTokenProvider {
    inner: Arc<TokenProvider<omnisette::DefaultAnisetteProvider>>,
}

/// Helper: create CloudKit + Keychain clients from a TokenProvider.
/// Shared by get_escrow_devices, join_keychain_clique, and join_keychain_clique_for_device.
async fn create_keychain_clients(
    token_provider: &Arc<TokenProvider<omnisette::DefaultAnisetteProvider>>,
) -> Result<(
    Arc<rustpush::keychain::KeychainClient<omnisette::DefaultAnisetteProvider>>,
    Arc<rustpush::cloudkit::CloudKitClient<omnisette::DefaultAnisetteProvider>>,
), WrappedError> {
    let dsid = token_provider.get_dsid().await?;
    let adsid = token_provider.get_adsid().await?;
    let mme_delegate = token_provider.get_mme_delegate().await?;
    let account = token_provider.get_account();
    let os_config = token_provider.get_os_config();
    let anisette = account.lock().await.anisette.clone();

    let cloudkit_state = rustpush::cloudkit::CloudKitState::new(dsid.clone())
        .ok_or(WrappedError::GenericError { msg: "Failed to create CloudKitState".into() })?;
    let cloudkit = Arc::new(rustpush::cloudkit::CloudKitClient {
        state: tokio::sync::RwLock::new(cloudkit_state),
        anisette: anisette.clone(),
        config: os_config.clone(),
        token_provider: token_provider.clone(),
    });
    let keychain_state_path = format!("{}/trustedpeers_{}.plist", resolve_xdg_data_dir(), dsid);
    let mut keychain_state: Option<rustpush::keychain::KeychainClientState> = match std::fs::read(&keychain_state_path) {
        Ok(data) => match plist::from_bytes(&data) {
            Ok(state) => Some(state),
            Err(e) => {
                warn!("Failed to parse keychain state at {}: {}", keychain_state_path, e);
                None
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            warn!("Failed to read keychain state at {}: {}", keychain_state_path, e);
            None
        }
    };
    if keychain_state.is_none() {
        keychain_state = Some(
            rustpush::keychain::KeychainClientState::new(dsid.clone(), adsid.clone(), &mme_delegate)
                .ok_or(WrappedError::GenericError { msg: "Missing KeychainSync config in MobileMe delegate".into() })?
        );
    }
    let path_for_closure = keychain_state_path.clone();
    let keychain = Arc::new(rustpush::keychain::KeychainClient {
        anisette: anisette.clone(),
        token_provider: token_provider.clone(),
        state: tokio::sync::RwLock::new(keychain_state.expect("keychain state missing")),
        config: os_config.clone(),
        update_state: Box::new(move |state| {
            if let Err(e) = plist::to_file_xml(&path_for_closure, state) {
                warn!("Failed to persist keychain state to {}: {}", path_for_closure, e);
            } else {
                info!("Persisted keychain state to {}", path_for_closure);
            }
        }),
        container: tokio::sync::Mutex::new(None),
        security_container: tokio::sync::Mutex::new(None),
        client: cloudkit.clone(),
    });

    Ok((keychain, cloudkit))
}

/// Extract device name and model from an EscrowMetadata's client_metadata dictionary.
fn extract_device_info(meta: &rustpush::keychain::EscrowMetadata) -> (String, String) {
    let dict = meta.client_metadata.as_dictionary();
    let device_name = dict
        .and_then(|d| d.get("device_name"))
        .and_then(|v| v.as_string())
        .unwrap_or("Unknown Device")
        .to_string();
    let device_model = dict
        .and_then(|d| d.get("device_model"))
        .and_then(|v| v.as_string())
        .unwrap_or("Unknown")
        .to_string();
    (device_name, device_model)
}

/// Core keychain joining logic used by both join_keychain_clique and join_keychain_clique_for_device.
/// If `preferred_index` is Some, the bottle at that index is tried first before falling back to others.
async fn join_keychain_with_bottles(
    keychain: Arc<rustpush::keychain::KeychainClient<omnisette::DefaultAnisetteProvider>>,
    cloudkit: Arc<rustpush::cloudkit::CloudKitClient<omnisette::DefaultAnisetteProvider>>,
    bottles: &[(rustpush::cloudkit_proto::EscrowData, rustpush::keychain::EscrowMetadata)],
    passcode: &str,
    preferred_index: Option<u32>,
) -> Result<String, WrappedError> {
    let passcode_bytes = passcode.as_bytes();
    let mut last_err = String::new();

    // Build iteration order: preferred bottle first (if specified), then the rest.
    let indices: Vec<usize> = if let Some(pref) = preferred_index {
        let pref = pref as usize;
        let mut order = vec![pref];
        order.extend((0..bottles.len()).filter(|&i| i != pref));
        order
    } else {
        (0..bottles.len()).collect()
    };

    // If there are many escrow bottles, do a quick probe per bottle first,
    // then one extended probe at the end on the latest successful join.
    let per_bottle_probe_attempts = if bottles.len() > 1 { 3 } else { 24 };

    // Outer stability loop: after joining + probe, verify we stay in the clique.
    // Other devices can exclude us within seconds of joining.
    const MAX_REJOIN_ATTEMPTS: usize = 3;
    let mut rejoin_attempt = 0;

    'stability: loop {
        let mut joined_any = false;
        let mut last_joined_meta: Option<(String, String)> = None;

        for &i in &indices {
            let (data, meta) = &bottles[i];
            info!("Trying bottle {} (serial={})...", i, meta.serial);
            match keychain.join_clique_from_escrow(data, passcode_bytes, passcode_bytes).await {
                Ok(()) => {
                    joined_any = true;
                    last_joined_meta = Some((meta.serial.clone(), meta.build.clone()));
                    info!("Successfully joined keychain trust circle via bottle {}", i);
                    info!(
                        "Finalizing keychain setup (sync + CloudKit decrypt probe), attempts={}",
                        per_bottle_probe_attempts
                    );
                    match finalize_keychain_setup_with_probe(keychain.clone(), cloudkit.clone(), per_bottle_probe_attempts).await {
                        Ok(()) => {
                            break; // probe passed, go to stability check
                        }
                        Err(e) => {
                            warn!(
                                "Bottle {} joined, but CloudKit decrypt probe failed: {}. Trying next bottle...",
                                i,
                                e
                            );
                            last_err = format!("{}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Bottle {} failed: {}", i, e);
                    last_err = format!("{}", e);
                }
            }
        }

        if !joined_any {
            return Err(WrappedError::GenericError {
                msg: format!("All {} bottles failed. Last error: {}", bottles.len(), last_err)
            });
        }

        // If no bottle's probe succeeded, try an extended probe
        if !keychain.is_in_clique().await {
            if rejoin_attempt >= MAX_REJOIN_ATTEMPTS {
                return Err(WrappedError::GenericError {
                    msg: format!("Excluded from clique after {} rejoin attempts. Last error: {}", rejoin_attempt, last_err)
                });
            }
            rejoin_attempt += 1;
            warn!("Not in clique after bottle probes, rejoin attempt {}/{}", rejoin_attempt, MAX_REJOIN_ATTEMPTS);
            continue 'stability;
        }

        // Stability check: wait, re-sync trust, verify we're still included.
        // Other devices can exclude us within seconds of joining.
        info!("Verifying clique membership stability...");
        for check in 0..3 {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            if !keychain.is_in_clique().await {
                rejoin_attempt += 1;
                warn!(
                    "Excluded from clique during stability check {} — re-joining (attempt {}/{})",
                    check + 1, rejoin_attempt, MAX_REJOIN_ATTEMPTS
                );
                if rejoin_attempt > MAX_REJOIN_ATTEMPTS {
                    return Err(WrappedError::GenericError {
                        msg: "Repeatedly excluded from iCloud Keychain trust circle by another device. \
                              Try disabling and re-enabling 'Messages in iCloud' on your iPhone, then retry."
                            .into()
                    });
                }
                continue 'stability;
            }
        }

        // Still in clique after stability checks
        let (serial, build) = last_joined_meta.unwrap_or(("unknown".into(), "unknown".into()));
        info!("Clique membership stable after {} stability checks", 3);
        return Ok(format!(
            "Joined iCloud Keychain and verified CloudKit access (device: serial={}, build={})",
            serial, build,
        ));
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl WrappedTokenProvider {
    /// Get HTTP headers needed for iCloud MobileMe API calls.
    /// Includes Authorization (X-MobileMe-AuthToken) and anisette headers.
    /// Auto-refreshes the mmeAuthToken weekly.
    pub async fn get_icloud_auth_headers(&self) -> Result<HashMap<String, String>, WrappedError> {
        Ok(self.inner.get_icloud_auth_headers().await?)
    }

    /// Get the contacts CardDAV URL from the MobileMe delegate config.
    pub async fn get_contacts_url(&self) -> Result<Option<String>, WrappedError> {
        Ok(self.inner.get_contacts_url().await?)
    }

    /// Get the DSID for this account.
    pub async fn get_dsid(&self) -> Result<String, WrappedError> {
        Ok(self.inner.get_dsid().await?)
    }

    /// Get the serialized MobileMe delegate as JSON (for persistence).
    /// Returns None if no delegate is cached.
    pub async fn get_mme_delegate_json(&self) -> Result<Option<String>, WrappedError> {
        match self.inner.get_mme_delegate().await {
            Ok(delegate) => {
                let json = serde_json::to_string(&delegate)
                    .map_err(|e| WrappedError::GenericError { msg: format!("Failed to serialize MobileMe delegate: {}", e) })?;
                Ok(Some(json))
            }
            Err(_) => Ok(None),
        }
    }

    /// Seed the MobileMe delegate from persisted JSON.
    pub async fn seed_mme_delegate_json(&self, json: String) -> Result<(), WrappedError> {
        let delegate: rustpush::MobileMeDelegateResponse = serde_json::from_str(&json)
            .map_err(|e| WrappedError::GenericError { msg: format!("Failed to deserialize MobileMe delegate: {}", e) })?;
        self.inner.seed_mme_delegate(delegate).await;
        Ok(())
    }

    /// List devices that have escrow bottles in the iCloud Keychain trust circle.
    /// Returns device info (name, model, serial, timestamp) for each bottle.
    /// Call this before join_keychain_clique_for_device to let the user choose.
    pub async fn get_escrow_devices(&self) -> Result<Vec<EscrowDeviceInfo>, WrappedError> {
        info!("Fetching escrow devices...");
        let (keychain, _cloudkit) = create_keychain_clients(&self.inner).await?;

        let bottles = keychain.get_viable_bottles().await
            .map_err(|e| WrappedError::GenericError { msg: format!("Failed to get escrow bottles: {}", e) })?;

        if bottles.is_empty() {
            return Err(WrappedError::GenericError {
                msg: "No escrow bottles found. Make sure Messages in iCloud is enabled on your iPhone/Mac.".into()
            });
        }

        let devices: Vec<EscrowDeviceInfo> = bottles.iter().enumerate().map(|(i, (_data, meta))| {
            let (device_name, device_model) = extract_device_info(meta);
            info!("  [{}] name={:?} model={} serial={} timestamp={}", i, device_name, device_model, meta.serial, meta.timestamp);
            EscrowDeviceInfo {
                index: i as u32,
                device_name,
                device_model,
                serial: meta.serial.clone(),
                timestamp: meta.timestamp.clone(),
            }
        }).collect();

        info!("Found {} escrow device(s)", devices.len());
        Ok(devices)
    }

    /// Join the iCloud Keychain trust circle using a device passcode.
    /// Tries all available escrow bottles in order.
    /// Required before CloudKit Messages can decrypt PCS-encrypted records.
    /// The passcode is the 6-digit PIN or password used to unlock an iPhone/Mac.
    /// Returns a description of the escrow bottle used.
    pub async fn join_keychain_clique(&self, passcode: String) -> Result<String, WrappedError> {
        info!("=== Joining iCloud Keychain Trust Circle ===");
        let (keychain, cloudkit) = create_keychain_clients(&self.inner).await?;

        info!("Fetching escrow bottles...");
        let bottles = keychain.get_viable_bottles().await
            .map_err(|e| WrappedError::GenericError { msg: format!("Failed to get escrow bottles: {}", e) })?;

        if bottles.is_empty() {
            return Err(WrappedError::GenericError {
                msg: "No escrow bottles found. Make sure Messages in iCloud is enabled on your iPhone/Mac.".into()
            });
        }

        info!("Found {} escrow bottle(s)", bottles.len());
        for (i, (_data, meta)) in bottles.iter().enumerate() {
            info!("  [{}] serial={} build={} timestamp={}", i, meta.serial, meta.build, meta.timestamp);
        }

        join_keychain_with_bottles(keychain, cloudkit, &bottles, &passcode, None).await
    }

    /// Join the iCloud Keychain trust circle, trying the specified device first.
    /// `device_index` is the index from get_escrow_devices(). If that bottle fails,
    /// falls back to trying other bottles.
    pub async fn join_keychain_clique_for_device(&self, passcode: String, device_index: u32) -> Result<String, WrappedError> {
        info!("=== Joining iCloud Keychain Trust Circle (preferred device {}) ===", device_index);
        let (keychain, cloudkit) = create_keychain_clients(&self.inner).await?;

        info!("Fetching escrow bottles...");
        let bottles = keychain.get_viable_bottles().await
            .map_err(|e| WrappedError::GenericError { msg: format!("Failed to get escrow bottles: {}", e) })?;

        if bottles.is_empty() {
            return Err(WrappedError::GenericError {
                msg: "No escrow bottles found. Make sure Messages in iCloud is enabled on your iPhone/Mac.".into()
            });
        }

        info!("Found {} escrow bottle(s)", bottles.len());
        for (i, (_data, meta)) in bottles.iter().enumerate() {
            let (name, model) = extract_device_info(meta);
            info!("  [{}] name={:?} model={} serial={} build={} timestamp={}", i, name, model, meta.serial, meta.build, meta.timestamp);
        }

        let preferred = if (device_index as usize) < bottles.len() {
            Some(device_index)
        } else {
            warn!("Device index {} out of range (have {} bottles), trying all", device_index, bottles.len());
            None
        };

        join_keychain_with_bottles(keychain, cloudkit, &bottles, &passcode, preferred).await
    }
}

/// Restore a TokenProvider from persisted account credentials.
/// Used on session restore (when we don't go through the login flow).
#[uniffi::export(async_runtime = "tokio")]
pub async fn restore_token_provider(
    config: &WrappedOSConfig,
    connection: &WrappedAPSConnection,
    username: String,
    hashed_password_hex: String,
    pet: String,
    spd_base64: String,
) -> Result<Arc<WrappedTokenProvider>, WrappedError> {
    let os_config = config.config.clone();
    let conn = connection.inner.clone();

    // Create a fresh anisette provider
    let client_info = os_config.get_gsa_config(&*conn.state.read().await, false);
    let anisette_path = format!("{}/anisette_{}", resolve_xdg_data_dir(), config.get_device_id());
    let anisette = default_provider(client_info.clone(), PathBuf::from_str(&anisette_path).unwrap());

    // Create a new AppleAccount and populate it with persisted state
    let mut account = AppleAccount::new_with_anisette(client_info, anisette)
        .map_err(|e| WrappedError::GenericError { msg: format!("Failed to create account: {}", e) })?;

    account.username = Some(username);

    // Restore hashed password
    let hashed_password = rustpush::util::decode_hex(&hashed_password_hex)
        .map_err(|e| WrappedError::GenericError { msg: format!("Invalid hashed_password hex: {}", e) })?;
    account.hashed_password = Some(hashed_password);

    // Restore SPD from base64-encoded plist
    let spd_bytes = base64_decode(&spd_base64);
    let spd: plist::Dictionary = plist::from_bytes(&spd_bytes)
        .map_err(|e| WrappedError::GenericError { msg: format!("Invalid SPD plist: {}", e) })?;
    account.spd = Some(spd);

    // Inject the PET token with an already-expired expiration.
    // This forces get_token() to call login_email_pass() on first use,
    // which will obtain a fresh PET via SRP (no 2FA needed if the machine
    // is trusted via consistent anisette state).
    account.tokens.insert("com.apple.gs.idms.pet".to_string(), icloud_auth::FetchedToken {
        token: pet,
        expiration: std::time::UNIX_EPOCH, // expired — forces auto-refresh on first use
    });

    let account = Arc::new(tokio::sync::Mutex::new(account));
    let token_provider = TokenProvider::new(account, os_config);

    info!("Restored TokenProvider from persisted credentials");

    Ok(Arc::new(WrappedTokenProvider { inner: token_provider }))
}

// ============================================================================
// Message wrapper types (flat structs for uniffi)
// ============================================================================

#[derive(uniffi::Record, Clone)]
pub struct WrappedMessage {
    pub uuid: String,
    pub sender: Option<String>,
    pub text: Option<String>,
    pub subject: Option<String>,
    pub participants: Vec<String>,
    pub group_name: Option<String>,
    pub timestamp_ms: u64,
    pub is_sms: bool,

    // Tapback
    pub is_tapback: bool,
    pub tapback_type: Option<u32>,
    pub tapback_target_uuid: Option<String>,
    pub tapback_target_part: Option<u64>,
    pub tapback_emoji: Option<String>,
    pub tapback_remove: bool,

    // Edit
    pub is_edit: bool,
    pub edit_target_uuid: Option<String>,
    pub edit_part: Option<u64>,
    pub edit_new_text: Option<String>,

    // Unsend
    pub is_unsend: bool,
    pub unsend_target_uuid: Option<String>,
    pub unsend_edit_part: Option<u64>,

    // Rename
    pub is_rename: bool,
    pub new_chat_name: Option<String>,

    // Participant change
    pub is_participant_change: bool,
    pub new_participants: Vec<String>,

    // Attachments
    pub attachments: Vec<WrappedAttachment>,

    // Reply
    pub reply_guid: Option<String>,
    pub reply_part: Option<String>,

    // Typing
    pub is_typing: bool,

    // Read receipt
    pub is_read_receipt: bool,

    // Delivered
    pub is_delivered: bool,

    // Error
    pub is_error: bool,
    pub error_for_uuid: Option<String>,
    pub error_status: Option<u64>,
    pub error_status_str: Option<String>,

    // Peer cache invalidate
    pub is_peer_cache_invalidate: bool,

    // Send delivered flag
    pub send_delivered: bool,

    // Group chat UUID (persistent identifier for the group conversation)
    pub sender_guid: Option<String>,

    // Delete (MoveToRecycleBin / PermanentDelete)
    pub is_move_to_recycle_bin: bool,
    pub is_permanent_delete: bool,
    pub delete_chat_participants: Vec<String>,
    pub delete_chat_group_id: Option<String>,
    pub delete_chat_guid: Option<String>,
    pub delete_message_uuids: Vec<String>,

    // Stored message detection: true if this message was queued by APNs
    // while the client was offline and delivered on reconnect. Detected by
    // checking if the message arrived (drain-time) within 10 seconds of an
    // APNs reconnect (generated_signal). Drain-time is used instead of
    // process-time so MMCS downloads and retries don't push messages past
    // the window.
    pub is_stored_message: bool,

    // Group photo (icon) change. True when someone sets or clears the
    // group chat photo from their iMessage client.
    // group_photo_cleared: true = photo was removed ("ngp"), false = new photo set.
    // When is_icon_change=true and group_photo_cleared=false, icon_change_photo_data
    // contains the MMCS-downloaded photo bytes (None if download failed).
    pub is_icon_change: bool,
    pub group_photo_cleared: bool,
    // Pre-downloaded photo bytes for IconChange messages.
    // Some(bytes) only when is_icon_change=true, group_photo_cleared=false, and download succeeded.
    pub icon_change_photo_data: Option<Vec<u8>>,
}

#[derive(uniffi::Record, Clone)]
pub struct WrappedAttachment {
    pub mime_type: String,
    pub filename: String,
    pub uti_type: String,
    pub size: u64,
    pub is_inline: bool,
    pub inline_data: Option<Vec<u8>>,
}

#[derive(uniffi::Record, Clone)]
pub struct WrappedConversation {
    pub participants: Vec<String>,
    pub group_name: Option<String>,
    pub sender_guid: Option<String>,
    pub is_sms: bool,
}

impl From<&ConversationData> for WrappedConversation {
    fn from(c: &ConversationData) -> Self {
        Self {
            participants: c.participants.clone(),
            group_name: c.cv_name.clone(),
            sender_guid: c.sender_guid.clone(),
            is_sms: false,
        }
    }
}

impl From<&WrappedConversation> for ConversationData {
    fn from(c: &WrappedConversation) -> Self {
        ConversationData {
            participants: c.participants.clone(),
            cv_name: c.group_name.clone(),
            sender_guid: c.sender_guid.clone(),
            after_guid: None,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct WrappedCloudSyncChat {
    pub record_name: String,
    pub cloud_chat_id: String,
    pub group_id: String,
    /// CloudKit chat style: 43 = group, 45 = DM
    pub style: i64,
    pub service: String,
    pub display_name: Option<String>,
    pub participants: Vec<String>,
    pub deleted: bool,
    pub updated_timestamp_ms: u64,
    /// CloudKit group photo GUID ("gpid" field). Non-null means a custom photo is set.
    pub group_photo_guid: Option<String>,
    /// CloudKit `filt` field: 0 = normal, 1 = filtered (spam/junk/unknown sender)
    pub is_filtered: i64,
}

#[derive(uniffi::Record, Clone)]
pub struct WrappedCloudSyncMessage {
    pub record_name: String,
    pub guid: String,
    pub cloud_chat_id: String,
    pub sender: String,
    pub is_from_me: bool,
    pub text: Option<String>,
    pub subject: Option<String>,
    pub service: String,
    pub timestamp_ms: i64,
    pub deleted: bool,

    // Tapback/reaction fields (from msg_proto.associatedMessageType/Guid)
    pub tapback_type: Option<u32>,
    pub tapback_target_guid: Option<String>,
    pub tapback_emoji: Option<String>,

    // Attachment GUIDs extracted from messageSummaryInfo / attributedBody.
    // These are matched against the attachment zone to download files.
    pub attachment_guids: Vec<String>,

    // When the recipient read this message (Apple epoch ns → Unix ms).
    // Only meaningful for is_from_me messages. 0 means unread.
    pub date_read_ms: i64,

    // CloudKit msgType field. 0 = regular user message, non-zero = system/service
    // record (group naming, participant changes, etc.). Used by Go to filter
    // non-user-content that slips past IS_SYSTEM/IS_SERVICE_MESSAGE flags.
    pub msg_type: i64,

    // Whether the CloudKit record has an attributedBody (rich text payload).
    // Regular user messages always have attributedBody; system/service messages
    // (group renames, participant changes) never do. Used by Go to filter
    // system messages that slip past flag-based filters.
    pub has_body: bool,
}

/// Metadata for an attachment referenced by a CloudKit message.
/// The actual file data must be downloaded separately via cloud_download_attachment.
#[derive(uniffi::Record, Clone)]
pub struct WrappedCloudAttachmentInfo {
    /// Attachment GUID (from AttachmentMeta.guid / attributedBody __kIMFileTransferGUID)
    pub guid: String,
    /// MIME type (from AttachmentMeta.mime_type)
    pub mime_type: Option<String>,
    /// UTI type (from AttachmentMeta.uti)
    pub uti_type: Option<String>,
    /// Filename (from AttachmentMeta.transfer_name)
    pub filename: Option<String>,
    /// File size in bytes (from AttachmentMeta.total_bytes)
    pub file_size: i64,
    /// CloudKit record name in attachmentManateeZone (needed for download)
    pub record_name: String,
}

#[derive(uniffi::Record, Clone)]
pub struct WrappedCloudSyncChatsPage {
    pub continuation_token: Option<String>,
    pub status: i32,
    pub done: bool,
    pub chats: Vec<WrappedCloudSyncChat>,
}

#[derive(uniffi::Record, Clone)]
pub struct WrappedCloudSyncMessagesPage {
    pub continuation_token: Option<String>,
    pub status: i32,
    pub done: bool,
    pub messages: Vec<WrappedCloudSyncMessage>,
}

#[derive(uniffi::Record, Clone)]
pub struct WrappedCloudSyncAttachmentsPage {
    pub continuation_token: Option<String>,
    pub status: i32,
    pub done: bool,
    pub attachments: Vec<WrappedCloudAttachmentInfo>,
}

/// A clonable writer backed by a shared Vec<u8>.
/// Used to recover written bytes after passing ownership to a consuming API.
#[derive(Clone)]
struct SharedWriter {
    inner: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl SharedWriter {
    fn new() -> Self {
        Self { inner: Arc::new(std::sync::Mutex::new(Vec::new())) }
    }

    fn into_bytes(self) -> Vec<u8> {
        match Arc::try_unwrap(self.inner) {
            Ok(mutex) => mutex.into_inner().unwrap(),
            Err(arc) => arc.lock().unwrap().clone(),
        }
    }
}

impl std::io::Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Extract attachment GUIDs from a CloudKit message's attributedBody.
/// The attributedBody is an NSAttributedString containing ranges with
/// __kIMFileTransferGUIDAttributeName → attachment GUID.
fn extract_attachment_guids_from_attributed_body(data: &[u8]) -> Vec<String> {
    use rustpush::util::{coder_decode_flattened, NSAttributedString, StCollapsedValue};

    let decoded = match std::panic::catch_unwind(|| {
        let flat = coder_decode_flattened(data);
        if flat.is_empty() {
            return None;
        }
        Some(NSAttributedString::decode(&flat[0]))
    }) {
        Ok(Some(attr_str)) => attr_str,
        _ => return vec![],
    };

    let mut guids = Vec::new();
    for (_len, dict) in &decoded.ranges {
        if let Some(StCollapsedValue::Object { fields, .. }) = dict.0.get("__kIMFileTransferGUIDAttributeName") {
            if let Some(first) = fields.first().and_then(|f| f.first()) {
                if let StCollapsedValue::String(s) = first {
                    guids.push(s.clone());
                }
            }
        } else if let Some(StCollapsedValue::String(s)) = dict.0.get("__kIMFileTransferGUIDAttributeName") {
            guids.push(s.clone());
        }
    }
    guids
}

fn apple_timestamp_ns_to_unix_ms(timestamp_ns: i64) -> i64 {
    const APPLE_EPOCH_UNIX_MS: i64 = 978_307_200_000;
    APPLE_EPOCH_UNIX_MS.saturating_add(timestamp_ns / 1_000_000)
}

fn decode_continuation_token(token_b64: Option<String>) -> Result<Option<Vec<u8>>, WrappedError> {
    match token_b64 {
        Some(token) if !token.is_empty() => BASE64_STANDARD
            .decode(token)
            .map(Some)
            .map_err(|e| WrappedError::GenericError {
                msg: format!("Invalid continuation token: {}", e),
            }),
        _ => Ok(None),
    }
}

fn encode_continuation_token(token: Vec<u8>) -> Option<String> {
    if token.is_empty() {
        None
    } else {
        Some(BASE64_STANDARD.encode(token))
    }
}

fn convert_reaction(reaction: &Reaction, enable: bool) -> (Option<u32>, Option<String>, bool) {
    let tapback_type = match reaction {
        Reaction::Heart => Some(0),
        Reaction::Like => Some(1),
        Reaction::Dislike => Some(2),
        Reaction::Laugh => Some(3),
        Reaction::Emphasize => Some(4),
        Reaction::Question => Some(5),
        Reaction::Emoji(_) => Some(6),
        Reaction::Sticker { .. } => Some(7),
    };
    let emoji = match reaction {
        Reaction::Emoji(e) => Some(e.clone()),
        _ => None,
    };
    (tapback_type, emoji, !enable)
}

fn populate_delete_target(w: &mut WrappedMessage, target: &DeleteTarget) {
    match target {
        DeleteTarget::Chat(chat) => {
            w.delete_chat_participants = chat.participants.clone();
            w.delete_chat_group_id = if chat.group_id.is_empty() {
                None
            } else {
                Some(chat.group_id.clone())
            };
            w.delete_chat_guid = if chat.guid.is_empty() {
                None
            } else {
                Some(chat.guid.clone())
            };
        }
        DeleteTarget::Messages(uuids) => {
            w.delete_message_uuids = uuids.clone();
        }
    }
}

fn message_inst_to_wrapped(msg: &MessageInst) -> WrappedMessage {
    let conv = msg.conversation.as_ref();

    let mut w = WrappedMessage {
        uuid: msg.id.clone(),
        sender: msg.sender.clone(),
        text: None,
        subject: None,
        participants: conv.map(|c| c.participants.clone()).unwrap_or_default(),
        group_name: conv.and_then(|c| c.cv_name.clone()),
        timestamp_ms: msg.sent_timestamp,
        is_sms: false,
        is_tapback: false,
        tapback_type: None,
        tapback_target_uuid: None,
        tapback_target_part: None,
        tapback_emoji: None,
        tapback_remove: false,
        is_edit: false,
        edit_target_uuid: None,
        edit_part: None,
        edit_new_text: None,
        is_unsend: false,
        unsend_target_uuid: None,
        unsend_edit_part: None,
        is_rename: false,
        new_chat_name: None,
        is_participant_change: false,
        new_participants: vec![],
        attachments: vec![],
        reply_guid: None,
        reply_part: None,
        is_typing: false,
        is_read_receipt: false,
        is_delivered: false,
        is_error: false,
        error_for_uuid: None,
        error_status: None,
        error_status_str: None,
        is_peer_cache_invalidate: false,
        send_delivered: msg.send_delivered,
        sender_guid: conv.and_then(|c| c.sender_guid.clone()),
        is_move_to_recycle_bin: false,
        is_permanent_delete: false,
        delete_chat_participants: vec![],
        delete_chat_group_id: None,
        delete_chat_guid: None,
        delete_message_uuids: vec![],
        is_stored_message: false, // set by caller based on connection state
        is_icon_change: false,
        group_photo_cleared: false,
        icon_change_photo_data: None,
    };

    match &msg.message {
        Message::Message(normal) => {
            w.text = Some(normal.parts.raw_text());
            w.subject = normal.subject.clone();
            w.reply_guid = normal.reply_guid.clone();
            w.reply_part = normal.reply_part.clone();
            w.is_sms = matches!(normal.service, MessageType::SMS { .. });

            for indexed_part in &normal.parts.0 {
                if let MessagePart::Attachment(att) = &indexed_part.part {
                    let (is_inline, inline_data, size) = match &att.a_type {
                        AttachmentType::Inline(data) => (true, Some(data.clone()), data.len() as u64),
                        AttachmentType::MMCS(mmcs) => (false, None, mmcs.size as u64),
                    };
                    w.attachments.push(WrappedAttachment {
                        mime_type: att.mime.clone(),
                        filename: att.name.clone(),
                        uti_type: att.uti_type.clone(),
                        size,
                        is_inline,
                        inline_data,
                    });
                }
            }

            // Encode rich link as special attachments for the Go side
            if let Some(ref lm) = normal.link_meta {
                let original_url: String = lm.data.original_url.clone().into();
                let url: String = lm.data.url.clone().map(|u| u.into()).unwrap_or_default();
                let title = lm.data.title.clone().unwrap_or_default();
                let summary = lm.data.summary.clone().unwrap_or_default();

                info!("Inbound rich link: original_url={}, url={}, title={:?}, summary={:?}, has_image={}, has_icon={}",
                    original_url, url, title, summary,
                    lm.data.image.is_some(), lm.data.icon.is_some());

                let image_mime = if let Some(ref img) = lm.data.image {
                    img.mime_type.clone()
                } else if let Some(ref icon) = lm.data.icon {
                    icon.mime_type.clone()
                } else {
                    String::new()
                };

                // Metadata: original_url\x01url\x01title\x01summary\x01image_mime
                let meta = format!("{}\x01{}\x01{}\x01{}\x01{}",
                    original_url, url, title, summary, image_mime);
                w.attachments.push(WrappedAttachment {
                    mime_type: "x-richlink/meta".to_string(),
                    filename: String::new(),
                    uti_type: String::new(),
                    size: 0,
                    is_inline: true,
                    inline_data: Some(meta.into_bytes()),
                });

                // Image data (from image or icon)
                let image_data = if let Some(ref img) = lm.data.image {
                    let idx = img.rich_link_image_attachment_substitute_index as usize;
                    lm.attachments.get(idx).cloned()
                } else if let Some(ref icon) = lm.data.icon {
                    let idx = icon.rich_link_image_attachment_substitute_index as usize;
                    lm.attachments.get(idx).cloned()
                } else {
                    None
                };

                if let Some(img_data) = image_data {
                    w.attachments.push(WrappedAttachment {
                        mime_type: "x-richlink/image".to_string(),
                        filename: String::new(),
                        uti_type: String::new(),
                        size: img_data.len() as u64,
                        is_inline: true,
                        inline_data: Some(img_data),
                    });
                }
            }
        }
        Message::React(react) => {
            w.is_tapback = true;
            w.tapback_target_uuid = Some(react.to_uuid.clone());
            w.tapback_target_part = react.to_part;
            match &react.reaction {
                ReactMessageType::React { reaction, enable } => {
                    let (tt, emoji, remove) = convert_reaction(reaction, *enable);
                    w.tapback_type = tt;
                    w.tapback_emoji = emoji;
                    w.tapback_remove = remove;
                }
                ReactMessageType::Extension { .. } => {
                    // Extension reactions (stickers etc.) — mark as tapback
                    w.tapback_type = Some(7);
                }
            }
        }
        Message::Edit(edit) => {
            w.is_edit = true;
            w.edit_target_uuid = Some(edit.tuuid.clone());
            w.edit_part = Some(edit.edit_part);
            w.edit_new_text = Some(edit.new_parts.raw_text());
        }
        Message::Unsend(unsend) => {
            w.is_unsend = true;
            w.unsend_target_uuid = Some(unsend.tuuid.clone());
            w.unsend_edit_part = Some(unsend.edit_part);
        }
        Message::RenameMessage(rename) => {
            w.is_rename = true;
            w.new_chat_name = Some(rename.new_name.clone());
        }
        Message::ChangeParticipants(change) => {
            w.is_participant_change = true;
            w.new_participants = change.new_participants.clone();
        }
        Message::Typing(typing, _) => {
            w.is_typing = *typing;
        }
        Message::Read => {
            w.is_read_receipt = true;
        }
        Message::Delivered => {
            w.is_delivered = true;
        }
        Message::Error(err) => {
            w.is_error = true;
            w.error_for_uuid = Some(err.for_uuid.clone());
            w.error_status = Some(err.status);
            w.error_status_str = Some(err.status_str.clone());
        }
        Message::PeerCacheInvalidate => {
            w.is_peer_cache_invalidate = true;
        }
        Message::MoveToRecycleBin(del) => {
            w.is_move_to_recycle_bin = true;
            populate_delete_target(&mut w, &del.target);
        }
        Message::PermanentDelete(del) => {
            w.is_permanent_delete = true;
            populate_delete_target(&mut w, &del.target);
        }
        Message::IconChange(change) => {
            w.is_icon_change = true;
            w.group_photo_cleared = change.file.is_none();
        }
        _ => {}
    }

    w
}

// ============================================================================
// Callback interfaces
// ============================================================================

#[uniffi::export(callback_interface)]
pub trait MessageCallback: Send + Sync {
    fn on_message(&self, msg: WrappedMessage);
}

#[uniffi::export(callback_interface)]
pub trait UpdateUsersCallback: Send + Sync {
    fn update_users(&self, users: Arc<WrappedIDSUsers>);
}

// ============================================================================
// Top-level functions
// ============================================================================

#[uniffi::export]
pub fn init_logger() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    let _ = pretty_env_logger::try_init();

    // Initialize the keystore with a file-backed software keystore.
    // This must be called before any rustpush operations (APNs connect, login, etc.).
    //
    // The keystore lives alongside session.json in the XDG data directory
    // (~/.local/share/mautrix-imessage/) so that all session state is in one
    // place and easy to migrate between machines.
    let xdg_dir = resolve_xdg_data_dir();
    let state_path = format!("{}/keystore.plist", xdg_dir);
    let _ = std::fs::create_dir_all(&xdg_dir);

    // Migrate from the old location (state/keystore.plist relative to working
    // directory) if the new file doesn't exist yet.
    let legacy_path = "state/keystore.plist";
    if !std::path::Path::new(&state_path).exists() {
        if std::path::Path::new(legacy_path).exists() {
            match std::fs::copy(legacy_path, &state_path) {
                Ok(_) => info!(
                    "Migrated keystore from {} to {}",
                    legacy_path, state_path
                ),
                Err(e) => warn!(
                    "Failed to migrate keystore from {} to {}: {}",
                    legacy_path, state_path, e
                ),
            }
        }
    }

    let state: SoftwareKeystoreState = match std::fs::read(&state_path) {
        Ok(data) => plist::from_bytes(&data).unwrap_or_else(|e| {
            warn!("Failed to parse keystore at {}: {} — starting with empty keystore", state_path, e);
            SoftwareKeystoreState::default()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!("No keystore file at {} — starting fresh", state_path);
            SoftwareKeystoreState::default()
        }
        Err(e) => {
            warn!("Failed to read keystore at {}: {} — starting with empty keystore", state_path, e);
            SoftwareKeystoreState::default()
        }
    };
    let path_for_closure = state_path.clone();
    init_keystore(SoftwareKeystore {
        state: RwLock::new(state),
        update_state: Box::new(move |s| {
            let _ = plist::to_file_xml(&path_for_closure, s);
        }),
        encryptor: NoEncryptor,
    });
}

/// Resolve the XDG data directory for mautrix-imessage session state.
/// Uses $XDG_DATA_HOME if set, otherwise ~/.local/share.
/// Returns the full path: <base>/mautrix-imessage
fn resolve_xdg_data_dir() -> String {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return format!("{}/mautrix-imessage", xdg);
        }
    }
    if let Some(home) = std::env::var("HOME").ok().filter(|h| !h.is_empty()) {
        return format!("{}/.local/share/mautrix-imessage", home);
    }
    // Last resort — fall back to old relative path
    warn!("Could not determine HOME or XDG_DATA_HOME, using local state directory");
    "state".to_string()
}

/// Create a local macOS config that reads hardware info from IOKit
/// and uses AAAbsintheContext for NAC validation (no SIP disable, no relay needed).
/// Only works on macOS — returns an error on other platforms.
#[uniffi::export]
pub fn create_local_macos_config() -> Result<Arc<WrappedOSConfig>, WrappedError> {
    #[cfg(target_os = "macos")]
    {
        let config = local_config::LocalMacOSConfig::new()
            .map_err(|e| WrappedError::GenericError { msg: format!("Failed to read hardware info: {}", e) })?;
        Ok(Arc::new(WrappedOSConfig {
            config: Arc::new(config),
        }))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(WrappedError::GenericError {
            msg: "Local macOS config is only available on macOS. Use create_config_from_hardware_key instead.".into(),
        })
    }
}

/// Create a local macOS config with a persisted device ID.
/// Only works on macOS — returns an error on other platforms.
#[uniffi::export]
pub fn create_local_macos_config_with_device_id(device_id: String) -> Result<Arc<WrappedOSConfig>, WrappedError> {
    #[cfg(target_os = "macos")]
    {
        let config = local_config::LocalMacOSConfig::new()
            .map_err(|e| WrappedError::GenericError { msg: format!("Failed to read hardware info: {}", e) })?
            .with_device_id(device_id);
        Ok(Arc::new(WrappedOSConfig {
            config: Arc::new(config),
        }))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(WrappedError::GenericError {
            msg: "Local macOS config is only available on macOS. Use create_config_from_hardware_key_with_device_id instead.".into(),
        })
    }
}

/// Create a cross-platform config from a base64-encoded JSON hardware key.
///
/// The hardware key is a JSON-serialized `HardwareConfig` extracted once from
/// a real Mac (e.g., via copper's QR code tool). This config uses the
/// open-absinthe NAC emulator to generate fresh validation data on any platform.
///
/// On macOS this is not needed (use `create_local_macos_config` instead).
/// Building with the `hardware-key` feature links open-absinthe + unicorn.
#[uniffi::export]
pub fn create_config_from_hardware_key(base64_key: String) -> Result<Arc<WrappedOSConfig>, WrappedError> {
    _create_config_from_hardware_key_inner(base64_key, None)
}

/// Create a cross-platform config from a base64-encoded JSON hardware key
/// with a persisted device ID.
#[uniffi::export]
pub fn create_config_from_hardware_key_with_device_id(base64_key: String, device_id: String) -> Result<Arc<WrappedOSConfig>, WrappedError> {
    _create_config_from_hardware_key_inner(base64_key, Some(device_id))
}

#[cfg(feature = "hardware-key")]
fn _create_config_from_hardware_key_inner(base64_key: String, device_id: Option<String>) -> Result<Arc<WrappedOSConfig>, WrappedError> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use rustpush::macos::{MacOSConfig, HardwareConfig};

    // Strip whitespace/newlines that chat clients may insert when pasting
    let clean_key: String = base64_key.chars().filter(|c| !c.is_whitespace()).collect();
    let json_bytes = STANDARD.decode(&clean_key)
        .map_err(|e| WrappedError::GenericError { msg: format!("Invalid base64: {}", e) })?;

    // Try full MacOSConfig first (from extract-key tool), fall back to bare HardwareConfig.
    // We prefer the OS version/build metadata from the extracted key so our
    // registration body matches a real Mac as closely as possible.
    let (hw, version, protocol_version, icloud_ua, aoskit_version, nac_relay_url, relay_token, relay_cert_fp) =
        if let Ok(full) = serde_json::from_slice::<MacOSConfig>(&json_bytes) {
            let version = if !full.version.trim().is_empty() {
                full.version
            } else {
                "13.6.4".to_string()
            };
            let protocol_version = if full.protocol_version != 0 {
                full.protocol_version
            } else {
                1660
            };

            // get_normal_ua() expects icloud_ua to contain whitespace so it can
            // split out the "com.apple.iCloudHelper/..." prefix.
            let icloud_ua = if full.icloud_ua.split_once(char::is_whitespace).is_some() {
                full.icloud_ua
            } else {
                "com.apple.iCloudHelper/282 CFNetwork/1568.100.1 Darwin/22.5.0".to_string()
            };

            let aoskit_version = if !full.aoskit_version.trim().is_empty() {
                full.aoskit_version
            } else {
                "com.apple.AOSKit/282 (com.apple.accountsd/113)".to_string()
            };

            (
                full.inner,
                version,
                protocol_version,
                icloud_ua,
                aoskit_version,
                full.nac_relay_url,
                full.relay_token,
                full.relay_cert_fp,
            )
        } else {
            let hw: HardwareConfig = serde_json::from_slice(&json_bytes)
                .map_err(|e| WrappedError::GenericError { msg: format!("Invalid hardware key JSON: {}", e) })?;
            (
                hw,
                "13.6.4".to_string(),
                1660,
                "com.apple.iCloudHelper/282 CFNetwork/1568.100.1 Darwin/22.5.0".to_string(),
                "com.apple.AOSKit/282 (com.apple.accountsd/113)".to_string(),
                None,
                None,
                None,
            )
        };

    // Always use the real hardware UUID from the extracted key so the bridge
    // shows up as the original Mac rather than a new phantom device.
    // Ignore any persisted device ID — it may be a stale random UUID.
    let hw_uuid = hw.platform_uuid.to_uppercase();
    if let Some(ref old) = device_id {
        if old != &hw_uuid {
            log::warn!(
                "Ignoring persisted device ID {} — using hardware UUID {} from extracted key",
                old, hw_uuid
            );
        }
    }
    let device_id = hw_uuid;

    let config = MacOSConfig {
        inner: hw,
        version,
        protocol_version,
        device_id: device_id.clone(),
        icloud_ua,
        aoskit_version,
        // Avoid panics in codepaths that expect a UDID (Find My, CloudKit, etc).
        // On macOS, using the device UUID is sufficient.
        udid: Some(device_id),
        nac_relay_url,
        relay_token,
        relay_cert_fp,
    };

    Ok(Arc::new(WrappedOSConfig {
        config: Arc::new(config),
    }))
}

#[cfg(not(feature = "hardware-key"))]
fn _create_config_from_hardware_key_inner(base64_key: String, _device_id: Option<String>) -> Result<Arc<WrappedOSConfig>, WrappedError> {
    let _ = base64_key;
    Err(WrappedError::GenericError {
        msg: "Hardware key support not available in this build. \
              On macOS, use the Apple ID login flow instead (which uses native validation). \
              To enable hardware key support, rebuild with: cargo build --features hardware-key".into(),
    })
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn connect(
    config: &WrappedOSConfig,
    state: &WrappedAPSState,
) -> Arc<WrappedAPSConnection> {
    let config = config.config.clone();
    let state = state.inner.clone();
    let (connection, error) = APSConnectionResource::new(config, state).await;
    if let Some(error) = error {
        error!("APS connection error (non-fatal, will retry): {}", error);
    }
    Arc::new(WrappedAPSConnection { inner: connection })
}

/// Login session object that holds state between login steps.
#[derive(uniffi::Object)]
pub struct LoginSession {
    account: tokio::sync::Mutex<Option<AppleAccount<omnisette::DefaultAnisetteProvider>>>,
    username: String,
    password_hash: Vec<u8>,
    needs_2fa: bool,
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn login_start(
    apple_id: String,
    password: String,
    config: &WrappedOSConfig,
    connection: &WrappedAPSConnection,
) -> Result<Arc<LoginSession>, WrappedError> {
    let os_config = config.config.clone();
    let conn = connection.inner.clone();

    let user_trimmed = apple_id.trim().to_string();
    // Apple's GSA SRP expects the password to be pre-hashed with SHA-256.
    // See upstream test.rs: sha256(password.as_bytes())
    let pw_bytes = {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(password.trim().as_bytes());
        hasher.finalize().to_vec()
    };

    let client_info = os_config.get_gsa_config(&*conn.state.read().await, false);
    let anisette_path = format!("{}/anisette_{}", resolve_xdg_data_dir(), config.get_device_id());
    let anisette = default_provider(client_info.clone(), PathBuf::from_str(&anisette_path).unwrap());

    let mut account = AppleAccount::new_with_anisette(client_info, anisette)
        .map_err(|e| WrappedError::GenericError { msg: format!("Failed to create account: {}", e) })?;

    let result = account.login_email_pass(&user_trimmed, &pw_bytes).await
        .map_err(|e| WrappedError::GenericError { msg: format!("Login failed: {}", e) })?;

    info!("login_email_pass returned: {:?}", result);
    let needs_2fa = match result {
        icloud_auth::LoginState::LoggedIn => {
            info!("Login completed without 2FA");
            false
        }
        icloud_auth::LoginState::Needs2FAVerification => {
            info!("2FA required (Needs2FAVerification — push already sent by Apple)");
            true
        }
        icloud_auth::LoginState::NeedsDevice2FA | icloud_auth::LoginState::NeedsSMS2FA => {
            info!("2FA required — sending trusted device push");
            match account.send_2fa_to_devices().await {
                Ok(_) => info!("send_2fa_to_devices succeeded"),
                Err(e) => error!("send_2fa_to_devices failed: {}", e),
            }
            true
        }
        icloud_auth::LoginState::NeedsSMS2FAVerification(_) => {
            info!("2FA required (NeedsSMS2FAVerification — SMS already sent)");
            true
        }
        icloud_auth::LoginState::NeedsExtraStep(ref step) => {
            if account.get_pet().is_some() {
                info!("Login completed (extra step ignored, PET available)");
                false
            } else {
                return Err(WrappedError::GenericError { msg: format!("Login requires extra step: {}", step) });
            }
        }
        icloud_auth::LoginState::NeedsLogin => {
            return Err(WrappedError::GenericError { msg: "Login failed - bad credentials".to_string() });
        }
    };

    Ok(Arc::new(LoginSession {
        account: tokio::sync::Mutex::new(Some(account)),
        username: user_trimmed,
        password_hash: pw_bytes,
        needs_2fa,
    }))
}

#[uniffi::export(async_runtime = "tokio")]
impl LoginSession {
    pub fn needs_2fa(&self) -> bool {
        self.needs_2fa
    }

    pub async fn submit_2fa(&self, code: String) -> Result<bool, WrappedError> {
        let mut guard = self.account.lock().await;
        let account = guard.as_mut().ok_or(WrappedError::GenericError { msg: "No active session".to_string() })?;

        info!("Verifying 2FA code via trusted device endpoint (verify_2fa)");
        let result = account.verify_2fa(code).await
            .map_err(|e| WrappedError::GenericError { msg: format!("2FA verification failed: {}", e) })?;

        info!("2FA verification returned: {:?}", result);
        info!("PET token available: {}", account.get_pet().is_some());

        match result {
            icloud_auth::LoginState::LoggedIn => Ok(true),
            icloud_auth::LoginState::NeedsExtraStep(_) => {
                Ok(account.get_pet().is_some())
            }
            _ => Ok(false),
        }
    }

    pub async fn finish(
        &self,
        config: &WrappedOSConfig,
        connection: &WrappedAPSConnection,
        existing_identity: Option<Arc<WrappedIDSNGMIdentity>>,
        existing_users: Option<Arc<WrappedIDSUsers>>,
    ) -> Result<IDSUsersWithIdentityRecord, WrappedError> {
        let os_config = config.config.clone();
        let conn = connection.inner.clone();

        let mut guard = self.account.lock().await;
        let account = guard.as_mut().ok_or(WrappedError::GenericError { msg: "No active session".to_string() })?;

        let pet = account.get_pet()
            .ok_or(WrappedError::GenericError { msg: "No PET token available after login".to_string() })?;

        let spd = account.spd.as_ref().expect("No SPD after login");
        let adsid = spd.get("adsid").expect("No adsid").as_string().unwrap().to_string();
        let dsid = spd.get("DsPrsId").or_else(|| spd.get("dsid"))
            .and_then(|v| {
                if let Some(s) = v.as_string() {
                    Some(s.to_string())
                } else if let Some(i) = v.as_signed_integer() {
                    Some(i.to_string())
                } else if let Some(i) = v.as_unsigned_integer() {
                    Some(i.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        // Build persist data before delegates call (while we have SPD access)
        let hashed_password_hex = account.hashed_password.as_ref()
            .map(|p| encode_hex(p))
            .unwrap_or_default();
        let mut spd_bytes = Vec::new();
        plist::to_writer_binary(&mut spd_bytes, spd)
            .map_err(|e| WrappedError::GenericError { msg: format!("Failed to serialize SPD: {}", e) })?;
        let spd_base64 = rustpush::util::base64_encode(&spd_bytes);

        let account_persist = AccountPersistData {
            username: self.username.clone(),
            hashed_password_hex,
            pet: pet.clone(),
            adsid: adsid.clone(),
            dsid: dsid.clone(),
            spd_base64,
        };

        // Request both IDS (for messaging) and MobileMe (for contacts CardDAV URL)
        let delegates = login_apple_delegates(
            &self.username,
            &pet,
            &adsid,
            None,
            &mut *account.anisette.lock().await,
            &*os_config,
            &[LoginDelegate::IDS, LoginDelegate::MobileMe],
        ).await.map_err(|e| WrappedError::GenericError { msg: format!("Failed to get delegates: {}", e) })?;

        let ids_delegate = delegates.ids.ok_or(WrappedError::GenericError { msg: "No IDS delegate in response".to_string() })?;
        let fresh_user = authenticate_apple(ids_delegate, &*os_config).await
            .map_err(|e| WrappedError::GenericError { msg: format!("IDS authentication failed: {}", e) })?;

        // Resolve identity: reuse existing or generate new
        let identity = match existing_identity {
            Some(wrapped) => {
                info!("Reusing existing identity (avoiding new device notification)");
                wrapped.inner.clone()
            }
            None => {
                info!("Generating new identity (first login)");
                IDSNGMIdentity::new()
                    .map_err(|e| WrappedError::GenericError {
                        msg: format!("Failed to create identity: {}", e)
                    })?
            }
        };

        // Decide whether to reuse existing registration or register fresh.
        let users = match existing_users {
            Some(ref wrapped) if !wrapped.inner.is_empty() => {
                let has_valid_registration = wrapped.inner[0]
                    .registration.get("com.apple.madrid")
                    .map(|r| r.calculate_rereg_time_s().map(|t| t > 0).unwrap_or(false))
                    .unwrap_or(false);

                if has_valid_registration {
                    info!("Reusing existing registration (still valid, skipping register endpoint)");
                    let mut existing = wrapped.inner.clone();
                    existing[0].auth_keypair = fresh_user.auth_keypair.clone();
                    existing
                } else {
                    info!("Existing registration expired, must re-register");
                    let mut users = vec![fresh_user];
                    register(
                        &*os_config,
                        &*conn.state.read().await,
                        &[&MADRID_SERVICE],
                        &mut users,
                        &identity,
                    ).await.map_err(|e| WrappedError::GenericError { msg: format!("Registration failed: {}", e) })?;
                    users
                }
            }
            _ => {
                let mut users = vec![fresh_user];
                if users[0].registration.is_empty() {
                    info!("Registering identity (first login)...");
                    register(
                        &*os_config,
                        &*conn.state.read().await,
                        &[&MADRID_SERVICE],
                        &mut users,
                        &identity,
                    ).await.map_err(|e| WrappedError::GenericError { msg: format!("Registration failed: {}", e) })?;
                }
                users
            }
        };

        // Take ownership of the account to create a TokenProvider.
        // The MobileMe delegate from `delegates` is seeded into the provider
        // so the first get_mme_token() doesn't need to re-fetch.
        let owned_account = guard.take()
            .ok_or(WrappedError::GenericError { msg: "Account already consumed".to_string() })?;
        let account_arc = Arc::new(tokio::sync::Mutex::new(owned_account));
        let token_provider = TokenProvider::new(account_arc, os_config.clone());

        // Seed the MobileMe delegate so get_contacts_url() and get_mme_token()
        // work immediately without a network round-trip.
        if let Some(mobileme) = delegates.mobileme {
            token_provider.seed_mme_delegate(mobileme).await;
        }

        Ok(IDSUsersWithIdentityRecord {
            users: Arc::new(WrappedIDSUsers { inner: users }),
            identity: Arc::new(WrappedIDSNGMIdentity { inner: identity }),
            token_provider: Some(Arc::new(WrappedTokenProvider { inner: token_provider })),
            account_persist: Some(account_persist),
        })
    }
}

// ============================================================================
// Attachment download helper
// ============================================================================

/// Download any MMCS (non-inline) attachments from the message and convert them
/// to inline data in the wrapped message, so the Go side can upload them to Matrix.
async fn download_mmcs_attachments(
    wrapped: &mut WrappedMessage,
    msg_inst: &MessageInst,
    conn: &rustpush::APSConnectionResource,
) {
    if let Message::Message(normal) = &msg_inst.message {
        let mut att_idx = 0;
        for indexed_part in &normal.parts.0 {
            if let MessagePart::Attachment(att) = &indexed_part.part {
                if let AttachmentType::MMCS(_) = &att.a_type {
                    if att_idx < wrapped.attachments.len() {
                        let mut buf: Vec<u8> = Vec::new();
                        match att.get_attachment(conn, &mut buf, |_, _| {}).await {
                            Ok(()) => {
                                info!(
                                    "Downloaded MMCS attachment: {} ({} bytes)",
                                    att.name,
                                    buf.len()
                                );
                                wrapped.attachments[att_idx].is_inline = true;
                                wrapped.attachments[att_idx].inline_data = Some(buf);
                            }
                            Err(e) => {
                                error!("Failed to download MMCS attachment {}: {}", att.name, e);
                            }
                        }
                    }
                }
                att_idx += 1;
            }
        }
    }
}

/// Download the group photo for an IconChange message via MMCS.
/// Apple delivers group photo changes as MMCS file transfers inside IconChange
/// APNs messages — NOT via CloudKit. This downloads the photo inline so the
/// Go side can use msg.icon_change_photo_data directly without any CloudKit
/// round-trip (which would fail for Apple-set photos anyway).
async fn download_icon_change_photo(
    wrapped: &mut WrappedMessage,
    msg_inst: &MessageInst,
    conn: &rustpush::APSConnectionResource,
) {
    if let Message::IconChange(change) = &msg_inst.message {
        if let Some(mmcs_file) = &change.file {
            let att = Attachment {
                a_type: AttachmentType::MMCS(mmcs_file.clone()),
                part: 0,
                uti_type: String::new(),
                mime: String::from("image/jpeg"),
                name: String::from("group_photo"),
                iris: false,
            };
            let mut buf: Vec<u8> = Vec::new();
            match att.get_attachment(conn, &mut buf, |_, _| {}).await {
                Ok(()) => {
                    info!("Downloaded group photo via MMCS ({} bytes)", buf.len());
                    wrapped.icon_change_photo_data = Some(buf);
                }
                Err(e) => {
                    error!("Failed to download group photo via MMCS: {}", e);
                }
            }
        }
    }
}

// ============================================================================
// Client
// ============================================================================

#[derive(uniffi::Object)]
pub struct Client {
    client: Arc<IMClient>,
    conn: rustpush::APSConnection,
    receive_handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    token_provider: Option<Arc<WrappedTokenProvider>>,
    cloud_messages_client: tokio::sync::Mutex<Option<Arc<rustpush::cloud_messages::CloudMessagesClient<omnisette::DefaultAnisetteProvider>>>>,
    cloud_keychain_client: tokio::sync::Mutex<Option<Arc<rustpush::keychain::KeychainClient<omnisette::DefaultAnisetteProvider>>>>,
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn new_client(
    connection: &WrappedAPSConnection,
    users: &WrappedIDSUsers,
    identity: &WrappedIDSNGMIdentity,
    config: &WrappedOSConfig,
    token_provider: Option<Arc<WrappedTokenProvider>>,
    message_callback: Box<dyn MessageCallback>,
    update_users_callback: Box<dyn UpdateUsersCallback>,
) -> Result<Arc<Client>, WrappedError> {
    let conn = connection.inner.clone();
    let users_clone = users.inner.clone();
    let identity_clone = identity.inner.clone();
    let config_clone = config.config.clone();

    let xdg_data_dir = resolve_xdg_data_dir();
    let _ = std::fs::create_dir_all(&xdg_data_dir);
    let cache_key = users_clone
        .first()
        .map(|u| u.user_id.chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect::<String>())
        .unwrap_or_else(|| "default".to_string());
    let cache_path = format!("{}/id_cache_{}.plist", xdg_data_dir, cache_key);

    let client = Arc::new(
        IMClient::new(
            conn.clone(),
            users_clone,
            identity_clone,
            &[&MADRID_SERVICE],
            cache_path.into(),
            config_clone,
            Box::new(move |updated_keys| {
                update_users_callback.update_users(Arc::new(WrappedIDSUsers {
                    inner: updated_keys,
                }));
                debug!("Updated IDS keys");
            }),
        )
        .await,
    );

    // Start receive loop.
    //
    // Architecture: two tasks connected by an unbounded mpsc channel.
    //
    // 1. **Drain task** — reads from the tokio broadcast channel as fast as
    //    possible and forwards every APSMessage into the mpsc.  Because it does
    //    zero processing, it will almost never lag behind the broadcast.  If it
    //    *does* lag (broadcast capacity 9999 exhausted), it logs the count and
    //    continues — there is nothing we can do about already-dropped broadcast
    //    messages, but we won't compound the loss by being slow.
    //
    // 2. **Process task** — reads from the mpsc (unbounded, so no back-pressure
    //    on the drain task) and handles each message: decrypting, downloading
    //    MMCS attachments, and calling the Go callback.  Transient errors are
    //    retried with exponential back-off.  This task can take as long as it
    //    needs without risking broadcast lag.
    let client_for_recv = client.clone();
    let callback = Arc::new(message_callback);

    // Shared reconnect timestamp: set when APNs reconnects (generated_signal
    // fires) or when the drain task starts listening (initial connection).
    // Messages arriving within RECONNECT_WINDOW_MS of a (re)connect are
    // marked as stored — they were cached by Apple's servers while offline.
    const RECONNECT_WINDOW_MS: u64 = 30_000; // 30 seconds
    // Initialize to 0 — the drain task sets it to now() right before
    // entering the receive loop. This ensures the window starts when we're
    // actually listening for messages, not when receive() is called (which
    // can be 20-30s earlier during Go startup).
    let reconnected_at = Arc::new(AtomicU64::new(0));

    let receive_handle = tokio::spawn({
        let conn = connection.inner.clone();
        let conn_for_download = connection.inner.clone();
        let reconnected_at = reconnected_at.clone();
        async move {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(rustpush::APSMessage, u64)>();
            let pending = Arc::new(AtomicU64::new(0));

            // --- Drain task: broadcast → mpsc + reconnect detection ------
            // Combines message draining AND reconnect detection in a SINGLE
            // task using select!. This eliminates the scheduling race from
            // the old two-task approach: resource_state changes are handled
            // in the same task that receives messages, so reconnected_at is
            // always updated before the next message is forwarded.
            let drain_pending = pending.clone();
            let drain_handle = tokio::spawn({
                let conn = conn.clone();
                let reconnected_at = reconnected_at.clone();
                async move {
                    let mut recv = conn.messages_cont.subscribe();
                    let mut state = conn.resource_state.subscribe();
                    // Mark the initial resource_state value as seen so we
                    // only trigger on future transitions.
                    state.borrow_and_update();
                    // Set reconnected_at NOW — right when we start listening.
                    // Covers stored messages delivered on first connect.
                    let start_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    reconnected_at.store(start_ms, Ordering::Relaxed);
                    info!("Drain task started, marking messages as stored for {}ms", RECONNECT_WINDOW_MS);
                    loop {
                        tokio::select! {
                            biased;
                            // Reconnect detection: resource_state → Generating
                            // fires BEFORE generate() establishes the new
                            // connection, so reconnected_at is set before any
                            // stored messages can arrive on messages_cont.
                            result = state.changed() => {
                                if result.is_err() {
                                    info!("Resource state sender dropped, stopping drain task");
                                    break;
                                }
                                let current = state.borrow_and_update().clone();
                                if matches!(current, ResourceState::Generating) {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_millis() as u64;
                                    reconnected_at.store(now, Ordering::Relaxed);
                                    info!("APNs reconnecting (Generating), marking messages as stored for {}ms", RECONNECT_WINDOW_MS);
                                }
                            }
                            // Message drain: forward APNs messages to process task
                            result = recv.recv() => {
                                match result {
                                    Ok(msg) => {
                                        drain_pending.fetch_add(1, Ordering::Relaxed);
                                        let drain_ts = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_millis() as u64;
                                        if tx.send((msg, drain_ts)).is_err() {
                                            info!("Process task gone, stopping drain");
                                            break;
                                        }
                                    }
                                    Err(broadcast::error::RecvError::Lagged(n)) => {
                                        error!(
                                            "APS broadcast receiver lagged — {} messages were DROPPED by the \
                                             broadcast channel before we could read them. Real-time messages \
                                             may have been lost. Consider increasing broadcast capacity or \
                                             investigating processing backlog (pending={}).",
                                            n,
                                            drain_pending.load(Ordering::Relaxed),
                                        );
                                    }
                                    Err(broadcast::error::RecvError::Closed) => {
                                        info!("Broadcast channel closed, stopping drain task");
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            });

            // --- Process task: mpsc → handle + callback -----------------
            const MAX_RETRIES: u32 = 5;
            const INITIAL_BACKOFF: Duration = Duration::from_millis(500);

            while let Some((msg, drain_ts)) = rx.recv().await {
                let mut retries = 0u32;
                let mut backoff = INITIAL_BACKOFF;

                loop {
                    match client_for_recv.handle(msg.clone()).await {
                        Ok(Some(msg_inst)) => {
                            if msg_inst.has_payload() || matches!(msg_inst.message, Message::Typing(_, _) | Message::Read | Message::Delivered | Message::Error(_) | Message::PeerCacheInvalidate) {
                                let mut wrapped = message_inst_to_wrapped(&msg_inst);

                                // Mark as stored if within the post-reconnect window.
                                // Uses the drain timestamp (when the message was received
                                // from APNs) instead of now, so MMCS download time and
                                // retry backoff don't push messages past the window.
                                let reconn = reconnected_at.load(Ordering::Relaxed);
                                if reconn > 0 {
                                    let delta = drain_ts.saturating_sub(reconn);
                                    wrapped.is_stored_message = delta < RECONNECT_WINDOW_MS;
                                    if wrapped.is_stored_message {
                                        info!("Stored message detected: uuid={} delta={}ms (window={}ms)", wrapped.uuid, delta, RECONNECT_WINDOW_MS);
                                    }
                                }

                                // Download MMCS attachments so Go receives inline data
                                download_mmcs_attachments(&mut wrapped, &msg_inst, &conn_for_download).await;
                                // Download group photo for IconChange messages via MMCS
                                if wrapped.is_icon_change && !wrapped.group_photo_cleared {
                                    download_icon_change_photo(&mut wrapped, &msg_inst, &conn_for_download).await;
                                }
                                callback.on_message(wrapped);
                            }
                            break; // success
                        }
                        Ok(None) => {
                            break; // message intentionally ignored by handle()
                        }
                        Err(e) => {
                            // Classify: retryable vs permanent
                            let is_permanent = matches!(
                                e,
                                rustpush::PushError::BadMsg
                                    | rustpush::PushError::DoNotRetry(_)
                                    | rustpush::PushError::VerificationFailed
                            );

                            if is_permanent || retries >= MAX_RETRIES {
                                error!(
                                    "Failed to handle APS message after {} attempt(s) (permanent={}): {:?}",
                                    retries + 1,
                                    is_permanent,
                                    e
                                );
                                break;
                            }

                            retries += 1;
                            warn!(
                                "Transient error handling APS message (attempt {}/{}), retrying in {:?}: {:?}",
                                retries,
                                MAX_RETRIES,
                                backoff,
                                e
                            );
                            tokio::time::sleep(backoff).await;
                            backoff = std::cmp::min(backoff * 2, Duration::from_secs(15));
                        }
                    }
                }

                pending.fetch_sub(1, Ordering::Relaxed);
            }

            drain_handle.abort();
            info!("Receive loop exited");
        }
    });

    Ok(Arc::new(Client {
        client,
        conn: connection.inner.clone(),
        receive_handle: tokio::sync::Mutex::new(Some(receive_handle)),
        token_provider,
        cloud_messages_client: tokio::sync::Mutex::new(None),
        cloud_keychain_client: tokio::sync::Mutex::new(None),
    }))
}

impl Client {
    async fn get_or_init_cloud_messages_client(&self) -> Result<Arc<rustpush::cloud_messages::CloudMessagesClient<omnisette::DefaultAnisetteProvider>>, WrappedError> {
        let mut locked = self.cloud_messages_client.lock().await;
        if let Some(client) = &*locked {
            return Ok(client.clone());
        }

        let tp = self.token_provider.as_ref().ok_or(WrappedError::GenericError {
            msg: "No TokenProvider available".into(),
        })?;

        let dsid = tp.inner.get_dsid().await?;
        let adsid = tp.inner.get_adsid().await?;
        let mme_delegate = tp.inner.get_mme_delegate().await?;
        let account = tp.inner.get_account();
        let os_config = tp.inner.get_os_config();
        let anisette = account.lock().await.anisette.clone();

        let cloudkit_state = rustpush::cloudkit::CloudKitState::new(dsid.clone()).ok_or(
            WrappedError::GenericError {
                msg: "Failed to create CloudKitState".into(),
            },
        )?;
        let cloudkit = Arc::new(rustpush::cloudkit::CloudKitClient {
            state: tokio::sync::RwLock::new(cloudkit_state),
            anisette: anisette.clone(),
            config: os_config.clone(),
            token_provider: tp.inner.clone(),
        });

        let keychain_state_path = format!("{}/trustedpeers_{}.plist", resolve_xdg_data_dir(), dsid);
        let mut keychain_state: Option<rustpush::keychain::KeychainClientState> = match std::fs::read(&keychain_state_path) {
            Ok(data) => match plist::from_bytes(&data) {
                Ok(state) => Some(state),
                Err(e) => {
                    warn!("Failed to parse keychain state at {}: {}", keychain_state_path, e);
                    None
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                warn!("Failed to read keychain state at {}: {}", keychain_state_path, e);
                None
            }
        };
        if keychain_state.is_none() {
            keychain_state = Some(
                rustpush::keychain::KeychainClientState::new(dsid, adsid, &mme_delegate)
                    .ok_or(WrappedError::GenericError {
                        msg: "Missing KeychainSync config in MobileMe delegate".into(),
                    })?
            );
        }
        let path_for_closure = keychain_state_path.clone();

        let keychain = Arc::new(rustpush::keychain::KeychainClient {
            anisette,
            token_provider: tp.inner.clone(),
            state: tokio::sync::RwLock::new(keychain_state.expect("keychain state missing")),
            config: os_config,
            update_state: Box::new(move |state| {
                if let Err(e) = plist::to_file_xml(&path_for_closure, state) {
                    warn!("Failed to persist keychain state to {}: {}", path_for_closure, e);
                }
            }),
            container: tokio::sync::Mutex::new(None),
            security_container: tokio::sync::Mutex::new(None),
            client: cloudkit.clone(),
        });

        // Aggressively load all PCS keys during init to prevent sync_records
        // from silently skipping records encrypted with old/rotated keys.
        // Step 1: Fetch recoverable TLK shares for our identity — this pulls
        // in key shares that sync_keychain alone might not discover.
        if let Err(e) = refresh_recoverable_tlk_shares(&keychain, "Cloud client init").await {
            warn!("Cloud client init: TLK share refresh failed (non-fatal): {}", e);
        }
        // Step 2: Full keychain sync with retries.
        sync_keychain_with_retries(&keychain, 6, "Cloud client init").await?;

        let cloud_messages = Arc::new(rustpush::cloud_messages::CloudMessagesClient::new(
            cloudkit, keychain.clone(),
        ));

        // Step 3: Pre-fetch and cache zone encryption configs for all Manatee zones.
        // This ensures the PCS zone keys derived from the keychain are cached
        // before sync_records tries to decrypt individual records.
        if let Err(e) = cloud_messages.warm_zone_keys().await {
            warn!("Cloud client init: zone key warm-up failed (non-fatal): {}", e);
        }

        // Step 4: Log server-side record counts for diagnostics.
        match cloud_messages.count_records().await {
            Ok(summary) => {
                info!("CloudKit server record counts — messages: {}, chats: {}, attachments: {}",
                    summary.messages_summary.len(), summary.chat_summary.len(), summary.attachment_summary.len());
            }
            Err(e) => {
                warn!("Cloud client init: count_records failed (non-fatal): {}", e);
            }
        }

        *locked = Some(cloud_messages.clone());
        *self.cloud_keychain_client.lock().await = Some(keychain);
        Ok(cloud_messages)
    }

    async fn get_or_init_cloud_keychain_client(&self) -> Result<Arc<rustpush::keychain::KeychainClient<omnisette::DefaultAnisetteProvider>>, WrappedError> {
        let _ = self.get_or_init_cloud_messages_client().await?;
        self.cloud_keychain_client
            .lock()
            .await
            .clone()
            .ok_or(WrappedError::GenericError {
                msg: "No keychain client available".into(),
            })
    }

    async fn recover_cloud_pcs_state(&self, context: &str) -> Result<(), WrappedError> {
        info!("{}: starting keychain resync recovery", context);
        let keychain = self.get_or_init_cloud_keychain_client().await?;
        refresh_recoverable_tlk_shares(&keychain, context).await?;
        sync_keychain_with_retries(&keychain, 6, context).await
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl Client {
    /// Reset the cached CloudKit client so the next CloudKit operation
    /// re-initializes it with fresh auth tokens.  Call this after a sync
    /// failure (e.g. TokenMissing) before retrying.
    pub async fn reset_cloud_client(&self) {
        *self.cloud_messages_client.lock().await = None;
        *self.cloud_keychain_client.lock().await = None;
    }

    pub async fn get_handles(&self) -> Vec<String> {
        self.client.identity.get_handles().await
    }

    /// Get iCloud auth headers (Authorization + anisette) for MobileMe API calls.
    /// Returns None if no token provider is available.
    pub async fn get_icloud_auth_headers(&self) -> Result<Option<HashMap<String, String>>, WrappedError> {
        match &self.token_provider {
            Some(tp) => Ok(Some(tp.inner.get_icloud_auth_headers().await?)),
            None => Ok(None),
        }
    }

    /// Get the contacts CardDAV URL from the MobileMe delegate.
    /// Returns None if no token provider is available.
    pub async fn get_contacts_url(&self) -> Result<Option<String>, WrappedError> {
        match &self.token_provider {
            Some(tp) => Ok(tp.inner.get_contacts_url().await?),
            None => Ok(None),
        }
    }

    /// Get the DSID for this account.
    pub async fn get_dsid(&self) -> Result<Option<String>, WrappedError> {
        match &self.token_provider {
            Some(tp) => Ok(Some(tp.inner.get_dsid().await?)),
            None => Ok(None),
        }
    }

    pub async fn validate_targets(
        &self,
        targets: Vec<String>,
        handle: String,
    ) -> Vec<String> {
        self.client
            .identity
            .validate_targets(&targets, "com.apple.madrid", &handle)
            .await
            .unwrap_or_default()
    }

    pub async fn send_message(
        &self,
        conversation: WrappedConversation,
        text: String,
        handle: String,
        reply_guid: Option<String>,
        reply_part: Option<String>,
    ) -> Result<String, WrappedError> {
        let conv: ConversationData = (&conversation).into();
        let service = if conversation.is_sms {
            MessageType::SMS {
                is_phone: false,
                using_number: handle.clone(),
                from_handle: None,
            }
        } else {
            MessageType::IMessage
        };

        // Parse rich link encoded as prefix: \x00RL\x01original_url\x01url\x01title\x01summary\x00actual_text
        let (actual_text, link_meta) = if text.starts_with("\x00RL\x01") {
            let rest = &text[4..]; // skip "\x00RL\x01"
            if let Some(end) = rest.find('\x00') {
                let metadata = &rest[..end];
                let actual = rest[end + 1..].to_string();
                let fields: Vec<&str> = metadata.splitn(4, '\x01').collect();
                let original_url_str = fields.first().copied().unwrap_or("");
                let url_str = fields.get(1).copied().unwrap_or("");
                let title_str = fields.get(2).copied().unwrap_or("");
                let summary_str = fields.get(3).copied().unwrap_or("");

                let original_url = NSURL {
                    base: "$null".to_string(),
                    relative: original_url_str.to_string(),
                };
                let url = if url_str.is_empty() {
                    None
                } else {
                    Some(NSURL {
                        base: "$null".to_string(),
                        relative: url_str.to_string(),
                    })
                };
                let title = if title_str.is_empty() { None } else { Some(title_str.to_string()) };
                let summary = if summary_str.is_empty() { None } else { Some(summary_str.to_string()) };

                info!("Sending rich link: url={}, title={:?}", original_url_str, title);

                let lm = LinkMeta {
                    data: LPLinkMetadata {
                        image_metadata: None,
                        version: 1,
                        icon_metadata: None,
                        original_url,
                        url,
                        title,
                        summary,
                        image: None,
                        icon: None,
                        images: None,
                        icons: None,
                    },
                    attachments: vec![],
                };
                (actual, Some(lm))
            } else {
                (text, None)
            }
        } else {
            (text, None)
        };

        let mut normal = NormalMessage::new(actual_text.clone(), service);
        normal.link_meta = link_meta;
        normal.reply_guid = reply_guid.clone();
        normal.reply_part = reply_part.clone();
        let mut msg = MessageInst::new(
            conv.clone(),
            &handle,
            Message::Message(normal),
        );
        match self.client.send(&mut msg).await {
            Ok(_) => Ok(msg.id.clone()),
            Err(rustpush::PushError::NoValidTargets) if !conversation.is_sms => {
                // iMessage failed — no IDS targets. Retry as SMS (without rich link).
                info!("No IDS targets, falling back to SMS for {:?}", conv.participants);
                let sms_service = MessageType::SMS {
                    is_phone: false,
                    using_number: handle.clone(),
                    from_handle: None,
                };
                let mut sms_msg = MessageInst::new(
                    conv,
                    &handle,
                    Message::Message(NormalMessage::new(actual_text, sms_service)),
                );
                self.client.send(&mut sms_msg).await
                    .map_err(|e| WrappedError::GenericError { msg: format!("Failed to send SMS: {}", e) })?;
                Ok(sms_msg.id.clone())
            }
            Err(e) => Err(WrappedError::GenericError { msg: format!("Failed to send message: {}", e) }),
        }
    }

    pub async fn send_tapback(
        &self,
        conversation: WrappedConversation,
        target_uuid: String,
        target_part: u64,
        reaction: u32,
        emoji: Option<String>,
        remove: bool,
        handle: String,
    ) -> Result<String, WrappedError> {
        let conv: ConversationData = (&conversation).into();
        let reaction_val = match (reaction, &emoji) {
            (0, _) => Reaction::Heart,
            (1, _) => Reaction::Like,
            (2, _) => Reaction::Dislike,
            (3, _) => Reaction::Laugh,
            (4, _) => Reaction::Emphasize,
            (5, _) => Reaction::Question,
            (6, Some(em)) => Reaction::Emoji(em.clone()),
            _ => Reaction::Heart,
        };
        let mut msg = MessageInst::new(
            conv,
            &handle,
            Message::React(ReactMessage {
                to_uuid: target_uuid,
                to_part: Some(target_part),
                reaction: ReactMessageType::React { reaction: reaction_val, enable: !remove },
                to_text: String::new(),
                embedded_profile: None,
            }),
        );
        self.client.send(&mut msg).await
            .map_err(|e| WrappedError::GenericError { msg: format!("Failed to send tapback: {}", e) })?;
        Ok(msg.id.clone())
    }

    pub async fn send_typing(
        &self,
        conversation: WrappedConversation,
        typing: bool,
        handle: String,
    ) -> Result<(), WrappedError> {
        let conv: ConversationData = (&conversation).into();
        let mut msg = MessageInst::new(conv, &handle, Message::Typing(typing, None));
        self.client.send(&mut msg).await
            .map_err(|e| WrappedError::GenericError { msg: format!("Failed to send typing: {}", e) })?;
        Ok(())
    }

    pub async fn send_read_receipt(
        &self,
        conversation: WrappedConversation,
        handle: String,
        for_uuid: Option<String>,
    ) -> Result<(), WrappedError> {
        let conv: ConversationData = (&conversation).into();
        let mut msg = MessageInst::new(conv, &handle, Message::Read);
        if let Some(uuid) = for_uuid {
            msg.id = uuid;
        }
        self.client.send(&mut msg).await
            .map_err(|e| WrappedError::GenericError { msg: format!("Failed to send read receipt: {}", e) })?;
        Ok(())
    }

    pub async fn send_delivery_receipt(
        &self,
        conversation: WrappedConversation,
        handle: String,
    ) -> Result<(), WrappedError> {
        let conv: ConversationData = (&conversation).into();
        let mut msg = MessageInst::new(conv, &handle, Message::Delivered);
        self.client.send(&mut msg).await
            .map_err(|e| WrappedError::GenericError { msg: format!("Failed to send delivery receipt: {}", e) })?;
        Ok(())
    }

    pub async fn send_edit(
        &self,
        conversation: WrappedConversation,
        target_uuid: String,
        edit_part: u64,
        new_text: String,
        handle: String,
    ) -> Result<String, WrappedError> {
        let conv: ConversationData = (&conversation).into();
        let mut msg = MessageInst::new(
            conv,
            &handle,
            Message::Edit(EditMessage {
                tuuid: target_uuid,
                edit_part,
                new_parts: MessageParts(vec![IndexedMessagePart {
                    part: MessagePart::Text(new_text, Default::default()),
                    idx: None,
                    ext: None,
                }]),
            }),
        );
        self.client.send(&mut msg).await
            .map_err(|e| WrappedError::GenericError { msg: format!("Failed to send edit: {}", e) })?;
        Ok(msg.id.clone())
    }

    pub async fn send_unsend(
        &self,
        conversation: WrappedConversation,
        target_uuid: String,
        edit_part: u64,
        handle: String,
    ) -> Result<String, WrappedError> {
        let conv: ConversationData = (&conversation).into();
        let mut msg = MessageInst::new(
            conv,
            &handle,
            Message::Unsend(UnsendMessage {
                tuuid: target_uuid,
                edit_part,
            }),
        );
        self.client.send(&mut msg).await
            .map_err(|e| WrappedError::GenericError { msg: format!("Failed to send unsend: {}", e) })?;
        Ok(msg.id.clone())
    }

    /// Send a MoveToRecycleBin message to notify other Apple devices that a chat was deleted.
    pub async fn send_move_to_recycle_bin(
        &self,
        conversation: WrappedConversation,
        handle: String,
        chat_guid: String,
    ) -> Result<(), WrappedError> {
        let conv: ConversationData = (&conversation).into();
        // Strip mailto:/tel: prefixes and exclude the sender's own handle.
        // Apple's OperatedChat.ptcpts contains only the OTHER party's handles,
        // not the user's own handle. Including it causes the Mac to not
        // recognise the chat being deleted.
        let bare_handle = handle.replace("mailto:", "").replace("tel:", "");
        let bare_participants: Vec<String> = conv.participants.iter()
            .map(|p| p.replace("mailto:", "").replace("tel:", ""))
            .filter(|p| p != &bare_handle)
            .collect();
        let operated_chat = OperatedChat {
            participants: bare_participants,
            group_id: conv.sender_guid.clone().unwrap_or_default(),
            guid: chat_guid,
            delete_incoming_messages: None,
            was_reported_as_junk: None,
        };
        let delete_msg = MoveToRecycleBinMessage {
            target: DeleteTarget::Chat(operated_chat.clone()),
            recoverable_delete_date: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        };
        let mut msg = MessageInst::new(conv.clone(), &handle, Message::MoveToRecycleBin(delete_msg));
        self.client.send(&mut msg).await
            .map_err(|e| WrappedError::GenericError { msg: format!("Failed to send MoveToRecycleBin: {}", e) })?;

        // Follow up with PermanentDelete to actually remove from CloudKit.
        // MoveToRecycleBin only moves to "Recently Deleted" (30-day retention).
        // Without PermanentDelete, records stay in CloudKit and get re-downloaded
        // on every sync, resurrecting the portal.
        let perm_msg = PermanentDeleteMessage {
            target: DeleteTarget::Chat(operated_chat),
            is_scheduled: false,
        };
        let mut perm = MessageInst::new(conv, &handle, Message::PermanentDelete(perm_msg));
        self.client.send(&mut perm).await
            .map_err(|e| WrappedError::GenericError { msg: format!("Failed to send PermanentDelete: {}", e) })?;
        Ok(())
    }

    /// Delete chat records from CloudKit so they don't reappear during future syncs.
    pub async fn delete_cloud_chats(
        &self,
        chat_ids: Vec<String>,
    ) -> Result<(), WrappedError> {
        let cloud_messages = self.get_or_init_cloud_messages_client().await?;
        cloud_messages.delete_chats(&chat_ids).await
            .map_err(|e| WrappedError::GenericError { msg: format!("Failed to delete CloudKit chats: {}", e) })?;
        Ok(())
    }

    /// Delete message records from CloudKit so they don't reappear during future syncs.
    pub async fn delete_cloud_messages(
        &self,
        message_ids: Vec<String>,
    ) -> Result<(), WrappedError> {
        let cloud_messages = self.get_or_init_cloud_messages_client().await?;
        cloud_messages.delete_messages(&message_ids).await
            .map_err(|e| WrappedError::GenericError { msg: format!("Failed to delete CloudKit messages: {}", e) })?;
        Ok(())
    }

    /// Purge the recoverable-delete zones from CloudKit to prevent deleted
    /// messages from resurrecting. After MoveToRecycleBin, Apple parks records
    /// in recoverableMessageDeleteZone; nuking that zone ensures they stay dead.
    pub async fn purge_recoverable_zones(&self) -> Result<(), WrappedError> {
        let cloud_messages = self.get_or_init_cloud_messages_client().await?;
        let container = cloud_messages.get_container().await
            .map_err(|e| WrappedError::GenericError { msg: format!("Failed to get CloudKit container: {}", e) })?;
        container.perform_operations_checked(
            &CloudKitSession::new(),
            &[
                ZoneDeleteOperation::new(container.private_zone("recoverableMessageDeleteZone".to_string())),
                ZoneDeleteOperation::new(container.private_zone("chatBotRecoverableMessageDeleteZone".to_string())),
            ],
            IsolationLevel::Operation,
        ).await
            .map_err(|e| WrappedError::GenericError { msg: format!("Failed to purge recoverable zones: {}", e) })?;
        Ok(())
    }

    pub async fn send_attachment(
        &self,
        conversation: WrappedConversation,
        data: Vec<u8>,
        mime: String,
        uti_type: String,
        filename: String,
        handle: String,
        reply_guid: Option<String>,
        reply_part: Option<String>,
    ) -> Result<String, WrappedError> {
        let conv: ConversationData = (&conversation).into();
        // Detect voice messages by UTI (CAF files from OGG→CAF remux are voice recordings)
        let is_voice = uti_type == "com.apple.coreaudio-format";
        let service = if conversation.is_sms {
            MessageType::SMS {
                is_phone: false,
                using_number: handle.clone(),
                from_handle: None,
            }
        } else {
            MessageType::IMessage
        };

        // Prepare and upload the attachment via MMCS
        let cursor = Cursor::new(&data);
        let prepared = MMCSFile::prepare_put(cursor).await
            .map_err(|e| WrappedError::GenericError { msg: format!("Failed to prepare MMCS upload: {}", e) })?;

        let cursor2 = Cursor::new(&data);
        let attachment = Attachment::new_mmcs(
            &self.conn,
            &prepared,
            cursor2,
            &mime,
            &uti_type,
            &filename,
            |_current, _total| {},
        ).await.map_err(|e| WrappedError::GenericError { msg: format!("Failed to upload attachment: {}", e) })?;

        let parts = vec![IndexedMessagePart {
            part: MessagePart::Attachment(attachment.clone()),
            idx: None,
            ext: None,
        }];

        let mut msg = MessageInst::new(
            conv.clone(),
            &handle,
            Message::Message(NormalMessage {
                parts: MessageParts(parts),
                effect: None,
                reply_guid: reply_guid.clone(),
                reply_part: reply_part.clone(),
                service,
                subject: None,
                app: None,
                link_meta: None,
                voice: is_voice,
                scheduled: None,
                embedded_profile: None,
            }),
        );
        match self.client.send(&mut msg).await {
            Ok(_) => Ok(msg.id.clone()),
            Err(rustpush::PushError::NoValidTargets) if !conversation.is_sms => {
                info!("No IDS targets for attachment, falling back to SMS for {:?}", conv.participants);
                let sms_service = MessageType::SMS {
                    is_phone: false,
                    using_number: handle.clone(),
                    from_handle: None,
                };
                let sms_parts = vec![IndexedMessagePart {
                    part: MessagePart::Attachment(attachment),
                    idx: None,
                    ext: None,
                }];
                let mut sms_msg = MessageInst::new(
                    conv,
                    &handle,
                    Message::Message(NormalMessage {
                        parts: MessageParts(sms_parts),
                        effect: None,
                        reply_guid: reply_guid,
                        reply_part: reply_part,
                        service: sms_service,
                        subject: None,
                        app: None,
                        link_meta: None,
                        voice: is_voice,
                        scheduled: None,
                        embedded_profile: None,
                    }),
                );
                self.client.send(&mut sms_msg).await
                    .map_err(|e| WrappedError::GenericError { msg: format!("Failed to send SMS attachment: {}", e) })?;
                Ok(sms_msg.id.clone())
            }
            Err(e) => Err(WrappedError::GenericError { msg: format!("Failed to send attachment: {}", e) }),
        }
    }

    pub async fn cloud_sync_chats(
        &self,
        continuation_token: Option<String>,
    ) -> Result<WrappedCloudSyncChatsPage, WrappedError> {
        let token = decode_continuation_token(continuation_token)?;
        let cloud_messages = self.get_or_init_cloud_messages_client().await?;

        const MAX_SYNC_ATTEMPTS: usize = 4;
        let mut sync_result = None;
        let mut last_pcs_err: Option<rustpush::PushError> = None;

        for attempt in 0..MAX_SYNC_ATTEMPTS {
            match cloud_messages.sync_chats(token.clone()).await {
                Ok(result) => {
                    sync_result = Some(result);
                    break;
                }
                Err(err) if is_pcs_recoverable_error(&err) => {
                    let attempt_no = attempt + 1;
                    warn!(
                        "CloudKit chats sync hit PCS key error on attempt {}/{}: {}",
                        attempt_no,
                        MAX_SYNC_ATTEMPTS,
                        err
                    );
                    last_pcs_err = Some(err);
                    if attempt_no < MAX_SYNC_ATTEMPTS {
                        self.recover_cloud_pcs_state("CloudKit chats sync").await?;
                        continue;
                    }
                }
                Err(err) => {
                    return Err(WrappedError::GenericError {
                        msg: format!("Failed to sync CloudKit chats: {}", err),
                    });
                }
            }
        }

        let (next_token, chats, status) = match sync_result {
            Some(result) => result,
            None => {
                let err = last_pcs_err.map(|e| e.to_string()).unwrap_or_else(|| "unknown error".into());
                return Err(WrappedError::GenericError {
                    msg: format!("Failed to sync CloudKit chats after PCS recovery retries: {}", err),
                });
            }
        };

        let updated_timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|dur| dur.as_millis() as u64)
            .unwrap_or_default();

        let mut normalized = Vec::with_capacity(chats.len());
        for (record_name, chat_opt) in chats {
            if let Some(chat) = chat_opt {
                let cloud_chat_id = if chat.chat_identifier.is_empty() {
                    record_name.clone()
                } else {
                    chat.chat_identifier.clone()
                };
                normalized.push(WrappedCloudSyncChat {
                    record_name,
                    cloud_chat_id,
                    group_id: chat.group_id,
                    style: chat.style,
                    service: chat.service_name,
                    display_name: chat.display_name,
                    participants: chat.participants.into_iter().map(|p| p.uri).collect(),
                    deleted: false,
                    updated_timestamp_ms,
                    group_photo_guid: chat.group_photo_guid,
                    is_filtered: chat.is_filtered,
                });
            } else {
                normalized.push(WrappedCloudSyncChat {
                    cloud_chat_id: record_name.clone(),
                    group_id: String::new(),
                    style: 0,
                    record_name,
                    service: String::new(),
                    display_name: None,
                    participants: vec![],
                    deleted: true,
                    updated_timestamp_ms,
                    group_photo_guid: None,
                    is_filtered: 0,
                });
            }
        }

        Ok(WrappedCloudSyncChatsPage {
            continuation_token: encode_continuation_token(next_token),
            status,
            done: status == 3,
            chats: normalized,
        })
    }

    /// Dump ALL CloudKit chat records as raw JSON (paginating until done).
    /// Returns a JSON array of objects with record_name + all CloudChat fields.
    pub async fn cloud_dump_chats_json(&self) -> Result<String, WrappedError> {
        let cloud_messages = self.get_or_init_cloud_messages_client().await?;

        let mut all_records: Vec<serde_json::Value> = Vec::new();
        let mut token: Option<Vec<u8>> = None;

        for page in 0..256 {
            let (next_token, chats, status) = cloud_messages.sync_chats(token).await
                .map_err(|e| WrappedError::GenericError {
                    msg: format!("CloudKit chat dump page {} failed: {}", page, e),
                })?;

            for (record_name, chat_opt) in &chats {
                let mut obj = if let Some(chat) = chat_opt {
                    serde_json::to_value(chat).unwrap_or(serde_json::Value::Null)
                } else {
                    serde_json::json!({"deleted": true})
                };
                if let Some(map) = obj.as_object_mut() {
                    map.insert("_record_name".to_string(), serde_json::Value::String(record_name.clone()));
                }
                all_records.push(obj);
            }

            info!("CloudKit chat dump page {}: {} records, status={}", page, chats.len(), status);

            if status == 3 {
                break;
            }
            token = Some(next_token);
        }

        serde_json::to_string_pretty(&all_records).map_err(|e| WrappedError::GenericError {
            msg: format!("JSON serialization failed: {}", e),
        })
    }

    pub async fn cloud_sync_messages(
        &self,
        continuation_token: Option<String>,
    ) -> Result<WrappedCloudSyncMessagesPage, WrappedError> {
        let token = decode_continuation_token(continuation_token)?;
        info!(
            "cloud_sync_messages: token={}, token_bytes={}",
            if token.is_some() { "present" } else { "nil" },
            token.as_ref().map_or(0, |t| t.len())
        );
        let cloud_messages = self.get_or_init_cloud_messages_client().await?;

        const MAX_SYNC_ATTEMPTS: usize = 4;
        let mut sync_result = None;
        let mut last_pcs_err: Option<rustpush::PushError> = None;

        for attempt in 0..MAX_SYNC_ATTEMPTS {
            let cm_spawn = Arc::clone(&cloud_messages);
            let tok_spawn = token.clone();
            let spawn_result = tokio::task::spawn(async move {
                cm_spawn.sync_messages(tok_spawn).await
            }).await;

            match spawn_result {
                Ok(Ok(result)) => {
                    info!(
                        "cloud_sync_messages: sync_messages returned {} records, status={}",
                        result.1.len(), result.2
                    );
                    sync_result = Some(result);
                    break;
                }
                Ok(Err(err)) if is_pcs_recoverable_error(&err) => {
                    let attempt_no = attempt + 1;
                    warn!(
                        "CloudKit messages sync hit PCS key error on attempt {}/{}: {}",
                        attempt_no,
                        MAX_SYNC_ATTEMPTS,
                        err
                    );
                    last_pcs_err = Some(err);
                    if attempt_no < MAX_SYNC_ATTEMPTS {
                        self.recover_cloud_pcs_state("CloudKit messages sync").await?;
                        continue;
                    }
                }
                Ok(Err(err)) => {
                    return Err(WrappedError::GenericError {
                        msg: format!("Failed to sync CloudKit messages: {}", err),
                    });
                }
                Err(join_err) => {
                    warn!(
                        "cloud_sync_messages: sync_messages panicked on attempt {}/{} \
                         (malformed CloudKit record); trying per-record fallback. panic={}",
                        attempt + 1, MAX_SYNC_ATTEMPTS, join_err
                    );
                    match sync_messages_fallback(&cloud_messages, token.clone()).await {
                        Ok(result) => {
                            sync_result = Some(result);
                            break;
                        }
                        Err(e) => {
                            warn!("cloud_sync_messages: fallback also failed: {}; returning empty done page", e);
                            return Ok(WrappedCloudSyncMessagesPage {
                                continuation_token: None,
                                status: 0,
                                done: true,
                                messages: vec![],
                            });
                        }
                    }
                }
            }
        }

        let (next_token, messages, status) = match sync_result {
            Some(result) => result,
            None => {
                let err = last_pcs_err.map(|e| e.to_string()).unwrap_or_else(|| "unknown error".into());
                return Err(WrappedError::GenericError {
                    msg: format!("Failed to sync CloudKit messages after PCS recovery retries: {}", err),
                });
            }
        };

        let mut normalized = Vec::with_capacity(messages.len());
        let mut skipped_messages = 0usize;
        for (record_name, msg_opt) in messages {
            if let Some(msg) = msg_opt {
                // Skip system/service messages (group renames, participant changes,
                // location sharing, etc.). IS_SYSTEM_MESSAGE covers explicit system
                // notifications; IS_SERVICE_MESSAGE covers service-generated inline
                // notifications (e.g. "You named the conversation"). Neither type
                // is user-authored content.
                if msg.flags.intersects(
                    rustpush::cloud_messages::MessageFlags::IS_SYSTEM_MESSAGE
                    | rustpush::cloud_messages::MessageFlags::IS_SERVICE_MESSAGE
                ) {
                    skipped_messages += 1;
                    continue;
                }
                // Wrap per-message normalization in catch_unwind so one bad
                // CloudKit record doesn't fail the entire page.
                let rn = record_name.clone();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let guid = if msg.guid.is_empty() {
                        rn.clone()
                    } else {
                        msg.guid.clone()
                    };
                    let text = msg.msg_proto.text.clone();
                    let subject = msg.msg_proto.subject.clone();

                    // Extract tapback/reaction info from proto fields
                    let tapback_type = msg.msg_proto.associated_message_type;
                    let tapback_target_guid = msg.msg_proto.associated_message_guid.clone();
                    let tapback_emoji = msg.msg_proto_4.as_ref()
                        .and_then(|p4| p4.associated_message_emoji.clone());

                    // Extract attachment GUIDs from attributedBody
                    let attachment_guids: Vec<String> = msg.msg_proto.attributed_body
                        .as_ref()
                        .map(|body| extract_attachment_guids_from_attributed_body(body))
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|g| !g.is_empty() && g.len() <= 256 && g.is_ascii())
                        .collect();

                    let date_read_ms = msg.msg_proto.date_read
                        .map(|dr| apple_timestamp_ns_to_unix_ms(dr as i64))
                        .unwrap_or(0);

                    let has_body = msg.msg_proto.attributed_body.is_some();

                    WrappedCloudSyncMessage {
                        record_name: rn,
                        guid,
                        cloud_chat_id: msg.chat_id.clone(),
                        sender: msg.sender.clone(),
                        is_from_me: msg
                            .flags
                            .contains(rustpush::cloud_messages::MessageFlags::IS_FROM_ME),
                        text,
                        subject,
                        service: msg.service.clone(),
                        timestamp_ms: apple_timestamp_ns_to_unix_ms(msg.time),
                        deleted: false,
                        tapback_type,
                        tapback_target_guid,
                        tapback_emoji,
                        attachment_guids,
                        date_read_ms,
                        msg_type: msg.r#type,
                        has_body,
                    }
                }));

                match result {
                    Ok(wrapped) => normalized.push(wrapped),
                    Err(panic_val) => {
                        let panic_msg = if let Some(s) = panic_val.downcast_ref::<String>() {
                            s.clone()
                        } else if let Some(s) = panic_val.downcast_ref::<&str>() {
                            s.to_string()
                        } else {
                            "unknown panic".to_string()
                        };
                        warn!(
                            "Skipping CloudKit message {} due to normalization panic: {}",
                            record_name, panic_msg
                        );
                        skipped_messages += 1;
                    }
                }
            } else {
                normalized.push(WrappedCloudSyncMessage {
                    guid: record_name.clone(),
                    record_name,
                    cloud_chat_id: String::new(),
                    sender: String::new(),
                    is_from_me: false,
                    text: None,
                    subject: None,
                    service: String::new(),
                    timestamp_ms: 0,
                    deleted: true,
                    tapback_type: None,
                    tapback_target_guid: None,
                    tapback_emoji: None,
                    attachment_guids: vec![],
                    date_read_ms: 0,
                    msg_type: 0,
                    has_body: false,
                });
            }
        }

        if skipped_messages > 0 {
            warn!(
                "CloudKit message sync: skipped {} message(s) due to normalization errors",
                skipped_messages
            );
        }

        info!(
            "CloudKit message sync page: {} messages normalized, {} skipped",
            normalized.len(), skipped_messages
        );

        Ok(WrappedCloudSyncMessagesPage {
            continuation_token: encode_continuation_token(next_token),
            status,
            done: status == 3,
            messages: normalized,
        })
    }

    /// Sync CloudKit attachment zone and return metadata for all attachments.
    /// Returns a page of attachment metadata (record_name → attachment info).
    /// Paginate with continuation_token until done == true.
    pub async fn cloud_sync_attachments(
        &self,
        continuation_token: Option<String>,
    ) -> Result<WrappedCloudSyncAttachmentsPage, WrappedError> {
        let token = decode_continuation_token(continuation_token)?;
        let cloud_messages = self.get_or_init_cloud_messages_client().await?;

        let (next_token, attachments, status) = cloud_messages.sync_attachments(token).await
            .map_err(|e| WrappedError::GenericError {
                msg: format!("Failed to sync CloudKit attachments: {}", e),
            })?;

        let mut normalized = Vec::with_capacity(attachments.len());
        for (record_name, att_opt) in attachments {
            if let Some(att) = att_opt {
                normalized.push(WrappedCloudAttachmentInfo {
                    guid: att.cm.guid.clone(),
                    mime_type: att.cm.mime_type.clone(),
                    uti_type: att.cm.uti.clone(),
                    filename: att.cm.transfer_name.clone().or_else(|| att.cm.filename.clone()),
                    file_size: att.cm.total_bytes,
                    record_name,
                });
            }
            // Deleted attachments are simply not included
        }

        Ok(WrappedCloudSyncAttachmentsPage {
            continuation_token: encode_continuation_token(next_token),
            status,
            done: status == 3,
            attachments: normalized,
        })
    }

    /// Download an attachment from CloudKit by its record name.
    /// Returns the raw file bytes.
    pub async fn cloud_download_attachment(
        &self,
        record_name: String,
    ) -> Result<Vec<u8>, WrappedError> {
        let cloud_messages = self.get_or_init_cloud_messages_client().await?;

        // download_attachment consumes the writer via into_values().
        // Use a SharedWriter so we can recover the written bytes after the call.
        let shared = SharedWriter::new();
        let mut files = HashMap::new();
        files.insert(record_name.clone(), shared.clone());
        cloud_messages.download_attachment(files).await
            .map_err(|e| WrappedError::GenericError {
                msg: format!("Failed to download CloudKit attachment {}: {}", record_name, e),
            })?;
        Ok(shared.into_bytes())
    }

    /// Download a group photo from CloudKit by the chat's record name.
    /// Returns the raw image bytes. The record_name is the CloudKit record
    /// in chatManateeZone where the chat's "gp" asset is stored.
    pub async fn cloud_download_group_photo(
        &self,
        record_name: String,
    ) -> Result<Vec<u8>, WrappedError> {
        let cloud_messages = self.get_or_init_cloud_messages_client().await?;

        let shared = SharedWriter::new();
        let mut files = HashMap::new();
        files.insert(record_name.clone(), shared.clone());
        cloud_messages.download_group_photo(files).await
            .map_err(|e| WrappedError::GenericError {
                msg: format!("Failed to download CloudKit group photo {}: {}", record_name, e),
            })?;
        Ok(shared.into_bytes())
    }

    /// Diagnostic: do a full fresh sync from scratch (no continuation token)
    /// and return total record count + the newest message timestamps per chat.
    /// This bypasses any stored token to check what CloudKit actually has.
    pub async fn cloud_diag_full_count(
        &self,
    ) -> Result<String, WrappedError> {
        let cloud_messages = self.get_or_init_cloud_messages_client().await?;
        
        let mut token: Option<Vec<u8>> = None;
        let mut total_records: usize = 0;
        let mut total_deleted: usize = 0;
        let mut total_skipped: usize = 0;
        let mut chat_id_counts: HashMap<String, usize> = HashMap::new();
        let mut newest_ts: i64 = 0;
        let mut newest_guid = String::new();
        let mut newest_chat = String::new();
        
        for page in 0..512 {
            let (next_token, messages, status) = cloud_messages.sync_messages(token).await
                .map_err(|e| WrappedError::GenericError { msg: format!("diag sync page {} failed: {}", page, e) })?;
            
            let page_total = messages.len();
            let mut page_present = 0usize;
            let mut page_deleted = 0usize;
            for (_record_name, msg_opt) in &messages {
                if let Some(msg) = msg_opt {
                    page_present += 1;
                    total_records += 1;
                    let ts = apple_timestamp_ns_to_unix_ms(msg.time);
                    let chat = &msg.chat_id;
                    *chat_id_counts.entry(chat.clone()).or_insert(0) += 1;
                    if ts > newest_ts {
                        newest_ts = ts;
                        newest_guid = msg.guid.clone();
                        newest_chat = chat.clone();
                    }
                } else {
                    page_deleted += 1;
                    total_deleted += 1;
                }
            }
            // Records that are neither present nor deleted were skipped by PCS errors in sync_records
            total_skipped += page_total.saturating_sub(page_present + page_deleted);
            
            info!("diag page {} => {} records (status={})", page, page_total, status);
            
            if status == 3 {
                break;
            }
            token = Some(next_token);
        }
        
        let unique_chats = chat_id_counts.len();
        let result = format!(
            "total_records={} deleted={} unique_chats={} newest_ts={} newest_guid={} newest_chat={}",
            total_records, total_deleted, unique_chats, newest_ts, newest_guid, newest_chat
        );
        info!("CloudKit diag: {}", result);
        Ok(result)
    }

    pub async fn cloud_fetch_recent_messages(
        &self,
        since_timestamp_ms: u64,
        chat_id: Option<String>,
        max_pages: u32,
        max_results: u32,
    ) -> Result<Vec<WrappedCloudSyncMessage>, WrappedError> {
        let cloud_messages = self.get_or_init_cloud_messages_client().await?;
        let since = since_timestamp_ms as i64;
        let max_pages = if max_pages == 0 { 1 } else { max_pages };
        let max_results = if max_results == 0 { 1 } else { max_results as usize };

        let mut token: Option<Vec<u8>> = None;
        let mut deduped: HashMap<String, WrappedCloudSyncMessage> = HashMap::new();

        'pages: for _ in 0..max_pages {
            const MAX_SYNC_ATTEMPTS: usize = 4;
            let mut sync_result = None;
            let mut last_pcs_err: Option<rustpush::PushError> = None;

            for attempt in 0..MAX_SYNC_ATTEMPTS {
                match cloud_messages.sync_messages(token.clone()).await {
                    Ok(result) => {
                        sync_result = Some(result);
                        break;
                    }
                    Err(err) if is_pcs_recoverable_error(&err) => {
                        let attempt_no = attempt + 1;
                        warn!(
                            "CloudKit recent fetch hit PCS key error on attempt {}/{}: {}",
                            attempt_no,
                            MAX_SYNC_ATTEMPTS,
                            err
                        );
                        last_pcs_err = Some(err);
                        if attempt_no < MAX_SYNC_ATTEMPTS {
                            self.recover_cloud_pcs_state("CloudKit recent fetch").await?;
                            continue;
                        }
                    }
                    Err(err) => {
                        return Err(WrappedError::GenericError {
                            msg: format!("Failed to sync CloudKit messages: {}", err),
                        });
                    }
                }
            }

            let (next_token, messages, status) = match sync_result {
                Some(result) => result,
                None => {
                    let err = last_pcs_err.map(|e| e.to_string()).unwrap_or_else(|| "unknown error".into());
                    return Err(WrappedError::GenericError {
                        msg: format!("Failed to sync CloudKit messages after PCS recovery retries: {}", err),
                    });
                }
            };

            for (record_name, msg_opt) in messages {
                let Some(msg) = msg_opt else {
                    continue;
                };

                // Skip system/service messages (group renames, participant changes, etc.)
                if msg.flags.intersects(
                    rustpush::cloud_messages::MessageFlags::IS_SYSTEM_MESSAGE
                    | rustpush::cloud_messages::MessageFlags::IS_SERVICE_MESSAGE
                ) {
                    continue;
                }

                if let Some(ref wanted_chat) = chat_id {
                    if &msg.chat_id != wanted_chat {
                        continue;
                    }
                }

                let timestamp_ms = apple_timestamp_ns_to_unix_ms(msg.time);
                if timestamp_ms < since {
                    continue;
                }

                let guid = if msg.guid.is_empty() {
                    record_name.clone()
                } else {
                    msg.guid.clone()
                };

                let tapback_type = msg.msg_proto.associated_message_type;
                let tapback_target_guid = msg.msg_proto.associated_message_guid.clone();
                let tapback_emoji = msg.msg_proto_4.as_ref()
                    .and_then(|p4| p4.associated_message_emoji.clone());

                let date_read_ms = msg.msg_proto.date_read
                    .map(|dr| apple_timestamp_ns_to_unix_ms(dr as i64))
                    .unwrap_or(0);

                deduped.insert(
                    guid.clone(),
                    WrappedCloudSyncMessage {
                        record_name,
                        guid,
                        cloud_chat_id: msg.chat_id,
                        sender: msg.sender,
                        is_from_me: msg
                            .flags
                            .contains(rustpush::cloud_messages::MessageFlags::IS_FROM_ME),
                        text: msg.msg_proto.text.clone(),
                        subject: msg.msg_proto.subject.clone(),
                        service: msg.service,
                        timestamp_ms,
                        deleted: false,
                        tapback_type,
                        tapback_target_guid,
                        tapback_emoji,
                        attachment_guids: vec![],
                        date_read_ms,
                        msg_type: msg.r#type,
                        has_body: msg.msg_proto.attributed_body.is_some(),
                    },
                );

                if deduped.len() >= max_results {
                    break 'pages;
                }
            }

            if status == 3 {
                break;
            }
            token = Some(next_token);
        }

        let mut output = deduped.into_values().collect::<Vec<_>>();
        output.sort_by(|a, b| {
            a.timestamp_ms
                .cmp(&b.timestamp_ms)
                .then_with(|| a.guid.cmp(&b.guid))
        });
        if output.len() > max_results {
            output = output[output.len() - max_results..].to_vec();
        }

        Ok(output)
    }

    /// Test CloudKit Messages access: creates CloudKitClient + KeychainClient + CloudMessagesClient,
    /// then tries to sync chats and messages. Logs results. Returns a summary string.
    pub async fn test_cloud_messages(&self) -> Result<String, WrappedError> {
        let tp = self.token_provider.as_ref()
            .ok_or(WrappedError::GenericError { msg: "No TokenProvider available".into() })?;

        info!("=== CloudKit Messages Test ===");

        // Get needed credentials
        let dsid = tp.inner.get_dsid().await?;
        let adsid = tp.inner.get_adsid().await?;
        let mme_delegate = tp.inner.get_mme_delegate().await?;
        let account = tp.inner.get_account();
        let os_config = tp.inner.get_os_config();

        info!("DSID: {}, ADSID: {}", dsid, adsid);

        // Get anisette client from the account
        let anisette = account.lock().await.anisette.clone();

        // Create CloudKitState
        let cloudkit_state = rustpush::cloudkit::CloudKitState::new(dsid.clone())
            .ok_or(WrappedError::GenericError { msg: "Failed to create CloudKitState".into() })?;

        // Create CloudKitClient
        let cloudkit = Arc::new(rustpush::cloudkit::CloudKitClient {
            state: tokio::sync::RwLock::new(cloudkit_state),
            anisette: anisette.clone(),
            config: os_config.clone(),
            token_provider: tp.inner.clone(),
        });

        // Create KeychainClientState
        let keychain_state = rustpush::keychain::KeychainClientState::new(dsid.clone(), adsid.clone(), &mme_delegate)
            .ok_or(WrappedError::GenericError { msg: "Failed to create KeychainClientState — missing KeychainSync config in MobileMe delegate".into() })?;

        info!("KeychainClientState created successfully");

        // Create KeychainClient
        let keychain = Arc::new(rustpush::keychain::KeychainClient {
            anisette: anisette.clone(),
            token_provider: tp.inner.clone(),
            state: tokio::sync::RwLock::new(keychain_state),
            config: os_config.clone(),
            update_state: Box::new(|_state| {
                // For now, don't persist keychain state
                info!("Keychain state updated (not persisted yet)");
            }),
            container: tokio::sync::Mutex::new(None),
            security_container: tokio::sync::Mutex::new(None),
            client: cloudkit.clone(),
        });

        // Try to sync the keychain (needed for PCS decryption keys)
        info!("Syncing iCloud Keychain...");
        match keychain.sync_keychain(&rustpush::keychain::KEYCHAIN_ZONES).await {
            Ok(()) => info!("Keychain sync successful"),
            Err(e) => {
                let msg = format!("Keychain sync failed: {}. This likely means we need to join the trust circle first.", e);
                warn!("{}", msg);
                return Ok(msg);
            }
        }

        // Create CloudMessagesClient
        let cloud_messages = rustpush::cloud_messages::CloudMessagesClient::new(cloudkit.clone(), keychain.clone());

        // Try counting records first
        info!("Counting CloudKit message records...");
        match cloud_messages.count_records().await {
            Ok(summary) => {
                info!("CloudKit record counts — messages: {}, chats: {}, attachments: {}",
                    summary.messages_summary.len(), summary.chat_summary.len(), summary.attachment_summary.len());
            }
            Err(e) => {
                warn!("Failed to count records: {}", e);
            }
        }

        // Try syncing chats
        info!("Syncing CloudKit chats...");
        let mut total_chats = 0;
        let mut chat_names: Vec<String> = Vec::new();
        match cloud_messages.sync_chats(None).await {
            Ok((_token, chats, status)) => {
                info!("Chat sync returned {} chats (status={})", chats.len(), status);
                for (id, chat_opt) in &chats {
                    if let Some(chat) = chat_opt {
                        let name = chat.display_name.as_deref().unwrap_or("(unnamed)");
                        let participants: Vec<&str> = chat.participants.iter().map(|p| p.uri.as_str()).collect();
                        info!("  Chat: {} | id={} | svc={} | participants={:?}", name, chat.chat_identifier, chat.service_name, participants);
                        chat_names.push(format!("{}: {} [{}]", id, name, chat.chat_identifier));
                    } else {
                        info!("  Chat {} deleted", id);
                    }
                    total_chats += 1;
                }
            }
            Err(e) => {
                let msg = format!("Chat sync failed: {}", e);
                warn!("{}", msg);
                return Ok(msg);
            }
        }

        // Try syncing messages (first page)
        info!("Syncing CloudKit messages (first page)...");
        let mut total_messages = 0;
        match cloud_messages.sync_messages(None).await {
            Ok((_token, messages, status)) => {
                info!("Message sync returned {} messages (status={})", messages.len(), status);
                for (id, msg_opt) in messages.iter().take(20) {
                    if let Some(msg) = msg_opt {
                        let from_me = msg.flags.contains(rustpush::cloud_messages::MessageFlags::IS_FROM_ME);
                        info!("  Msg: {} | chat={} | sender={} | from_me={} | svc={} | guid={}",
                            id, msg.chat_id, msg.sender, from_me, msg.service, msg.guid);
                    } else {
                        info!("  Msg {} deleted", id);
                    }
                    total_messages += 1;
                }
                if messages.len() > 20 {
                    info!("  ... and {} more messages", messages.len() - 20);
                    total_messages = messages.len();
                }
            }
            Err(e) => {
                let msg = format!("Message sync failed: {}", e);
                warn!("{}", msg);
                return Ok(format!("Chats OK ({} chats), but message sync failed: {}", total_chats, e));
            }
        }

        let summary = format!("CloudKit sync OK: {} chats, {} messages (first page)", total_chats, total_messages);
        info!("{}", summary);
        Ok(summary)
    }

    pub async fn stop(&self) {
        let mut handle = self.receive_handle.lock().await;
        if let Some(h) = handle.take() {
            h.abort();
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Ok(mut handle) = self.receive_handle.try_lock() {
            if let Some(h) = handle.take() {
                h.abort();
            }
        }
    }
}

/// Fallback for cloud_sync_messages when sync_messages panics on a malformed CloudKit record.
/// Replicates sync_records logic for "messageManateeZone" but handles None proto fields
/// gracefully (no .unwrap()) and wraps from_record_encrypted in catch_unwind per record.
async fn sync_messages_fallback(
    cloud_messages: &Arc<rustpush::cloud_messages::CloudMessagesClient<omnisette::DefaultAnisetteProvider>>,
    token: Option<Vec<u8>>,
) -> Result<(Vec<u8>, HashMap<String, Option<rustpush::cloud_messages::CloudMessage>>, i32), rustpush::PushError> {
    use rustpush::cloudkit::{pcs_keys_for_record, FetchRecordChangesOperation, CloudKitSession, NO_ASSETS};
    use rustpush::cloudkit_proto::CloudKitRecord;
    use rustpush::cloud_messages::{MESSAGES_SERVICE, CloudMessage};

    let container = cloud_messages.get_container().await?;
    let zone_id = container.private_zone("messageManateeZone".to_string());
    let key = container
        .get_zone_encryption_config(&zone_id, &cloud_messages.keychain, &MESSAGES_SERVICE)
        .await?;

    let (_assets, response) = container
        .perform(
            &CloudKitSession::new(),
            FetchRecordChangesOperation::new(zone_id, token, &NO_ASSETS),
        )
        .await?;

    let mut results: HashMap<String, Option<CloudMessage>> = HashMap::new();
    let mut skipped = 0usize;

    for change in &response.change {
        // Graceful identifier extraction — no .unwrap()
        let id_proto = match change.identifier.as_ref() {
            Some(p) => p,
            None => { warn!("sync_messages_fallback: skipping change with missing identifier"); skipped += 1; continue; }
        };
        let id_value = match id_proto.value.as_ref() {
            Some(v) => v,
            None => { warn!("sync_messages_fallback: skipping change with missing identifier value"); skipped += 1; continue; }
        };
        let identifier = id_value.name().to_string();

        let record = match &change.record {
            Some(r) => r,
            None => { results.insert(identifier, None); continue; } // deleted record
        };

        // Graceful type check — no .unwrap()
        if record.r#type.as_ref().map_or(true, |t| t.name() != CloudMessage::record_type()) {
            continue;
        }

        let pcskey = match pcs_keys_for_record(record, &key) {
            Ok(k) => k,
            Err(e) => {
                warn!("sync_messages_fallback: skipping record {}: PCS key error: {}", identifier, e);
                skipped += 1;
                continue;
            }
        };

        let rec_id = match record.record_identifier.as_ref() {
            Some(id) => id,
            None => {
                warn!("sync_messages_fallback: skipping record {}: missing record_identifier", identifier);
                skipped += 1;
                continue;
            }
        };

        // from_record_encrypted may panic on corrupt field data — catch it
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            CloudMessage::from_record_encrypted(&record.record_field, Some((&pcskey, rec_id)))
        }));

        match result {
            Ok(msg) => { results.insert(identifier, Some(msg)); }
            Err(e) => {
                let msg = if let Some(s) = e.downcast_ref::<String>() { s.clone() }
                          else if let Some(s) = e.downcast_ref::<&str>() { s.to_string() }
                          else { "unknown panic".to_string() };
                warn!("sync_messages_fallback: skipping record {}: deserialization panic: {}", identifier, msg);
                skipped += 1;
            }
        }
    }

    if skipped > 0 {
        warn!("sync_messages_fallback: skipped {} malformed record(s)", skipped);
    }

    Ok((
        response.sync_continuation_token().to_vec(),
        results,
        response.status(),
    ))
}

uniffi::setup_scaffolding!();
