//! Linux anisette wrapper around upstream's `RemoteAnisetteProviderV3`.
//!
//! Upstream's provisioning has three bugs we work around here:
//!   1. The `ProvisionInput` enum is missing `EndProvisioningError`, so a
//!      transient Apple rejection crashes serde instead of returning an error.
//!   2. The provision() loop (`let Some(Ok(data)) = ... else { continue }`)
//!      spins forever if the WebSocket stream closes.
//!   3. `get_anisette_headers` contains a bare `panic!()` for any
//!      non-`AnisetteNotProvisioned` error from `get_headers` (see
//!      `remote_anisette_v3.rs:417`). If that panic unwinds across the
//!      uniffi FFI boundary while the caller holds the shared
//!      `tokio::sync::Mutex<anisette>` (TokenProvider, CloudKitClient,
//!      KeychainClient all share it), every subsequent anisette-touching
//!      operation deadlocks — including message send.
//!
//! This wrapper catches those failures, cleans state, retries, and adds a
//! timeout. All Apple-facing requests go through upstream's code unchanged.

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::time::Duration;

use futures::FutureExt;
use log::{info, warn};
use omnisette::remote_anisette_v3::RemoteAnisetteProviderV3;
use omnisette::{AnisetteError, AnisetteProvider, LoginClientInfo};

const ANISETTE_URL: &str = "https://ani.sidestore.io";
const PROVISION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RETRIES: usize = 3;

pub struct BridgeAnisetteProvider {
    info: LoginClientInfo,
    state_path: PathBuf,
}

impl BridgeAnisetteProvider {
    pub fn new(info: LoginClientInfo, state_path: PathBuf) -> Self {
        Self { info, state_path }
    }

    /// Delete the cached anisette state so the next attempt provisions fresh.
    fn clear_state(&self) {
        let p = self.state_path.join("state.plist");
        if p.exists() {
            if let Err(e) = std::fs::remove_file(&p) {
                warn!("anisette: failed to remove stale state: {}", e);
            } else {
                info!("anisette: cleared stale state for retry");
            }
        }
    }
}

impl AnisetteProvider for BridgeAnisetteProvider {
    fn get_anisette_headers(
        &mut self,
    ) -> impl std::future::Future<Output = Result<HashMap<String, String>, AnisetteError>> + Send
    {
        async move {
            let mut last_err = None;

            for attempt in 0..MAX_RETRIES {
                // Fresh upstream provider each attempt — it reads state from
                // disk so a cleared state.plist forces re-provisioning.
                let mut upstream = RemoteAnisetteProviderV3::new(
                    ANISETTE_URL.to_string(),
                    self.info.clone(),
                    self.state_path.clone(),
                );

                // AssertUnwindSafe + catch_unwind turns upstream's bare
                // `panic!()` into a caught panic payload. Without this the
                // panic unwinds into the caller's critical section and can
                // leave shared mutexes locked.
                let inner = AssertUnwindSafe(upstream.get_anisette_headers()).catch_unwind();
                match tokio::time::timeout(PROVISION_TIMEOUT, inner).await {
                    Ok(Ok(Ok(headers))) => return Ok(headers),
                    Ok(Ok(Err(AnisetteError::SerdeError(ref e)))) => {
                        // Upstream's ProvisionInput enum is missing variants
                        // (e.g. EndProvisioningError). Clear state and retry —
                        // the rejection may be transient.
                        warn!(
                            "anisette: upstream serde error on attempt {}/{}: {}",
                            attempt + 1,
                            MAX_RETRIES,
                            e
                        );
                        self.clear_state();
                        last_err = Some(AnisetteError::InvalidArgument(format!(
                            "Anisette provisioning was rejected by the server \
                             (attempt {}/{}). Error: {}",
                            attempt + 1,
                            MAX_RETRIES,
                            e
                        )));
                    }
                    Ok(Ok(Err(e))) => {
                        // Non-serde error — don't retry blindly.
                        return Err(e);
                    }
                    Ok(Err(panic_payload)) => {
                        // Upstream `RemoteAnisetteProviderV3::get_anisette_headers`
                        // contains `panic!()` for non-`AnisetteNotProvisioned`
                        // errors. Convert to a retryable error so the panic
                        // doesn't unwind past this point.
                        let msg = if let Some(s) = panic_payload.downcast_ref::<&'static str>() {
                            (*s).to_string()
                        } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                            s.clone()
                        } else {
                            "unknown panic payload".into()
                        };
                        warn!(
                            "anisette: upstream panicked on attempt {}/{}: {}",
                            attempt + 1,
                            MAX_RETRIES,
                            msg
                        );
                        self.clear_state();
                        last_err = Some(AnisetteError::InvalidArgument(format!(
                            "Anisette call panicked (attempt {}/{}): {}",
                            attempt + 1,
                            MAX_RETRIES,
                            msg
                        )));
                    }
                    Err(_) => {
                        // Timeout — likely the upstream infinite-loop bug.
                        warn!(
                            "anisette: upstream timed out on attempt {}/{} \
                             (likely infinite loop on WS drop)",
                            attempt + 1,
                            MAX_RETRIES,
                        );
                        self.clear_state();
                        last_err = Some(AnisetteError::InvalidArgument(
                            format!(
                                "Anisette provisioning timed out (attempt {}/{}). \
                                 The anisette server (ani.sidestore.io) may be down.",
                                attempt + 1,
                                MAX_RETRIES,
                            ),
                        ));
                    }
                }
            }

            Err(last_err.unwrap_or_else(|| {
                AnisetteError::InvalidArgument("Anisette provisioning failed".into())
            }))
        }
    }
}
