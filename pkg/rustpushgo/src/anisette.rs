//! Linux anisette wrapper around upstream's `RemoteAnisetteProviderV3`.
//!
//! Upstream's provisioning has two bugs we work around here:
//!   1. The `ProvisionInput` enum is missing `EndProvisioningError`, so a
//!      transient Apple rejection crashes serde instead of returning an error.
//!   2. The provision() loop (`let Some(Ok(data)) = ... else { continue }`)
//!      spins forever if the WebSocket stream closes.
//!
//! This wrapper catches those failures, cleans state, retries, and adds a
//! timeout. All Apple-facing requests go through upstream's code unchanged.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

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

                match tokio::time::timeout(
                    PROVISION_TIMEOUT,
                    upstream.get_anisette_headers(),
                )
                .await
                {
                    Ok(Ok(headers)) => return Ok(headers),
                    Ok(Err(AnisetteError::SerdeError(ref e))) => {
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
                    Ok(Err(e)) => {
                        // Non-serde error — don't retry blindly.
                        return Err(e);
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
