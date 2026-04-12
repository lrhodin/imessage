//! Thin wrapper around upstream's RemoteAnisetteProviderV3 that adds
//! a timeout to prevent the infinite loop in upstream's provision().
//!
//! Upstream's provision() loop: `let Some(Ok(data)) = connection.next()
//! .await else { continue }` — loops forever if the WS stream ends.
//! We wrap the call with a timeout so it fails fast instead of hanging.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use log::warn;
use omnisette::remote_anisette_v3::RemoteAnisetteProviderV3;
use omnisette::{AnisetteError, AnisetteProvider, LoginClientInfo};

const ANISETTE_URL: &str = "https://ani.sidestore.io";
const PROVISION_TIMEOUT: Duration = Duration::from_secs(30);

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
            let mut upstream = RemoteAnisetteProviderV3::new(
                ANISETTE_URL.to_string(),
                self.info.clone(),
                self.state_path.clone(),
            );
            match tokio::time::timeout(PROVISION_TIMEOUT, upstream.get_anisette_headers()).await {
                Ok(result) => result,
                Err(_) => {
                    warn!("anisette: upstream provision timed out after {}s (likely infinite loop on WS drop)", PROVISION_TIMEOUT.as_secs());
                    Err(AnisetteError::InvalidArgument(
                        "Anisette provisioning timed out. The anisette server (ani.sidestore.io) may be down. Try again shortly.".into()
                    ))
                }
            }
        }
    }
}
