//! register_once
//!
//! Purpose:
//! - Developer/debugging helper to run a single IDS `register()` call from Linux
//!   using already-persisted bridge session state + a hardware key.
//! - Lets us validate registration behavior (headers/body/status) without going
//!   through the full Matrix/Beeper login orchestration.
//!
//! Notes:
//! - This is NOT used by the normal bridge runtime path.
//! - It intentionally forces local x86 NAC emulation (`nac_relay_url = None`) so
//!   Intel/mac-less experiments are deterministic.

use std::{env, fs, path::PathBuf, sync::RwLock};

use base64::{engine::general_purpose::STANDARD, Engine};
use keystore::{
    init_keystore,
    software::{NoEncryptor, SoftwareKeystore, SoftwareKeystoreState},
};
use rustpush::{register, APSState, IDSNGMIdentity, IDSUser, MADRID_SERVICE};
use rustpush::macos::{HardwareConfig, MacOSConfig};
use serde::Deserialize;

#[derive(Deserialize)]
struct PersistedSessionState {
    ids_identity: String,
    aps_state: String,
    ids_users: String,
}

fn default_xdg_dir() -> PathBuf {
    if let Ok(xdg) = env::var("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("mautrix-imessage");
        }
    }
    if let Ok(home) = env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home).join(".local/share/mautrix-imessage");
        }
    }
    PathBuf::from("state")
}

fn init_software_keystore(state_path: PathBuf) {
    let state = match fs::read(&state_path) {
        Ok(bytes) => plist::from_bytes::<SoftwareKeystoreState>(&bytes).unwrap_or_default(),
        Err(_) => SoftwareKeystoreState::default(),
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

fn load_hw_config(path: &str) -> Result<MacOSConfig, Box<dyn std::error::Error>> {
    let key_b64 = fs::read_to_string(path)?;
    let clean_key: String = key_b64.chars().filter(|c| !c.is_whitespace()).collect();
    let json_bytes = STANDARD.decode(clean_key)?;

    let mut cfg = if let Ok(full) = serde_json::from_slice::<MacOSConfig>(&json_bytes) {
        full
    } else {
        let hw: HardwareConfig = serde_json::from_slice(&json_bytes)?;
        MacOSConfig {
            inner: hw,
            version: "13.6.6".to_string(),
            protocol_version: 1660,
            device_id: "".to_string(),
            icloud_ua: "com.apple.iCloudHelper/282 CFNetwork/1568.100.1 Darwin/22.6.0".to_string(),
            aoskit_version: "com.apple.AOSKit/282 (com.apple.accountsd/113)".to_string(),
            udid: None,
            nac_relay_url: None,
        }
    };

    cfg.device_id = cfg.inner.platform_uuid.to_uppercase();
    if cfg.udid.is_none() {
        cfg.udid = Some(cfg.device_id.clone());
    }
    // Force local x86 NAC emulation path for this experiment.
    cfg.nac_relay_url = None;

    Ok(cfg)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Usage: {} <session-json> <hardware-key-b64-file> [keystore-plist]",
            args[0]
        );
        std::process::exit(2);
    }

    let session_path = &args[1];
    let hw_key_path = &args[2];
    let keystore_path = if args.len() >= 4 {
        PathBuf::from(&args[3])
    } else {
        default_xdg_dir().join("identity.plist")
    };

    eprintln!("[register-once] session={}", session_path);
    eprintln!("[register-once] hw_key={}", hw_key_path);
    eprintln!("[register-once] keystore={}", keystore_path.display());

    init_software_keystore(keystore_path);

    let session_json = fs::read_to_string(session_path)?;
    let persisted: PersistedSessionState = serde_json::from_str(&session_json)?;

    let aps_state: APSState = plist::from_bytes(persisted.aps_state.as_bytes())?;
    let mut users: Vec<IDSUser> = plist::from_bytes(persisted.ids_users.as_bytes())?;
    let identity: IDSNGMIdentity = plist::from_bytes(persisted.ids_identity.as_bytes())?;

    let cfg = load_hw_config(hw_key_path)?;

    eprintln!(
        "[register-once] model={} build={} serial={} _enc lens: serial={} uuid={} disk={} rom={} mlb={}",
        cfg.inner.product_name,
        cfg.inner.os_build_num,
        cfg.inner.platform_serial_number,
        cfg.inner.platform_serial_number_enc.len(),
        cfg.inner.platform_uuid_enc.len(),
        cfg.inner.root_disk_uuid_enc.len(),
        cfg.inner.rom_enc.len(),
        cfg.inner.mlb_enc.len()
    );

    register(&cfg, &aps_state, &[&MADRID_SERVICE], &mut users, &identity).await?;

    eprintln!("[register-once] register() completed successfully");
    Ok(())
}
