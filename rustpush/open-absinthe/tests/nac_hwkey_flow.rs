//! test_nac_validation_flow_from_hw_key_env
//!
//! Purpose:
//! - End-to-end NAC validation smoke test using a real extracted hardware key.
//! - Verifies that `ValidationCtx::{new,key_establishment,sign}` works against
//!   Apple's live validation endpoints from Linux.
//!
//! How to run:
//! - Set `HW_KEY_B64` to the base64 key, OR set `HW_KEY_FILE` to a file path.
//! - Run this single test with `-- --nocapture` to inspect lengths and progress.
//!
//! Notes:
//! - If neither env var is set, the test exits early (skip-like behavior).
//! - This is tooling for validation and debugging; production code does not
//!   depend on this test.

use std::io::{Cursor, Read};

use open_absinthe::nac::{HardwareConfig, ValidationCtx};
use serde::Deserialize;

fn read_response_bytes(resp: ureq::Response) -> Vec<u8> {
    let mut buf = Vec::new();
    resp.into_reader().read_to_end(&mut buf).unwrap();
    buf
}

#[derive(Deserialize)]
struct WrappedHardwareConfig {
    inner: HardwareConfig,
}

fn parse_hw_key_b64(raw: &str) -> HardwareConfig {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let cleaned: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = STANDARD.decode(cleaned).expect("invalid base64 hardware key");

    if let Ok(wrapped) = serde_json::from_slice::<WrappedHardwareConfig>(&bytes) {
        wrapped.inner
    } else {
        serde_json::from_slice::<HardwareConfig>(&bytes)
            .expect("invalid hardware key json (expected wrapped MacOSConfig or bare HardwareConfig)")
    }
}

#[test]
fn test_nac_validation_flow_from_hw_key_env() {
    let key_b64 = if let Ok(v) = std::env::var("HW_KEY_B64") {
        v
    } else if let Ok(path) = std::env::var("HW_KEY_FILE") {
        std::fs::read_to_string(path).expect("failed to read HW_KEY_FILE")
    } else {
        eprintln!("Skipping test_nac_validation_flow_from_hw_key_env: set HW_KEY_B64 or HW_KEY_FILE");
        return;
    };

    let hw = parse_hw_key_b64(&key_b64);

    println!(
        "HW key: model={} build={} serial={} _enc_lens: serial={} uuid={} disk={} rom={} mlb={}",
        hw.product_name,
        hw.os_build_num,
        hw.platform_serial_number,
        hw.platform_serial_number_enc.len(),
        hw.platform_uuid_enc.len(),
        hw.root_disk_uuid_enc.len(),
        hw.rom_enc.len(),
        hw.mlb_enc.len()
    );

    // Build agent with native TLS for Apple's cert chain
    let agent = ureq::AgentBuilder::new()
        .tls_connector(std::sync::Arc::new(native_tls::TlsConnector::new().unwrap()))
        .build();

    // Step 1: Fetch validation cert from Apple
    let cert_resp = agent
        .get("http://static.ess.apple.com/identity/validation/cert-1.0.plist")
        .call()
        .unwrap();
    let cert_data = read_response_bytes(cert_resp);
    let cert_plist: plist::Value = plist::from_reader(Cursor::new(&cert_data)).unwrap();
    let cert_bytes = cert_plist
        .as_dictionary()
        .unwrap()
        .get("cert")
        .unwrap()
        .as_data()
        .unwrap()
        .to_vec();

    println!("Fetched validation cert: {} bytes", cert_bytes.len());

    // Step 2: nac_init
    let mut request_bytes = vec![];
    let mut ctx = ValidationCtx::new(&cert_bytes, &mut request_bytes, &hw).unwrap();
    assert!(!request_bytes.is_empty(), "nac_init should produce request bytes");
    println!("nac_init OK: {} request bytes", request_bytes.len());

    // Step 3: Send session-info-request to Apple, get session-info back
    let session_req = plist::Value::Dictionary(plist::Dictionary::from_iter([(
        "session-info-request".to_string(),
        plist::Value::Data(request_bytes),
    )]));
    let mut body = vec![];
    plist::to_writer_xml(&mut body, &session_req).unwrap();

    let session_resp = agent
        .post("https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/initializeValidation")
        .send_bytes(&body)
        .unwrap();
    let resp_data = read_response_bytes(session_resp);
    let resp_plist: plist::Value = plist::from_reader(Cursor::new(&resp_data)).unwrap();
    let session_info = resp_plist
        .as_dictionary()
        .unwrap()
        .get("session-info")
        .unwrap()
        .as_data()
        .unwrap()
        .to_vec();

    println!("Got session-info: {} bytes", session_info.len());

    // Step 4: nac_key_establishment
    ctx.key_establishment(&session_info).unwrap();
    println!("nac_key_establishment OK");

    // Step 5: nac_sign
    let validation_data = ctx.sign().unwrap();
    assert!(!validation_data.is_empty(), "nac_sign should produce validation data");
    println!("nac_sign OK: {} bytes of validation data", validation_data.len());

    // Typical observed value is around 517 bytes; keep this check loose.
    assert!(
        (450..=700).contains(&validation_data.len()),
        "unexpected validation data length: {}",
        validation_data.len()
    );

    println!("SUCCESS: Full NAC validation flow completed using provided hardware key");
}
