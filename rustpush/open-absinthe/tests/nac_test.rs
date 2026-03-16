use std::io::{Cursor, Read};
use open_absinthe::nac::{HardwareConfig, ValidationCtx};

fn base64_dec(s: &str) -> Vec<u8> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.decode(s).unwrap()
}

fn read_response_bytes(resp: ureq::Response) -> Vec<u8> {
    let mut buf = Vec::new();
    resp.into_reader().read_to_end(&mut buf).unwrap();
    buf
}

fn sample_hw() -> HardwareConfig {
    HardwareConfig {
        product_name: "MacBookAir8,1".into(),
        io_mac_address: [0xa4, 0x83, 0xe7, 0x11, 0x47, 0x1c],
        platform_serial_number: "C02YT1YMJK7M".into(),
        platform_uuid: "11D299A5-CF0B-544D-BAD3-7AC7A6E452D7".into(),
        root_disk_uuid: "FCDB63B5-D208-4AEE-B368-3DE952B911FF".into(),
        board_id: "Mac-827FAC58A8FDFA22".into(),
        os_build_num: "22G513".into(),
        platform_serial_number_enc: base64_dec("c3kZ7+WofxcjaBTInJCwSV0="),
        platform_uuid_enc: base64_dec("jGguP3mQH+Vw6dMAWrqZOnk="),
        root_disk_uuid_enc: base64_dec("VvJODAsuSRdGQlhB5kPgf2M="),
        rom: base64_dec("V9BNndaG"),
        rom_enc: base64_dec("wWF12gciXzN/96bIt/ufTB0="),
        mlb: "C02923200KVKN3YAG".into(),
        mlb_enc: base64_dec("CKp4ROiInBYAdvnbrbNjjkM="),
    }
}

#[test]
fn test_nac_validation_flow() {
    let hw = sample_hw();

    // Build agent with native TLS for Apple's cert chain
    let agent = ureq::AgentBuilder::new()
        .tls_connector(std::sync::Arc::new(native_tls::TlsConnector::new().unwrap()))
        .build();

    // Step 1: Fetch validation cert from Apple (HTTP, no TLS issue)
    let cert_resp = agent.get("http://static.ess.apple.com/identity/validation/cert-1.0.plist")
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
    assert!(
        !request_bytes.is_empty(),
        "nac_init should produce request bytes"
    );
    println!("nac_init OK: {} request bytes", request_bytes.len());

    // Step 3: Send session-info-request to Apple, get session-info back
    let session_req =
        plist::Value::Dictionary(plist::Dictionary::from_iter([(
            "session-info-request".to_string(),
            plist::Value::Data(request_bytes),
        )]));
    let mut body = vec![];
    plist::to_writer_xml(&mut body, &session_req).unwrap();

    let session_resp = agent.post(
        "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/initializeValidation",
    )
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
    assert!(
        !validation_data.is_empty(),
        "nac_sign should produce validation data"
    );
    println!(
        "nac_sign OK: {} bytes of validation data",
        validation_data.len()
    );
    println!("SUCCESS: Full NAC validation flow completed on Linux!");
}

#[test]
fn test_hardware_config_apple_silicon() {
    // Apple Silicon keys have empty _enc fields — verify deserialization works
    let json = r#"{
        "product_name": "Mac14,14",
        "io_mac_address": [164, 252, 20, 17, 24, 231],
        "platform_serial_number": "GYD6Q9YDH4",
        "platform_uuid": "4E2CDE99-F091-5723-980B-482821B8A20A",
        "root_disk_uuid": "10B6A4C2-D5EB-4CDC-9C60-31325B64AAAE",
        "board_id": "Mac14,14",
        "os_build_num": "25B78",
        "platform_serial_number_enc": [],
        "platform_uuid_enc": [],
        "root_disk_uuid_enc": [],
        "rom": [164, 252, 20, 17, 24, 231],
        "rom_enc": [],
        "mlb": "H28328500MN21G6AR",
        "mlb_enc": []
    }"#;

    let hw: HardwareConfig = serde_json::from_str(json).expect("deser failed");
    assert_eq!(hw.product_name, "Mac14,14");
    assert_eq!(hw.platform_serial_number, "GYD6Q9YDH4");
    assert_eq!(hw.mlb, "H28328500MN21G6AR");
    assert_eq!(hw.rom.len(), 6);
    assert!(hw.platform_serial_number_enc.is_empty());
    assert!(hw.mlb_enc.is_empty());
    assert!(hw.rom_enc.is_empty());
    println!("Apple Silicon HardwareConfig deserialized OK: {}", hw.product_name);
}

#[test]
fn test_hardware_config_json_roundtrip() {
    let hw = sample_hw();
    let json = serde_json::to_vec(&hw).unwrap();
    let decoded: HardwareConfig = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded.platform_serial_number, "C02YT1YMJK7M");
    assert_eq!(decoded.io_mac_address, [0xa4, 0x83, 0xe7, 0x11, 0x47, 0x1c]);
    assert_eq!(decoded.product_name, "MacBookAir8,1");
    assert_eq!(decoded.board_id, "Mac-827FAC58A8FDFA22");
    assert_eq!(decoded.mlb, "C02923200KVKN3YAG");
    println!("JSON roundtrip OK");
}
