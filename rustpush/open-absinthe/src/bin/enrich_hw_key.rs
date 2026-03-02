// enrich_hw_key: Enriches a base64-encoded hardware key with missing _enc
// fields by computing them from plaintext values using the XNU kernel
// encryption function. Only works on x86_64 Linux.
//
// Usage:
//   cargo build --bin enrich_hw_key
//   ./target/debug/enrich_hw_key --key <base64>
//   ./target/debug/enrich_hw_key --file ~/hwkey.b64
//   echo '<base64>' | ./target/debug/enrich_hw_key

use base64::{engine::general_purpose::STANDARD, Engine};
use open_absinthe::nac::{enrich_missing_enc_fields, HardwareConfig};
use std::io::{self, Read};

/// Wrapper with inner HardwareConfig, matching MacOSConfig layout.
#[derive(serde::Serialize, serde::Deserialize)]
struct WrappedConfig {
    inner: HardwareConfig,
    #[serde(flatten)]
    rest: serde_json::Value,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Parse input: --key <base64>, --file <path>, or stdin
    let b64_input = if let Some(pos) = args.iter().position(|a| a == "--key") {
        args.get(pos + 1)
            .expect("--key requires a base64 argument")
            .clone()
    } else if let Some(pos) = args.iter().position(|a| a == "--file") {
        let path = args
            .get(pos + 1)
            .expect("--file requires a file path argument");
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| {
                eprintln!("Failed to read {}: {}", path, e);
                std::process::exit(1);
            })
            .trim()
            .to_string()
    } else {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf).unwrap_or_else(|e| {
            eprintln!("Failed to read stdin: {}", e);
            std::process::exit(1);
        });
        buf.trim().to_string()
    };

    if b64_input.is_empty() {
        eprintln!("Usage: enrich_hw_key --key <base64>");
        eprintln!("       enrich_hw_key --file <path>");
        eprintln!("       echo '<base64>' | enrich_hw_key");
        std::process::exit(1);
    }

    // Decode base64
    let json_bytes = STANDARD.decode(&b64_input).unwrap_or_else(|e| {
        eprintln!("Base64 decode error: {}", e);
        std::process::exit(1);
    });

    // Try parsing as wrapped MacOSConfig first, then as bare HardwareConfig
    let (mut hw, wrapper): (HardwareConfig, Option<serde_json::Value>) =
        if let Ok(wrapped) = serde_json::from_slice::<WrappedConfig>(&json_bytes) {
            eprintln!("Parsed as MacOSConfig (wrapped)");
            let rest = wrapped.rest;
            (wrapped.inner, Some(rest))
        } else if let Ok(hw) = serde_json::from_slice::<HardwareConfig>(&json_bytes) {
            eprintln!("Parsed as bare HardwareConfig");
            (hw, None)
        } else {
            eprintln!("Failed to parse JSON as HardwareConfig or MacOSConfig");
            std::process::exit(1);
        };

    // Log before state
    eprintln!("Before enrichment:");
    eprintln!(
        "  platform_serial_number_enc: {} bytes",
        hw.platform_serial_number_enc.len()
    );
    eprintln!("  platform_uuid_enc: {} bytes", hw.platform_uuid_enc.len());
    eprintln!(
        "  root_disk_uuid_enc: {} bytes",
        hw.root_disk_uuid_enc.len()
    );
    eprintln!("  rom_enc: {} bytes", hw.rom_enc.len());
    eprintln!("  mlb_enc: {} bytes", hw.mlb_enc.len());

    // Enrich
    if let Err(e) = enrich_missing_enc_fields(&mut hw) {
        eprintln!("Enrichment failed: {}", e);
        std::process::exit(1);
    }

    // Log after state
    eprintln!("After enrichment:");
    eprintln!(
        "  platform_serial_number_enc: {} bytes",
        hw.platform_serial_number_enc.len()
    );
    eprintln!("  platform_uuid_enc: {} bytes", hw.platform_uuid_enc.len());
    eprintln!(
        "  root_disk_uuid_enc: {} bytes",
        hw.root_disk_uuid_enc.len()
    );
    eprintln!("  rom_enc: {} bytes", hw.rom_enc.len());
    eprintln!("  mlb_enc: {} bytes", hw.mlb_enc.len());

    // Re-serialize
    let output_json = if let Some(rest) = wrapper {
        let wrapped = WrappedConfig { inner: hw, rest };
        serde_json::to_vec(&wrapped).expect("JSON serialization failed")
    } else {
        serde_json::to_vec(&hw).expect("JSON serialization failed")
    };

    let output_b64 = STANDARD.encode(&output_json);
    println!("{}", output_b64);
}
