// enrich_hw_key: Enriches a base64-encoded hardware key with missing _enc
// fields by computing them from plaintext values using the XNU kernel
// encryption function. Only works on x86_64 Linux.
//
// Preserves the original JSON key ordering so the output is byte-compatible
// with the input tool (Go extract-key, SwiftUI app, etc.).
//
// Usage:
//   cargo build --bin enrich_hw_key
//   ./target/debug/enrich_hw_key --key <base64>
//   ./target/debug/enrich_hw_key --file ~/hwkey.b64
//   echo '<base64>' | ./target/debug/enrich_hw_key

use base64::{engine::general_purpose::STANDARD, Engine};
use open_absinthe::nac::{enrich_missing_enc_fields, HardwareConfig};
use serde_json::{Map, Value};
use std::io::{self, Read};

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

    // Parse as serde_json::Value to preserve original key ordering.
    // With the preserve_order feature, Map uses IndexMap which maintains
    // insertion order through serialize/deserialize round-trips.
    let mut root: Value = serde_json::from_slice(&json_bytes).unwrap_or_else(|e| {
        eprintln!("JSON parse error: {}", e);
        std::process::exit(1);
    });

    // Find the inner HardwareConfig — either root.inner (MacOSConfig) or root itself
    let is_wrapped = root.get("inner").is_some();
    let inner_value = if is_wrapped {
        eprintln!("Parsed as MacOSConfig (wrapped)");
        root.get("inner").unwrap().clone()
    } else {
        eprintln!("Parsed as bare HardwareConfig");
        root.clone()
    };

    // Deserialize inner as HardwareConfig for enrichment
    let mut hw: HardwareConfig = serde_json::from_value(inner_value).unwrap_or_else(|e| {
        eprintln!("Failed to parse HardwareConfig: {}", e);
        std::process::exit(1);
    });

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

    // Write enriched _enc fields back into the original Value tree,
    // preserving the original key ordering for all other fields.
    let target = if is_wrapped {
        root.get_mut("inner").unwrap()
    } else {
        &mut root
    };

    if let Value::Object(map) = target {
        write_enc_field(map, "platform_serial_number_enc", &hw.platform_serial_number_enc);
        write_enc_field(map, "platform_uuid_enc", &hw.platform_uuid_enc);
        write_enc_field(map, "root_disk_uuid_enc", &hw.root_disk_uuid_enc);
        write_enc_field(map, "rom_enc", &hw.rom_enc);
        write_enc_field(map, "mlb_enc", &hw.mlb_enc);
    }

    // Reorder keys to match the exact ordering that Apple expects.
    // This matches the Go extract-key tool and Swift app output.
    let reordered = if is_wrapped {
        let inner_map = root.get("inner").unwrap().as_object().unwrap();
        let outer_map = root.as_object().unwrap();
        let inner_ordered = reorder_inner(inner_map);
        let mut outer = Map::new();
        // Outer key order: aoskit_version, inner, protocol_version, device_id, icloud_ua, version
        for key in &[
            "aoskit_version",
            "inner",
            "protocol_version",
            "device_id",
            "icloud_ua",
            "version",
        ] {
            if *key == "inner" {
                outer.insert("inner".to_string(), Value::Object(inner_ordered.clone()));
            } else if let Some(v) = outer_map.get(*key) {
                outer.insert(key.to_string(), v.clone());
            }
        }
        Value::Object(outer)
    } else {
        let map = root.as_object().unwrap();
        Value::Object(reorder_inner(map))
    };

    let output_json = serde_json::to_vec(&reordered).expect("JSON serialization failed");
    let output_b64 = STANDARD.encode(&output_json);
    println!("{}", output_b64);
}

/// Write an _enc field value into a JSON map, preserving its position if it
/// already exists, or appending it if new.
fn write_enc_field(map: &mut Map<String, Value>, key: &str, data: &[u8]) {
    let arr = Value::Array(data.iter().map(|b| Value::Number((*b).into())).collect());
    map.insert(key.to_string(), arr);
}

/// Reorder inner (HardwareConfig) keys to match the expected ordering.
fn reorder_inner(map: &Map<String, Value>) -> Map<String, Value> {
    let key_order = [
        "root_disk_uuid",
        "mlb",
        "product_name",
        "platform_uuid_enc",
        "rom",
        "platform_serial_number",
        "io_mac_address",
        "platform_uuid",
        "os_build_num",
        "platform_serial_number_enc",
        "board_id",
        "root_disk_uuid_enc",
        "mlb_enc",
        "rom_enc",
    ];
    let mut ordered = Map::new();
    for key in &key_order {
        if let Some(v) = map.get(*key) {
            ordered.insert(key.to_string(), v.clone());
        }
    }
    // Include any extra keys not in the standard order (e.g. relay fields)
    for (k, v) in map {
        if !ordered.contains_key(k) {
            ordered.insert(k.clone(), v.clone());
        }
    }
    ordered
}
