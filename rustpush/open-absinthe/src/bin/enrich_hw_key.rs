use std::{env, fs, io::{self, Read}};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use open_absinthe::nac::{enrich_missing_enc_fields, HardwareConfig};
use serde_json::Value;

fn usage(bin: &str) {
    eprintln!("Usage:");
    eprintln!("  {bin} --key <base64-hardware-key>");
    eprintln!("  {bin} --file <path-to-base64-key-file>");
    eprintln!("  {bin}    # reads base64 key from stdin");
    eprintln!();
    eprintln!("Output:");
    eprintln!("  Prints enriched base64 hardware key to stdout.");
    eprintln!("  Prints diagnostics to stderr.");
}

fn read_input_key(args: &[String]) -> Result<String, String> {
    if args.is_empty() {
        let mut input = String::new();
        io::stdin()
            .read_to_string(&mut input)
            .map_err(|e| format!("failed to read stdin: {e}"))?;
        if input.trim().is_empty() {
            return Err("stdin is empty".into());
        }
        return Ok(input);
    }

    if args.len() != 2 {
        return Err("expected exactly one input flag".into());
    }

    match args[0].as_str() {
        "--key" => Ok(args[1].clone()),
        "--file" => fs::read_to_string(&args[1])
            .map_err(|e| format!("failed to read {}: {e}", args[1])),
        "--help" | "-h" => Err("help".into()),
        other => Err(format!("unknown flag: {other}")),
    }
}

#[derive(Clone, Copy)]
struct EncLens {
    serial: usize,
    uuid: usize,
    disk: usize,
    rom: usize,
    mlb: usize,
}

impl EncLens {
    fn from(hw: &HardwareConfig) -> Self {
        Self {
            serial: hw.platform_serial_number_enc.len(),
            uuid: hw.platform_uuid_enc.len(),
            disk: hw.root_disk_uuid_enc.len(),
            rom: hw.rom_enc.len(),
            mlb: hw.mlb_enc.len(),
        }
    }
}

fn parse_hw_from_json_value(v: &Value) -> Result<(HardwareConfig, bool), String> {
    if let Some(inner) = v.get("inner") {
        let hw = serde_json::from_value::<HardwareConfig>(inner.clone())
            .map_err(|e| format!("invalid wrapped hardware key JSON (.inner): {e}"))?;
        Ok((hw, true))
    } else {
        let hw = serde_json::from_value::<HardwareConfig>(v.clone())
            .map_err(|e| format!("invalid hardware key JSON: {e}"))?;
        Ok((hw, false))
    }
}

fn update_json_with_hw(mut root: Value, hw: &HardwareConfig, wrapped: bool) -> Result<Value, String> {
    if wrapped {
        let obj = root
            .as_object_mut()
            .ok_or_else(|| "expected wrapped hardware key to be a JSON object".to_string())?;
        obj.insert(
            "inner".to_string(),
            serde_json::to_value(hw).map_err(|e| format!("failed to serialize enriched inner key: {e}"))?,
        );
        Ok(root)
    } else {
        serde_json::to_value(hw).map_err(|e| format!("failed to serialize enriched key: {e}"))
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let bin = args.first().cloned().unwrap_or_else(|| "enrich_hw_key".into());
    let arg_slice = &args[1..];
    if matches!(arg_slice.first().map(|s| s.as_str()), Some("--help" | "-h")) {
        usage(&bin);
        return Ok(());
    }

    let raw_b64 = read_input_key(arg_slice)?;
    let clean_b64: String = raw_b64.chars().filter(|c| !c.is_whitespace()).collect();

    let json_bytes = BASE64_STANDARD
        .decode(clean_b64)
        .map_err(|e| format!("invalid base64 key: {e}"))?;

    let root: Value =
        serde_json::from_slice(&json_bytes).map_err(|e| format!("invalid key JSON payload: {e}"))?;
    let (mut hw, wrapped) = parse_hw_from_json_value(&root)?;

    let before = EncLens::from(&hw);
    enrich_missing_enc_fields(&mut hw).map_err(|e| e.to_string())?;
    let after = EncLens::from(&hw);

    let out_root = update_json_with_hw(root, &hw, wrapped)?;
    let out_json = serde_json::to_vec(&out_root)
        .map_err(|e| format!("failed to serialize enriched key JSON: {e}"))?;
    let out_b64 = BASE64_STANDARD.encode(out_json);

    eprintln!(
        "Input _enc lengths:  serial={} uuid={} disk={} rom={} mlb={}",
        before.serial, before.uuid, before.disk, before.rom, before.mlb
    );
    eprintln!(
        "Output _enc lengths: serial={} uuid={} disk={} rom={} mlb={}",
        after.serial, after.uuid, after.disk, after.rom, after.mlb
    );

    println!("{out_b64}");
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        if err == "help" {
            usage(&env::args().next().unwrap_or_else(|| "enrich_hw_key".into()));
            return;
        }
        eprintln!("Error: {err}");
        eprintln!("Use --help for usage.");
        std::process::exit(1);
    }
}
