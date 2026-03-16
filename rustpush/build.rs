use std::io::Result;
use std::path::Path;
use std::fs;

const FAIRPLAY_CERT_NAMES: &[&str] = &[
    "4056631661436364584235346952193",
    "4056631661436364584235346952194",
    "4056631661436364584235346952195",
    "4056631661436364584235346952196",
    "4056631661436364584235346952197",
    "4056631661436364584235346952198",
    "4056631661436364584235346952199",
    "4056631661436364584235346952200",
    "4056631661436364584235346952201",
    "4056631661436364584235346952208",
];

/// Bootstrap FairPlay certs from legacy-fairplay/ if certs/fairplay/ is missing.
/// The legacy certs are committed in the repo; the per-name copies are gitignored.
fn bootstrap_fairplay_certs() {
    let fairplay_dir = Path::new("certs/fairplay");
    let first_cert = fairplay_dir.join(format!("{}.crt", FAIRPLAY_CERT_NAMES[0]));

    if first_cert.exists() {
        return; // Already bootstrapped
    }

    // Try legacy-fairplay/ first (committed in repo)
    let legacy_crt = Path::new("certs/legacy-fairplay/fairplay.crt");
    let legacy_pem = Path::new("certs/legacy-fairplay/fairplay.pem");

    let (crt_data, pem_data) = if legacy_crt.exists() && legacy_pem.exists() {
        eprintln!("cargo:warning=Bootstrapping FairPlay certs from certs/legacy-fairplay/");
        (fs::read(legacy_crt).expect("read legacy crt"), fs::read(legacy_pem).expect("read legacy pem"))
    } else {
        // Download from upstream OpenBubbles/rustpush
        eprintln!("cargo:warning=Downloading FairPlay certs from OpenBubbles/rustpush...");
        let crt = download("https://raw.githubusercontent.com/OpenBubbles/rustpush/master/certs/legacy-fairplay/fairplay.crt");
        let pem = download("https://raw.githubusercontent.com/OpenBubbles/rustpush/master/certs/legacy-fairplay/fairplay.pem");
        (crt, pem)
    };

    fs::create_dir_all(fairplay_dir).expect("create certs/fairplay/");
    for name in FAIRPLAY_CERT_NAMES {
        fs::write(fairplay_dir.join(format!("{}.crt", name)), &crt_data).expect("write crt");
        fs::write(fairplay_dir.join(format!("{}.pem", name)), &pem_data).expect("write pem");
    }
    eprintln!("cargo:warning=FairPlay certs bootstrapped ({} pairs)", FAIRPLAY_CERT_NAMES.len());
}

fn download(url: &str) -> Vec<u8> {
    let output = std::process::Command::new("curl")
        .args(["-sfL", url])
        .output()
        .expect("curl failed");
    if !output.status.success() {
        panic!("Failed to download {}: {}", url, String::from_utf8_lossy(&output.stderr));
    }
    output.stdout
}

fn main() -> Result<()> {
    bootstrap_fairplay_certs();

    let proto_files = &["src/icloud/mmcs.proto", "src/ids/ids.proto", "src/facetime.proto", "src/statuskit.proto", "src/imessage/cloud_messages.proto"];
    for proto in proto_files {
        println!("cargo:rerun-if-changed={}", proto);
    }

    let mut prost_build = prost_build::Config::new();
    // Enable a protoc experimental feature.
    prost_build.protoc_arg("--experimental_allow_proto3_optional");
    prost_build.compile_protos(proto_files, &["src/"])?;
    Ok(())
}
