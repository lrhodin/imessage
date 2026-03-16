use std::env;
use std::process::Command;

fn main() {
    // Declare the custom cfg so cargo doesn't warn about it
    println!("cargo:rustc-check-cfg=cfg(has_xnu_encrypt)");

    let target = env::var("TARGET").unwrap_or_default();

    // Only compile the XNU encrypt assembly on x86_64 Linux targets
    if !target.starts_with("x86_64") || !target.contains("linux") {
        return;
    }

    let out_dir = env::var("OUT_DIR").unwrap();
    let asm_src = "src/asm/encrypt.s";
    let obj_path = format!("{}/encrypt.o", out_dir);
    let lib_path = format!("{}/libxnu_encrypt.a", out_dir);

    // Assemble encrypt.s → encrypt.o
    let status = Command::new("cc")
        .args(["-c", "-o", &obj_path, asm_src])
        .status()
        .expect("Failed to run assembler on encrypt.s");
    assert!(status.success(), "Assembly of encrypt.s failed");

    // Create static library
    let status = Command::new("ar")
        .args(["rcs", &lib_path, &obj_path])
        .status()
        .expect("Failed to run ar");
    assert!(status.success(), "ar failed to create libxnu_encrypt.a");

    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=xnu_encrypt");
    println!("cargo:rerun-if-changed={}", asm_src);

    // Tell the rest of the crate that the encrypt function is available
    println!("cargo:rustc-cfg=has_xnu_encrypt");
}
