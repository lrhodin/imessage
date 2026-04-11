fn main() {
    println!("cargo:rerun-if-changed=src/validation_data.m");
    println!("cargo:rerun-if-changed=src/validation_data.h");

    // Compile the Objective-C file
    cc::Build::new()
        .file("src/validation_data.m")
        .flag("-fobjc-arc")
        .flag("-fmodules") // for @import if needed
        .define("NAC_NO_MAIN", None) // exclude main() when building as a library
        .compile("validation_data");

    // Link with Foundation framework
    println!("cargo:rustc-link-lib=framework=Foundation");
}
