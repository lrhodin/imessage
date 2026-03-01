# Open Absinthe

Cross-platform NAC (Network Attestation Check) validation using x86_64 emulation. Runs Apple's `IMDAppleServices` binary inside [unicorn-engine](https://www.unicorn-engine.org/), hooking CoreFoundation, IOKit, and DiskArbitration calls and feeding them hardware data extracted from a real Mac. This lets the iMessage bridge generate valid Apple validation data on Linux without a macOS runtime.

Based on the approach from [nacserver](https://github.com/JJTech0130/nacserver), ported to Rust.

## Enrich Hardware Keys

If a hardware key is missing `_enc` fields (common with some Intel/macOS
versions), you can enrich it on x86_64 Linux:

```bash
cargo run --bin enrich_hw_key -- --key '<base64-hardware-key>'
```

Or read from stdin / file:

```bash
cat hwkey.b64 | cargo run --bin enrich_hw_key --
cargo run --bin enrich_hw_key -- --file hwkey.b64
```

The command prints diagnostics to stderr and writes the enriched base64 key to
stdout.
