# Open Absinthe

Cross-platform NAC (Network Attestation Check) validation using x86_64 emulation. Runs Apple's `IMDAppleServices` binary inside [unicorn-engine](https://www.unicorn-engine.org/), hooking CoreFoundation, IOKit, and DiskArbitration calls and feeding them hardware data extracted from a real Mac. This lets the iMessage bridge generate valid Apple validation data on Linux without a macOS runtime.

Based on the approach from [nacserver](https://github.com/JJTech0130/nacserver), ported to Rust.