# Dev notes

## FFI boundary (Go ↔ Rust)

**Never hand-edit** `pkg/rustpushgo/rustpushgo.go` or `rustpushgo.h`. Always regenerate:

```bash
make bindings   # requires uniffi-bindgen-go on PATH
make build
```

Install `uniffi-bindgen-go` (must match UniFFI 0.25.0):
```bash
cargo install uniffi-bindgen-go --git https://github.com/AO-AO/uniffi-bindgen-go --tag v0.2.2+v0.25.0
```
