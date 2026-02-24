# Multi-stage Dockerfile for mautrix-imessage (Linux AMD64)
#
# Build:
#   docker build -t mautrix-imessage .
#
# Run:
#   docker run -v /path/to/data:/data mautrix-imessage

# ── Build stage ───────────────────────────────────────────────────────────────
# golang:1.25-bookworm provides Go matching the toolchain in go.mod.
FROM golang:1.25-bookworm AS builder

# System build dependencies (see scripts/bootstrap-linux.sh for rationale).
# libunicorn-dev: avoids building Unicorn Engine / QEMU from source via cmake.
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        protobuf-compiler \
        build-essential \
        pkg-config \
        libclang-dev \
        libssl-dev \
        libolm-dev \
        libunicorn-dev \
        zlib1g-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Install Rust to system-wide paths so it persists across RUN layers.
ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup
ENV PATH=$CARGO_HOME/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --no-modify-path

# Working directory without spaces — required by CGO ${SRCDIR} expansion.
WORKDIR /build

# ── Rust build (cached independently from Go changes) ────────────────────────
# Copy Cargo manifests + all Rust source first. This layer is only invalidated
# when Rust code changes, avoiding expensive re-compilation for Go-only edits.
COPY pkg/rustpushgo/Cargo.toml pkg/rustpushgo/Cargo.lock ./pkg/rustpushgo/
COPY pkg/rustpushgo/src/ ./pkg/rustpushgo/src/
COPY rustpush/ ./rustpush/
COPY nac-validation/ ./nac-validation/

# Build the Rust static library.
# --features hardware-key enables open-absinthe (x86 NAC emulator via unicorn),
# required on Linux in place of the macOS-native AAAbsintheContext.
RUN cd pkg/rustpushgo \
    && cargo build --release --features hardware-key \
    && cp target/release/librustpushgo.a /build/

# ── Go build ──────────────────────────────────────────────────────────────────
# Pre-download modules so this layer is cached when only source files change.
COPY go.mod go.sum ./
RUN GOTOOLCHAIN=local go mod download

# Copy all Go source including generated CGO bindings (rustpushgo.go/.h/.c).
COPY cmd/ ./cmd/
COPY pkg/ ./pkg/
COPY imessage/ ./imessage/
COPY ipc/ ./ipc/

# Build the binary.
# - GOTOOLCHAIN=local: prevents Go from downloading a newer toolchain.
# - CGO_LDFLAGS: supplements the #cgo LDFLAGS ${SRCDIR} path in rustpushgo.go,
#   ensuring the linker finds librustpushgo.a at /build/.
ARG VERSION=0.1.0
ARG COMMIT=unknown
RUN BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
    && GOTOOLCHAIN=local \
       CGO_LDFLAGS="-L/build" \
       go build \
         -ldflags "-X main.Tag=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}" \
         -o /build/mautrix-imessage-v2 \
         ./cmd/mautrix-imessage/

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM ubuntu:24.04

# Runtime shared-library dependencies:
#   libolm3      — Matrix end-to-bridge encryption (Olm/Megolm)
#   libunicorn2  — x86 NAC emulator (hardware-key / open-absinthe)
#   libssl3      — TLS, dynamically linked by the Rust layer (-lssl -lcrypto)
#   ca-certificates, openssl, wget — CA bundle + Apple Root CA installation
RUN apt-get update && apt-get install -y --no-install-recommends \
        libolm3 \
        libunicorn2 \
        libssl3 \
        ca-certificates \
        openssl \
        wget \
    && wget -qO /tmp/AppleRootCA.cer \
         'https://www.apple.com/appleca/AppleIncRootCertificate.cer' \
    && openssl x509 -inform DER -in /tmp/AppleRootCA.cer \
         -out /usr/local/share/ca-certificates/AppleRootCA.crt \
    && update-ca-certificates \
    && rm -f /tmp/AppleRootCA.cer \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/mautrix-imessage-v2 /usr/local/bin/mautrix-imessage-v2

VOLUME /data
WORKDIR /data

ENTRYPOINT ["/usr/local/bin/mautrix-imessage-v2"]
CMD ["-c", "/data/config.yaml"]
