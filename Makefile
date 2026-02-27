APP_NAME    := mautrix-imessage-v2
CMD_PKG     := mautrix-imessage
BUNDLE_ID   := com.lrhodin.mautrix-imessage
VERSION     := 0.1.0
COMMIT      := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME  := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
DATA_DIR    ?= $(HOME)/.local/share/mautrix-imessage
UNAME_S     := $(shell uname -s)

RUST_LIB    := librustpushgo.a
RUST_SRC    := $(shell find pkg/rustpushgo/src -name '*.rs' 2>/dev/null)
RUSTPUSH_SRC:= $(shell find rustpush/src rustpush/apple-private-apis rustpush/open-absinthe/src -name '*.rs' -o -name '*.s' 2>/dev/null) $(wildcard rustpush/open-absinthe/build.rs)
CARGO_FILES := $(shell find . -name 'Cargo.toml' -o -name 'Cargo.lock' 2>/dev/null | grep -v target)
GO_SRC      := $(shell find pkg/ cmd/ -name '*.go' 2>/dev/null)

BBCTL       := bbctl
LDFLAGS     := -X main.Tag=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildTime=$(BUILD_TIME)

# Track the git commit so ldflags changes trigger a Go rebuild.
# .build-commit is updated whenever HEAD changes.
COMMIT_FILE := .build-commit
PREV_COMMIT := $(shell cat $(COMMIT_FILE) 2>/dev/null)
ifneq ($(COMMIT),$(PREV_COMMIT))
  $(shell echo $(COMMIT) > $(COMMIT_FILE))
endif

.PHONY: build clean install install-beeper install-beeper-multi uninstall reset rust bindings check-deps check-deps-linux

# ===========================================================================
# Path validation – spaces in the working directory break CGO linker flags
# and #cgo LDFLAGS ${SRCDIR} expansion. Detect early with a clear message.
# ===========================================================================
ifneq ($(word 2,$(CURDIR)),)
  $(error The project path "$(CURDIR)" contains spaces. CGO and the linker cannot handle spaces in library paths. Please clone or move the project to a path without spaces, e.g.: /home/$$USER/imessage)
endif

# ===========================================================================
# Platform detection
# ===========================================================================

ifeq ($(UNAME_S),Darwin)
  # macOS paths and settings
  export PATH := /opt/homebrew/bin:/opt/homebrew/sbin:$(PATH)
  APP_BUNDLE  := $(APP_NAME).app
  BINARY      := $(APP_BUNDLE)/Contents/MacOS/$(APP_NAME)
  INFO_PLIST  := $(APP_BUNDLE)/Contents/Info.plist
  CGO_CFLAGS  := -I/opt/homebrew/include
  CGO_LDFLAGS := -L/opt/homebrew/lib -L$(CURDIR)
  CARGO_ENV   := MACOSX_DEPLOYMENT_TARGET=13.0
else
  # Linux: include Go and Rust installed by bootstrap
  export PATH := /usr/local/go/bin:$(HOME)/.cargo/bin:$(PATH)
  BINARY      := $(APP_NAME)
  CGO_CFLAGS  :=
  CGO_LDFLAGS := -L$(CURDIR)
  CARGO_ENV   :=
endif

# ===========================================================================
# Dependency checks
# ===========================================================================

# macOS: auto-install via Homebrew
check-deps:
ifeq ($(UNAME_S),Darwin)
	@if ! command -v brew >/dev/null 2>&1; then \
		echo "Installing Homebrew..."; \
		NONINTERACTIVE=1 /bin/bash -c "$$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"; \
		eval "$$(/opt/homebrew/bin/brew shellenv)"; \
	fi; \
	missing=""; \
	command -v go >/dev/null 2>&1    || missing="$$missing go"; \
	command -v cargo >/dev/null 2>&1 || missing="$$missing rust"; \
	command -v protoc >/dev/null 2>&1|| missing="$$missing protobuf"; \
	command -v tmux >/dev/null 2>&1  || missing="$$missing tmux"; \
	[ -f /opt/homebrew/include/olm/olm.h ] || [ -f /usr/local/include/olm/olm.h ] || missing="$$missing libolm"; \
	if [ -n "$$missing" ]; then \
		echo "Installing dependencies:$$missing"; \
		brew install $$missing; \
	fi
else
	@scripts/bootstrap-linux.sh
endif

# ===========================================================================
# Rust static library
# ===========================================================================

# On Linux, enable hardware-key feature (open-absinthe x86 NAC emulator).
# On macOS, native AAAbsintheContext is used — no unicorn/cmake needed.
ifeq ($(UNAME_S),Darwin)
  CARGO_FEATURES :=
else
  CARGO_FEATURES := --features hardware-key
endif

$(RUST_LIB): $(RUST_SRC) $(RUSTPUSH_SRC) $(CARGO_FILES)
	cd pkg/rustpushgo && $(CARGO_ENV) cargo build --release $(CARGO_FEATURES)
	cp pkg/rustpushgo/target/release/librustpushgo.a .

rust: $(RUST_LIB)

# ===========================================================================
# Go bindings
# ===========================================================================

bindings: $(RUST_LIB)
	cd pkg/rustpushgo && uniffi-bindgen-go target/release/librustpushgo.a --library --out-dir ..
	python3 scripts/patch_bindings.py

# ===========================================================================
# Build
# ===========================================================================

ifeq ($(UNAME_S),Darwin)
build: check-deps $(RUST_LIB) $(BINARY) $(BBCTL)
	codesign --force --deep --sign - $(APP_BUNDLE)
	@echo "Built $(APP_BUNDLE) + $(BBCTL) ($(VERSION)-$(COMMIT))"

$(BINARY): $(GO_SRC) $(shell find . -name '*.m' -o -name '*.h' 2>/dev/null | grep -v target) go.mod go.sum $(RUST_LIB) $(COMMIT_FILE)
	@mkdir -p $(APP_BUNDLE)/Contents/MacOS
	@cp Info.plist $(INFO_PLIST)
	CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" \
		go build -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/$(CMD_PKG)/
else
build: check-deps $(RUST_LIB) $(BINARY) $(BBCTL)
	@echo "Built $(BINARY) + $(BBCTL) ($(VERSION)-$(COMMIT))"

$(BINARY): $(GO_SRC) go.mod go.sum $(RUST_LIB) $(COMMIT_FILE)
	CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$(CGO_LDFLAGS)" \
		go build -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/$(CMD_PKG)/
endif

$(BBCTL): $(GO_SRC) go.mod go.sum
	go build -o $(BBCTL) ./cmd/bbctl/

# ===========================================================================
# Install / uninstall (macOS)
# ===========================================================================

install: build
ifeq ($(UNAME_S),Darwin)
	@scripts/install.sh "$(BINARY)" "$(DATA_DIR)" "$(BUNDLE_ID)"
else
	@scripts/install-linux.sh "$(BINARY)" "$(DATA_DIR)"
endif

install-beeper: build
ifeq ($(UNAME_S),Darwin)
	@scripts/install-beeper.sh "$(BINARY)" "$(DATA_DIR)" "$(BUNDLE_ID)" "$(CURDIR)/$(BBCTL)"
else
	@scripts/install-beeper-linux.sh "$(BINARY)" "$(DATA_DIR)" "$(CURDIR)/$(BBCTL)"
endif

install-beeper-multi: build
	@echo ""; \
	echo "Multi-instance iMessage Bridge Setup"; \
	echo ""; \
	read -p "How many bridges would you like to create? " COUNT; \
	for i in $$(seq 1 $$COUNT); do \
		PORT=$$((4000 + $$i)); \
		if lsof -iTCP:$$PORT -sTCP:LISTEN >/dev/null 2>&1; then \
			echo ""; \
			echo "ERROR: Port $$PORT is already in use (needed for sh-imessage-$$i)"; \
			exit 1; \
		fi; \
		echo ""; \
		echo "═══════════════════════════════════════════════"; \
		echo "  Setting up bridge $$i of $$COUNT (sh-imessage-$$i)"; \
		echo "═══════════════════════════════════════════════"; \
		BRIDGE_NAME=sh-imessage-$$i \
		XDG_DATA_HOME=$(HOME)/.local/share/imessage-$$i \
		DATA_DIR=$(HOME)/.local/share/imessage-$$i/mautrix-imessage \
		BUNDLE_ID=com.lrhodin.mautrix-imessage-$$i \
		BRIDGE_PORT=$$PORT \
		$(MAKE) install-beeper; \
	done

reset:
ifeq ($(UNAME_S),Darwin)
	@scripts/reset-bridge.sh "$(BUNDLE_ID)"
else
	@scripts/reset-bridge.sh
endif

uninstall:
ifeq ($(UNAME_S),Darwin)
	-launchctl unload ~/Library/LaunchAgents/$(BUNDLE_ID).plist 2>/dev/null
	rm -f ~/Library/LaunchAgents/$(BUNDLE_ID).plist
	@echo "LaunchAgent removed. App bundle at $(APP_BUNDLE) left in place."
else
	@echo "On Linux, stop the service and remove the binary manually."
endif

# ===========================================================================
# Extract-key (hardware key extraction tool)
# ===========================================================================
# extract-key uses CGO with Objective-C and macOS frameworks (Foundation,
# IOKit, DiskArbitration), so it can only be compiled on macOS.
# It has its own go.mod (Go 1.20) so it can build on macOS 10.13 High Sierra.
#
# On older Macs without Go installed, use the self-contained build script:
#   cd tools/extract-key && ./build.sh

.PHONY: extract-key

ifeq ($(UNAME_S),Darwin)
extract-key:
	cd tools/extract-key && go build -trimpath -o ../../extract-key .
else
extract-key:
	@echo "Error: extract-key must be built on macOS." >&2
	@echo "It uses Objective-C and macOS frameworks (IOKit, Foundation, DiskArbitration)." >&2
	@echo "" >&2
	@echo "On the target Mac (including High Sierra 10.13+):" >&2
	@echo "  cd tools/extract-key && ./build.sh" >&2
	@exit 1
endif

clean:
ifeq ($(UNAME_S),Darwin)
	rm -rf $(APP_NAME).app
endif
	rm -f $(APP_NAME) $(BBCTL) $(RUST_LIB) extract-key tools/extract-key/extract-key
	cd pkg/rustpushgo && cargo clean 2>/dev/null || true
