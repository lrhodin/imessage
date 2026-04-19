@echo off
REM Windows equivalent of `make bindings`.
REM
REM The Makefile's `bindings` target hardcodes UNIX lib naming
REM (librustpushgo.a). On Windows with the MSVC toolchain, cargo emits
REM `rustpushgo.lib` instead, so the Makefile target can't find the artifact.
REM Rather than fork the Makefile for Windows, this script reproduces the
REM target's two real steps against Windows-native paths:
REM
REM   1. cd pkg\rustpushgo && uniffi-bindgen-go <lib> --library --out-dir ..
REM   2. python scripts\patch_bindings.py
REM
REM Usage:
REM     dev\windows-dev-env.bat && dev\windows-bindings.bat
REM
REM Assumes dev\windows-dev-env.bat has already run (sets PATH, LIBCLANG_PATH,
REM ensures uniffi-bindgen-go is installed, creates the python3 alias). Run it
REM first in the same shell session.

setlocal

REM Resolve the repo root (parent of this script's dir).
for %%I in ("%~dp0..") do set "REPO=%%~fI"

REM Figure out where cargo put the static lib. If CARGO_TARGET_DIR is set
REM (e.g. pointing outside a cloud-sync folder), use that; otherwise use the
REM default in-crate location.
if defined CARGO_TARGET_DIR (
    set "CARGO_OUT=%CARGO_TARGET_DIR%\release"
) else (
    set "CARGO_OUT=%REPO%\pkg\rustpushgo\target\release"
)

set "RUST_LIB=%CARGO_OUT%\rustpushgo.lib"

REM Build the static lib if it's missing. Safe to re-run: cargo is incremental.
if not exist "%RUST_LIB%" (
    echo rustpushgo.lib missing at %RUST_LIB% — running cargo build...
    pushd "%REPO%\pkg\rustpushgo"
    cargo build --release
    if errorlevel 1 (
        echo.
        echo ERROR: cargo build failed. Fix compile errors and re-run.
        popd
        exit /b 1
    )
    popd
)

if not exist "%RUST_LIB%" (
    echo.
    echo ERROR: expected rustpushgo.lib at %RUST_LIB% but it is still missing.
    echo Did cargo succeed but write to a different path? Check CARGO_TARGET_DIR
    echo and that crate-type includes "staticlib".
    exit /b 1
)

REM Check uniffi-bindgen-go is on PATH. The dev-env script auto-installs it.
where uniffi-bindgen-go >nul 2>&1
if errorlevel 1 (
    echo.
    echo ERROR: uniffi-bindgen-go not found on PATH.
    echo Run `dev\windows-dev-env.bat` first to install it.
    exit /b 1
)

REM Step 1: regenerate Go bindings from the Rust FFI surface.
REM Mirrors the Makefile's command:
REM     cd pkg/rustpushgo && uniffi-bindgen-go target/release/librustpushgo.a --library --out-dir ..
echo.
echo === Regenerating UniFFI Go bindings ===
pushd "%REPO%\pkg\rustpushgo"
uniffi-bindgen-go "%RUST_LIB%" --library --out-dir ..
if errorlevel 1 (
    echo.
    echo ERROR: uniffi-bindgen-go failed. Likely causes:
    echo   - Rust FFI signature changed without a matching uniffi version bump
    echo   - The v0.2.2+v0.25.0 tag in windows-dev-env.bat no longer matches Cargo.toml's uniffi pin
    popd
    exit /b 1
)
popd

REM Step 2: run the bindings post-processor. The Makefile invokes `python3`;
REM windows-dev-env.bat drops a python3.bat shim into %USERPROFILE%\.cargo\bin
REM so this call resolves whether invoked from cmd or git-bash.
echo.
echo === Patching bindings ===
pushd "%REPO%"
python3 scripts\patch_bindings.py
if errorlevel 1 (
    echo.
    echo ERROR: patch_bindings.py failed.
    popd
    exit /b 1
)
popd

echo.
echo === Bindings regenerated successfully ===
endlocal
