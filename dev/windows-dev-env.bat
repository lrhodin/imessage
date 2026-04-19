@echo off
REM Sets up the Windows development environment for building the Rust crate.
REM
REM Why this exists: vcvarsall.bat auto-detects the Windows SDK via vswhere.exe,
REM which lives under the Visual Studio Installer directory and isn't in PATH
REM by default. Without vswhere, vcvarsall sets LIB to only the MSVC compiler's
REM own lib dir (missing kernel32.lib, ntdll.lib, ws2_32.lib) and cargo builds
REM fail with `LINK : fatal error LNK1181: cannot open input file 'kernel32.lib'`.
REM
REM Usage from git-bash or cmd:
REM     scripts\windows-dev-env.bat && cargo build --release
REM
REM After this script, the CURRENT cmd session has:
REM     * MSVC compiler/linker in PATH
REM     * LIB/INCLUDE pointing at MSVC + Windows SDK
REM     * Cargo in PATH
REM
REM Requires one-time installs:
REM     winget install --id Microsoft.VisualStudio.2022.BuildTools --override "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
REM     winget install --id Microsoft.WindowsSDK.10.0.26100
REM     winget install --id Rustlang.Rustup
REM     winget install --id StrawberryPerl.StrawberryPerl   (for openssl-sys build script)
REM     winget install --id Kitware.CMake                   (for unicorn-engine-sys / NAC emulator)
REM     winget install --id Python.Python.3.12              (unicorn-engine build script needs python)
REM     winget install --id Google.Protobuf                 (cloudkit-proto build uses protoc)
REM     winget install --id LLVM.LLVM                       (bindgen in unicorn-engine-sys needs libclang)
REM
REM CARGO_TARGET_DIR override: this repo lives under Dropbox, which races with
REM cargo's build outputs and causes `os error 32: file in use` failures on
REM openssl-sys and similar native builds. Redirecting the target dir to a
REM path outside Dropbox eliminates the race entirely.

REM Prepend the VS Installer dir so vcvarsall can find vswhere.
set "PATH=C:\Program Files (x86)\Microsoft Visual Studio\Installer;%PATH%"

REM Set up the MSVC + Windows SDK environment (LIB, INCLUDE, PATH additions).
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1

REM Prepend Strawberry Perl so openssl-sys's Configure script (which needs
REM Locale::Maketext::Simple and other standard Perl modules) uses the full
REM Strawberry distribution instead of git-bash's stripped-down perl.
set "PATH=C:\Strawberry\perl\bin;C:\Strawberry\c\bin;%PATH%"

REM Ensure cargo is available.
set "PATH=C:\Users\%USERNAME%\.cargo\bin;%PATH%"

REM Add CMake + Python + protoc + LLVM (installed via winget to standard locations).
set "PATH=C:\Program Files\CMake\bin;C:\Program Files\Python312;C:\Users\%USERNAME%\AppData\Local\Microsoft\WinGet\Packages\Google.Protobuf_Microsoft.Winget.Source_8wekyb3d8bbwe\bin;C:\Program Files\LLVM\bin;%PATH%"

REM bindgen (used by unicorn-engine-sys) looks up libclang via LIBCLANG_PATH.
if not defined LIBCLANG_PATH set "LIBCLANG_PATH=C:\Program Files\LLVM\bin"

REM Redirect cargo build output away from Dropbox to avoid sync races on
REM openssl-sys / unicorn-engine-sys intermediate files.
if not defined CARGO_TARGET_DIR set "CARGO_TARGET_DIR=C:\Users\%USERNAME%\AppData\Local\cargo-target\imessage"
