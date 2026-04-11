//! Apple APNs validation data generation for macOS 13+ (Ventura or later)
//!
//! This crate provides `generate_validation_data()` which calls the NAC
//! (Network Attestation Credential) functions via Apple's private
//! `AppleAccount.framework` (class `AAAbsintheContext`) to produce the
//! opaque validation data blob required for IDS registration.
//!
//! # Requirements
//! - macOS 13+ (Ventura or later)
//! - SIP can remain enabled
//! - No jailbreak or code injection required
//! - Network access to Apple's servers
//!
//! # Build
//! The `validation_data.m` Objective-C file must be compiled and linked.
//! Use the provided `build.rs` or compile manually:
//! ```sh
//! cc -c validation_data.m -framework Foundation -fobjc-arc -o validation_data.o
//! ```

use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::ptr;

// C FFI surface — kept in sync with `src/validation_data.h`.
extern "C" {
    fn nac_generate_validation_data(
        out_buf: *mut *mut u8,
        out_len: *mut usize,
        out_err_buf: *mut *mut c_char,
    ) -> i32;

    fn nac_ctx_init(
        cert_buf: *const u8,
        cert_len: usize,
        out_handle: *mut *mut c_void,
        out_request_buf: *mut *mut u8,
        out_request_len: *mut usize,
        out_err_buf: *mut *mut c_char,
    ) -> i32;

    fn nac_ctx_key_establishment(
        handle: *mut c_void,
        session_info_buf: *const u8,
        session_info_len: usize,
        out_err_buf: *mut *mut c_char,
    ) -> i32;

    fn nac_ctx_sign(
        handle: *mut c_void,
        out_buf: *mut *mut u8,
        out_len: *mut usize,
        out_err_buf: *mut *mut c_char,
    ) -> i32;

    fn nac_ctx_free(handle: *mut c_void);
}

/// Error type for validation data generation.
#[derive(Debug, thiserror::Error)]
pub enum NacError {
    #[error("NAC error (code {code}): {message}")]
    NacFailed { code: i32, message: String },
}

/// Generate APNs validation data for IDS registration.
///
/// This handles the full NAC protocol:
/// 1. Fetches validation certificate from Apple
/// 2. NACInit with the certificate
/// 3. Sends session info request to Apple's servers
/// 4. NACKeyEstablishment with the response
/// 5. NACSign to produce the final validation data
///
/// Hardware identifiers are read automatically from IOKit.
///
/// Returns the raw validation data bytes on success.
pub fn generate_validation_data() -> Result<Vec<u8>, NacError> {
    let mut buf: *mut u8 = ptr::null_mut();
    let mut len: usize = 0;
    let mut err_buf: *mut std::os::raw::c_char = ptr::null_mut();

    let result = unsafe { nac_generate_validation_data(&mut buf, &mut len, &mut err_buf) };

    if result == 0 && !buf.is_null() {
        let data = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
        unsafe { libc::free(buf as *mut _) };
        Ok(data)
    } else {
        let message = if !err_buf.is_null() {
            let msg = unsafe { CStr::from_ptr(err_buf) }
                .to_string_lossy()
                .into_owned();
            unsafe { libc::free(err_buf as *mut _) };
            msg
        } else {
            format!("Unknown NAC error (code {})", result)
        };

        Err(NacError::NacFailed {
            code: result,
            message,
        })
    }
}

/// An initialized `AAAbsintheContext` that exposes the three NAC steps
/// (`NACInit` → `NACKeyEstablishment` → `NACSign`) as separate Rust methods.
///
/// This lets callers that already own the `id-initialize-validation` POST
/// (such as `rustpush`'s `MacOSConfig::generate_validation_data`, via
/// `open-absinthe`'s `ValidationCtx`) drive the full protocol one step at a
/// time while delegating each call to Apple's native framework. The result
/// is byte-identical to [`generate_validation_data`] but integrates cleanly
/// with an HTTP flow that the caller controls — no double POST to Apple,
/// no stub request bytes, no modification of upstream rustpush.
pub struct NacContext {
    handle: *mut c_void,
}

// The underlying AAAbsintheContext is not Send/Sync by default; upstream
// rustpush uses it from a single async task so we mirror that pattern.
unsafe impl Send for NacContext {}

impl NacContext {
    /// Step 1: `NACInit`.
    ///
    /// Creates a fresh `AAAbsintheContext`, calls `NACInit(cert)`, and
    /// returns the initialized context together with the session-info
    /// request bytes the caller should POST to
    /// `id-initialize-validation`.
    pub fn init(cert: &[u8]) -> Result<(Self, Vec<u8>), NacError> {
        let mut handle: *mut c_void = ptr::null_mut();
        let mut req_buf: *mut u8 = ptr::null_mut();
        let mut req_len: usize = 0;
        let mut err_buf: *mut c_char = ptr::null_mut();

        let result = unsafe {
            nac_ctx_init(
                cert.as_ptr(),
                cert.len(),
                &mut handle,
                &mut req_buf,
                &mut req_len,
                &mut err_buf,
            )
        };

        if result == 0 && !handle.is_null() && !req_buf.is_null() {
            let request_bytes =
                unsafe { std::slice::from_raw_parts(req_buf, req_len) }.to_vec();
            unsafe { libc::free(req_buf as *mut _) };
            Ok((Self { handle }, request_bytes))
        } else {
            // Best-effort cleanup if the C side partially succeeded.
            if !handle.is_null() {
                unsafe { nac_ctx_free(handle) };
            }
            if !req_buf.is_null() {
                unsafe { libc::free(req_buf as *mut _) };
            }
            Err(take_err(result, err_buf))
        }
    }

    /// Step 2: `NACKeyEstablishment`.
    ///
    /// Feeds Apple's session-info response bytes back into the context.
    pub fn key_establishment(&mut self, session_info: &[u8]) -> Result<(), NacError> {
        let mut err_buf: *mut c_char = ptr::null_mut();
        let result = unsafe {
            nac_ctx_key_establishment(
                self.handle,
                session_info.as_ptr(),
                session_info.len(),
                &mut err_buf,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(take_err(result, err_buf))
        }
    }

    /// Step 3: `NACSign`.
    ///
    /// Produces the final validation data bytes.
    pub fn sign(&mut self) -> Result<Vec<u8>, NacError> {
        let mut buf: *mut u8 = ptr::null_mut();
        let mut len: usize = 0;
        let mut err_buf: *mut c_char = ptr::null_mut();
        let result =
            unsafe { nac_ctx_sign(self.handle, &mut buf, &mut len, &mut err_buf) };

        if result == 0 && !buf.is_null() {
            let data = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
            unsafe { libc::free(buf as *mut _) };
            Ok(data)
        } else {
            if !buf.is_null() {
                unsafe { libc::free(buf as *mut _) };
            }
            Err(take_err(result, err_buf))
        }
    }
}

impl Drop for NacContext {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { nac_ctx_free(self.handle) };
            self.handle = ptr::null_mut();
        }
    }
}

fn take_err(code: i32, err_buf: *mut c_char) -> NacError {
    let message = if !err_buf.is_null() {
        let msg = unsafe { CStr::from_ptr(err_buf) }
            .to_string_lossy()
            .into_owned();
        unsafe { libc::free(err_buf as *mut _) };
        msg
    } else {
        format!("Unknown NAC error (code {})", code)
    };
    NacError::NacFailed { code, message }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_validation_data() {
        let data = generate_validation_data().expect("Failed to generate validation data");
        assert!(!data.is_empty(), "Validation data should not be empty");
        assert!(
            data.len() > 100,
            "Validation data should be substantial (got {} bytes)",
            data.len()
        );
        eprintln!(
            "Generated {} bytes of validation data",
            data.len()
        );
    }
}
