//! LocalMacOSConfig — An OSConfig implementation that reads hardware info from IOKit
//! and uses our local NAC crate for validation data generation.
//!
//! This replaces the need for:
//! - open-absinthe (FairPlay-based NAC, requires SIP disabled or relay)
//! - A registration relay server
//!
//! Instead, it uses AAAbsintheContext from AppleAccount.framework (which works
//! with SIP enabled on any Mac) for NAC, and reads real hardware identifiers
//! from IOKit for IDS registration.

use std::collections::HashMap;
use std::ffi::CStr;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use plist::{Dictionary, Value};
use uuid::Uuid;

use rustpush::{activation::ActivationInfo, APSState, DebugMeta, LoginClientInfo, OSConfig, PushError, RegisterMeta};

// FFI for hardware_info.m
#[repr(C)]
struct CHardwareInfo {
    product_name: *mut std::os::raw::c_char,
    serial_number: *mut std::os::raw::c_char,
    platform_uuid: *mut std::os::raw::c_char,
    board_id: *mut std::os::raw::c_char,
    os_build_num: *mut std::os::raw::c_char,
    os_version: *mut std::os::raw::c_char,
    rom: *mut u8,
    rom_len: usize,
    mlb: *mut std::os::raw::c_char,
    mac_address: *mut u8,
    mac_address_len: usize,
    root_disk_uuid: *mut std::os::raw::c_char,
    darwin_version: *mut std::os::raw::c_char,
    error: *mut std::os::raw::c_char,
}

extern "C" {
    fn hw_info_read() -> CHardwareInfo;
    fn hw_info_free(info: *mut CHardwareInfo);
}

fn c_str_to_string(ptr: *mut std::os::raw::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned())
}

fn c_data_to_vec(ptr: *mut u8, len: usize) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        return vec![];
    }
    unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Hardware info read from IOKit.
#[derive(Debug, Clone)]
pub struct HardwareInfo {
    pub product_name: String,
    pub serial_number: String,
    pub platform_uuid: String,
    pub board_id: String,
    pub os_build_num: String,
    pub os_version: String,
    pub rom: Vec<u8>,
    pub mlb: String,
    pub mac_address: [u8; 6],
    pub root_disk_uuid: String,
    pub darwin_version: String,
}

impl HardwareInfo {
    pub fn read() -> Result<Self, String> {
        let mut raw = unsafe { hw_info_read() };

        if !raw.error.is_null() {
            let err = c_str_to_string(raw.error).unwrap_or_default();
            unsafe { hw_info_free(&mut raw) };
            return Err(err);
        }

        let mac_vec = c_data_to_vec(raw.mac_address, raw.mac_address_len);
        let mac_address: [u8; 6] = if mac_vec.len() == 6 {
            mac_vec.try_into().unwrap()
        } else {
            [0; 6]
        };

        let info = HardwareInfo {
            product_name: c_str_to_string(raw.product_name).unwrap_or_else(|| "Mac".to_string()),
            serial_number: c_str_to_string(raw.serial_number).unwrap_or_default(),
            platform_uuid: c_str_to_string(raw.platform_uuid).unwrap_or_else(|| Uuid::new_v4().to_string()),
            board_id: c_str_to_string(raw.board_id).unwrap_or_default(),
            os_build_num: c_str_to_string(raw.os_build_num).unwrap_or_else(|| "25B78".to_string()),
            os_version: c_str_to_string(raw.os_version).unwrap_or_else(|| "26.1".to_string()),
            rom: c_data_to_vec(raw.rom, raw.rom_len),
            mlb: c_str_to_string(raw.mlb).unwrap_or_default(),
            mac_address,
            root_disk_uuid: c_str_to_string(raw.root_disk_uuid).unwrap_or_default(),
            darwin_version: c_str_to_string(raw.darwin_version).unwrap_or_else(|| "24.0.0".to_string()),
        };

        unsafe { hw_info_free(&mut raw) };
        Ok(info)
    }
}

/// Local macOS configuration for iMessage registration.
/// Uses real hardware identifiers from IOKit and local NAC for validation.
#[derive(Clone)]
pub struct LocalMacOSConfig {
    pub hw: HardwareInfo,
    pub device_id: String,
    pub protocol_version: u32,
    pub icloud_ua: String,
    pub aoskit_version: String,
}

impl LocalMacOSConfig {
    pub fn new() -> Result<Self, String> {
        let hw = HardwareInfo::read()?;
        // Use the real hardware UUID as device ID — AAAbsintheContext
        // embeds the real hardware UUID in validation data, so a random
        // UUID would cause Apple to reject the registration (error 6001).
        let device_id = hw.platform_uuid.to_uppercase();

        // Build UA strings using the real Darwin version from this Mac
        // instead of hardcoding values from a different macOS release.
        let darwin = &hw.darwin_version;
        let icloud_ua = format!(
            "com.apple.iCloudHelper/282 CFNetwork/1568.100.1 Darwin/{}",
            darwin
        );
        let aoskit_version = "com.apple.AOSKit/282 (com.apple.accountsd/113)".to_string();

        Ok(Self {
            hw,
            device_id,
            protocol_version: 1660,
            icloud_ua,
            aoskit_version,
        })
    }

    pub fn with_device_id(self, id: String) -> Self {
        // For LocalMacOSConfig, the device ID must always be the hardware
        // UUID because AAAbsintheContext embeds it in the validation data.
        // Ignore any persisted device ID — it may be a stale random UUID
        // from before this fix.
        if id != self.device_id {
            log::warn!(
                "Ignoring persisted device ID {} — LocalMacOSConfig must use hardware UUID {}",
                id, self.device_id
            );
        }
        self
    }
}

#[async_trait]
impl OSConfig for LocalMacOSConfig {
    fn build_activation_info(&self, csr: Vec<u8>) -> ActivationInfo {
        ActivationInfo {
            activation_randomness: Uuid::new_v4().to_string().to_uppercase(),
            activation_state: "Unactivated",
            build_version: self.hw.os_build_num.clone(),
            device_cert_request: csr.into(),
            device_class: "MacOS".to_string(),
            product_type: self.hw.product_name.clone(),
            product_version: self.hw.os_version.clone(),
            serial_number: self.hw.serial_number.clone(),
            unique_device_id: self.device_id.clone(),
        }
    }

    fn get_udid(&self) -> String {
        self.device_id.clone()
    }

    fn get_normal_ua(&self, item: &str) -> String {
        let part = self.icloud_ua.split_once(char::is_whitespace).unwrap().0;
        format!("{item} {part}")
    }

    fn get_aoskit_version(&self) -> String {
        self.aoskit_version.clone()
    }

    fn get_mme_clientinfo(&self, for_item: &str) -> String {
        format!(
            "<{}> <macOS;{};{}> <{}>",
            self.hw.product_name, self.hw.os_version, self.hw.os_build_num, for_item
        )
    }

    fn get_version_ua(&self) -> String {
        format!(
            "[macOS,{},{},{}]",
            self.hw.os_version, self.hw.os_build_num, self.hw.product_name
        )
    }

    fn get_activation_device(&self) -> String {
        "MacOS".to_string()
    }

    fn get_device_uuid(&self) -> String {
        self.device_id.clone()
    }

    fn get_device_name(&self) -> String {
        format!("Mac-{}", self.hw.serial_number)
    }

    async fn generate_validation_data(&self) -> Result<Vec<u8>, PushError> {
        // Use our local NAC crate (AAAbsintheContext) instead of open-absinthe/relay
        nac_validation::generate_validation_data()
            .map_err(|e| PushError::IoError(std::io::Error::other(
                format!("NAC validation failed: {}", e),
            )))
    }

    fn get_protocol_version(&self) -> u32 {
        self.protocol_version
    }

    fn get_register_meta(&self) -> RegisterMeta {
        RegisterMeta {
            hardware_version: self.hw.product_name.clone(),
            os_version: format!("macOS,{},{}", self.hw.os_version, self.hw.os_build_num),
            software_version: self.hw.os_build_num.clone(),
        }
    }

    fn get_debug_meta(&self) -> DebugMeta {
        DebugMeta {
            user_version: self.hw.os_version.clone(),
            hardware_version: self.hw.product_name.clone(),
            serial_number: self.hw.serial_number.clone(),
        }
    }

    fn get_gsa_hardware_headers(&self) -> HashMap<String, String> {
        [
            ("X-Apple-I-MLB", self.hw.mlb.as_str()),
            ("X-Apple-I-ROM", &encode_hex(&self.hw.rom)),
            ("X-Apple-I-SRL-NO", &self.hw.serial_number),
        ]
        .into_iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect()
    }

    fn get_serial_number(&self) -> String {
        self.hw.serial_number.clone()
    }

    fn get_login_url(&self) -> &'static str {
        "https://setup.icloud.com/setup/prefpane/loginDelegates"
    }

    fn get_private_data(&self) -> Dictionary {
        let apple_epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(978307200);
        Dictionary::from_iter([
            ("ap", Value::String("0".to_string())),
            (
                "d",
                Value::String(format!(
                    "{:.6}",
                    apple_epoch.elapsed().unwrap().as_secs_f64()
                )),
            ),
            ("dt", Value::Integer(1.into())),
            ("gt", Value::String("0".to_string())),
            ("h", Value::String("1".to_string())),
            ("m", Value::String("0".to_string())),
            ("p", Value::String("0".to_string())),
            ("pb", Value::String(self.hw.os_build_num.clone())),
            ("pn", Value::String("macOS".to_string())),
            ("pv", Value::String(self.hw.os_version.clone())),
            ("s", Value::String("0".to_string())),
            ("t", Value::String("0".to_string())),
            (
                "u",
                Value::String(self.device_id.clone().to_uppercase()),
            ),
            ("v", Value::String("1".to_string())),
        ])
    }

    fn get_gsa_config(&self, push: &APSState, require_mac: bool) -> LoginClientInfo {
        LoginClientInfo {
            ak_context_type: "imessage".to_string(),
            client_app_name: "Messages".to_string(),
            client_bundle_id: "com.apple.MobileSMS".to_string(),
            mme_client_info_akd: self.get_adi_mme_info("com.apple.AuthKit/1 (com.apple.akd/1.0)", require_mac),
            mme_client_info: self.get_adi_mme_info("com.apple.AuthKit/1 (com.apple.MobileSMS/1262.500.151.1.2)", require_mac),
            akd_user_agent: format!("akd/1.0 CFNetwork/1568.100.1 Darwin/{}", self.hw.darwin_version),
            browser_user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)".to_string(),
            hardware_headers: self.get_gsa_hardware_headers(),
            push_token: push.token.map(|i| encode_hex(&i).to_uppercase()),
            update_account_bundle_id: self.get_adi_mme_info("com.apple.AppleAccount/1.0 (com.apple.systempreferences.AppleIDSettings/1)", require_mac),
        }
    }
}
