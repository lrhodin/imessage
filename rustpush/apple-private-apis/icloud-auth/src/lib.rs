pub mod anisette;
mod client;
use std::fmt::Display;

pub use client::{AppleAccount, FetchedToken, LoginState, TrustedPhoneNumber, AuthenticationExtras, VerifyBody, CircleSendMessage};
pub use omnisette::{LoginClientInfo, default_provider, ArcAnisetteClient, DefaultAnisetteProvider};



use thiserror::Error;
#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to parse the response")]
    Parse,
    #[error("Failed to authenticate.")]
    AuthSrp,
    #[error("Failed to have a happy birthday!.")]
    HappyBirthdayError,
    #[error("Bad 2fa code.")]
    Bad2faCode,
    #[error("{1} ({0})")]
    AuthSrpWithMessage(i64, String),
    #[error("Please login to appleid.apple.com to fix this account")]
    ExtraStep(String),
    #[error("Failed to parse a plist {0}")]
    PlistError(#[from] plist::Error),
    #[error("Request failed {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("Failed getting anisette data {0}")]
    ErrorGettingAnisette(#[from] omnisette::AnisetteError),
    #[error("Disable Advanced Data Protection")]
    FailedGetting2FAConfig,
    #[error("Serde Error")]
    SerdeError(#[from] serde_json::Error),
    #[error("Disable hardware authentication keys and try again!")]
    HardwareKeyError,
}