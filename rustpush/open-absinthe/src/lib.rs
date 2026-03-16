use std::{error::Error, fmt::Display};

pub mod nac;

#[derive(Debug)]
pub enum AbsintheError {
    NacError(i32),
    Other(String),
}

impl Display for AbsintheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AbsintheError::NacError(code) => write!(f, "NAC error: {}", code),
            AbsintheError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl Error for AbsintheError {}

impl From<String> for AbsintheError {
    fn from(s: String) -> Self {
        AbsintheError::Other(s)
    }
}

impl From<&str> for AbsintheError {
    fn from(s: &str) -> Self {
        AbsintheError::Other(s.to_string())
    }
}

impl From<std::io::Error> for AbsintheError {
    fn from(e: std::io::Error) -> Self {
        AbsintheError::Other(format!("IO error: {}", e))
    }
}
