#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod crypto;
pub mod engine;
pub mod factory;
pub mod identity;
pub mod native_adi;
pub mod native_otp;
pub mod protocol;
pub mod server;
pub mod store;
pub mod transport;

pub const CLIENT_INFO: &str =
    "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKitWin/7.3 (com.apple.iCloud/15.10.0.39)>";
pub const USER_AGENT: &str = "com.apple.AuthKitWin/7.3";
pub const MAX_BLOB: usize = 1024 * 1024;

/// Errors deliberately contain no protocol payloads, identity material, or keys.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid Windows identity inputs")]
    Identity,
    #[error("invalid Apple provisioning response")]
    Protocol,
    #[error("Apple provisioning service reported an error")]
    AppleStatus,
    #[error("Apple provisioning HTTPS request failed")]
    Transport,
    #[error("Apple root certificate does not match the pinned SHA-256 fingerprint")]
    Certificate,
    #[error("CoreADI engine rejected the operation")]
    Engine,
    #[error("invalid arithmetic circuit or circuit input")]
    Circuit,
    #[error("input follows an unsupported arithmetic circuit path")]
    CircuitPath(usize),
    #[error("invalid private state: {0}")]
    State(&'static str),
    #[error("private state is in use by another process")]
    Locked,
    #[error("filesystem operation failed")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
