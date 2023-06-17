//! Controlling Gree Smart air conditioning units via Rust
//! 
//! This crate defines two clients, `GreeClient` and `Gree`, for each of two programming styles (synchronous and asynchronous).
//! 
//! See docs under [sync_client] and [async_client].
//! 
//! See also: <https://github.com/tomikaa87/gree-remote> - Protocol description, API in several languages, CLI in python

mod apdu;
mod state;
pub mod sync_client;
pub mod async_client;


pub use apdu::{vars, vars::DEFAULT as DEFAULT_VARS};
pub use state::*;
pub use serde_json::Value;

use apdu::{*, vars::VarName};
use log::{trace, debug, error};

//pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = std::result::Result<T, Error>;

const GENERIC_KEY: &str = "a3K8Bx%2r8Y7#xDh";
const PORT: u16 = 7000;

#[derive(Debug)]
pub enum Error {
    SerDe(serde_json::Error),
    Base64Decode(base64::DecodeError),
    Io(std::io::Error),
    Send,
    RecvTimeout,
    ParseInt(std::num::ParseIntError),

    ResponseTimeout,
    MacNotBound(String),
    NotFound(String),
    InvalidVar(String),
    InvalidValue(VarName, String),
}

impl Error {
    pub fn response_timeout() -> Self { Self::ResponseTimeout }
    pub fn mac_not_bound(mac: &str) -> Self { Self::MacNotBound(mac.to_owned()) }
    pub fn not_found(id: &str) -> Self { Self::NotFound(id.to_owned()) }
    pub fn invalid_var(id: &str) -> Self { Self::NotFound(id.to_owned()) }
    pub fn invalid_value(var: VarName, value: &str) -> Self { Self::InvalidValue(var, value.to_owned()) }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::SerDe(value)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(value: base64::DecodeError) -> Self {
        Self::Base64Decode(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl<T> From<std::sync::mpsc::SendError<T>> for Error {
    fn from(_: std::sync::mpsc::SendError<T>) -> Self {
        Self::Send
    }
}

impl From<std::sync::mpsc::RecvTimeoutError> for Error {
    fn from(_: std::sync::mpsc::RecvTimeoutError) -> Self {
        Self::RecvTimeout
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(value: std::num::ParseIntError) -> Self {
        Self::ParseInt(value)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Base64Decode(e) => write!(f, "Base64Decode: {e}"),
            Self::SerDe(e) => write!(f, "SerDe: {e}"),
            Self::Io(e) => write!(f, "Base64Decode: {e}"),
            Self::Send => write!(f, "Send"),
            Self::RecvTimeout => write!(f, "RecvTimeout"),
            Self::ParseInt(e) => write!(f, "ParseInt: {e}"),

            Self::ResponseTimeout => write!(f, "ResponseTimeout"),
            Self::MacNotBound(s) => write!(f, "MacNotBound: {s}"),
            Self::NotFound(s) => write!(f, "NotFound: {s}"),
            Self::InvalidVar(s) => write!(f, "InvalidVar: {s}"),
            Self::InvalidValue(n, s) => write!(f, "InvalidValue for {n}: {s}"),
        }
    }
}

impl std::error::Error for Error { }




/* 

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
*/