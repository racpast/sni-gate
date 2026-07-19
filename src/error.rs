//! Typed error hierarchy for the parts of the program where callers need to
//! distinguish failure modes (config loading, ECH resolution). Connection
//! handling uses `anyhow` since those errors are only ever logged.

use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {0}: {1}")]
    Read(PathBuf, #[source] std::io::Error),

    #[error("failed to parse config: {0}")]
    Parse(#[source] toml::de::Error),

    #[error("invalid config: {0}")]
    Invalid(String),
}

#[derive(Debug, Error)]
pub enum EchError {
    #[error("no HTTPS record with an ech= parameter found for {0}")]
    NoRecord(String),

    #[error("DoH lookup for {name} failed: {source}")]
    Lookup {
        name: String,
        #[source]
        source: anyhow::Error,
    },

    #[error("failed to base64-decode the supplied ECHConfigList: {0}")]
    Base64(#[source] base64::DecodeError),

    #[error("no ECHConfig in the list was compatible with the local HPKE suites")]
    NoCompatibleConfig,

    #[error("failed to build the rustls client configuration: {0}")]
    Rustls(#[source] rustls::Error),
}
