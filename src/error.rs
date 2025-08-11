use thiserror::Error;

#[derive(Error, Debug)]
pub enum KcfgVexError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),

    #[error("CVE not found: {0}")]
    CveNotFound(String),

    #[error("Invalid kernel configuration: {0}")]
    InvalidConfig(String),

    #[error("Trace error: {0}")]
    Trace(String),
}

pub type Result<T> = std::result::Result<T, KcfgVexError>;
