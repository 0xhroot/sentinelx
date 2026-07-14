use thiserror::Error;

pub type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Configuration file error: {0}")]
    FileError(#[from] std::io::Error),

    #[error("TOML parsing error: {0}")]
    ParseError(#[from] toml::de::Error),

    #[error("Configuration validation error: {0}")]
    ValidationError(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid value for field '{field}': {reason}")]
    InvalidValue { field: String, reason: String },
}
