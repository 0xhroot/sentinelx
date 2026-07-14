use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("Discovery error: {0}")]
    Discovery(String),

    #[error("Metadata error: {0}")]
    Metadata(String),

    #[error("Assessment error: {0}")]
    Assessment(String),

    #[error("Evidence error: {0}")]
    Evidence(String),

    #[error("Pipeline error: {0}")]
    Pipeline(String),
}
