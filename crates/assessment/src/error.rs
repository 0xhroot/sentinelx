use thiserror::Error;

#[derive(Error, Debug)]
pub enum AssessmentError {
    #[error("Config error: {0}")]
    Config(String),

    #[error("Store error: {0}")]
    Store(String),

    #[error("Scoring error: {0}")]
    Scoring(String),

    #[error("Database error: {0}")]
    Database(String),
}

pub type Result<T> = std::result::Result<T, AssessmentError>;
