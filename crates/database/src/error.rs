use thiserror::Error;

pub type Result<T> = std::result::Result<T, DatabaseError>;

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("SQLx error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Query failed: {0}")]
    QueryFailed(String),

    #[error("Migration failed: {0}")]
    MigrationFailed(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Record not found: {0}")]
    NotFound(String),
}
