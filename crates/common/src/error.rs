pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("eBPF error: {0}")]
    Ebpf(String),

    #[error("Kernel access error: {0}")]
    KernelAccess(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Detection failed: {0}")]
    DetectionFailed(String),

    #[error("Integrity violation: {0}")]
    IntegrityViolation(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Unsupported: {0}")]
    Unsupported(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl Error {
    pub fn severity(&self) -> crate::severity::Severity {
        match self {
            Error::IntegrityViolation(_) => crate::severity::Severity::Critical,
            Error::DetectionFailed(_) => crate::severity::Severity::High,
            Error::KernelAccess(_) => crate::severity::Severity::High,
            Error::PermissionDenied(_) => crate::severity::Severity::Medium,
            _ => crate::severity::Severity::Low,
        }
    }
}
