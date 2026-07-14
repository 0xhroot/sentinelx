use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Detection error: {0}")]
    Detection(String),

    #[error("Validation error: {0}")]
    Validation(String),
}

impl From<sentinelx_common::Error> for ApiError {
    fn from(e: sentinelx_common::Error) -> Self {
        match e {
            sentinelx_common::Error::NotFound(s) => ApiError::NotFound(s),
            sentinelx_common::Error::Database(s) => ApiError::Database(s),
            sentinelx_common::Error::DetectionFailed(s) => ApiError::Detection(s),
            _ => ApiError::Internal(e.to_string()),
        }
    }
}

impl From<sentinelx_database::DatabaseError> for ApiError {
    fn from(e: sentinelx_database::DatabaseError) -> Self {
        ApiError::Database(e.to_string())
    }
}

impl From<sentinelx_config::ConfigError> for ApiError {
    fn from(e: sentinelx_config::ConfigError) -> Self {
        ApiError::Internal(e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
            ApiError::Database(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", msg),
            ),
            ApiError::Detection(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Detection error: {}", msg),
            ),
            ApiError::Validation(msg) => (
                StatusCode::BAD_REQUEST,
                format!("Validation error: {}", msg),
            ),
        };

        let body = json!({
            "error": {
                "code": status.as_u16(),
                "message": message,
            }
        });

        (status, axum::Json(body)).into_response()
    }
}
