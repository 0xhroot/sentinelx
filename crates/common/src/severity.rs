use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn from_score(score: f64) -> Self {
        match score {
            s if s >= 90.0 => Severity::Critical,
            s if s >= 70.0 => Severity::High,
            s if s >= 40.0 => Severity::Medium,
            s if s >= 20.0 => Severity::Low,
            _ => Severity::Info,
        }
    }

    pub fn score(&self) -> f64 {
        match self {
            Severity::Info => 0.0,
            Severity::Low => 25.0,
            Severity::Medium => 50.0,
            Severity::High => 75.0,
            Severity::Critical => 95.0,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
