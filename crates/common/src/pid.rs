use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Pid(u32);

impl Pid {
    pub fn new(pid: u32) -> Self {
        Self(pid)
    }

    pub fn as_u32(self) -> u32 {
        self.0
    }

    pub fn is_valid(self) -> bool {
        self.0 > 0
    }
}

impl fmt::Display for Pid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for Pid {
    fn from(pid: u32) -> Self {
        Self(pid)
    }
}

impl From<Pid> for u32 {
    fn from(pid: Pid) -> u32 {
        pid.0
    }
}
