pub mod file;
pub mod kernel;
pub mod memory;
pub mod module;
pub mod network;
pub mod process;
pub mod service;

pub use file::FileAssessor;
pub use kernel::KernelAssessor;
pub use memory::MemoryAssessor;
pub use module::ModuleAssessor;
pub use network::NetworkAssessor;
pub use process::ProcessAssessor;
pub use service::ServiceAssessor;

use async_trait::async_trait;
use sentinelx_core::error::CoreError;
use sentinelx_core::object::SentinelObject;

use crate::config::ScoringConfig;
use crate::types::ObjectAssessment;

#[async_trait]
pub trait Assessor: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn supported_object_types(&self) -> Vec<sentinelx_core::object::ObjectType>;
    async fn assess(
        &self,
        object: &SentinelObject,
        config: &ScoringConfig,
    ) -> Result<ObjectAssessment, CoreError>;
}
