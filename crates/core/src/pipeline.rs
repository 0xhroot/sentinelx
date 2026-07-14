use std::sync::Arc;
use tokio::sync::RwLock;

use crate::assessment::AssessmentEngine;
use crate::discovery::DiscoveryEngine;
use crate::error::CoreError;
use crate::evidence::CoreEvidence;
use crate::metadata::MetadataEngine;
use crate::object::SentinelObject;

pub struct PipelineResult {
    pub objects_discovered: usize,
    pub objects_enriched: usize,
    pub objects_assessed: usize,
    pub evidence_count: usize,
    pub duration_ms: u64,
    pub objects: Vec<SentinelObject>,
    pub evidence: Vec<CoreEvidence>,
}

pub struct PipelineCoordinator {
    discovery: DiscoveryEngine,
    metadata: MetadataEngine,
    assessment: AssessmentEngine,
    evidence_store: Arc<RwLock<Vec<CoreEvidence>>>,
}

impl PipelineCoordinator {
    pub fn new() -> Self {
        Self {
            discovery: DiscoveryEngine::new(),
            metadata: MetadataEngine::new(),
            assessment: AssessmentEngine::new(),
            evidence_store: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn discovery(&mut self) -> &mut DiscoveryEngine {
        &mut self.discovery
    }

    pub fn metadata(&mut self) -> &mut MetadataEngine {
        &mut self.metadata
    }

    pub fn assessment(&mut self) -> &mut AssessmentEngine {
        &mut self.assessment
    }

    pub fn evidence_store(&self) -> &Arc<RwLock<Vec<CoreEvidence>>> {
        &self.evidence_store
    }

    pub async fn get_evidence(&self) -> Vec<CoreEvidence> {
        self.evidence_store.read().await.clone()
    }

    pub async fn clear_evidence(&self) {
        self.evidence_store.write().await.clear();
    }

    pub async fn run(&self) -> Result<PipelineResult, CoreError> {
        let start = std::time::Instant::now();

        // Phase 1: Discovery
        let discovery_results = self.discovery.discover_all().await;
        let mut objects: Vec<SentinelObject> = discovery_results
            .into_iter()
            .flat_map(|r| r.objects)
            .collect();
        let objects_discovered = objects.len();

        // Phase 2: Metadata enrichment
        let objects_enriched = self.metadata.enrich_all(&mut objects).await.unwrap_or(0);

        // Phase 3: Assessment
        let objects_assessed = self.assessment.assess_all(&mut objects).await.unwrap_or(0);

        // Phase 4: Evidence generation from assessments (mandatory: no assessment = no evidence)
        let mut evidence_items = Vec::new();
        for object in &objects {
            if object.assessments.is_empty() {
                tracing::debug!(
                    object_id = %object.id,
                    "Skipping evidence generation: no assessment available"
                );
                continue;
            }
            for assessment in &object.assessments {
                if assessment.risk != crate::assessment::RiskLevel::None {
                    use crate::evidence::{CoreEvidenceType, CoreSeverity};

                    let severity = match assessment.risk {
                        crate::assessment::RiskLevel::Critical => CoreSeverity::Critical,
                        crate::assessment::RiskLevel::High => CoreSeverity::High,
                        crate::assessment::RiskLevel::Medium => CoreSeverity::Medium,
                        crate::assessment::RiskLevel::Low => CoreSeverity::Low,
                        crate::assessment::RiskLevel::None => continue,
                    };

                    let evidence_type = match object.object_type {
                        crate::object::ObjectType::Process => CoreEvidenceType::ProcessIntegrity,
                        crate::object::ObjectType::KernelModule => {
                            CoreEvidenceType::KernelIntegrity
                        }
                        crate::object::ObjectType::NetworkConnection => {
                            CoreEvidenceType::NetworkIntegrity
                        }
                        crate::object::ObjectType::File => CoreEvidenceType::FileIntegrity,
                        crate::object::ObjectType::MemoryRegion => {
                            CoreEvidenceType::MemoryIntegrity
                        }
                        crate::object::ObjectType::Service => {
                            CoreEvidenceType::PersistenceIntegrity
                        }
                        _ => CoreEvidenceType::SystemIntegrity,
                    };

                    let ev = CoreEvidence::new(
                        &object.id,
                        evidence_type,
                        severity,
                        &assessment.assessor,
                    )
                    .with_confidence(assessment.confidence)
                    .with_assessment(assessment.clone());

                    evidence_items.push(ev);
                }
            }
        }

        // Store evidence
        {
            let mut store = self.evidence_store.write().await;
            store.extend(evidence_items.clone());
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        let evidence_count = evidence_items.len();

        tracing::info!(
            objects_discovered,
            objects_enriched,
            objects_assessed,
            evidence_count,
            duration_ms,
            "Pipeline execution completed"
        );

        Ok(PipelineResult {
            objects_discovered,
            objects_enriched,
            objects_assessed,
            evidence_count,
            duration_ms,
            objects,
            evidence: evidence_items,
        })
    }
}

impl Default for PipelineCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assessment::*;
    use crate::discovery::*;
    use crate::object::*;

    struct MockDiscoveryProvider {
        name: String,
        object_count: usize,
    }

    #[async_trait::async_trait]
    impl DiscoveryProvider for MockDiscoveryProvider {
        fn name(&self) -> &str {
            &self.name
        }

        fn description(&self) -> &str {
            "Mock provider"
        }

        fn supported_object_types(&self) -> Vec<ObjectType> {
            vec![ObjectType::Process]
        }

        async fn discover(&self) -> Result<Vec<SentinelObject>, CoreError> {
            Ok((0..self.object_count)
                .map(|i| {
                    SentinelObject::new(ObjectType::Process, &self.name, format!("proc_{}", i))
                })
                .collect())
        }
    }

    struct MockAssessor {
        name: String,
        risk_level: RiskLevel,
    }

    #[async_trait::async_trait]
    impl ObjectAssessor for MockAssessor {
        fn name(&self) -> &str {
            &self.name
        }

        fn description(&self) -> &str {
            "Mock assessor"
        }

        fn supported_object_types(&self) -> Vec<ObjectType> {
            vec![ObjectType::Process]
        }

        async fn assess(&self, object: &SentinelObject) -> Result<AssessmentResult, CoreError> {
            Ok(AssessmentResult::new(&object.id, &self.name)
                .with_trust(TrustLevel::Unknown)
                .with_integrity(IntegrityLevel::Unknown)
                .with_risk(self.risk_level)
                .with_confidence(0.8))
        }
    }

    #[tokio::test]
    async fn test_pipeline_creation() {
        let coordinator = PipelineCoordinator::new();
        let result = coordinator.run().await.unwrap();
        assert_eq!(result.objects_discovered, 0);
    }

    #[tokio::test]
    async fn test_pipeline_run_with_mock_providers() {
        let mut coordinator = PipelineCoordinator::new();
        coordinator
            .discovery()
            .register(Arc::new(Box::new(MockDiscoveryProvider {
                name: "test_discovery".to_string(),
                object_count: 3,
            })));
        coordinator.assessment().register(Arc::new(MockAssessor {
            name: "test_assessor".to_string(),
            risk_level: RiskLevel::Medium,
        }));

        let result = coordinator.run().await.unwrap();
        assert_eq!(result.objects_discovered, 3);
        assert!(result.objects_discovered >= 1);
        assert!(result.objects_assessed > 0);
        assert_eq!(result.evidence_count, 3);
        assert!(!result.objects.is_empty());
    }

    #[tokio::test]
    async fn test_pipeline_evidence_storage() {
        let mut coordinator = PipelineCoordinator::new();
        coordinator
            .discovery()
            .register(Arc::new(Box::new(MockDiscoveryProvider {
                name: "test".to_string(),
                object_count: 2,
            })));
        coordinator.assessment().register(Arc::new(MockAssessor {
            name: "test".to_string(),
            risk_level: RiskLevel::High,
        }));

        coordinator.run().await.unwrap();

        let evidence = coordinator.get_evidence().await;
        assert_eq!(evidence.len(), 2);

        coordinator.clear_evidence().await;
        let evidence = coordinator.get_evidence().await;
        assert!(evidence.is_empty());
    }

    #[tokio::test]
    async fn test_pipeline_no_evidence_for_low_risk() {
        let mut coordinator = PipelineCoordinator::new();
        coordinator
            .discovery()
            .register(Arc::new(Box::new(MockDiscoveryProvider {
                name: "test".to_string(),
                object_count: 1,
            })));
        coordinator.assessment().register(Arc::new(MockAssessor {
            name: "test".to_string(),
            risk_level: RiskLevel::None,
        }));

        let result = coordinator.run().await.unwrap();
        assert_eq!(result.evidence_count, 0);
    }

    #[tokio::test]
    async fn test_pipeline_empty() {
        let coordinator = PipelineCoordinator::new();
        let result = coordinator.run().await.unwrap();
        assert_eq!(result.objects_discovered, 0);
        assert_eq!(result.evidence_count, 0);
    }
}
