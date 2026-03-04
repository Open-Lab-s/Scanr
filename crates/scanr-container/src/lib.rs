use scanr_engine::{EngineType, ScanEngine, ScanInput, ScanMetadata, ScanResult};
use scanr_sca::ScaEngine;

#[derive(Debug, Default, Clone)]
pub struct ContainerEngine {
    pub sca_engine: ScaEngine,
}

impl ContainerEngine {
    pub fn new() -> Self {
        Self {
            sca_engine: ScaEngine::new(),
        }
    }
}

impl ScanEngine for ContainerEngine {
    fn name(&self) -> &'static str {
        "container"
    }

    fn scan(&self, input: ScanInput) -> scanr_engine::EngineResult<ScanResult> {
        let target = match input {
            ScanInput::Image(image) => image,
            ScanInput::Tar(path) | ScanInput::Path(path) => path.display().to_string(),
        };

        let _ = &self.sca_engine;

        Ok(ScanResult {
            findings: Vec::new(),
            metadata: ScanMetadata {
                engine: EngineType::Container,
                engine_name: self.name().to_string(),
                target,
                total_dependencies: 0,
                total_vulnerabilities: 0,
            },
        })
    }
}
