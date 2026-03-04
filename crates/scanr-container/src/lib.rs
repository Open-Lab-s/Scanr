use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Command;

use scanr_engine::{EngineError, EngineType, ScanEngine, ScanInput, ScanMetadata, ScanResult};
use scanr_sca::ScaEngine;
use tempfile::TempDir;

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

#[derive(Debug, Clone, Copy)]
enum ImageSourceMode {
    Docker,
    Tar,
}

#[derive(Debug)]
struct AcquiredImage {
    source_mode: ImageSourceMode,
    target_display: String,
    extract_path: PathBuf,
    _temp_dir: TempDir,
}

impl ScanEngine for ContainerEngine {
    fn name(&self) -> &'static str {
        "container"
    }

    fn scan(&self, input: ScanInput) -> Result<ScanResult, EngineError> {
        let acquired = self.acquire_image(input)?;

        let _ = &self.sca_engine;
        let _ = acquired.extract_path;
        let _ = acquired.source_mode;

        Ok(ScanResult {
            findings: Vec::new(),
            metadata: ScanMetadata {
                engine: EngineType::Container,
                engine_name: self.name().to_string(),
                target: acquired.target_display,
                total_dependencies: 0,
                total_vulnerabilities: 0,
            },
        })
    }
}

impl ContainerEngine {
    fn acquire_image(&self, input: ScanInput) -> Result<AcquiredImage, EngineError> {
        match input {
            ScanInput::Image(image) => self.acquire_from_docker(&image),
            ScanInput::Tar(path) | ScanInput::Path(path) => self.acquire_from_tar(&path),
        }
    }

    fn acquire_from_docker(&self, image: &str) -> Result<AcquiredImage, EngineError> {
        let temp_dir = TempDir::new().map_err(|error| {
            EngineError::new(format!(
                "failed to create temporary working directory for container scan: {error}"
            ))
        })?;
        let archive_path = temp_dir.path().join("image.tar");
        let extract_path = temp_dir.path().join("extracted");

        let output = Command::new("docker")
            .arg("save")
            .arg(image)
            .arg("-o")
            .arg(&archive_path)
            .output()
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    EngineError::new(
                        "docker is not installed or not available in PATH. Install Docker to scan image targets.",
                    )
                } else {
                    EngineError::new(format!("failed to execute docker save: {error}"))
                }
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if stderr.to_ascii_lowercase().contains("no such image") {
                return Err(EngineError::new(format!(
                    "container image not found: {image}. Pull/build the image before scanning."
                )));
            }
            return Err(EngineError::new(format!(
                "docker save failed for '{image}': {}",
                if stderr.is_empty() {
                    "unknown docker error"
                } else {
                    &stderr
                }
            )));
        }

        self.extract_tar_archive(&archive_path, &extract_path)?;

        Ok(AcquiredImage {
            source_mode: ImageSourceMode::Docker,
            target_display: image.to_string(),
            extract_path,
            _temp_dir: temp_dir,
        })
    }

    fn acquire_from_tar(&self, tar_path: &Path) -> Result<AcquiredImage, EngineError> {
        if !tar_path.is_file() {
            return Err(EngineError::new(format!(
                "invalid tar input '{}': file not found or not a regular file",
                tar_path.display()
            )));
        }

        let temp_dir = TempDir::new().map_err(|error| {
            EngineError::new(format!(
                "failed to create temporary working directory for tar scan: {error}"
            ))
        })?;
        let extract_path = temp_dir.path().join("extracted");
        self.extract_tar_archive(tar_path, &extract_path)?;

        Ok(AcquiredImage {
            source_mode: ImageSourceMode::Tar,
            target_display: tar_path.display().to_string(),
            extract_path,
            _temp_dir: temp_dir,
        })
    }

    fn extract_tar_archive(
        &self,
        archive_path: &Path,
        extract_path: &Path,
    ) -> Result<(), EngineError> {
        fs::create_dir_all(extract_path).map_err(|error| {
            EngineError::new(format!(
                "failed to create extraction directory '{}': {error}",
                extract_path.display()
            ))
        })?;

        let archive_file = File::open(archive_path).map_err(|error| {
            EngineError::new(format!(
                "failed to open tar archive '{}': {error}",
                archive_path.display()
            ))
        })?;

        let mut archive = tar::Archive::new(archive_file);
        archive.unpack(extract_path).map_err(|error| {
            EngineError::new(format!(
                "invalid tar archive '{}': {error}",
                archive_path.display()
            ))
        })
    }
}
