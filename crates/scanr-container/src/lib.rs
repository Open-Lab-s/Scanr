use std::ffi::OsStr;
use std::fs::{self, File};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use scanr_engine::{EngineError, EngineType, ScanEngine, ScanInput, ScanMetadata, ScanResult};
use scanr_sca::ScaEngine;
use serde::Deserialize;
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

    pub fn detect_distro_for_rootfs(&self, rootfs_path: &Path) -> Distro {
        self.detect_distro(rootfs_path)
    }
}

#[derive(Debug, Clone, Copy)]
enum ImageSourceMode {
    Docker,
    Tar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distro {
    Alpine,
    Debian,
    Ubuntu,
    RHEL,
    Distroless,
    Unknown,
}

#[derive(Debug)]
pub struct RootFs {
    pub path: PathBuf,
}

#[derive(Debug)]
struct AcquiredImage {
    source_mode: ImageSourceMode,
    target_display: String,
    image_extract_path: PathBuf,
    _temp_dir: TempDir,
}

#[derive(Debug, Deserialize)]
struct ImageManifestEntry {
    #[serde(rename = "Layers")]
    layers: Vec<String>,
}

const MAX_EXTRACTION_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_EXTRACTION_ENTRIES: usize = 200_000;
const MAX_PATH_COMPONENTS: usize = 64;
const EXTRACTION_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug)]
struct ExtractionGuard {
    started_at: Instant,
    bytes: u64,
    entries: usize,
}

impl ExtractionGuard {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            bytes: 0,
            entries: 0,
        }
    }

    fn register_entry(&mut self, bytes: u64, archive_label: &str) -> Result<(), EngineError> {
        if self.started_at.elapsed() > EXTRACTION_TIMEOUT {
            return Err(EngineError::new(format!(
                "extraction timeout exceeded while processing {archive_label}"
            )));
        }

        self.entries = self.entries.saturating_add(1);
        if self.entries > MAX_EXTRACTION_ENTRIES {
            return Err(EngineError::new(format!(
                "tar bomb protection triggered for {archive_label}: too many entries"
            )));
        }

        self.bytes = self.bytes.saturating_add(bytes);
        if self.bytes > MAX_EXTRACTION_BYTES {
            return Err(EngineError::new(format!(
                "max extraction size exceeded for {archive_label}"
            )));
        }

        Ok(())
    }
}

impl ScanEngine for ContainerEngine {
    fn name(&self) -> &'static str {
        "container"
    }

    fn scan(&self, input: ScanInput) -> Result<ScanResult, EngineError> {
        let acquired = self.acquire_image(input)?;
        let rootfs = self.build_rootfs(&acquired.image_extract_path)?;
        let _distro = self.detect_distro(&rootfs.path);

        let _ = &self.sca_engine;
        let _ = rootfs.path;
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
        let image_extract_path = temp_dir.path().join("image");

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

        self.extract_tar_archive(&archive_path, &image_extract_path)?;

        Ok(AcquiredImage {
            source_mode: ImageSourceMode::Docker,
            target_display: image.to_string(),
            image_extract_path,
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
        let image_extract_path = temp_dir.path().join("image");
        self.extract_tar_archive(tar_path, &image_extract_path)?;

        Ok(AcquiredImage {
            source_mode: ImageSourceMode::Tar,
            target_display: tar_path.display().to_string(),
            image_extract_path,
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
        let mut guard = ExtractionGuard::new();

        let entries = archive.entries().map_err(|error| {
            EngineError::new(format!(
                "invalid tar archive '{}': {error}",
                archive_path.display()
            ))
        })?;

        for entry in entries {
            let mut entry = entry.map_err(|error| {
                EngineError::new(format!(
                    "invalid tar archive '{}': {error}",
                    archive_path.display()
                ))
            })?;

            let entry_size = entry.header().size().map_err(|error| {
                EngineError::new(format!(
                    "failed to read tar entry size in '{}': {error}",
                    archive_path.display()
                ))
            })?;
            guard.register_entry(entry_size, &archive_path.display().to_string())?;

            let raw_path = entry.path().map_err(|error| {
                EngineError::new(format!(
                    "invalid tar entry path in '{}': {error}",
                    archive_path.display()
                ))
            })?;
            let relative_path = sanitize_relative_path(raw_path.as_ref())?;
            if relative_path.as_os_str().is_empty() {
                continue;
            }

            let unpacked = entry.unpack_in(extract_path).map_err(|error| {
                EngineError::new(format!(
                    "invalid tar archive '{}': {error}",
                    archive_path.display()
                ))
            })?;
            if !unpacked {
                return Err(EngineError::new(format!(
                    "tar bomb protection triggered for '{}': path traversal detected",
                    archive_path.display()
                )));
            }
        }

        Ok(())
    }

    fn build_rootfs(&self, image_extract_path: &Path) -> Result<RootFs, EngineError> {
        let layer_paths = self.read_manifest_layers(image_extract_path)?;
        let rootfs_path = image_extract_path
            .parent()
            .unwrap_or(image_extract_path)
            .join("rootfs");

        if rootfs_path.exists() {
            fs::remove_dir_all(&rootfs_path).map_err(|error| {
                EngineError::new(format!(
                    "failed to reset rootfs directory '{}': {error}",
                    rootfs_path.display()
                ))
            })?;
        }
        fs::create_dir_all(&rootfs_path).map_err(|error| {
            EngineError::new(format!(
                "failed to create rootfs directory '{}': {error}",
                rootfs_path.display()
            ))
        })?;

        let mut guard = ExtractionGuard::new();
        for layer_path in &layer_paths {
            self.apply_layer_tar(layer_path, &rootfs_path, &mut guard)?;
        }

        Ok(RootFs { path: rootfs_path })
    }

    fn detect_distro(&self, rootfs_path: &Path) -> Distro {
        let etc_path = rootfs_path.join("etc");

        if etc_path.join("alpine-release").is_file() {
            return Distro::Alpine;
        }

        let os_release_path = etc_path.join("os-release");
        if os_release_path.is_file()
            && let Ok(contents) = fs::read_to_string(&os_release_path)
        {
            let id = parse_os_release_value(&contents, "ID").unwrap_or_default();
            let id_like = parse_os_release_value(&contents, "ID_LIKE").unwrap_or_default();

            if id == "alpine" || id_like.contains("alpine") {
                return Distro::Alpine;
            }
            if id == "ubuntu" || id_like.contains("ubuntu") {
                return Distro::Ubuntu;
            }
            if id == "debian" || id_like.contains("debian") {
                return Distro::Debian;
            }
            if is_rhel_family(&id) || is_rhel_family(&id_like) {
                return Distro::RHEL;
            }
        }

        if etc_path.join("debian_version").is_file() {
            return Distro::Debian;
        }

        if looks_distroless(rootfs_path) {
            return Distro::Distroless;
        }

        Distro::Unknown
    }

    fn read_manifest_layers(&self, image_extract_path: &Path) -> Result<Vec<PathBuf>, EngineError> {
        let manifest_path = image_extract_path.join("manifest.json");
        let manifest_payload = fs::read_to_string(&manifest_path).map_err(|error| {
            EngineError::new(format!(
                "invalid tar input: failed to read '{}': {error}",
                manifest_path.display()
            ))
        })?;

        let entries: Vec<ImageManifestEntry> =
            serde_json::from_str(&manifest_payload).map_err(|error| {
                EngineError::new(format!(
                    "invalid tar input: failed to parse '{}': {error}",
                    manifest_path.display()
                ))
            })?;

        let first = entries.first().ok_or_else(|| {
            EngineError::new("invalid tar input: manifest.json has no image entries")
        })?;
        if first.layers.is_empty() {
            return Err(EngineError::new(
                "invalid tar input: manifest.json has no layers",
            ));
        }

        let mut layer_paths = Vec::with_capacity(first.layers.len());
        for layer in &first.layers {
            let sanitized_layer = sanitize_relative_path(Path::new(layer))?;
            if sanitized_layer.as_os_str().is_empty() {
                return Err(EngineError::new(
                    "invalid tar input: manifest contains an empty layer path",
                ));
            }
            let layer_path = image_extract_path.join(sanitized_layer);
            if !layer_path.is_file() {
                return Err(EngineError::new(format!(
                    "invalid tar input: layer not found '{}'",
                    layer_path.display()
                )));
            }
            layer_paths.push(layer_path);
        }
        Ok(layer_paths)
    }

    fn apply_layer_tar(
        &self,
        layer_path: &Path,
        rootfs_path: &Path,
        guard: &mut ExtractionGuard,
    ) -> Result<(), EngineError> {
        let layer_file = File::open(layer_path).map_err(|error| {
            EngineError::new(format!(
                "failed to open layer archive '{}': {error}",
                layer_path.display()
            ))
        })?;

        let mut archive = tar::Archive::new(layer_file);
        let entries = archive.entries().map_err(|error| {
            EngineError::new(format!(
                "invalid layer archive '{}': {error}",
                layer_path.display()
            ))
        })?;

        for entry in entries {
            let mut entry = entry.map_err(|error| {
                EngineError::new(format!(
                    "invalid layer archive '{}': {error}",
                    layer_path.display()
                ))
            })?;

            let entry_size = entry.header().size().map_err(|error| {
                EngineError::new(format!(
                    "failed to read layer entry size in '{}': {error}",
                    layer_path.display()
                ))
            })?;
            guard.register_entry(entry_size, &layer_path.display().to_string())?;

            let raw_path = entry.path().map_err(|error| {
                EngineError::new(format!(
                    "invalid layer entry path in '{}': {error}",
                    layer_path.display()
                ))
            })?;
            let relative_path = sanitize_relative_path(raw_path.as_ref())?;
            if relative_path.as_os_str().is_empty() {
                continue;
            }

            if handle_whiteout(rootfs_path, &relative_path)? {
                continue;
            }

            let unpacked = entry.unpack_in(rootfs_path).map_err(|error| {
                EngineError::new(format!(
                    "failed to unpack layer '{}' into rootfs: {error}",
                    layer_path.display()
                ))
            })?;
            if !unpacked {
                return Err(EngineError::new(format!(
                    "tar bomb protection triggered for '{}': path traversal detected",
                    layer_path.display()
                )));
            }
        }

        Ok(())
    }
}

fn sanitize_relative_path(path: &Path) -> Result<PathBuf, EngineError> {
    let mut sanitized = PathBuf::new();
    let mut depth = 0usize;
    for component in path.components() {
        match component {
            Component::Normal(segment) => {
                sanitized.push(segment);
                depth += 1;
                if depth > MAX_PATH_COMPONENTS {
                    return Err(EngineError::new("tar bomb protection: path depth exceeded"));
                }
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(EngineError::new(
                    "tar bomb protection: unsafe path detected in archive",
                ));
            }
        }
    }
    Ok(sanitized)
}

fn handle_whiteout(rootfs_path: &Path, relative_path: &Path) -> Result<bool, EngineError> {
    let Some(file_name) = relative_path.file_name().and_then(OsStr::to_str) else {
        return Ok(false);
    };
    if !file_name.starts_with(".wh.") {
        return Ok(false);
    }

    let parent_rel = relative_path.parent().unwrap_or_else(|| Path::new(""));
    if file_name == ".wh..wh..opq" {
        let opaque_dir = rootfs_path.join(parent_rel);
        if opaque_dir.is_dir() {
            for entry in fs::read_dir(&opaque_dir).map_err(|error| {
                EngineError::new(format!(
                    "failed to read opaque whiteout directory '{}': {error}",
                    opaque_dir.display()
                ))
            })? {
                let entry = entry.map_err(|error| {
                    EngineError::new(format!(
                        "failed to iterate opaque whiteout directory '{}': {error}",
                        opaque_dir.display()
                    ))
                })?;
                remove_fs_path(entry.path())?;
            }
        }
        return Ok(true);
    }

    let target_name = &file_name[4..];
    if target_name.is_empty() {
        return Ok(true);
    }
    let target_rel = parent_rel.join(target_name);
    let target_path = rootfs_path.join(target_rel);
    remove_fs_path(target_path)?;
    Ok(true)
}

fn remove_fs_path(path: PathBuf) -> Result<(), EngineError> {
    if !path.exists() {
        return Ok(());
    }

    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        EngineError::new(format!(
            "failed to inspect filesystem entry '{}': {error}",
            path.display()
        ))
    })?;

    if metadata.is_dir() {
        fs::remove_dir_all(&path).map_err(|error| {
            EngineError::new(format!(
                "failed to remove directory '{}': {error}",
                path.display()
            ))
        })?;
    } else {
        fs::remove_file(&path).map_err(|error| {
            EngineError::new(format!(
                "failed to remove file '{}': {error}",
                path.display()
            ))
        })?;
    }

    Ok(())
}

fn parse_os_release_value(contents: &str, key: &str) -> Option<String> {
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let (lhs, rhs) = trimmed.split_once('=')?;
        if lhs.trim() != key {
            continue;
        }

        let mut value = rhs.trim().to_ascii_lowercase();
        if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
            value = value[1..value.len() - 1].to_string();
        }

        return Some(value);
    }
    None
}

fn is_rhel_family(value: &str) -> bool {
    value
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .any(|token| {
            matches!(
                token,
                "rhel" | "centos" | "fedora" | "rocky" | "almalinux" | "ol"
            )
        })
}

fn looks_distroless(rootfs_path: &Path) -> bool {
    let etc_path = rootfs_path.join("etc");
    if !etc_path.is_dir() {
        return false;
    }

    let has_os_markers = etc_path.join("os-release").is_file()
        || etc_path.join("alpine-release").is_file()
        || etc_path.join("debian_version").is_file();
    if has_os_markers {
        return false;
    }

    let has_common_package_managers = rootfs_path.join("sbin/apk").exists()
        || rootfs_path.join("usr/bin/apt").exists()
        || rootfs_path.join("usr/bin/apt-get").exists()
        || rootfs_path.join("usr/bin/dnf").exists()
        || rootfs_path.join("usr/bin/yum").exists()
        || rootfs_path.join("usr/bin/rpm").exists();
    let has_shell = rootfs_path.join("bin/sh").exists() || rootfs_path.join("usr/bin/sh").exists();

    !has_common_package_managers && !has_shell
}
