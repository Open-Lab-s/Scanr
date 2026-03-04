use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::{Dependency, ScanError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CacheEntry {
    pub fetched_at: String,
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub osv_response: JsonValue,
}

pub(crate) fn cache_file_path(base_path: &Path, dependency: &Dependency) -> PathBuf {
    let ecosystem = dependency.ecosystem.to_string();
    let package = sanitize_component(&dependency.name);
    let version = sanitize_component(&dependency.version);
    base_path.join(format!("{ecosystem}_{package}_{version}.json"))
}

pub(crate) fn read_cache_entry(path: &Path) -> Result<Option<CacheEntry>, ScanError> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            let entry = serde_json::from_str::<CacheEntry>(&contents).map_err(|source| {
                ScanError::Json {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
            Ok(Some(entry))
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(ScanError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

pub(crate) fn write_cache_entry(path: &Path, entry: &CacheEntry) -> Result<(), ScanError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| ScanError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let payload = serde_json::to_string_pretty(entry).map_err(|source| ScanError::Json {
        path: path.to_path_buf(),
        source,
    })?;

    fs::write(path, payload).map_err(|source| ScanError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn sanitize_component(raw: &str) -> String {
    let mut output = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '.' {
            output.push(ch);
        } else {
            output.push('_');
        }
    }

    if output.is_empty() {
        "_".to_string()
    } else {
        output
    }
}
