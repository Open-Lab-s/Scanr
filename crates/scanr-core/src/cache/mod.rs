mod store;
mod ttl;

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};

use serde_json::Value as JsonValue;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{Dependency, ScanError};
use store::{CacheEntry, cache_file_path, read_cache_entry, write_cache_entry};
use ttl::is_fresh;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheDataState {
    Hit,
    Refreshed,
    Fetched,
}

#[derive(Debug)]
pub(crate) enum CacheGetResult {
    Data {
        payload: JsonValue,
        state: CacheDataState,
    },
    OfflineMiss,
}

#[derive(Debug, Clone)]
pub(crate) struct CacheManager {
    pub base_path: PathBuf,
    pub ttl_hours: u64,
    pub offline: bool,
    pub force_refresh: bool,
    pub enabled: bool,
}

impl CacheManager {
    pub(crate) fn new(
        project_root: &Path,
        ttl_hours: u64,
        offline: bool,
        force_refresh: bool,
        enabled: bool,
    ) -> Self {
        Self {
            base_path: project_root.join(".scanr").join("cache"),
            ttl_hours,
            offline,
            force_refresh,
            enabled,
        }
    }

    pub(crate) async fn get_or_fetch<F, Fut>(
        &self,
        dependency: &Dependency,
        fetcher: F,
    ) -> Result<CacheGetResult, ScanError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<JsonValue, ScanError>>,
    {
        if !self.enabled {
            if self.offline {
                return Ok(CacheGetResult::OfflineMiss);
            }
            let payload = fetcher().await?;
            return Ok(CacheGetResult::Data {
                payload,
                state: CacheDataState::Fetched,
            });
        }

        fs::create_dir_all(&self.base_path).map_err(|source| ScanError::Io {
            path: self.base_path.clone(),
            source,
        })?;

        let path = cache_file_path(&self.base_path, dependency);
        let existing = read_cache_entry(&path)?;

        if self.offline {
            return match existing {
                Some(entry) => Ok(CacheGetResult::Data {
                    payload: entry.osv_response,
                    state: CacheDataState::Hit,
                }),
                None => Ok(CacheGetResult::OfflineMiss),
            };
        }

        if !self.force_refresh
            && let Some(entry) = &existing
            && is_fresh(&entry.fetched_at, self.ttl_hours, OffsetDateTime::now_utc())
        {
            return Ok(CacheGetResult::Data {
                payload: entry.osv_response.clone(),
                state: CacheDataState::Hit,
            });
        }

        let payload = fetcher().await?;
        let fetched_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());

        let entry = CacheEntry {
            fetched_at,
            ecosystem: dependency.ecosystem.to_string(),
            package: dependency.name.clone(),
            version: dependency.version.clone(),
            osv_response: payload.clone(),
        };
        write_cache_entry(&path, &entry)?;

        Ok(CacheGetResult::Data {
            payload,
            state: if existing.is_some() {
                CacheDataState::Refreshed
            } else {
                CacheDataState::Fetched
            },
        })
    }
}
