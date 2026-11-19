//! FileProvenance — workspace file source tracking
//!
//! Tracks the origin of every file in the agent workspace so that
//! ShellRisk can elevate the risk level when a Downloaded or Unknown
//! file is about to be executed.
//!
//! Persistence: rusqlite (agent restart-safe).
//! Design: `docs/08-security.md` §11.2

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Source classification for a workspace file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FileSource {
    /// Agent created the file via a tool (file_write, etc.)
    CreatedByTool { tool: String, at: DateTime<Utc> },
    /// File was downloaded from a URL (network_fetch, web_fetch)
    Downloaded { from_url: String, at: DateTime<Utc> },
    /// File existed before the agent started
    PreExisting,
    /// Source unknown (e.g. created by a shell subprocess)
    Unknown,
}

impl FileSource {
    /// Serialize to a (type_key, detail, timestamp) triple for DB storage.
    fn to_db_row(&self) -> (&'static str, Option<String>, Option<String>) {
        match self {
            FileSource::CreatedByTool { tool, at } => {
                ("created_by_tool", Some(tool.clone()), Some(at.to_rfc3339()))
            }
            FileSource::Downloaded { from_url, at } => {
                ("downloaded", Some(from_url.clone()), Some(at.to_rfc3339()))
            }
            FileSource::PreExisting => ("pre_existing", None, None),
            FileSource::Unknown => ("unknown", None, None),
        }
    }

    /// Deserialize from DB columns.
    fn from_db_row(type_key: &str, detail: Option<String>, timestamp: Option<String>) -> Self {
        match type_key {
            "created_by_tool" => FileSource::CreatedByTool {
                tool: detail.unwrap_or_default(),
                at: timestamp
                    .and_then(|t| DateTime::parse_from_rfc3339(&t).ok())
                    .map(|dt| dt.to_utc())
                    .unwrap_or_else(Utc::now),
            },
            "downloaded" => FileSource::Downloaded {
                from_url: detail.unwrap_or_default(),
                at: timestamp
                    .and_then(|t| DateTime::parse_from_rfc3339(&t).ok())
                    .map(|dt| dt.to_utc())
                    .unwrap_or_else(Utc::now),
            },
            "pre_existing" => FileSource::PreExisting,
            _ => FileSource::Unknown,
        }
    }

    /// Returns true if this source is considered high-risk for execution.
    pub fn is_high_risk(&self) -> bool {
        matches!(self, FileSource::Downloaded { .. } | FileSource::Unknown)
    }
}

/// Persistent file-provenance store backed by SQLite.
pub struct FileProvenanceStore {
    conn: Mutex<Connection>,
}

impl FileProvenanceStore {
    /// Open (or create) the provenance database at the given path.
    pub fn open(path: &Path) -> Result<Self, ProvenanceError> {
        let conn = Connection::open(path).map_err(|e| ProvenanceError::Database(e.to_string()))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self, ProvenanceError> {
        let conn =
            Connection::open_in_memory().map_err(|e| ProvenanceError::Database(e.to_string()))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<(), ProvenanceError> {
        self.conn
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            );
            INSERT OR IGNORE INTO schema_version (version) VALUES (1);

            CREATE TABLE IF NOT EXISTS file_provenance (
                path TEXT PRIMARY KEY,
                source_type TEXT NOT NULL,
                detail TEXT,
                timestamp TEXT,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_provenance_source_type
                ON file_provenance (source_type);
            ",
            )
            .map_err(|e| ProvenanceError::Database(e.to_string()))?;
        Ok(())
    }

    /// Record or update the provenance of a single file.
    pub fn record(&self, path: &Path, source: &FileSource) -> Result<(), ProvenanceError> {
        let (source_type, detail, timestamp) = source.to_db_row();
        self.conn
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO file_provenance (path, source_type, detail, timestamp)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(path) DO UPDATE SET
                source_type = excluded.source_type,
                detail = excluded.detail,
                timestamp = excluded.timestamp,
                updated_at = datetime('now')",
                params![path.to_string_lossy(), source_type, detail, timestamp],
            )
            .map_err(|e| ProvenanceError::Database(e.to_string()))?;
        Ok(())
    }

    /// Batch-record provenance for multiple files.
    pub fn record_batch(&self, entries: &[(PathBuf, FileSource)]) -> Result<(), ProvenanceError> {
        let conn = self.conn.lock().unwrap();
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| ProvenanceError::Database(e.to_string()))?;
        {
            for (path, source) in entries {
                let (source_type, detail, timestamp) = source.to_db_row();
                tx.execute(
                    "INSERT INTO file_provenance (path, source_type, detail, timestamp)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(path) DO UPDATE SET
                        source_type = excluded.source_type,
                        detail = excluded.detail,
                        timestamp = excluded.timestamp,
                        updated_at = datetime('now')",
                    params![path.to_string_lossy(), source_type, detail, timestamp],
                )
                .map_err(|e| ProvenanceError::Database(e.to_string()))?;
            }
        }
        tx.commit()
            .map_err(|e| ProvenanceError::Database(e.to_string()))?;
        Ok(())
    }

    /// Look up the provenance of a file.
    pub fn get(&self, path: &Path) -> Result<Option<FileSource>, ProvenanceError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT source_type, detail, timestamp FROM file_provenance WHERE path = ?1")
            .map_err(|e| ProvenanceError::Database(e.to_string()))?;
        let result: Option<(String, Option<String>, Option<String>)> = stmt
            .query_row(params![path.to_string_lossy()], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .optional()
            .map_err(|e| ProvenanceError::Database(e.to_string()))?;

        Ok(result.map(|(t, d, ts)| FileSource::from_db_row(&t, d, ts)))
    }

    /// Remove provenance record for a file.
    pub fn remove(&self, path: &Path) -> Result<(), ProvenanceError> {
        self.conn
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM file_provenance WHERE path = ?1",
                params![path.to_string_lossy()],
            )
            .map_err(|e| ProvenanceError::Database(e.to_string()))?;
        Ok(())
    }

    /// List all files with a given source type.
    pub fn list_by_source(
        &self,
        source_type: &str,
    ) -> Result<Vec<(PathBuf, FileSource)>, ProvenanceError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT path, source_type, detail, timestamp FROM file_provenance WHERE source_type = ?1")
            .map_err(|e| ProvenanceError::Database(e.to_string()))?;
        let rows = stmt
            .query_map(params![source_type], |row| {
                let path: String = row.get(0)?;
                let st: String = row.get(1)?;
                let detail: Option<String> = row.get(2)?;
                let ts: Option<String> = row.get(3)?;
                Ok((
                    PathBuf::from(path),
                    FileSource::from_db_row(&st, detail, ts),
                ))
            })
            .map_err(|e| ProvenanceError::Database(e.to_string()))?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| ProvenanceError::Database(e.to_string()))?);
        }
        Ok(result)
    }

    /// List all high-risk files (Downloaded or Unknown).
    pub fn list_high_risk_files(&self) -> Result<Vec<(PathBuf, FileSource)>, ProvenanceError> {
        let mut result = Vec::new();
        result.extend(self.list_by_source("downloaded")?);
        result.extend(self.list_by_source("unknown")?);
        Ok(result)
    }

    /// Scan a directory and mark all existing files as PreExisting.
    /// Called at agent startup to establish baseline provenance.
    pub fn scan_and_mark_preexisting(
        &self,
        workspace_dir: &Path,
    ) -> Result<usize, ProvenanceError> {
        let mut count = 0;
        let entries =
            std::fs::read_dir(workspace_dir).map_err(|e| ProvenanceError::Io(e.to_string()))?;

        let mut batch = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| ProvenanceError::Io(e.to_string()))?;
            let path = entry.path();
            if path.is_file() {
                batch.push((path, FileSource::PreExisting));
                count += 1;
            } else if path.is_dir() {
                // Recurse into subdirectories
                count += self.scan_dir_recursive(&path, &mut batch);
            }
        }
        if !batch.is_empty() {
            self.record_batch(&batch)?;
        }
        Ok(count)
    }

    fn scan_dir_recursive(&self, dir: &Path, batch: &mut Vec<(PathBuf, FileSource)>) -> usize {
        let mut count = 0;
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return 0,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                batch.push((path, FileSource::PreExisting));
                count += 1;
            } else if path.is_dir() {
                count += self.scan_dir_recursive(&path, batch);
            }
        }
        count
    }

    /// Clear all provenance records.
    pub fn clear(&self) -> Result<(), ProvenanceError> {
        self.conn
            .lock()
            .unwrap()
            .execute("DELETE FROM file_provenance", [])
            .map_err(|e| ProvenanceError::Database(e.to_string()))?;
        Ok(())
    }
}

/// Error type for provenance operations.
#[derive(Debug, thiserror::Error)]
pub enum ProvenanceError {
    #[error("Database error: {0}")]
    Database(String),
    #[error("IO error: {0}")]
    Io(String),
}

/// High-level FileProvenance tracker that wraps the store
/// and provides workspace-relative path resolution.
pub struct FileProvenance {
    store: FileProvenanceStore,
    workspace_dir: PathBuf,
}

impl FileProvenance {
    /// Create a new FileProvenance tracker.
    pub fn new(workspace_dir: &Path, store: FileProvenanceStore) -> Self {
        Self {
            store,
            workspace_dir: workspace_dir.to_path_buf(),
        }
    }

    /// Create with an in-memory store (for testing).
    pub fn new_in_memory(workspace_dir: &Path) -> Result<Self, ProvenanceError> {
        Ok(Self {
            store: FileProvenanceStore::open_in_memory()?,
            workspace_dir: workspace_dir.to_path_buf(),
        })
    }

    /// Initialize workspace by scanning for pre-existing files.
    pub fn init_workspace(&self) -> Result<usize, ProvenanceError> {
        self.store.scan_and_mark_preexisting(&self.workspace_dir)
    }

    /// Record that a file was created by a tool.
    pub fn record_tool_created(&self, path: &Path, tool_name: &str) -> Result<(), ProvenanceError> {
        self.store.record(
            path,
            &FileSource::CreatedByTool {
                tool: tool_name.to_string(),
                at: Utc::now(),
            },
        )
    }

    /// Record that a file was downloaded from a URL.
    pub fn record_downloaded(&self, path: &Path, url: &str) -> Result<(), ProvenanceError> {
        self.store.record(
            path,
            &FileSource::Downloaded {
                from_url: url.to_string(),
                at: Utc::now(),
            },
        )
    }

    /// Record that a file has unknown provenance (e.g. shell subprocess created).
    pub fn record_unknown(&self, path: &Path) -> Result<(), ProvenanceError> {
        self.store.record(path, &FileSource::Unknown)
    }

    /// Look up the provenance of a file (exact path match).
    pub fn get(&self, path: &Path) -> Result<Option<FileSource>, ProvenanceError> {
        self.store.get(path)
    }

    /// Look up the provenance of a file with smart path resolution.
    ///
    /// Resolution order:
    /// 1. Exact path match
    /// 2. Prepend workspace directory (for relative paths like `./script.sh`)
    /// 3. Match by filename (for relative/absolute path mismatches)
    ///
    /// This is the primary lookup method for ShellRisk integration,
    /// where the command may reference files with relative paths
    /// while the store records absolute paths.
    pub fn lookup(&self, path: &Path) -> Option<FileSource> {
        // 1. Exact match
        if let Some(source) = self.store.get(path).unwrap_or(None) {
            return Some(source);
        }

        // 2. Prepend workspace dir (e.g., "./script.sh" → "/workspace/script.sh")
        let abs_path = self.workspace_dir.join(path);
        if let Some(source) = self.store.get(&abs_path).unwrap_or(None) {
            return Some(source);
        }

        // 3. Match by filename (fallback for path format mismatches)
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !file_name.is_empty() {
            for src_type in &["downloaded", "unknown", "created_by_tool", "pre_existing"] {
                if let Ok(list) = self.store.list_by_source(src_type)
                    && let Some((_, source)) = list
                        .iter()
                        .find(|(p, _)| p.file_name().and_then(|n| n.to_str()) == Some(file_name))
                {
                    return Some(source.clone());
                }
            }
        }

        None
    }

    /// Get the underlying store reference.
    pub fn store(&self) -> &FileProvenanceStore {
        &self.store
    }

    /// Get the workspace directory.
    pub fn workspace_dir(&self) -> &Path {
        &self.workspace_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_dir() -> PathBuf {
        PathBuf::from("/tmp/acowork-test-provenance")
    }

    #[test]
    fn test_file_source_serialization() {
        let now = Utc::now();
        let source = FileSource::CreatedByTool {
            tool: "file_write".to_string(),
            at: now,
        };
        let (type_key, detail, ts) = source.to_db_row();
        assert_eq!(type_key, "created_by_tool");
        assert_eq!(detail.as_deref(), Some("file_write"));
        assert!(ts.is_some());

        let restored = FileSource::from_db_row(type_key, detail, ts);
        assert_eq!(restored, source);
    }

    #[test]
    fn test_file_source_downloaded() {
        let source = FileSource::Downloaded {
            from_url: "https://example.com/file.sh".to_string(),
            at: Utc::now(),
        };
        assert!(source.is_high_risk());
    }

    #[test]
    fn test_file_source_preexisting_not_high_risk() {
        let source = FileSource::PreExisting;
        assert!(!source.is_high_risk());
    }

    #[test]
    fn test_store_record_and_get() {
        let store = FileProvenanceStore::open_in_memory().unwrap();
        let path = PathBuf::from("/workspace/data.csv");

        store
            .record(
                &path,
                &FileSource::CreatedByTool {
                    tool: "file_write".to_string(),
                    at: Utc::now(),
                },
            )
            .unwrap();

        let result = store.get(&path).unwrap().unwrap();
        assert!(matches!(result, FileSource::CreatedByTool { tool, .. } if tool == "file_write"));
    }

    #[test]
    fn test_store_record_overwrite() {
        let store = FileProvenanceStore::open_in_memory().unwrap();
        let path = PathBuf::from("/workspace/data.csv");

        store.record(&path, &FileSource::PreExisting).unwrap();
        store
            .record(
                &path,
                &FileSource::Downloaded {
                    from_url: "https://example.com/data.csv".to_string(),
                    at: Utc::now(),
                },
            )
            .unwrap();

        let result = store.get(&path).unwrap().unwrap();
        assert!(matches!(result, FileSource::Downloaded { .. }));
    }

    #[test]
    fn test_store_missing_file() {
        let store = FileProvenanceStore::open_in_memory().unwrap();
        let result = store.get(Path::new("/workspace/nonexistent.txt")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_store_remove() {
        let store = FileProvenanceStore::open_in_memory().unwrap();
        let path = PathBuf::from("/workspace/temp.txt");

        store.record(&path, &FileSource::Unknown).unwrap();
        assert!(store.get(&path).unwrap().is_some());

        store.remove(&path).unwrap();
        assert!(store.get(&path).unwrap().is_none());
    }

    #[test]
    fn test_store_batch_record() {
        let store = FileProvenanceStore::open_in_memory().unwrap();
        let entries = vec![
            (PathBuf::from("/workspace/a.txt"), FileSource::PreExisting),
            (PathBuf::from("/workspace/b.txt"), FileSource::Unknown),
            (
                PathBuf::from("/workspace/c.txt"),
                FileSource::CreatedByTool {
                    tool: "file_write".to_string(),
                    at: Utc::now(),
                },
            ),
        ];

        store.record_batch(&entries).unwrap();

        assert!(store.get(Path::new("/workspace/a.txt")).unwrap().is_some());
        assert!(store.get(Path::new("/workspace/b.txt")).unwrap().is_some());
        assert!(store.get(Path::new("/workspace/c.txt")).unwrap().is_some());
    }

    #[test]
    fn test_store_list_high_risk() {
        let store = FileProvenanceStore::open_in_memory().unwrap();

        store
            .record(Path::new("/workspace/safe.txt"), &FileSource::PreExisting)
            .unwrap();
        store
            .record(
                Path::new("/workspace/downloaded.sh"),
                &FileSource::Downloaded {
                    from_url: "https://evil.com/payload.sh".to_string(),
                    at: Utc::now(),
                },
            )
            .unwrap();
        store
            .record(Path::new("/workspace/unknown.bin"), &FileSource::Unknown)
            .unwrap();

        let high_risk = store.list_high_risk_files().unwrap();
        assert_eq!(high_risk.len(), 2);
    }

    #[test]
    fn test_file_provenance_tracker() {
        let dir = test_dir();
        let provenance = FileProvenance::new_in_memory(&dir).unwrap();

        let path = Path::new("/workspace/output.csv");
        provenance.record_tool_created(path, "file_write").unwrap();

        let source = provenance.get(path).unwrap().unwrap();
        assert!(matches!(source, FileSource::CreatedByTool { tool, .. } if tool == "file_write"));
    }

    #[test]
    fn test_lookup_exact_path() {
        let dir = PathBuf::from("/workspace");
        let provenance = FileProvenance::new_in_memory(&dir).unwrap();

        let abs_path = Path::new("/workspace/script.sh");
        provenance
            .record_downloaded(abs_path, "https://evil.com/script.sh")
            .unwrap();

        // Exact match
        let source = provenance.lookup(abs_path);
        assert!(source.is_some());
        assert!(matches!(source.unwrap(), FileSource::Downloaded { .. }));
    }

    #[test]
    fn test_lookup_relative_path() {
        let dir = PathBuf::from("/workspace");
        let provenance = FileProvenance::new_in_memory(&dir).unwrap();

        // Store with absolute path
        let abs_path = Path::new("/workspace/script.sh");
        provenance
            .record_downloaded(abs_path, "https://evil.com/script.sh")
            .unwrap();

        // Lookup with relative path
        let rel_path = Path::new("./script.sh");
        let source = provenance.lookup(rel_path);
        assert!(source.is_some());
        assert!(source.unwrap().is_high_risk());
    }

    #[test]
    fn test_lookup_filename_fallback() {
        let dir = PathBuf::from("/workspace/subdir");
        let provenance = FileProvenance::new_in_memory(&dir).unwrap();

        // Store with deeply nested absolute path
        let abs_path = Path::new("/workspace/subdir/deep/payload.sh");
        provenance
            .record_downloaded(abs_path, "https://evil.com/payload.sh")
            .unwrap();

        // Lookup by filename only
        let query = Path::new("payload.sh");
        let source = provenance.lookup(query);
        assert!(source.is_some());
    }

    #[test]
    fn test_lookup_not_found() {
        let dir = PathBuf::from("/workspace");
        let provenance = FileProvenance::new_in_memory(&dir).unwrap();

        let source = provenance.lookup(Path::new("nonexistent.txt"));
        assert!(source.is_none());
    }
}
