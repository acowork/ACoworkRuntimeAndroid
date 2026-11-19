//! `.agent` ZIP / directory loader (vendored from upstream
//! `acowork-runtime::package::loader`).
//!
//! Uses [`crate::node::package::ManifestSummary`] instead of
//! `acowork_core::AgentManifest` so this crate stays free of upstream crate
//! deps (ADR-AND-003). Full manifest validation and signature enforcement
//! remain deferred.

use std::fs;
use std::path::{Path, PathBuf};

use crate::node::package::ManifestSummary;

/// Loaded package ready for a Runtime boot.
#[derive(Debug, Clone)]
pub struct LoadedPackage {
    /// Parsed manifest summary.
    pub manifest: ManifestSummary,
    /// Path to the extracted (or already-on-disk) package directory.
    pub package_dir: PathBuf,
}

/// Failures while loading a package for Runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageLoadError {
    /// Path / I/O / ZIP / manifest problem.
    Package(String),
}

impl std::fmt::Display for PackageLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackageLoadError::Package(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PackageLoadError {}

/// Load a `.agent` ZIP file or an already-extracted directory.
pub fn load_package(package_path: &Path) -> Result<LoadedPackage, PackageLoadError> {
    if !package_path.exists() {
        return Err(PackageLoadError::Package(format!(
            "Package path does not exist: {}",
            package_path.display()
        )));
    }

    let package_dir = if package_path.is_file() {
        extract_zip_package(package_path)?
    } else if package_path.is_dir() {
        package_path.to_path_buf()
    } else {
        return Err(PackageLoadError::Package(format!(
            "Package path is neither a file nor a directory: {}",
            package_path.display()
        )));
    };

    let manifest = load_manifest(&package_dir)?;
    eprintln!(
        "acowork-android runtime: manifest agent_id={} version={} name={}",
        manifest.agent_id, manifest.version, manifest.name
    );

    if has_signing_block(&package_dir) {
        eprintln!("acowork-android runtime: package has signing block — verify deferred");
    } else {
        eprintln!("acowork-android runtime: package is unsigned — skipping signature verification");
    }

    Ok(LoadedPackage {
        manifest,
        package_dir,
    })
}

fn extract_zip_package(zip_path: &Path) -> Result<PathBuf, PackageLoadError> {
    let file = fs::File::open(zip_path).map_err(|e| {
        PackageLoadError::Package(format!("Failed to open ZIP file: {e}"))
    })?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| {
        PackageLoadError::Package(format!("Failed to read ZIP archive: {e}"))
    })?;

    let zip_stem = zip_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("agent-package");
    let extract_dir = std::env::temp_dir().join(format!("acowork-android-agent-{zip_stem}"));

    if extract_dir.exists() {
        fs::remove_dir_all(&extract_dir).map_err(|e| {
            PackageLoadError::Package(format!("Failed to clean extract dir: {e}"))
        })?;
    }
    fs::create_dir_all(&extract_dir).map_err(|e| {
        PackageLoadError::Package(format!("Failed to create extract dir: {e}"))
    })?;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| {
            PackageLoadError::Package(format!("Failed to read ZIP entry {i}: {e}"))
        })?;
        let out_path = match entry.enclosed_name() {
            Some(path) => extract_dir.join(path),
            None => continue,
        };
        if entry.is_dir() {
            fs::create_dir_all(&out_path).map_err(|e| {
                PackageLoadError::Package(format!("Failed to create dir: {e}"))
            })?;
        } else {
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    PackageLoadError::Package(format!("Failed to create parent dir: {e}"))
                })?;
            }
            let mut outfile = fs::File::create(&out_path).map_err(|e| {
                PackageLoadError::Package(format!("Failed to create file: {e}"))
            })?;
            std::io::copy(&mut entry, &mut outfile).map_err(|e| {
                PackageLoadError::Package(format!("Failed to extract file: {e}"))
            })?;
        }
    }
    Ok(extract_dir)
}

fn load_manifest(package_dir: &Path) -> Result<ManifestSummary, PackageLoadError> {
    let manifest_path = package_dir.join("manifest.toml");
    if !manifest_path.exists() {
        return Err(PackageLoadError::Package(
            "manifest.toml not found in package".into(),
        ));
    }
    let toml_str = fs::read_to_string(&manifest_path).map_err(|e| {
        PackageLoadError::Package(format!("Failed to read manifest.toml: {e}"))
    })?;
    ManifestSummary::from_toml(&toml_str).map_err(|e| PackageLoadError::Package(e.to_string()))
}

fn has_signing_block(package_dir: &Path) -> bool {
    package_dir.join("META-INF").join("SIGNING.BLOCK").exists()
}

/// List `prompts/*.{md,txt}` under the package (upstream helper).
pub fn list_prompt_files(package_dir: &Path) -> Result<Vec<PathBuf>, PackageLoadError> {
    let prompts_dir = package_dir.join("prompts");
    if !prompts_dir.exists() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(&prompts_dir)
        .map_err(|e| PackageLoadError::Package(format!("Failed to read prompts dir: {e}")))?
    {
        let entry = entry
            .map_err(|e| PackageLoadError::Package(format!("Failed to read dir entry: {e}")))?;
        let path = entry.path();
        if path.is_file()
            && path
                .extension()
                .is_some_and(|ext| ext == "md" || ext == "txt")
        {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// List `skills/*/SKILL.md` under the package (upstream helper).
pub fn list_skill_files(package_dir: &Path) -> Result<Vec<PathBuf>, PackageLoadError> {
    let skills_dir = package_dir.join("skills");
    if !skills_dir.exists() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(&skills_dir)
        .map_err(|e| PackageLoadError::Package(format!("Failed to read skills dir: {e}")))?
    {
        let entry = entry
            .map_err(|e| PackageLoadError::Package(format!("Failed to read dir entry: {e}")))?;
        let path = entry.path();
        if path.is_dir() {
            let skill_md = path.join("SKILL.md");
            if skill_md.exists() {
                files.push(skill_md);
            }
        }
    }
    files.sort();
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn create_test_package_dir() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "acowork-android-test-pkg-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("prompts")).unwrap();
        fs::create_dir_all(dir.join("skills").join("greeting")).unwrap();
        fs::write(
            dir.join("manifest.toml"),
            r#"
agent_id = "com.test.demo"
version = "1.0.0"
name = "Demo Agent"
description = "A test agent"
"#,
        )
        .unwrap();
        fs::write(dir.join("prompts").join("system.md"), "You are helpful.").unwrap();
        fs::write(
            dir.join("skills").join("greeting").join("SKILL.md"),
            "# Greeting\nHello.",
        )
        .unwrap();
        dir
    }

    #[test]
    fn load_from_directory() {
        let dir = create_test_package_dir();
        let loaded = load_package(&dir).unwrap();
        assert_eq!(loaded.manifest.agent_id, "com.test.demo");
        assert_eq!(loaded.manifest.name, "Demo Agent");
        assert_eq!(list_prompt_files(&dir).unwrap().len(), 1);
        assert_eq!(list_skill_files(&dir).unwrap().len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_from_zip() {
        let dir = create_test_package_dir();
        let zip_path = dir.parent().unwrap().join(format!(
            "acowork-android-zip-{}.agent",
            std::process::id()
        ));
        {
            let file = fs::File::create(&zip_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            zip.start_file("manifest.toml", opts).unwrap();
            zip.write_all(
                br#"
agent_id = "com.zip.demo"
version = "0.1.0"
name = "Zip"
description = "z"
"#,
            )
            .unwrap();
            zip.start_file("prompts/a.md", opts).unwrap();
            zip.write_all(b"hi").unwrap();
            zip.finish().unwrap();
        }
        let loaded = load_package(&zip_path).unwrap();
        assert_eq!(loaded.manifest.agent_id, "com.zip.demo");
        assert!(loaded.package_dir.join("prompts").join("a.md").exists());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_file(&zip_path);
        let _ = fs::remove_dir_all(&loaded.package_dir);
    }
}
