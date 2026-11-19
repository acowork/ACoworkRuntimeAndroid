//! Local `.agent` package install / uninstall (ADR-055 §6.5 shape).
//!
//! Vendored flow from upstream `acowork-node::package::install` and
//! `download_package` in `control/mod.rs`:
//!
//! 1. Optional HTTP download of `package_url` → `{home}/downloads/{instance}.agent`
//! 2. Open ZIP (`.agent` is a ZIP) → read `manifest.toml` → extract under
//!    `{home}/packages/{agent_id}/{instance_id}/`
//! 3. Persist inventory in `{home}/installed.json` and emit retained
//!    `InstalledAgentInfo`
//!
//! Signature verification via `acowork-sign` is **not** linked here (ADR-AND-003:
//! no upstream crate dependency). Unsigned / unverified packages are accepted with
//! a warning — same soft stance as upstream runtime loader Phase 1. Directory
//! installs (dev / already-extracted) remain supported.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::proto::{AgentIdentity, DataEnvelope, InstalledAgentInfo, data_envelope};
use super::topics::node_agent_installed_topic;

/// Fields we need from `manifest.toml` without pulling `acowork-core::AgentManifest`.
///
/// Extra keys in the file are ignored (`deny_unknown_fields` is off).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestSummary {
    /// Reverse-domain package id (e.g. `com.example.weather`).
    pub agent_id: String,
    /// Semantic version string.
    #[serde(default)]
    pub version: String,
    /// Human-readable name.
    #[serde(default)]
    pub name: String,
    /// Short description (kept for retained inventory / future UI).
    #[serde(default)]
    pub description: String,
}

impl ManifestSummary {
    /// Parse a TOML string; requires non-empty `agent_id` with a reverse-domain dot.
    pub fn from_toml(toml_str: &str) -> Result<ManifestSummary, PackageError> {
        let m: ManifestSummary = toml::from_str(toml_str)
            .map_err(|e| PackageError::Invalid(format!("manifest.toml: {e}")))?;
        if m.agent_id.is_empty() {
            return Err(PackageError::Invalid(
                "manifest.toml: agent_id cannot be empty".into(),
            ));
        }
        if !m.agent_id.contains('.') {
            return Err(PackageError::Invalid(
                "manifest.toml: agent_id must be reverse-domain (e.g. com.example.agent)".into(),
            ));
        }
        Ok(m)
    }

    /// Effective display name (falls back to `agent_id`).
    pub fn display_name(&self) -> &str {
        if self.name.is_empty() {
            &self.agent_id
        } else {
            &self.name
        }
    }
}

/// One installed agent instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledPackage {
    /// Package id.
    pub agent_id: String,
    /// Instance id (Gateway-issued).
    pub instance_id: String,
    /// On-disk install directory.
    pub install_path: String,
    /// Display name (defaults to agent_id).
    pub name: String,
    /// Optional version string.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
}

/// In-memory + on-disk inventory keyed by instance id.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageInventory {
    /// instance_id → record.
    #[serde(default)]
    pub agents: BTreeMap<String, InstalledPackage>,
}

/// Package inventory / install failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageError {
    /// I/O failure.
    Io(String),
    /// Request shape refused or bad package.
    Invalid(String),
    /// HTTP download failed.
    Download(String),
}

impl std::fmt::Display for PackageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackageError::Io(e) | PackageError::Invalid(e) | PackageError::Download(e) => {
                write!(f, "{e}")
            }
        }
    }
}

impl std::error::Error for PackageError {}

impl PackageInventory {
    /// `{home}/installed.json`.
    pub fn path(home: &Path) -> PathBuf {
        home.join("installed.json")
    }

    /// Packages root: `{home}/packages`.
    pub fn packages_dir(home: &Path) -> PathBuf {
        home.join("packages")
    }

    /// Download spool: `{home}/downloads`.
    pub fn downloads_dir(home: &Path) -> PathBuf {
        home.join("downloads")
    }

    /// Load or empty.
    pub fn load(home: &Path) -> Result<PackageInventory, PackageError> {
        let path = Self::path(home);
        if !path.exists() {
            return Ok(PackageInventory::default());
        }
        let content = std::fs::read_to_string(&path)
            .map_err(|e| PackageError::Io(format!("read {}: {e}", path.display())))?;
        serde_json::from_str(&content)
            .map_err(|e| PackageError::Io(format!("parse {}: {e}", path.display())))
    }

    /// Persist.
    pub fn save(&self, home: &Path) -> Result<(), PackageError> {
        std::fs::create_dir_all(home)
            .map_err(|e| PackageError::Io(format!("mkdir {}: {e}", home.display())))?;
        let path = Self::path(home);
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| PackageError::Io(format!("serialize installed: {e}")))?;
        std::fs::write(&path, content)
            .map_err(|e| PackageError::Io(format!("write {}: {e}", path.display())))?;
        Ok(())
    }

    /// Install from a local `.agent` ZIP, plain ZIP, or already-extracted directory.
    ///
    /// `agent_id` from the control command is advisory when the ZIP carries a
    /// manifest; a mismatch is an error. Empty `agent_id` accepts the manifest's id.
    pub fn install_local(
        &mut self,
        home: &Path,
        agent_id: &str,
        instance_id: &str,
        local_path: &str,
        ensure: bool,
    ) -> Result<&InstalledPackage, PackageError> {
        if instance_id.is_empty() {
            return Err(PackageError::Invalid("instance_id is required".into()));
        }
        if local_path.is_empty() {
            return Err(PackageError::Invalid("local_path is required".into()));
        }
        if ensure {
            if agent_id.is_empty() {
                return Err(PackageError::Invalid(
                    "ensure requires agent_id when matching an existing install".into(),
                ));
            }
            if let Some(id) = self.ensure_existing(home, agent_id, instance_id)? {
                return self
                    .agents
                    .get(&id)
                    .ok_or_else(|| PackageError::Io("ensure lookup race".into()));
            }
        }
        if self.agents.contains_key(instance_id) {
            return self
                .agents
                .get(instance_id)
                .ok_or_else(|| PackageError::Io("already-installed lookup race".into()));
        }

        let src = Path::new(local_path);
        if !src.exists() {
            return Err(PackageError::Invalid(format!(
                "local_path does not exist: {local_path}"
            )));
        }

        let (manifest, dest) = if src.is_dir() {
            install_from_directory(home, src, agent_id, instance_id)?
        } else {
            install_from_agent_zip(home, src, agent_id, instance_id)?
        };

        let record = InstalledPackage {
            agent_id: manifest.agent_id.clone(),
            instance_id: instance_id.to_string(),
            install_path: dest.to_string_lossy().replace('\\', "/"),
            name: manifest.display_name().to_string(),
            version: manifest.version.clone(),
        };
        self.agents.insert(instance_id.to_string(), record);
        self.save(home)?;
        self.agents
            .get(instance_id)
            .ok_or_else(|| PackageError::Io("insert race".into()))
    }

    /// Download `package_url` then install (upstream `download_package` + `install_package`).
    ///
    /// `node_token` is sent as `X-ACowork-Node-Token` when present (ADR-055 Phase 5a).
    pub fn install_from_url(
        &mut self,
        home: &Path,
        agent_id: &str,
        instance_id: &str,
        package_url: &str,
        node_token: Option<&str>,
        ensure: bool,
    ) -> Result<&InstalledPackage, PackageError> {
        if package_url.is_empty() {
            return Err(PackageError::Invalid("package_url is required".into()));
        }
        if ensure && !agent_id.is_empty() {
            if let Some(id) = self.ensure_existing(home, agent_id, instance_id)? {
                return self
                    .agents
                    .get(&id)
                    .ok_or_else(|| PackageError::Io("ensure lookup race".into()));
            }
        }

        let dest_dir = Self::downloads_dir(home);
        std::fs::create_dir_all(&dest_dir)
            .map_err(|e| PackageError::Io(format!("mkdir {}: {e}", dest_dir.display())))?;
        let spool = dest_dir.join(format!("{instance_id}.agent"));
        download_package(package_url, &spool, node_token)?;
        let path = spool.to_string_lossy().to_string();
        self.install_local(home, agent_id, instance_id, &path, false)
    }


    /// If `agent_id` is already installed, return that record — rebinding the
    /// inventory key to `instance_id` when Gateway minted a fresh id.
    ///
    /// Desktop / Hub ensure waits on the ack's instance id. Returning the old
    /// id while Gateway polled the new one left the UI stuck on Installing and
    /// eventually failed with "did not appear in the Gateway inventory".
    fn ensure_existing(
        &mut self,
        home: &Path,
        agent_id: &str,
        instance_id: &str,
    ) -> Result<Option<String>, PackageError> {
        let Some(existing_id) = self
            .agents
            .values()
            .find(|p| p.agent_id == agent_id)
            .map(|p| p.instance_id.clone())
        else {
            return Ok(None);
        };
        if existing_id == instance_id {
            return Ok(Some(existing_id));
        }
        self.rebind_instance(home, &existing_id, instance_id)?;
        Ok(Some(instance_id.to_string()))
    }

    /// Move an inventory entry from `from_instance` to `to_instance` (same
    /// on-disk install). Used by ensure when the Gateway re-mints an id after
    /// inventory was empty (MQTT flap / Gateway restart).
    pub fn rebind_instance(
        &mut self,
        home: &Path,
        from_instance: &str,
        to_instance: &str,
    ) -> Result<&InstalledPackage, PackageError> {
        if to_instance.is_empty() {
            return Err(PackageError::Invalid("instance_id is required".into()));
        }
        if from_instance == to_instance {
            return self
                .agents
                .get(from_instance)
                .ok_or_else(|| PackageError::Io("rebind lookup race".into()));
        }
        if self.agents.contains_key(to_instance) {
            return Err(PackageError::Invalid(format!(
                "cannot rebind `{from_instance}` onto occupied instance `{to_instance}`"
            )));
        }
        let mut rec = self.agents.remove(from_instance).ok_or_else(|| {
            PackageError::Invalid(format!("instance `{from_instance}` is not installed"))
        })?;
        rec.instance_id = to_instance.to_string();
        self.agents.insert(to_instance.to_string(), rec);
        self.save(home)?;
        self.agents
            .get(to_instance)
            .ok_or_else(|| PackageError::Io("rebind insert race".into()))
    }

    /// Uninstall by instance id (idempotent).
    pub fn uninstall(
        &mut self,
        home: &Path,
        instance_id: &str,
        agent_id: &str,
    ) -> Result<(), PackageError> {
        if instance_id.is_empty() {
            return Err(PackageError::Invalid("instance_id is required".into()));
        }
        if let Some(rec) = self.agents.remove(instance_id) {
            if !agent_id.is_empty() && rec.agent_id != agent_id {
                let actual = rec.agent_id.clone();
                self.agents.insert(instance_id.to_string(), rec);
                return Err(PackageError::Invalid(format!(
                    "instance `{instance_id}` is package `{actual}`, not `{agent_id}`"
                )));
            }
            let path = PathBuf::from(&rec.install_path);
            if path.exists() {
                let _ = std::fs::remove_dir_all(&path);
            }
            self.save(home)?;
            return Ok(());
        }
        Ok(())
    }

    /// Build the retained inventory envelope for one instance.
    pub fn installed_envelope(pkg: &InstalledPackage) -> DataEnvelope {
        DataEnvelope {
            version: 1,
            payload: Some(data_envelope::Payload::InstalledAgentInfo(
                InstalledAgentInfo {
                    agent_id: pkg.agent_id.clone(),
                    version: pkg.version.clone(),
                    name: pkg.name.clone(),
                    install_path: pkg.install_path.clone(),
                    manifest_toml: std::fs::read_to_string(
                        Path::new(&pkg.install_path).join("manifest.toml"),
                    )
                    .unwrap_or_default(),
                    instance_id: pkg.instance_id.clone(),
                    identity: Some(AgentIdentity {
                        name: pkg.name.clone(),
                        avatar: String::new(),
                        builtin_avatar: String::new(),
                    }),
                },
            )),
        }
    }

    /// Topic for a retained inventory entry.
    pub fn installed_topic(node_id: &str, instance_id: &str) -> String {
        node_agent_installed_topic(node_id, instance_id)
    }
}

/// HTTP GET a `.agent` package to `dest` (upstream `download_package`).
///
/// Blocking. On the async Node path, wrap with `tokio::task::spawn_blocking`.
pub fn download_package(
    url: &str,
    dest: &Path,
    node_token: Option<&str>,
) -> Result<(), PackageError> {
    let mut req = ureq::get(url);
    if let Some(token) = node_token {
        req = req.set("X-ACowork-Node-Token", token);
    }
    let response = req
        .call()
        .map_err(|e| PackageError::Download(format!("GET {url}: {e}")))?;
    if !(200..300).contains(&response.status()) {
        return Err(PackageError::Download(format!(
            "GET {url}: HTTP {}",
            response.status()
        )));
    }
    let mut reader = response.into_reader();
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|e| PackageError::Download(format!("read body: {e}")))?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| PackageError::Io(format!("mkdir {}: {e}", parent.display())))?;
    }
    std::fs::write(dest, &bytes)
        .map_err(|e| PackageError::Io(format!("write {}: {e}", dest.display())))?;
    Ok(())
}

fn install_from_directory(
    home: &Path,
    src: &Path,
    agent_id: &str,
    instance_id: &str,
) -> Result<(ManifestSummary, PathBuf), PackageError> {
    let toml_str = std::fs::read_to_string(src.join("manifest.toml")).map_err(|e| {
        PackageError::Invalid(format!(
            "manifest.toml missing in {}: {e}",
            src.display()
        ))
    })?;
    let mut manifest = ManifestSummary::from_toml(&toml_str)?;
    if manifest.name.is_empty() {
        manifest.name = manifest.agent_id.clone();
    }
    check_agent_id(agent_id, &manifest.agent_id)?;
    let dest = PackageInventory::packages_dir(home)
        .join(&manifest.agent_id)
        .join(instance_id);
    if dest.exists() {
        let _ = std::fs::remove_dir_all(&dest);
    }
    std::fs::create_dir_all(&dest)
        .map_err(|e| PackageError::Io(format!("mkdir {}: {e}", dest.display())))?;
    copy_dir_recursive(src, &dest)?;
    warn_signing_block(&dest);
    Ok((manifest, dest))
}

fn install_from_agent_zip(
    home: &Path,
    package_path: &Path,
    agent_id: &str,
    instance_id: &str,
) -> Result<(ManifestSummary, PathBuf), PackageError> {
    // Soft signature stance (no acowork-sign linked): log only.
    eprintln!(
        "acowork-android: installing {} (signature verify deferred — no acowork-sign)",
        package_path.display()
    );

    let data = std::fs::read(package_path).map_err(|e| {
        PackageError::Io(format!(
            "Failed to read package '{}': {e}",
            package_path.display()
        ))
    })?;
    let reader = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(reader).map_err(|e| {
        PackageError::Invalid(format!(
            "Failed to read ZIP '{}': {e} (expected a .agent package)",
            package_path.display()
        ))
    })?;

    let mut manifest = extract_manifest(&mut archive)?;
    if manifest.name.is_empty() {
        manifest.name = manifest.agent_id.clone();
    }
    check_agent_id(agent_id, &manifest.agent_id)?;

    let agent_install_dir = PackageInventory::packages_dir(home)
        .join(&manifest.agent_id)
        .join(instance_id);
    if agent_install_dir.exists() {
        let _ = std::fs::remove_dir_all(&agent_install_dir);
    }
    std::fs::create_dir_all(&agent_install_dir).map_err(|e| {
        PackageError::Io(format!(
            "Failed to create install dir {}: {e}",
            agent_install_dir.display()
        ))
    })?;

    extract_archive(&mut archive, &agent_install_dir)?;
    warn_signing_block(&agent_install_dir);
    Ok((manifest, agent_install_dir))
}

fn extract_manifest(
    archive: &mut zip::ZipArchive<std::io::Cursor<Vec<u8>>>,
) -> Result<ManifestSummary, PackageError> {
    let mut manifest_file = archive.by_name("manifest.toml").map_err(|e| {
        PackageError::Invalid(format!("manifest.toml not found in package: {e}"))
    })?;
    let mut manifest_str = String::new();
    manifest_file
        .read_to_string(&mut manifest_str)
        .map_err(|e| PackageError::Io(format!("Failed to read manifest.toml: {e}")))?;
    ManifestSummary::from_toml(&manifest_str)
}

fn extract_archive(
    archive: &mut zip::ZipArchive<std::io::Cursor<Vec<u8>>>,
    dest: &Path,
) -> Result<(), PackageError> {
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| PackageError::Io(format!("ZIP read error: {e}")))?;
        let outpath = match file.enclosed_name() {
            Some(path) => dest.join(path),
            None => continue,
        };
        if file.is_dir() {
            std::fs::create_dir_all(&outpath).ok();
        } else {
            if let Some(p) = outpath.parent()
                && !p.exists()
            {
                std::fs::create_dir_all(p).ok();
            }
            let mut outfile = std::fs::File::create(&outpath).map_err(|e| {
                PackageError::Io(format!("Failed to create '{}': {e}", outpath.display()))
            })?;
            std::io::copy(&mut file, &mut outfile).map_err(|e| {
                PackageError::Io(format!("Failed to write '{}': {e}", outpath.display()))
            })?;
        }
    }
    Ok(())
}

fn check_agent_id(requested: &str, from_manifest: &str) -> Result<(), PackageError> {
    if !requested.is_empty() && requested != from_manifest {
        return Err(PackageError::Invalid(format!(
            "agent_id mismatch: command has `{requested}`, manifest has `{from_manifest}`"
        )));
    }
    Ok(())
}

fn warn_signing_block(install_dir: &Path) {
    let block = install_dir.join("META-INF").join("SIGNING.BLOCK");
    if block.exists() {
        eprintln!(
            "acowork-android: package has META-INF/SIGNING.BLOCK — verify deferred (no acowork-sign)"
        );
    } else {
        eprintln!("acowork-android: package is unsigned — accepting (dev soft-verify)");
    }
}

fn copy_dir_recursive(src: &Path, dest: &Path) -> Result<(), PackageError> {
    for entry in std::fs::read_dir(src)
        .map_err(|e| PackageError::Io(format!("read_dir {}: {e}", src.display())))?
    {
        let entry = entry.map_err(|e| PackageError::Io(e.to_string()))?;
        let ty = entry
            .file_type()
            .map_err(|e| PackageError::Io(e.to_string()))?;
        let to = dest.join(entry.file_name());
        if ty.is_dir() {
            std::fs::create_dir_all(&to)
                .map_err(|e| PackageError::Io(format!("mkdir {}: {e}", to.display())))?;
            copy_dir_recursive(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), &to)
                .map_err(|e| PackageError::Io(format!("copy {}: {e}", entry.path().display())))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_home(tag: &str) -> PathBuf {
        let home = std::env::temp_dir().join(format!(
            "acowork-pkg-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        home
    }

    fn write_agent_zip(dir: &Path, manifest: &str) -> PathBuf {
        let zip_path = dir.join("demo.agent");
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default();
        zip.start_file("manifest.toml", opts).unwrap();
        zip.write_all(manifest.as_bytes()).unwrap();
        zip.start_file("prompts/default.md", opts).unwrap();
        zip.write_all(b"You are a demo agent.").unwrap();
        zip.finish().unwrap();
        zip_path
    }

    #[test]
    fn install_agent_zip_and_uninstall() {
        let home = temp_home("zip");
        let src_dir = home.join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        let zip = write_agent_zip(
            &src_dir,
            r#"
agent_id = "com.demo.weather"
version = "1.0.0"
name = "Weather"
description = "demo"
"#,
        );

        let mut inv = PackageInventory::default();
        let pkg = inv
            .install_local(&home, "com.demo.weather", "inst-1", zip.to_str().unwrap(), false)
            .unwrap()
            .clone();
        assert_eq!(pkg.name, "Weather");
        assert_eq!(pkg.version, "1.0.0");
        let install = Path::new(&pkg.install_path);
        assert!(install.join("manifest.toml").exists());
        assert!(install.join("prompts").join("default.md").exists());

        inv.uninstall(&home, "inst-1", "com.demo.weather").unwrap();
        assert!(!inv.agents.contains_key("inst-1"));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn install_directory_and_ensure() {
        let home = temp_home("dir");
        let src = home.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("manifest.toml"),
            "agent_id = \"com.x.demo\"\nname = \"x\"\nversion = \"2\"\n",
        )
        .unwrap();

        let mut inv = PackageInventory::default();
        inv.install_local(&home, "com.x.demo", "a", src.to_str().unwrap(), false)
            .unwrap();
        let again = inv
            .install_local(&home, "com.x.demo", "b", src.to_str().unwrap(), true)
            .unwrap();
        // Gateway-minted id wins so Desktop wait_for(instance) can converge.
        assert_eq!(again.instance_id, "b");
        assert_eq!(inv.agents.len(), 1);
        assert!(inv.agents.contains_key("b"));
        assert!(!inv.agents.contains_key("a"));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn agent_id_mismatch_rejected() {
        let home = temp_home("mismatch");
        let src_dir = home.join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        let zip = write_agent_zip(
            &src_dir,
            "agent_id = \"com.real.pkg\"\nname = \"r\"\nversion = \"1\"\n",
        );
        let mut inv = PackageInventory::default();
        let err = inv
            .install_local(&home, "com.wrong.pkg", "i1", zip.to_str().unwrap(), false)
            .unwrap_err();
        assert!(err.to_string().contains("mismatch"), "{err}");
        let _ = std::fs::remove_dir_all(&home);
    }
}
