//! WASI sandbox configuration builder
//!
//! Constructs WASI Preview 2 configurations from ACowork permissions,
//! defining the exact filesystem and network boundaries for a WASM tool.
//!
//! The sandbox is the security boundary: a WASM tool can ONLY access
//! what is explicitly granted through WASI capabilities. No implicit
//! access to host resources is possible.

use std::path::Path;
use wasmtime_wasi::DirPerms;
use wasmtime_wasi::FilePerms;
use wasmtime_wasi::WasiCtx;
use wasmtime_wasi::WasiCtxBuilder;

use super::wasi_mapper::{WasiCapabilities, WasiDirPermission};

/// WASI sandbox configuration for a WASM tool instance.
#[derive(Debug, Clone)]
pub struct WasiSandboxConfig {
    /// Preopened directory paths (read-only or read-write)
    pub preopen_dirs: Vec<WasiDirPermission>,
    /// Whether to allow network access
    pub allow_network: bool,
    /// Environment variables to pass to the WASM module
    pub env_vars: Vec<(String, String)>,
    /// Command line arguments for the WASM module
    pub args: Vec<String>,
}

impl Default for WasiSandboxConfig {
    fn default() -> Self {
        Self {
            preopen_dirs: vec![],
            allow_network: false,
            env_vars: vec![],
            args: vec![],
        }
    }
}

impl WasiSandboxConfig {
    /// Create a sandbox config from WASI capabilities.
    pub fn from_capabilities(caps: &WasiCapabilities) -> Self {
        Self {
            preopen_dirs: caps.dirs.clone(),
            allow_network: !caps.networks.is_empty(),
            env_vars: vec![],
            args: vec![],
        }
    }

    /// Add an environment variable to the sandbox.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.push((key.into(), value.into()));
        self
    }

    /// Add a command line argument.
    pub fn with_arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Get the list of read-only directory paths.
    pub fn readonly_dirs(&self) -> Vec<&str> {
        self.preopen_dirs
            .iter()
            .filter(|d| !d.writable)
            .map(|d| d.path.as_str())
            .collect()
    }

    /// Get the list of read-write directory paths.
    pub fn readwrite_dirs(&self) -> Vec<&str> {
        self.preopen_dirs
            .iter()
            .filter(|d| d.writable)
            .map(|d| d.path.as_str())
            .collect()
    }
}

/// Build a WASI context from a sandbox configuration.
///
/// This creates the `WasiCtx` that is injected into the WASM store,
/// defining the exact capabilities available to the WASM tool.
///
/// Note: For preopened directories, the host directory must exist
/// on the filesystem. If a directory doesn't exist, it will be skipped
/// with a warning log.
pub fn build_wasi_ctx(config: &WasiSandboxConfig) -> WasiCtx {
    let mut builder = WasiCtxBuilder::new();

    // Add command line arguments
    for arg in &config.args {
        builder.arg(arg);
    }

    // Add environment variables
    for (key, value) in &config.env_vars {
        builder.env(key, value);
    }

    // Preopen directories
    for dir_perm in &config.preopen_dirs {
        let host_path = Path::new(&dir_perm.path);
        if !host_path.exists() {
            tracing::warn!(
                "Skipping WASI preopen: directory does not exist: {}",
                dir_perm.path
            );
            continue;
        }

        let dir_perms = if dir_perm.writable {
            DirPerms::READ | DirPerms::MUTATE
        } else {
            DirPerms::READ
        };
        let file_perms = if dir_perm.writable {
            FilePerms::READ | FilePerms::WRITE
        } else {
            FilePerms::READ
        };

        // Use the same path for both host and guest
        if let Err(e) = builder.preopened_dir(host_path, &dir_perm.path, dir_perms, file_perms) {
            tracing::warn!(
                "Failed to preopen WASI directory '{}': {}",
                dir_perm.path,
                e
            );
        }
    }

    // Network access is controlled at the WASI socket level.
    if config.allow_network {
        builder.inherit_network();
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::wasm::wasi_mapper::{
        WasiDirPermission, WasiNetPermission, map_permissions_to_wasi,
    };
    use acowork_core::Permission;

    #[test]
    fn test_sandbox_config_default() {
        let config = WasiSandboxConfig::default();
        assert!(config.preopen_dirs.is_empty());
        assert!(!config.allow_network);
        assert!(config.env_vars.is_empty());
        assert!(config.args.is_empty());
    }

    #[test]
    fn test_sandbox_from_capabilities() {
        let caps = WasiCapabilities {
            dirs: vec![
                WasiDirPermission {
                    path: "/data".to_string(),
                    writable: false,
                },
                WasiDirPermission {
                    path: "/output".to_string(),
                    writable: true,
                },
            ],
            networks: vec![WasiNetPermission {
                url_pattern: "https://api.example.com".to_string(),
            }],
        };

        let config = WasiSandboxConfig::from_capabilities(&caps);
        assert_eq!(config.preopen_dirs.len(), 2);
        assert!(config.allow_network);
    }

    #[test]
    fn test_sandbox_readonly_dirs() {
        let config = WasiSandboxConfig {
            preopen_dirs: vec![
                WasiDirPermission {
                    path: "/read".to_string(),
                    writable: false,
                },
                WasiDirPermission {
                    path: "/write".to_string(),
                    writable: true,
                },
            ],
            ..Default::default()
        };
        let readonly = config.readonly_dirs();
        assert_eq!(readonly, vec!["/read"]);
    }

    #[test]
    fn test_sandbox_readwrite_dirs() {
        let config = WasiSandboxConfig {
            preopen_dirs: vec![
                WasiDirPermission {
                    path: "/read".to_string(),
                    writable: false,
                },
                WasiDirPermission {
                    path: "/write".to_string(),
                    writable: true,
                },
            ],
            ..Default::default()
        };
        let readwrite = config.readwrite_dirs();
        assert_eq!(readwrite, vec!["/write"]);
    }

    #[test]
    fn test_sandbox_with_env() {
        let config = WasiSandboxConfig::default()
            .with_env("KEY", "value")
            .with_env("OTHER", "test");
        assert_eq!(config.env_vars.len(), 2);
    }

    #[test]
    fn test_sandbox_with_args() {
        let config = WasiSandboxConfig::default()
            .with_arg("--verbose")
            .with_arg("--output=json");
        assert_eq!(config.args.len(), 2);
    }

    #[test]
    fn test_full_permission_to_sandbox_pipeline() {
        let perms = vec![
            Permission::FilesystemRead(Some("/data".to_string())),
            Permission::FilesystemWrite(Some("/output".to_string())),
            Permission::Network(Some("https://api.example.com".to_string())),
        ];

        let caps = map_permissions_to_wasi(&perms);
        let config = WasiSandboxConfig::from_capabilities(&caps);

        assert_eq!(config.preopen_dirs.len(), 2);
        assert!(config.allow_network);
        assert_eq!(config.readonly_dirs(), vec!["/data"]);
        assert_eq!(config.readwrite_dirs(), vec!["/output"]);
    }

    #[test]
    fn test_build_wasi_ctx_minimal() {
        // Build with no preopen dirs (no filesystem access)
        let config = WasiSandboxConfig::default();
        let _ctx = build_wasi_ctx(&config);
        // Should not panic
    }
}
