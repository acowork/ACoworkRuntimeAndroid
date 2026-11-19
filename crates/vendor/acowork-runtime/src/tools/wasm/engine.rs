//! WasmEngine — Wasmtime engine singleton and configuration
//!
//! Manages the shared `wasmtime::Engine` instance and provides
//! module compilation with fuel metering and memory limits.
//!
//! Design decisions:
//! - Single Engine per Runtime process (thread-safe, shared across instances)
//! - Fuel metering enabled by default (prevents infinite loops)
//! - Memory limit configurable per tool instance
//! - Cranelift optimizer set to Speed for best throughput

use wasmtime::{Config, Engine, Module, OptLevel};

use crate::error::RuntimeError;

/// Configuration for the WASM engine.
#[derive(Debug, Clone)]
pub struct WasmEngineConfig {
    /// Maximum linear memory size in MB (default: 50)
    pub max_memory_mb: u32,
    /// Fuel limit per execution (estimated from max_execution_time_ms).
    /// Conversion: ~10K fuel units per millisecond (1 fuel ≈ 1 WASM instruction,
    /// modern CPU executes ~10B instructions/sec → 10M fuel/s → 10K fuel/ms).
    /// This is an empirical estimate; actual consumption varies by instruction mix.
    /// Configurable via `WasmEngineConfig::from_limits()`.
    pub fuel_limit: u64,
    /// Cranelift optimization level (default: Speed)
    pub cranelift_opt_level: OptLevel,
}

impl Default for WasmEngineConfig {
    fn default() -> Self {
        Self {
            max_memory_mb: 50,
            fuel_limit: 50_000, // ~5 seconds at 10K fuel/ms
            cranelift_opt_level: OptLevel::Speed,
        }
    }
}

impl WasmEngineConfig {
    /// Create config from resource limits defined in manifest.
    pub fn from_limits(max_memory_mb: u32, max_execution_time_ms: u64) -> Self {
        Self {
            max_memory_mb,
            fuel_limit: max_execution_time_ms * 10_000,
            cranelift_opt_level: OptLevel::Speed,
        }
    }
}

/// WASM engine singleton wrapping `wasmtime::Engine`.
///
/// Thread-safe: the inner Engine is `Send + Sync` and can be shared
/// across multiple tool instances.
pub struct WasmEngine {
    engine: Engine,
    config: WasmEngineConfig,
}

impl WasmEngine {
    /// Create a new WasmEngine with the given configuration.
    pub fn new(config: WasmEngineConfig) -> Result<Self, RuntimeError> {
        let mut wasm_config = Config::new();

        // Enable fuel consumption for CPU time metering
        wasm_config.consume_fuel(true);

        // Set Cranelift optimization level
        wasm_config.cranelift_opt_level(config.cranelift_opt_level);

        // Set max WASM linear memory size.
        // Per-instance memory limit is enforced by StoreLimits (ResourceLimiter)
        // configured in WasmToolInstance::from_module() — see S5.5.
        // The config.max_memory_mb value is propagated to HostState::with_limits()
        // which builds a StoreLimitsBuilder.memory_size() cap.
        wasm_config.max_wasm_stack(2 * 1024 * 1024); // 2MB stack

        let engine = Engine::new(&wasm_config)
            .map_err(|e| RuntimeError::Wasm(format!("Failed to create WASM engine: {}", e)))?;

        Ok(Self { engine, config })
    }

    /// Create a WasmEngine with default configuration.
    pub fn default_engine() -> Result<Self, RuntimeError> {
        Self::new(WasmEngineConfig::default())
    }

    /// Get a reference to the inner wasmtime Engine.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Get the engine configuration.
    pub fn config(&self) -> &WasmEngineConfig {
        &self.config
    }

    /// Compile a WASM module from bytes.
    ///
    /// The compiled module can be instantiated multiple times.
    pub fn compile(&self, wasm_bytes: &[u8]) -> Result<Module, RuntimeError> {
        Module::new(&self.engine, wasm_bytes)
            .map_err(|e| RuntimeError::Wasm(format!("Failed to compile WASM module: {}", e)))
    }

    /// Compile a WASM module from a file.
    pub fn compile_from_file(&self, path: &std::path::Path) -> Result<Module, RuntimeError> {
        Module::from_file(&self.engine, path)
            .map_err(|e| RuntimeError::Wasm(format!("Failed to compile WASM file: {}", e)))
    }

    /// Get the fuel limit for this engine.
    pub fn fuel_limit(&self) -> u64 {
        self.config.fuel_limit
    }

    /// Get the max memory in MB.
    pub fn max_memory_mb(&self) -> u32 {
        self.config.max_memory_mb
    }
}

impl std::fmt::Debug for WasmEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmEngine")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_default_creation() {
        let engine = WasmEngine::default_engine();
        assert!(engine.is_ok(), "Engine should create with default config");

        let engine = engine.unwrap();
        assert_eq!(engine.max_memory_mb(), 50);
        assert_eq!(engine.fuel_limit(), 50_000);
    }

    #[test]
    fn test_engine_custom_config() {
        let config = WasmEngineConfig {
            max_memory_mb: 128,
            fuel_limit: 100_000,
            cranelift_opt_level: OptLevel::Speed,
        };
        let engine = WasmEngine::new(config).unwrap();
        assert_eq!(engine.max_memory_mb(), 128);
        assert_eq!(engine.fuel_limit(), 100_000);
    }

    #[test]
    fn test_engine_config_from_limits() {
        let config = WasmEngineConfig::from_limits(64, 3000);
        assert_eq!(config.max_memory_mb, 64);
        assert_eq!(config.fuel_limit, 30_000_000); // 3000ms * 10K fuel/ms
    }

    #[test]
    fn test_engine_compile_empty_module() {
        let engine = WasmEngine::default_engine().unwrap();

        // Minimal valid WASM module (empty)
        let empty_wasm = wasm_generator::empty_module();
        let result = engine.compile(&empty_wasm);
        assert!(result.is_ok(), "Should compile empty WASM module");
    }

    #[test]
    fn test_engine_compile_invalid_bytes() {
        let engine = WasmEngine::default_engine().unwrap();

        let result = engine.compile(&[0x00, 0x01, 0x02, 0x03]);
        assert!(result.is_err(), "Should fail to compile invalid bytes");
    }

    #[test]
    fn test_engine_debug_format() {
        let engine = WasmEngine::default_engine().unwrap();
        let debug_str = format!("{:?}", engine);
        assert!(debug_str.contains("WasmEngine"));
        assert!(debug_str.contains("config"));
    }
}

/// Helper module to generate minimal WASM binaries for testing.
pub mod wasm_generator {
    /// Generate a minimal valid WASM module (empty function).
    pub fn empty_module() -> Vec<u8> {
        // WASM binary format:
        // \0asm - magic
        // 0x01 0x00 0x00 0x00 - version 1
        vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
    }

    /// Generate a WASM module with an `execute` export function.
    /// The function takes (i32, i32) and returns i32.
    pub fn module_with_execute() -> Vec<u8> {
        // Minimal WASM module with:
        // - A function type (i32, i32) -> i32
        // - A function that returns the sum of its two arguments
        // - Exported as "execute"
        vec![
            0x00, 0x61, 0x73, 0x6d, // magic
            0x01, 0x00, 0x00, 0x00, // version
            // Type section (section id = 1)
            0x01, // section id
            0x07, // section length = 7
            0x01, // 1 type
            0x60, // func type
            0x02, 0x7f, 0x7f, // 2 params: i32, i32
            0x01, 0x7f, // 1 result: i32
            // Function section (section id = 3)
            0x03, // section id
            0x02, // section length = 2
            0x01, // 1 function
            0x00, // type index 0
            // Export section (section id = 7)
            0x07, // section id
            0x0b, // section length = 11
            0x01, // 1 export
            0x07, // name length = 7
            b'e', b'x', b'e', b'c', b'u', b't', b'e', // "execute"
            0x00, // export kind: function
            0x00, // function index
            // Code section (section id = 10)
            0x0a, // section id
            0x09, // section length = 9
            0x01, // 1 function body
            0x07, // body length = 7
            0x00, // 0 locals
            0x20, 0x00, // local.get 0
            0x20, 0x01, // local.get 1
            0x6a, // i32.add
            0x0b, // end
        ]
    }

    /// Generate a WASM module with an `execute` function and memory export.
    pub fn module_with_memory() -> Vec<u8> {
        // WASM module with:
        // - Memory (1 page initial, 10 pages max)
        // - execute(i32, i32) -> i32 function
        // - Exported memory as "memory"
        vec![
            0x00, 0x61, 0x73, 0x6d, // magic
            0x01, 0x00, 0x00, 0x00, // version
            // Type section
            0x01, 0x07, // section id, length
            0x01, // 1 type
            0x60, // func type
            0x02, 0x7f, 0x7f, // 2 params: i32, i32
            0x01, 0x7f, // 1 result: i32
            // Function section
            0x03, 0x02, // section id, length
            0x01, // 1 function
            0x00, // type index 0
            // Memory section
            0x05, 0x04, // section id, length
            0x01, // 1 memory
            0x01, // has max
            0x01, // initial: 1 page
            0x0a, // max: 10 pages
            // Export section
            0x07, 0x14, // section id, length
            0x02, // 2 exports
            // Export "memory"
            0x06, // name length
            b'm', b'e', b'm', b'o', b'r', b'y', 0x02, // export kind: memory
            0x00, // memory index
            // Export "execute"
            0x07, // name length
            b'e', b'x', b'e', b'c', b'u', b't', b'e', 0x00, // export kind: function
            0x00, // function index
            // Code section
            0x0a, 0x09, // section id, length
            0x01, // 1 function body
            0x07, // body length
            0x00, // 0 locals
            0x20, 0x00, // local.get 0
            0x20, 0x01, // local.get 1
            0x6a, // i32.add
            0x0b, // end
        ]
    }
}
