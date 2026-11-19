//! Host function registration for WASM tool communication
//!
//! Defines the host-side functions that WASM tools can call to
//! communicate with the Runtime. These are registered as WASM
//! imports during instance creation.
//!
//! Phase 1 host functions:
//! - `acowork_execute(ptr, len)` — invoke a nested tool call
//! - `acowork_schema()` — get tool's JSON schema
//!
//! Security: Host functions are the ONLY way WASM tools can
//! interact with the host. No direct memory access is possible.

use wasmtime::{Engine, FuncType, ValType};

/// Host function registry for WASM instances.
///
/// Maintains references to host-side state and provides
/// functions that can be imported into WASM modules.
pub struct HostFunctions {
    /// Whether to allow nested tool calls from WASM
    allow_nested_calls: bool,
}

impl HostFunctions {
    /// Create a new HostFunctions registry.
    pub fn new() -> Self {
        Self {
            allow_nested_calls: false,
        }
    }

    /// Enable or disable nested tool calls.
    pub fn with_nested_calls(mut self, allow: bool) -> Self {
        self.allow_nested_calls = allow;
        self
    }

    /// Get the function type for `acowork_execute`.
    /// Signature: (ptr: i32, len: i32) -> i32
    pub fn execute_func_type(engine: &Engine) -> FuncType {
        FuncType::new(
            engine,
            [ValType::I32, ValType::I32].into_iter(),
            [ValType::I32].into_iter(),
        )
    }

    /// Get the function type for `acowork_log`.
    /// Signature: (ptr: i32, len: i32) -> ()
    pub fn log_func_type(engine: &Engine) -> FuncType {
        FuncType::new(
            engine,
            [ValType::I32, ValType::I32].into_iter(),
            [].into_iter(),
        )
    }

    /// Whether nested calls are allowed.
    pub fn allows_nested_calls(&self) -> bool {
        self.allow_nested_calls
    }
}

impl Default for HostFunctions {
    fn default() -> Self {
        Self::new()
    }
}

/// Input/Output bridge for Host-WASM communication.
///
/// Manages the shared buffers used to pass data between
/// the host and WASM linear memory.
pub struct HostIoBridge {
    /// Maximum input size in bytes (default: 1MB)
    pub max_input_size: usize,
    /// Maximum output size in bytes (default: 1MB)
    pub max_output_size: usize,
}

impl Default for HostIoBridge {
    fn default() -> Self {
        Self {
            max_input_size: 1024 * 1024,  // 1MB
            max_output_size: 1024 * 1024, // 1MB
        }
    }
}

impl HostIoBridge {
    /// Create a new HostIoBridge with default limits.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a HostIoBridge with custom size limits.
    pub fn with_limits(max_input: usize, max_output: usize) -> Self {
        Self {
            max_input_size: max_input,
            max_output_size: max_output,
        }
    }

    /// Validate input size against the limit.
    pub fn validate_input(&self, input: &[u8]) -> Result<(), String> {
        if input.len() > self.max_input_size {
            Err(format!(
                "Input too large: {} bytes (max: {})",
                input.len(),
                self.max_input_size
            ))
        } else {
            Ok(())
        }
    }

    /// Validate output size against the limit.
    pub fn validate_output(&self, output: &[u8]) -> Result<(), String> {
        if output.len() > self.max_output_size {
            Err(format!(
                "Output too large: {} bytes (max: {})",
                output.len(),
                self.max_output_size
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_functions_default() {
        let hf = HostFunctions::default();
        assert!(!hf.allows_nested_calls());
    }

    #[test]
    fn test_host_functions_with_nested_calls() {
        let hf = HostFunctions::new().with_nested_calls(true);
        assert!(hf.allows_nested_calls());
    }

    #[test]
    fn test_execute_func_type() {
        let engine = wasmtime::Engine::default();
        let ft = HostFunctions::execute_func_type(&engine);
        assert_eq!(ft.params().len(), 2);
        assert_eq!(ft.results().len(), 1);
    }

    #[test]
    fn test_log_func_type() {
        let engine = wasmtime::Engine::default();
        let ft = HostFunctions::log_func_type(&engine);
        assert_eq!(ft.params().len(), 2);
        assert_eq!(ft.results().len(), 0);
    }

    #[test]
    fn test_io_bridge_default_limits() {
        let bridge = HostIoBridge::new();
        assert_eq!(bridge.max_input_size, 1024 * 1024);
        assert_eq!(bridge.max_output_size, 1024 * 1024);
    }

    #[test]
    fn test_io_bridge_custom_limits() {
        let bridge = HostIoBridge::with_limits(512, 256);
        assert_eq!(bridge.max_input_size, 512);
        assert_eq!(bridge.max_output_size, 256);
    }

    #[test]
    fn test_io_bridge_validate_input_ok() {
        let bridge = HostIoBridge::with_limits(10, 10);
        assert!(bridge.validate_input(b"hello").is_ok());
    }

    #[test]
    fn test_io_bridge_validate_input_too_large() {
        let bridge = HostIoBridge::with_limits(5, 10);
        assert!(bridge.validate_input(b"hello world").is_err());
    }

    #[test]
    fn test_io_bridge_validate_output_ok() {
        let bridge = HostIoBridge::with_limits(10, 10);
        assert!(bridge.validate_output(b"ok").is_ok());
    }

    #[test]
    fn test_io_bridge_validate_output_too_large() {
        let bridge = HostIoBridge::with_limits(10, 5);
        assert!(bridge.validate_output(b"too large output").is_err());
    }
}
