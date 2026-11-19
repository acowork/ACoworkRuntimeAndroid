//! WasmToolInstance — lifecycle management for a single WASM tool execution
//!
//! Handles loading a compiled Module into a Store, instantiating,
//! executing the `execute` function, and reading results from memory.
//!
//! Security guarantees:
//! - Fuel metering prevents infinite loops
//! - Memory limit enforced by StoreLimits (ResourceLimiter) + WasmEngine config
//! - No access to host resources unless explicitly granted via WASI

use wasmtime::{AsContextMut, Instance, Memory, Store, StoreLimits, StoreLimitsBuilder, TypedFunc};

use super::engine::WasmEngine;
use crate::error::RuntimeError;

/// Host-side state shared between the Store and host functions.
///
/// Contains the `StoreLimits` that implement `wasmtime::ResourceLimiter`
/// to enforce per-instance memory allocation caps.
pub struct HostState {
    /// Input JSON bytes for the current execution
    pub input_buffer: Vec<u8>,
    /// Output JSON bytes from the last execution
    pub output_buffer: Vec<u8>,
    /// Whether the last execution completed successfully
    pub last_ok: bool,
    /// Error message if execution failed
    pub last_error: Option<String>,
    /// Resource limits enforced by wasmtime's ResourceLimiter.
    /// Constrains linear memory growth and instance/table/memory counts.
    pub limits: StoreLimits,
}

impl HostState {
    /// Create a new HostState with default (permissive) limits.
    pub fn new() -> Self {
        Self {
            input_buffer: Vec::new(),
            output_buffer: Vec::new(),
            last_ok: true,
            last_error: None,
            limits: StoreLimits::default(),
        }
    }

    /// Create a HostState with memory and instance limits.
    ///
    /// `max_memory_bytes` is the hard cap on total linear memory
    /// allocation across all memories in the store. This is the
    /// enforcement point for `WasmEngineConfig::max_memory_mb`.
    pub fn with_limits(max_memory_bytes: usize) -> Self {
        let limits = StoreLimitsBuilder::new()
            .memory_size(max_memory_bytes)
            .instances(1) // One instance per tool execution
            .memories(1) // One memory per instance
            .tables(10) // Reasonable table limit
            .build();
        Self {
            input_buffer: Vec::new(),
            output_buffer: Vec::new(),
            last_ok: true,
            last_error: None,
            limits,
        }
    }
}

impl Default for HostState {
    fn default() -> Self {
        Self::new()
    }
}

/// Execution result from a WASM tool.
#[derive(Debug, Clone)]
pub struct WasmExecutionResult {
    /// Whether execution succeeded
    pub ok: bool,
    /// Output JSON string from the tool
    pub output: String,
    /// Fuel consumed during execution
    pub fuel_consumed: u64,
    /// Error message if execution failed
    pub error: Option<String>,
}

/// A single WASM tool instance with its own Store and memory.
///
/// Each tool execution creates a new WasmToolInstance to ensure
/// complete isolation between invocations.
pub struct WasmToolInstance {
    /// The instantiated WASM module
    #[allow(dead_code)]
    instance: Instance,
    /// The store holding state and fuel
    store: Store<HostState>,
    /// The `execute` export function signature: (i32, i32) -> i32
    execute_fn: TypedFunc<(u32, u32), u32>,
    /// The exported memory (if any)
    memory: Option<Memory>,
    /// Fuel limit for this instance
    fuel_limit: u64,
}

impl WasmToolInstance {
    /// Create a new WasmToolInstance from compiled bytes.
    ///
    /// This compiles the module, creates a Store with fuel, and
    /// instantiates the module. The `execute` export function is
    /// looked up and bound.
    pub fn new(engine: &WasmEngine, wasm_bytes: &[u8]) -> Result<Self, RuntimeError> {
        let module = engine
            .compile(wasm_bytes)
            .map_err(|e| RuntimeError::Tool(format!("Failed to compile WASM module: {}", e)))?;

        Self::from_module(engine, &module)
    }

    /// Create a WasmToolInstance from an already-compiled Module.
    ///
    /// Creates a Store with fuel metering AND a ResourceLimiter that
    /// enforces the `max_memory_mb` cap from `WasmEngineConfig`. Without
    /// the limiter, a WASM module that declares unbounded memory could
    /// allocate far beyond the configured limit.
    pub fn from_module(
        engine: &WasmEngine,
        module: &wasmtime::Module,
    ) -> Result<Self, RuntimeError> {
        let fuel_limit = engine.fuel_limit();
        let max_memory_bytes = (engine.max_memory_mb() as usize) * 1024 * 1024;

        // Create store with host state and resource limits
        let mut store = Store::new(engine.engine(), HostState::with_limits(max_memory_bytes));

        // Register the ResourceLimiter so wasmtime consults HostState.limits
        // before allowing memory/table growth or instance creation.
        store.limiter(|state| &mut state.limits);

        store
            .set_fuel(fuel_limit)
            .map_err(|e| RuntimeError::Tool(format!("Failed to set fuel: {}", e)))?;

        // Instantiate module (no imports for simple modules)
        let instance = Instance::new(&mut store, module, &[])
            .map_err(|e| RuntimeError::Tool(format!("Failed to instantiate WASM module: {}", e)))?;

        // Look up the `execute` export
        let execute_fn = instance
            .get_typed_func::<(u32, u32), u32>(&mut store, "execute")
            .map_err(|e| {
                RuntimeError::Tool(format!("WASM module missing 'execute' export: {}", e))
            })?;

        // Look up optional memory export
        let memory = instance.get_memory(&mut store, "memory");

        Ok(Self {
            instance,
            store,
            execute_fn,
            memory,
            fuel_limit,
        })
    }

    /// Execute the WASM tool with JSON input.
    ///
    /// The input JSON is written to WASM memory, then the `execute`
    /// function is called with (input_ptr, input_len). The return
    /// value is used as output_ptr to read the result.
    ///
    /// For simple modules without memory export, a simpler protocol
    /// is used where the function return value is the result directly.
    pub fn execute(&mut self, input_json: &str) -> Result<WasmExecutionResult, RuntimeError> {
        let fuel_before = self.store.get_fuel().unwrap_or(0);

        // Reset state
        self.store.data_mut().input_buffer = input_json.as_bytes().to_vec();
        self.store.data_mut().output_buffer.clear();
        self.store.data_mut().last_ok = true;
        self.store.data_mut().last_error = None;

        // For modules with memory, write input and call execute(ptr, len)
        if let Some(_memory) = self.memory {
            self.execute_with_memory(input_json)?
        } else {
            // Fallback: call execute(0, input_len) for simple modules
            self.execute_simple(input_json.len() as u32)?
        }

        let fuel_after = self.store.get_fuel().unwrap_or(0);
        let fuel_consumed = fuel_before.saturating_sub(fuel_after);

        let state = self.store.data();
        let output = String::from_utf8_lossy(&state.output_buffer).to_string();

        Ok(WasmExecutionResult {
            ok: state.last_ok,
            output,
            fuel_consumed,
            error: state.last_error.clone(),
        })
    }

    /// Execute with memory-based communication.
    fn execute_with_memory(&mut self, input_json: &str) -> Result<(), RuntimeError> {
        let input_bytes = input_json.as_bytes();
        let input_len = input_bytes.len() as u32;

        // Write input to WASM memory at offset 0
        if let Some(memory) = self.memory {
            let mut ctx = self.store.as_context_mut();
            let mem_data = memory.data_mut(&mut ctx);
            let copy_len = std::cmp::min(input_bytes.len(), mem_data.len());
            mem_data[..copy_len].copy_from_slice(&input_bytes[..copy_len]);
        }

        // Call execute(input_ptr=0, input_len)
        match self.execute_fn.call(&mut self.store, (0, input_len)) {
            Ok(output_ptr) => {
                // Read output from memory at output_ptr
                if let Some(memory) = self.memory {
                    self.read_output_from_memory(memory, output_ptr)?;
                }
                Ok(())
            }
            Err(e) => {
                let err_msg = format!("{}", e);
                // Check if it's a fuel exhaustion trap
                if err_msg.contains("all fuel consumed") {
                    self.store.data_mut().last_ok = false;
                    self.store.data_mut().last_error =
                        Some("Fuel exhausted: execution timed out".to_string());
                } else {
                    self.store.data_mut().last_ok = false;
                    self.store.data_mut().last_error = Some(format!("WASM trap: {}", e));
                }
                Ok(()) // Don't propagate error; report it in the result
            }
        }
    }

    /// Simple execution for modules without memory export.
    fn execute_simple(&mut self, input_len: u32) -> Result<(), RuntimeError> {
        match self.execute_fn.call(&mut self.store, (0, input_len)) {
            Ok(_result) => {
                // For simple modules, any non-trap return is success
                self.store.data_mut().last_ok = true;
                self.store.data_mut().output_buffer = b"{\"status\": \"ok\"}".to_vec();
                Ok(())
            }
            Err(e) => {
                let err_msg = format!("{}", e);
                if err_msg.contains("all fuel consumed") {
                    self.store.data_mut().last_ok = false;
                    self.store.data_mut().last_error =
                        Some("Fuel exhausted: execution timed out".to_string());
                } else {
                    self.store.data_mut().last_ok = false;
                    self.store.data_mut().last_error = Some(format!("WASM trap: {}", e));
                }
                Ok(())
            }
        }
    }

    /// Read null-terminated output from WASM memory.
    fn read_output_from_memory(
        &mut self,
        memory: Memory,
        start_ptr: u32,
    ) -> Result<(), RuntimeError> {
        let ctx = self.store.as_context_mut();
        let mem_data = memory.data(&ctx);

        let start = start_ptr as usize;
        if start >= mem_data.len() {
            self.store.data_mut().last_ok = false;
            self.store.data_mut().last_error =
                Some("Output pointer out of memory bounds".to_string());
            return Ok(());
        }

        // Find null terminator or end of memory
        let output_bytes: Vec<u8> = mem_data[start..]
            .iter()
            .take_while(|&&b| b != 0)
            .copied()
            .collect();

        self.store.data_mut().output_buffer = output_bytes;
        Ok(())
    }

    /// Get remaining fuel in the store.
    pub fn remaining_fuel(&self) -> u64 {
        self.store.get_fuel().unwrap_or(0)
    }

    /// Get the fuel limit for this instance.
    pub fn fuel_limit(&self) -> u64 {
        self.fuel_limit
    }

    /// Check if this instance has a memory export.
    pub fn has_memory(&self) -> bool {
        self.memory.is_some()
    }
}

impl Drop for WasmToolInstance {
    fn drop(&mut self) {
        let remaining_fuel = self.store.get_fuel().unwrap_or(0);
        let consumed = self.fuel_limit.saturating_sub(remaining_fuel);
        tracing::debug!(
            tool = "wasm_instance",
            fuel_limit = self.fuel_limit,
            fuel_consumed = consumed,
            fuel_remaining = remaining_fuel,
            "WasmToolInstance dropped — fuel audit"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::wasm::engine::{WasmEngineConfig, wasm_generator};
    use wasmtime::ResourceLimiter;

    fn create_test_engine() -> WasmEngine {
        WasmEngine::default_engine().unwrap()
    }

    #[test]
    fn test_instance_create_empty_module() {
        let engine = create_test_engine();
        let empty_wasm = wasm_generator::empty_module();
        // Empty module has no `execute` export, should fail
        let result = WasmToolInstance::new(&engine, &empty_wasm);
        assert!(
            result.is_err(),
            "Empty module should fail (no execute export)"
        );
    }

    #[test]
    fn test_instance_create_with_execute() {
        let engine = create_test_engine();
        let wasm = wasm_generator::module_with_execute();
        let result = WasmToolInstance::new(&engine, &wasm);
        assert!(result.is_ok(), "Module with execute export should load");

        let instance = result.unwrap();
        assert!(
            !instance.has_memory(),
            "This module should not have memory export"
        );
    }

    #[test]
    fn test_instance_create_with_memory() {
        let engine = create_test_engine();
        let wasm = wasm_generator::module_with_memory();
        let result = WasmToolInstance::new(&engine, &wasm);
        assert!(result.is_ok(), "Module with memory export should load");

        let instance = result.unwrap();
        assert!(
            instance.has_memory(),
            "This module should have memory export"
        );
    }

    #[test]
    fn test_instance_execute_simple() {
        let engine = create_test_engine();
        let wasm = wasm_generator::module_with_execute();
        let mut instance = WasmToolInstance::new(&engine, &wasm).unwrap();

        let result = instance.execute(r#"{"a": 1, "b": 2}"#).unwrap();
        assert!(result.ok, "Simple execution should succeed");
        assert!(result.fuel_consumed > 0, "Should consume some fuel");
    }

    #[test]
    fn test_instance_execute_with_memory() {
        let engine = create_test_engine();
        let wasm = wasm_generator::module_with_memory();
        let mut instance = WasmToolInstance::new(&engine, &wasm).unwrap();

        let result = instance.execute(r#"{"test": true}"#).unwrap();
        // The test module adds input_ptr + input_len, so result is a number
        assert!(result.ok, "Memory execution should succeed");
        assert!(result.fuel_consumed > 0, "Should consume some fuel");
    }

    #[test]
    fn test_instance_fuel_tracking() {
        let engine = create_test_engine();
        let wasm = wasm_generator::module_with_execute();
        let mut instance = WasmToolInstance::new(&engine, &wasm).unwrap();

        let initial_fuel = instance.remaining_fuel();
        assert!(initial_fuel > 0, "Should have fuel allocated");

        instance.execute(r#"{}"#).unwrap();
        let remaining = instance.remaining_fuel();
        assert!(
            remaining < initial_fuel,
            "Fuel should decrease after execution"
        );
    }

    #[test]
    fn test_instance_invalid_bytes() {
        let engine = create_test_engine();
        let result = WasmToolInstance::new(&engine, &[0xFF, 0xFE, 0xFD]);
        assert!(result.is_err(), "Invalid WASM bytes should fail");
    }

    #[test]
    fn test_host_state_default() {
        let state = HostState::default();
        assert!(state.input_buffer.is_empty());
        assert!(state.output_buffer.is_empty());
        assert!(state.last_ok);
        assert!(state.last_error.is_none());
    }

    #[test]
    fn test_host_state_with_limits() {
        let state = HostState::with_limits(1024); // 1 KB limit
        assert!(state.input_buffer.is_empty());
        assert_eq!(state.limits.instances(), 1);
        assert_eq!(state.limits.memories(), 1);
        assert_eq!(state.limits.tables(), 10);
    }

    #[test]
    fn test_resource_limiter_memory_enforcement() {
        // Create engine with a very small memory limit (1 MB)
        let config = WasmEngineConfig::from_limits(1, 5000);
        let engine = WasmEngine::new(config).unwrap();

        // Module with memory (1 page initial, 10 pages max = 640 KB)
        // This should succeed since 640 KB < 1 MB
        let wasm = wasm_generator::module_with_memory();
        let result = WasmToolInstance::new(&engine, &wasm);
        assert!(
            result.is_ok(),
            "Module with small memory should load under 1MB limit"
        );
    }

    #[test]
    fn test_resource_limiter_rejects_large_memory() {
        // Create engine with a tiny memory limit (1 KB)
        let config = WasmEngineConfig::from_limits(0, 5000); // 0 MB = very small
        let engine = WasmEngine::new(config).unwrap();

        // Module with memory (1 page = 64 KB initial) should fail
        // since 64 KB > 0 MB limit (well, 0*1024*1024 = 0 bytes)
        // Actually 0 MB = 0 bytes, so even 1 page should be rejected
        let wasm = wasm_generator::module_with_memory();
        let result = WasmToolInstance::new(&engine, &wasm);
        assert!(
            result.is_err(),
            "Module with memory should fail under 0MB limit"
        );
    }

    #[test]
    fn test_drop_fuel_audit_does_not_panic() {
        let engine = create_test_engine();
        let wasm = wasm_generator::module_with_execute();
        let mut instance = WasmToolInstance::new(&engine, &wasm).unwrap();

        // Execute something
        let _ = instance.execute(r#"{}"#);

        // Drop should not panic and should log fuel consumption
        drop(instance);
    }
}
