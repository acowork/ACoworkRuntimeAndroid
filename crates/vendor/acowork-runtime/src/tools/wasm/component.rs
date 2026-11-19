//! Component model loader for WASM tool components
//!
//! Loads WASM components that follow the ACowork tool interface,
//! supporting both V1 (raw pointer) and V3 (typed component) protocols.
//!
//! The component model provides:
//! - Type-safe input/output through ToolInput/ToolOutput
//! - Backward compatibility with Phase 1 `execute(ptr, len)` protocol
//! - Automatic interface detection

use wasmtime::Module;

use super::engine::WasmEngine;
use super::instance::{WasmExecutionResult, WasmToolInstance};
use super::wit::{ComponentInterface, ComponentInterfaceVersion, ToolInput, ToolOutput};
use crate::error::RuntimeError;

/// A loaded WASM tool component with interface metadata.
pub struct WasmToolComponent {
    /// The tool name
    pub name: String,
    /// Detected interface version
    pub interface: ComponentInterface,
    /// The compiled module (shared for multiple instantiations)
    module: Module,
    /// Reference to the engine for creating instances
    engine_config: super::engine::WasmEngineConfig,
}

impl WasmToolComponent {
    /// Load a WASM tool component from bytes.
    ///
    /// Compiles the module and detects the interface version.
    pub fn load(name: &str, engine: &WasmEngine, wasm_bytes: &[u8]) -> Result<Self, RuntimeError> {
        let module = engine.compile(wasm_bytes)?;

        let interface = ComponentInterface::detect(
            name,
            &module,
            &mut wasmtime::Store::new(engine.engine(), ()),
        );

        Ok(Self {
            name: name.to_string(),
            interface,
            module,
            engine_config: engine.config().clone(),
        })
    }

    /// Load a WASM tool component from a file.
    pub fn load_from_file(
        name: &str,
        engine: &WasmEngine,
        path: &std::path::Path,
    ) -> Result<Self, RuntimeError> {
        let module = engine.compile_from_file(path)?;

        let interface = ComponentInterface::detect(
            name,
            &module,
            &mut wasmtime::Store::new(engine.engine(), ()),
        );

        Ok(Self {
            name: name.to_string(),
            interface,
            module,
            engine_config: engine.config().clone(),
        })
    }

    /// Execute the tool with typed input/output.
    ///
    /// Handles both V1 (raw pointer) and V3 (typed) protocols
    /// transparently.
    pub fn execute(
        &self,
        engine: &WasmEngine,
        input: &ToolInput,
    ) -> Result<ToolOutput, RuntimeError> {
        let mut instance = WasmToolInstance::from_module(engine, &self.module)?;

        let input_json = serde_json::to_string(&input.params)
            .map_err(|e| RuntimeError::Wasm(format!("Failed to serialize input: {}", e)))?;

        let result = instance.execute(&input_json)?;

        Ok(self.convert_result(result))
    }

    /// Execute with raw JSON string (backward compatible).
    pub fn execute_raw(
        &self,
        engine: &WasmEngine,
        input_json: &str,
    ) -> Result<WasmExecutionResult, RuntimeError> {
        let mut instance = WasmToolInstance::from_module(engine, &self.module)?;
        instance.execute(input_json)
    }

    /// Convert a raw execution result to typed ToolOutput.
    fn convert_result(&self, result: WasmExecutionResult) -> ToolOutput {
        if result.ok {
            match serde_json::from_str::<serde_json::Value>(&result.output) {
                Ok(data) => ToolOutput::ok(data),
                Err(_) => {
                    // If output isn't valid JSON, wrap it as a string
                    ToolOutput::ok(serde_json::json!({
                        "raw_output": result.output,
                        "fuel_consumed": result.fuel_consumed,
                    }))
                }
            }
        } else {
            ToolOutput::err(
                result
                    .error
                    .unwrap_or_else(|| "Unknown WASM execution error".to_string()),
            )
        }
    }

    /// Get the component name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the interface version.
    pub fn version(&self) -> ComponentInterfaceVersion {
        self.interface.version
    }

    /// Whether this component has a schema export.
    pub fn has_schema(&self) -> bool {
        self.interface.has_schema
    }

    /// Whether this component exports shared memory.
    pub fn has_memory(&self) -> bool {
        self.interface.has_memory
    }
}

impl std::fmt::Debug for WasmToolComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmToolComponent")
            .field("name", &self.name)
            .field("interface", &self.interface)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::wasm::engine::wasm_generator;

    fn create_test_engine() -> WasmEngine {
        WasmEngine::default_engine().unwrap()
    }

    #[test]
    fn test_component_load_with_execute() {
        let engine = create_test_engine();
        let wasm = wasm_generator::module_with_execute();
        let component = WasmToolComponent::load("test_tool", &engine, &wasm);
        assert!(
            component.is_ok(),
            "Should load component with execute export"
        );

        let component = component.unwrap();
        assert_eq!(component.name(), "test_tool");
    }

    #[test]
    fn test_component_load_with_memory() {
        let engine = create_test_engine();
        let wasm = wasm_generator::module_with_memory();
        let component = WasmToolComponent::load("memory_tool", &engine, &wasm);
        assert!(component.is_ok());

        let component = component.unwrap();
        assert!(component.has_memory());
    }

    #[test]
    fn test_component_execute_typed() {
        let engine = create_test_engine();
        let wasm = wasm_generator::module_with_execute();
        let component = WasmToolComponent::load("typed_tool", &engine, &wasm).unwrap();

        let input = ToolInput::new(serde_json::json!({"a": 1, "b": 2}));
        let output = component.execute(&engine, &input);
        assert!(output.is_ok(), "Typed execution should succeed");

        let output = output.unwrap();
        assert!(output.ok);
    }

    #[test]
    fn test_component_execute_raw() {
        let engine = create_test_engine();
        let wasm = wasm_generator::module_with_execute();
        let component = WasmToolComponent::load("raw_tool", &engine, &wasm).unwrap();

        let result = component.execute_raw(&engine, r#"{"test": true}"#);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.ok);
        assert!(result.fuel_consumed > 0);
    }

    #[test]
    fn test_component_load_invalid() {
        let engine = create_test_engine();
        let component = WasmToolComponent::load("bad", &engine, &[0xFF, 0xFE]);
        assert!(component.is_err(), "Invalid WASM should fail to load");
    }

    #[test]
    fn test_component_debug_format() {
        let engine = create_test_engine();
        let wasm = wasm_generator::module_with_execute();
        let component = WasmToolComponent::load("debug_tool", &engine, &wasm).unwrap();
        let debug_str = format!("{:?}", component);
        assert!(debug_str.contains("WasmToolComponent"));
        assert!(debug_str.contains("debug_tool"));
    }
}
