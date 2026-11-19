//! WIT component model interface definitions
//!
//! Defines the typed interface contract between the ACowork Runtime
//! (host) and WASM tool components. This replaces the raw pointer-based
//! `execute(ptr, len)` protocol with type-safe function calls.
//!
//! Current status: Phase 3 uses manual type definitions.
//! Future: auto-generate from .wit files using wit-bindgen.
//!
//! WIT interface (conceptual):
//! ```wit
//! package acowork:tool;
//!
//! interface tool {
//!   resource tool-input {
//!     get: func(key: string) -> option<string>;
//!   }
//!   resource tool-output {
//!     set: func(key: string, value: string);
//!   }
//!   execute: func(input: tool-input) -> result<tool-output, error>;
//! }
//! ```

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Typed input for a WASM tool component.
///
/// Wraps a JSON object with typed access methods,
/// replacing the raw `(ptr, len)` protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInput {
    /// The input parameters as a JSON object
    pub params: Value,
}

impl ToolInput {
    /// Create a ToolInput from a JSON value.
    pub fn new(params: Value) -> Self {
        Self { params }
    }

    /// Create an empty ToolInput.
    pub fn empty() -> Self {
        Self {
            params: Value::Object(serde_json::Map::new()),
        }
    }

    /// Create a ToolInput from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        Ok(Self {
            params: serde_json::from_str(json)?,
        })
    }

    /// Get a string parameter by key.
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.params.get(key).and_then(|v| v.as_str())
    }

    /// Get a numeric parameter by key.
    pub fn get_number(&self, key: &str) -> Option<f64> {
        self.params.get(key).and_then(|v| v.as_f64())
    }

    /// Get a boolean parameter by key.
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.params.get(key).and_then(|v| v.as_bool())
    }

    /// Get any parameter by key.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.params.get(key)
    }

    /// Serialize to JSON bytes for WASM memory transfer.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.params).unwrap_or_default()
    }
}

/// Typed output from a WASM tool component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOutput {
    /// The output as a JSON object
    pub data: Value,
    /// Whether the execution succeeded
    pub ok: bool,
    /// Optional error message
    pub error: Option<String>,
}

impl ToolOutput {
    /// Create a successful ToolOutput from a JSON value.
    pub fn ok(data: Value) -> Self {
        Self {
            data,
            ok: true,
            error: None,
        }
    }

    /// Create an error ToolOutput.
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            data: Value::Null,
            ok: false,
            error: Some(msg.into()),
        }
    }

    /// Create a ToolOutput from raw JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let data: Value = serde_json::from_slice(bytes)?;
        Ok(Self {
            data,
            ok: true,
            error: None,
        })
    }

    /// Serialize to JSON bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut obj = serde_json::Map::new();
        obj.insert("ok".to_string(), Value::Bool(self.ok));
        if !self.data.is_null() {
            obj.insert("data".to_string(), self.data.clone());
        }
        if let Some(ref err) = self.error {
            obj.insert("error".to_string(), Value::String(err.clone()));
        }
        serde_json::to_vec(&obj).unwrap_or_default()
    }
}

/// Component interface version for forward compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentInterfaceVersion {
    /// Phase 1 raw pointer protocol: execute(ptr, len) -> ptr
    V1RawPointer,
    /// Phase 3 typed component: execute(ToolInput) -> ToolOutput
    V3TypedComponent,
}

impl Default for ComponentInterfaceVersion {
    fn default() -> Self {
        Self::V1RawPointer
    }
}

/// Description of a WASM tool's component interface.
#[derive(Debug, Clone)]
pub struct ComponentInterface {
    /// Interface version
    pub version: ComponentInterfaceVersion,
    /// Tool name
    pub name: String,
    /// Whether the component exports a `schema` function
    pub has_schema: bool,
    /// Whether the component exports shared memory
    pub has_memory: bool,
}

impl ComponentInterface {
    /// Detect the interface version from a compiled WASM module.
    pub fn detect(name: &str, module: &wasmtime::Module, store: &mut wasmtime::Store<()>) -> Self {
        // Try to instantiate to check exports
        let instance = Instance::new(&mut *store, module, &[]);

        let mut has_schema = false;
        let mut has_memory = false;
        let mut version = ComponentInterfaceVersion::V1RawPointer;

        if let Ok(instance) = instance {
            // Check for typed component exports
            if instance.get_func(&mut *store, "execute").is_some() {
                // Has execute → at least V1
                version = ComponentInterfaceVersion::V1RawPointer;
            }
            if instance.get_func(&mut *store, "schema").is_some()
                || instance.get_func(&mut *store, "schema-ptr").is_some()
            {
                has_schema = true;
            }
            if instance.get_memory(&mut *store, "memory").is_some() {
                has_memory = true;
            }
        }

        Self {
            version,
            name: name.to_string(),
            has_schema,
            has_memory,
        }
    }
}

use wasmtime::Instance;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_input_new() {
        let input = ToolInput::new(serde_json::json!({"key": "value"}));
        assert_eq!(input.get_str("key"), Some("value"));
        assert!(input.get_str("missing").is_none());
    }

    #[test]
    fn test_tool_input_empty() {
        let input = ToolInput::empty();
        assert!(input.params.is_object());
    }

    #[test]
    fn test_tool_input_from_json() {
        let input = ToolInput::from_json(r#"{"name": "test"}"#).unwrap();
        assert_eq!(input.get_str("name"), Some("test"));
    }

    #[test]
    fn test_tool_input_get_number() {
        let input = ToolInput::new(serde_json::json!({"count": 42}));
        assert_eq!(input.get_number("count"), Some(42.0));
    }

    #[test]
    fn test_tool_input_get_bool() {
        let input = ToolInput::new(serde_json::json!({"active": true}));
        assert_eq!(input.get_bool("active"), Some(true));
    }

    #[test]
    fn test_tool_input_to_bytes() {
        let input = ToolInput::new(serde_json::json!({"x": 1}));
        let bytes = input.to_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_tool_output_ok() {
        let output = ToolOutput::ok(serde_json::json!({"result": 42}));
        assert!(output.ok);
        assert!(output.error.is_none());
    }

    #[test]
    fn test_tool_output_err() {
        let output = ToolOutput::err("something went wrong");
        assert!(!output.ok);
        assert_eq!(output.error, Some("something went wrong".to_string()));
    }

    #[test]
    fn test_tool_output_from_bytes() {
        let output = ToolOutput::ok(serde_json::json!({"status": "done"}));
        let bytes = output.to_bytes();
        let restored = ToolOutput::from_bytes(&bytes).unwrap();
        assert!(restored.ok);
    }

    #[test]
    fn test_component_interface_version_default() {
        assert_eq!(
            ComponentInterfaceVersion::default(),
            ComponentInterfaceVersion::V1RawPointer
        );
    }
}
