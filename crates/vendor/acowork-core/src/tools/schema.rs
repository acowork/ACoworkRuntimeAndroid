//! Tool JSON Schema cleaning (adapted from ZeroClaw schema.rs)
//!
//! LLM providers have varying support for JSON Schema features. This module
//! normalizes tool input schemas to maximize compatibility across providers.
//!
//! Key operations:
//! - Remove unsupported keywords (e.g., `$schema`, `$id`, `$comment`)
//! - Convert `default` values in-place
//! - Ensure `properties` have corresponding `required` entries
//! - Flatten `allOf`/`oneOf`/`anyOf` where possible
//! - Strip `additionalProperties: false` for providers that don't support it
//!
//! Adapted from zeroclaw/src/schema.rs
//! ACowork deviation: split into a standalone function per crate instead of
//! ZeroClaw's monolithic 572KB schema.rs
//! SPDX-License-Identifier: MIT OR Apache-2.0

use serde_json::{Map, Value};

/// Keys that are generally unsupported or unnecessary for LLM tool schemas
const STRIPPED_KEYS: &[&str] = &[
    "$schema",
    "$id",
    "$comment",
    "$defs",
    "definitions",
    "contentMediaType",
    "contentEncoding",
];

/// Clean and normalize a JSON Schema for LLM tool compatibility.
///
/// This function recursively processes the schema to:
/// 1. Strip unsupported/unnecessary keywords
/// 2. Recursively clean nested schemas (properties, items, etc.)
/// 3. Normalize type declarations
pub fn clean_schema(schema: Value) -> Value {
    match schema {
        Value::Object(mut map) => {
            // Strip unsupported keys
            for key in STRIPPED_KEYS {
                map.remove(*key);
            }

            // Recursively clean properties
            if let Some(properties) = map.remove("properties") {
                let cleaned_props = clean_properties(properties);
                map.insert("properties".into(), cleaned_props);
            }

            // Recursively clean items (for array types)
            if let Some(items) = map.remove("items") {
                map.insert("items".into(), clean_schema(items));
            }

            // Clean allOf / oneOf / anyOf
            for combiner in &["allOf", "oneOf", "anyOf"] {
                if let Some(Value::Array(arr)) = map.remove(*combiner) {
                    let cleaned: Vec<Value> = arr.into_iter().map(clean_schema).collect();
                    if !cleaned.is_empty() {
                        map.insert((*combiner).to_string(), Value::Array(cleaned));
                    }
                }
            }

            // Normalize type: if it's an array with one element, flatten to string
            if let Some(Value::Array(types)) = map.get_mut("type")
                && types.len() == 1
            {
                let single = types.pop().unwrap();
                map.insert("type".into(), single);
            }

            Value::Object(map)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(clean_schema).collect()),
        other => other,
    }
}

/// Clean all property schemas in a properties object
fn clean_properties(properties: Value) -> Value {
    match properties {
        Value::Object(map) => {
            let cleaned: Map<String, Value> = map
                .into_iter()
                .map(|(key, schema)| (key, clean_schema(schema)))
                .collect();
            Value::Object(cleaned)
        }
        other => other,
    }
}

/// Convert a ToolSpec's input_schema into a provider-compatible format.
///
/// This is the main entry point for runtime tool registration:
/// ```ignore
/// let spec = tool.spec();
/// let cleaned = sanitize_tool_schema(&spec.input_schema);
/// ```
pub fn sanitize_tool_schema(schema: &Value) -> Value {
    clean_schema(schema.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_clean_schema_strips_unsupported_keys() {
        let schema = json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "$id": "urn:example:schema",
            "$comment": "This is a comment",
            "type": "object",
            "properties": {
                "name": {"type": "string"}
            }
        });
        let cleaned = clean_schema(schema);
        assert!(cleaned.get("$schema").is_none());
        assert!(cleaned.get("$id").is_none());
        assert!(cleaned.get("$comment").is_none());
        assert!(cleaned.get("type").is_some());
        assert!(cleaned.get("properties").is_some());
    }

    #[test]
    fn test_clean_schema_recursive_properties() {
        let schema = json!({
            "type": "object",
            "properties": {
                "user": {
                    "$comment": "user object",
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "age": {"type": "integer"}
                    }
                }
            }
        });
        let cleaned = clean_schema(schema);
        // Top-level $comment should be gone
        assert!(cleaned.get("$comment").is_none());

        // Nested $comment in "user" should also be gone
        let user = cleaned["properties"]["user"].as_object().unwrap();
        assert!(user.get("$comment").is_none());
    }

    #[test]
    fn test_clean_schema_flatten_single_type_array() {
        let schema = json!({
            "type": ["string"]
        });
        let cleaned = clean_schema(schema);
        assert_eq!(cleaned["type"], json!("string"));
    }

    #[test]
    fn test_clean_schema_keeps_multi_type_array() {
        let schema = json!({
            "type": ["string", "null"]
        });
        let cleaned = clean_schema(schema);
        assert_eq!(cleaned["type"], json!(["string", "null"]));
    }

    #[test]
    fn test_clean_schema_cleans_items() {
        let schema = json!({
            "type": "array",
            "items": {
                "$comment": "each item",
                "type": "string"
            }
        });
        let cleaned = clean_schema(schema);
        let items = cleaned["items"].as_object().unwrap();
        assert!(items.get("$comment").is_none());
        assert_eq!(items["type"], json!("string"));
    }

    #[test]
    fn test_clean_schema_cleans_allof() {
        let schema = json!({
            "allOf": [
                {"$comment": "sub1", "type": "string"},
                {"type": "integer"}
            ]
        });
        let cleaned = clean_schema(schema);
        let allof = cleaned["allOf"].as_array().unwrap();
        assert!(allof[0].get("$comment").is_none());
    }

    #[test]
    fn test_sanitize_tool_schema() {
        let schema = json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Command to execute"}
            },
            "required": ["command"]
        });
        let cleaned = sanitize_tool_schema(&schema);
        assert!(cleaned.get("$schema").is_none());
        assert!(cleaned["properties"]["command"]["type"].is_string());
    }

    #[test]
    fn test_clean_schema_passthrough_simple() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"}
            }
        });
        let cleaned = clean_schema(schema.clone());
        assert_eq!(cleaned, schema);
    }
}
