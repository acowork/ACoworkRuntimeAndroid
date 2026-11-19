// Adapted from zeroclaw/src/tools/mcp_protocol.rs
// ACowork deviation: uses acowork_core::error::Result instead of anyhow
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};

pub const JSONRPC_VERSION: &str = "2.0";
pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

// Standard JSON-RPC 2.0 error codes
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

/// Outbound JSON-RPC request (client -> MCP server).
/// Used for both method calls (with id) and notifications (id = None).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

impl JsonRpcRequest {
    /// Create a method call request with a numeric id.
    pub fn new(id: u64, method: impl Into<String>, params: serde_json::Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: Some(serde_json::Value::Number(id.into())),
            method: method.into(),
            params: Some(params),
        }
    }

    /// Create a notification -- no id, no response expected from server.
    pub fn notification(method: impl Into<String>, params: serde_json::Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: None,
            method: method.into(),
            params: Some(params),
        }
    }
}

/// Inbound JSON-RPC response (MCP server -> client).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC error object embedded in a response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// A tool advertised by an MCP server (from `tools/list` response).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolDef {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

/// Expected shape of the `tools/list` result payload.
#[derive(Debug, Deserialize)]
pub struct McpToolsListResult {
    pub tools: Vec<McpToolDef>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_serializes_with_id() {
        let req = JsonRpcRequest::new(1, "tools/list", serde_json::json!({}));
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"id\":1"));
        assert!(s.contains("\"method\":\"tools/list\""));
        assert!(s.contains("\"jsonrpc\":\"2.0\""));
    }

    #[test]
    fn notification_omits_id() {
        let notif =
            JsonRpcRequest::notification("notifications/initialized", serde_json::json!({}));
        let s = serde_json::to_string(&notif).unwrap();
        assert!(!s.contains("\"id\""));
    }

    #[test]
    fn response_deserializes() {
        let json = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
        let resp: JsonRpcResponse = serde_json::from_str(json).unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn tool_def_deserializes_input_schema() {
        let json = r#"{"name":"read_file","description":"Read a file","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}"#;
        let def: McpToolDef = serde_json::from_str(json).unwrap();
        assert_eq!(def.name, "read_file");
        assert!(def.input_schema.is_object());
    }

    #[test]
    fn error_response_deserializes_with_code_and_message() {
        let json =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}"#;
        let resp: JsonRpcResponse = serde_json::from_str(json).unwrap();
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, METHOD_NOT_FOUND);
        assert_eq!(err.message, "Method not found");
        assert!(err.data.is_none());
    }

    #[test]
    fn tools_list_result_deserializes_multiple_tools() {
        let json = r#"{"tools":[{"name":"a","inputSchema":{}},{"name":"b","description":"B tool","inputSchema":{"type":"object"}}]}"#;
        let result: McpToolsListResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.tools.len(), 2);
        assert_eq!(result.tools[0].name, "a");
        assert_eq!(result.tools[1].name, "b");
        assert!(result.tools[1].description.is_some());
    }
}
