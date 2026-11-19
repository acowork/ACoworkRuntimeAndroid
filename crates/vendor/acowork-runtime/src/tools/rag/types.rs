//! RAG standard query protocol types.
//!
//! All types are defined in `acowork_core::rag` (migrated in ADR-051 C1).
//! This module re-exports them for backward compatibility with code that
//! imports from `crate::tools::rag::types`.
//!
//! Design ref: ADR-051 §5.1 - RAG protocol types migrated to acowork-core.

pub use acowork_core::rag::{
    AnnotatedRagResult, PROTOCOL_VERSION, RagQueryRequest, RagQueryResponse, RagResultItem,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rag_query_request_new() {
        let req = RagQueryRequest::new("product roadmap Q3".to_string(), 5);
        assert_eq!(req.protocol_version, "1.0");
        assert_eq!(req.query, "product roadmap Q3");
        assert_eq!(req.top_k, 5);
        assert!(req.collection.is_none());
        assert!(req.score_threshold.is_none());
    }

    #[test]
    fn test_rag_query_request_serialization() {
        let mut req = RagQueryRequest::new("test query".to_string(), 3);
        req.collection = Some("product_docs".to_string());
        req.score_threshold = Some(0.7);
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"protocol_version\":\"1.0\""));
        assert!(json.contains("\"query\":\"test query\""));
        assert!(json.contains("\"top_k\":3"));
        assert!(json.contains("\"collection\":\"product_docs\""));
        assert!(json.contains("\"score_threshold\":0.7"));
        // Optional fields with None should not appear
        assert!(!json.contains("\"filters\""));
        assert!(!json.contains("\"extensions\""));
    }

    #[test]
    fn test_rag_query_request_roundtrip() {
        let mut req = RagQueryRequest::new("test".to_string(), 10);
        req.collection = Some("docs".to_string());
        req.filters = Some(serde_json::json!({"category": "engineering"}));
        let json = serde_json::to_string(&req).unwrap();
        let parsed: RagQueryRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.protocol_version, "1.0");
        assert_eq!(parsed.query, "test");
        assert_eq!(parsed.top_k, 10);
        assert_eq!(parsed.collection.as_deref(), Some("docs"));
    }

    #[test]
    fn test_rag_query_response_deserialization() {
        let json = r#"{
            "protocol_version": "1.0",
            "results": [
                {
                    "content": "Q3 product roadmap includes AI assistant",
                    "source_url": "https://docs.corp.example.com/roadmap",
                    "chunk_id": "roadmap-3",
                    "score": 0.92
                }
            ]
        }"#;
        let resp: RagQueryResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.protocol_version, "1.0");
        assert_eq!(resp.results.len(), 1);
        assert_eq!(
            resp.results[0].content,
            "Q3 product roadmap includes AI assistant"
        );
        assert_eq!(resp.results[0].score, 0.92);
    }

    #[test]
    fn test_rag_query_response_roundtrip() {
        let resp = RagQueryResponse {
            protocol_version: PROTOCOL_VERSION.to_string(),
            results: vec![RagResultItem {
                content: "Test content".to_string(),
                source_url: Some("https://example.com".to_string()),
                chunk_id: Some("chunk-1".to_string()),
                score: 0.85,
            }],
            extensions: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: RagQueryResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.results.len(), 1);
        assert_eq!(parsed.results[0].content, "Test content");
    }

    #[test]
    fn test_annotated_rag_result() {
        let result = AnnotatedRagResult {
            item: RagResultItem {
                content: "test".to_string(),
                source_url: None,
                chunk_id: None,
                score: 0.9,
            },
            source_label: "[RAG:enterprise_knowledge]".to_string(),
            tool_name: "enterprise_knowledge".to_string(),
        };
        assert_eq!(result.source_label, "[RAG:enterprise_knowledge]");
        assert_eq!(result.item.score, 0.9);
    }
}
