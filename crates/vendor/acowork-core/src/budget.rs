//! Budget and usage report types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Budget configuration for an Agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Budget {
    /// Daily token limit
    #[serde(default)]
    pub daily_tokens: Option<u64>,
    /// Monthly token limit
    #[serde(default)]
    pub monthly_tokens: Option<u64>,
    /// Daily cost limit (USD)
    #[serde(default)]
    pub daily_cost_usd: Option<f64>,
    /// Monthly cost limit (USD)
    #[serde(default)]
    pub monthly_cost_usd: Option<f64>,
    /// Action when budget exceeded (deny/warn/fallback)
    #[serde(default = "default_exceeded_action")]
    pub exceeded_action: String,
}

fn default_exceeded_action() -> String {
    "deny".to_string()
}

/// Usage report from Agent Runtime to Gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageReport {
    /// Agent ID
    pub agent_id: String,
    /// Provider name (e.g., "openai", "ollama")
    pub provider: String,
    /// Number of tokens used
    pub tokens_used: u64,
    /// Estimated cost in USD
    pub cost_usd: f64,
    /// Timestamp of usage
    pub timestamp: DateTime<Utc>,
    /// Optional error information
    #[serde(default)]
    pub error: Option<String>,
}
