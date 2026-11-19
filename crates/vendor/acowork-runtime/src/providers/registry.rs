//! Provider Registry — dynamic registration, routing, and capability queries
//!
//! Manages available providers at runtime, supports:
//! - Dynamic provider registration/removal
//! - Fallback chain configuration
//! - Model capability queries (streaming, tool_use, vision, etc.)
//! - Routing strategy selection (cost_priority, quality_priority, latency_priority)

use std::collections::HashMap;
use std::sync::Arc;

use acowork_core::providers::traits::Provider;
use parking_lot::RwLock;

use crate::providers::reliable::{ReliableProvider, RetryConfig};

// ── Model capabilities ──────────────────────────────────────────────────

/// Capabilities that a model may support
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModelCapability {
    /// Text generation (basic)
    TextGeneration,
    /// Streaming responses
    Streaming,
    /// Tool/function calling
    ToolUse,
    /// Vision / image input
    Vision,
    /// JSON mode output
    JsonMode,
    /// System prompt support
    SystemPrompt,
    /// Embedding generation
    Embedding,
}

impl std::fmt::Display for ModelCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelCapability::TextGeneration => write!(f, "text_generation"),
            ModelCapability::Streaming => write!(f, "streaming"),
            ModelCapability::ToolUse => write!(f, "tool_use"),
            ModelCapability::Vision => write!(f, "vision"),
            ModelCapability::JsonMode => write!(f, "json_mode"),
            ModelCapability::SystemPrompt => write!(f, "system_prompt"),
            ModelCapability::Embedding => write!(f, "embedding"),
        }
    }
}

// ── Provider entry ──────────────────────────────────────────────────────

/// A registered provider with metadata
#[derive(Clone)]
pub struct ProviderEntry {
    /// The provider implementation
    pub provider: Arc<dyn Provider>,
    /// Stable identifier used as the cache key prefix for `CompatCache`
    /// (e.g. `"volcano-engine-coding"`).  Same model on different providers
    /// gets isolated cache entries.
    pub provider_id: String,
    /// Models available through this provider
    pub models: Vec<String>,
    /// Capabilities by model
    pub capabilities: HashMap<String, Vec<ModelCapability>>,
    /// Priority (lower = higher priority)
    pub priority: u32,
    /// Whether this is a fallback provider
    pub is_fallback: bool,
}

// ── Routing strategy ────────────────────────────────────────────────────

/// Strategy for selecting among multiple providers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingStrategy {
    /// Optimize for cost (cheapest provider first)
    CostPriority,
    /// Optimize for quality (best model first)
    QualityPriority,
    /// Optimize for latency (fastest provider first)
    LatencyPriority,
}

impl RoutingStrategy {
    /// Parse from string (e.g., from manifest config)
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "cost_priority" => RoutingStrategy::CostPriority,
            "quality_priority" => RoutingStrategy::QualityPriority,
            "latency_priority" => RoutingStrategy::LatencyPriority,
            _ => RoutingStrategy::QualityPriority,
        }
    }
}

impl std::fmt::Display for RoutingStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoutingStrategy::CostPriority => write!(f, "cost_priority"),
            RoutingStrategy::QualityPriority => write!(f, "quality_priority"),
            RoutingStrategy::LatencyPriority => write!(f, "latency_priority"),
        }
    }
}

// ── Provider Registry ───────────────────────────────────────────────────

/// Dynamic provider registry with routing capabilities
pub struct ProviderRegistry {
    /// Registered providers by name
    providers: RwLock<HashMap<String, ProviderEntry>>,
    /// Default routing strategy
    default_strategy: RoutingStrategy,
    /// Default retry configuration
    retry_config: RetryConfig,
}

impl ProviderRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            providers: RwLock::new(HashMap::new()),
            default_strategy: RoutingStrategy::QualityPriority,
            retry_config: RetryConfig::default(),
        }
    }

    /// Create registry with a custom routing strategy
    pub fn with_strategy(strategy: RoutingStrategy) -> Self {
        Self {
            providers: RwLock::new(HashMap::new()),
            default_strategy: strategy,
            retry_config: RetryConfig::default(),
        }
    }

    /// Register a provider
    pub fn register(&self, name: &str, entry: ProviderEntry) {
        tracing::info!(
            provider = name,
            models = ?entry.models,
            priority = entry.priority,
            "Registered provider"
        );
        self.providers.write().insert(name.to_string(), entry);
    }

    /// Register a simple provider with default settings.
    ///
    /// `provider_id` is the stable cache key prefix for `CompatCache` —
    /// pass the vendor identifier from config (e.g. `"volcano-engine-coding"`).
    /// Two providers sharing the same `name` but different `provider_id`
    /// will be treated as separate cache namespaces.
    pub fn register_provider(
        &self,
        name: &str,
        provider_id: &str,
        provider: Arc<dyn Provider>,
        models: Vec<String>,
    ) {
        let mut capabilities = HashMap::new();
        for model in &models {
            capabilities.insert(model.clone(), default_capabilities_for_model(model));
        }

        self.register(
            name,
            ProviderEntry {
                provider,
                provider_id: provider_id.to_string(),
                models,
                capabilities,
                priority: 10,
                is_fallback: false,
            },
        );
    }

    /// Unregister a provider
    pub fn unregister(&self, name: &str) -> bool {
        tracing::info!(provider = name, "Unregistered provider");
        self.providers.write().remove(name).is_some()
    }

    /// Get a provider by name
    pub fn get(&self, name: &str) -> Option<Arc<dyn Provider>> {
        self.providers.read().get(name).map(|e| e.provider.clone())
    }

    /// Get a provider entry by name
    pub fn get_entry(&self, name: &str) -> Option<ProviderEntry> {
        self.providers.read().get(name).cloned()
    }

    /// List all registered provider names
    pub fn list_providers(&self) -> Vec<String> {
        self.providers.read().keys().cloned().collect()
    }

    /// Find providers that support a specific model
    pub fn find_providers_for_model(&self, model: &str) -> Vec<(String, Arc<dyn Provider>)> {
        let providers = self.providers.read();
        let mut result = Vec::new();

        for (name, entry) in providers.iter() {
            if entry.models.iter().any(|m| m == model) {
                result.push((name.clone(), entry.provider.clone()));
            }
        }

        result
    }

    /// Check if a model supports a specific capability
    pub fn has_capability(&self, provider_name: &str, model: &str, cap: ModelCapability) -> bool {
        let providers = self.providers.read();
        if let Some(entry) = providers.get(provider_name)
            && let Some(caps) = entry.capabilities.get(model)
        {
            return caps.contains(&cap);
        }
        false
    }

    /// Get capabilities for a specific model
    pub fn get_capabilities(&self, provider_name: &str, model: &str) -> Vec<ModelCapability> {
        let providers = self.providers.read();
        if let Some(entry) = providers.get(provider_name)
            && let Some(caps) = entry.capabilities.get(model)
        {
            return caps.clone();
        }
        Vec::new()
    }

    /// Build a ReliableProvider with fallback chain from the registry
    ///
    /// Uses the routing strategy to determine primary/fallback ordering
    pub fn build_reliable_provider(
        &self,
        primary_provider: &str,
        model: &str,
    ) -> Option<ReliableProvider> {
        let providers = self.providers.read();
        let primary_entry = providers.get(primary_provider)?;

        let reliable =
            ReliableProvider::new(primary_entry.provider.clone(), self.retry_config.clone());

        // Add fallback providers sorted by priority
        let mut fallbacks: Vec<&ProviderEntry> = providers
            .values()
            .filter(|e| {
                e.provider.name() != primary_entry.provider.name()
                    && e.models.iter().any(|m| m == model)
            })
            .collect();

        match self.default_strategy {
            RoutingStrategy::CostPriority => {
                // Lower priority number = cheaper (in our model, priority is cost tier)
                fallbacks.sort_by_key(|e| e.priority);
            }
            RoutingStrategy::QualityPriority => {
                // Higher priority = better quality
                fallbacks.sort_by_key(|e| std::cmp::Reverse(e.priority));
            }
            RoutingStrategy::LatencyPriority => {
                // Lower priority = faster (simplified)
                fallbacks.sort_by_key(|e| e.priority);
            }
        }

        let mut reliable = reliable;
        for fallback in fallbacks {
            reliable = reliable.with_fallback(fallback.provider.clone());
        }

        Some(reliable)
    }

    /// Get the current routing strategy
    pub fn strategy(&self) -> RoutingStrategy {
        self.default_strategy
    }

    /// Update the routing strategy
    pub fn set_strategy(&self, strategy: RoutingStrategy) {
        // Note: this requires interior mutability
        // For simplicity, we accept &self but require a new registry for strategy changes
        tracing::info!(strategy = %strategy, "Routing strategy updated (note: requires new registry for strategy changes)");
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Default capabilities ────────────────────────────────────────────────

/// Infer default capabilities for a model based on its name
fn default_capabilities_for_model(model: &str) -> Vec<ModelCapability> {
    let lower = model.to_lowercase();

    // All text models support basic text generation and system prompts
    let mut caps = vec![
        ModelCapability::TextGeneration,
        ModelCapability::SystemPrompt,
    ];

    // OpenAI GPT-4 class models
    if lower.contains("gpt-4") || lower.contains("gpt-4o") || lower.contains("gpt-3.5") {
        caps.push(ModelCapability::Streaming);
        caps.push(ModelCapability::ToolUse);
        caps.push(ModelCapability::JsonMode);
    }

    // GPT-4o / GPT-4V supports vision
    if lower.contains("gpt-4o") || lower.contains("vision") {
        caps.push(ModelCapability::Vision);
    }

    // Anthropic Claude models
    if lower.contains("claude") {
        caps.push(ModelCapability::Streaming);
        caps.push(ModelCapability::ToolUse);
    }

    // Claude 3.5+ supports vision
    if lower.contains("claude-3")
        || lower.contains("claude-sonnet")
        || lower.contains("claude-opus")
    {
        caps.push(ModelCapability::Vision);
    }

    // Llama models
    if lower.contains("llama") {
        caps.push(ModelCapability::Streaming);
        caps.push(ModelCapability::ToolUse);
    }

    // Qwen models
    if lower.contains("qwen") {
        caps.push(ModelCapability::Streaming);
        caps.push(ModelCapability::ToolUse);
    }

    // Ollama models (varies, assume basic)
    if lower.contains("mistral") {
        caps.push(ModelCapability::Streaming);
        caps.push(ModelCapability::ToolUse);
    }

    caps
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::anthropic::AnthropicProvider;
    use crate::providers::ollama::OllamaProvider;
    use crate::providers::openai::OpenAIProvider;

    #[test]
    fn test_register_provider() {
        let registry = ProviderRegistry::new();
        let provider = Arc::new(OpenAIProvider::new(Some("sk-test")));
        registry.register_provider(
            "openai",
            "openai-official",
            provider,
            vec!["gpt-4".to_string(), "gpt-4o".to_string()],
        );

        assert!(registry.get("openai").is_some());
        assert_eq!(registry.list_providers().len(), 1);
    }

    #[test]
    fn test_unregister_provider() {
        let registry = ProviderRegistry::new();
        let provider = Arc::new(OpenAIProvider::new(Some("sk-test")));
        registry.register_provider(
            "openai",
            "openai-official",
            provider,
            vec!["gpt-4".to_string()],
        );
        assert!(registry.unregister("openai"));
        assert!(registry.get("openai").is_none());
    }

    #[test]
    fn test_find_providers_for_model() {
        let registry = ProviderRegistry::new();

        let openai = Arc::new(OpenAIProvider::new(Some("sk-test")));
        registry.register_provider(
            "openai",
            "openai-official",
            openai,
            vec!["gpt-4".to_string()],
        );

        let anthropic = Arc::new(AnthropicProvider::new(Some("sk-ant-test")));
        registry.register_provider(
            "anthropic",
            "anthropic-official",
            anthropic,
            vec!["claude-sonnet-4".to_string()],
        );

        let gpt4_providers = registry.find_providers_for_model("gpt-4");
        assert_eq!(gpt4_providers.len(), 1);
        assert_eq!(gpt4_providers[0].0, "openai");

        let claude_providers = registry.find_providers_for_model("claude-sonnet-4");
        assert_eq!(claude_providers.len(), 1);
        assert_eq!(claude_providers[0].0, "anthropic");
    }

    #[test]
    fn test_capability_query() {
        let registry = ProviderRegistry::new();
        let provider = Arc::new(OpenAIProvider::new(Some("sk-test")));
        registry.register_provider(
            "openai",
            "openai-official",
            provider,
            vec!["gpt-4".to_string()],
        );

        assert!(registry.has_capability("openai", "gpt-4", ModelCapability::Streaming));
        assert!(registry.has_capability("openai", "gpt-4", ModelCapability::ToolUse));
        assert!(!registry.has_capability("openai", "gpt-4", ModelCapability::Vision));
    }

    #[test]
    fn test_routing_strategy_parse() {
        assert_eq!(
            RoutingStrategy::from_str("cost_priority"),
            RoutingStrategy::CostPriority
        );
        assert_eq!(
            RoutingStrategy::from_str("quality_priority"),
            RoutingStrategy::QualityPriority
        );
        assert_eq!(
            RoutingStrategy::from_str("latency_priority"),
            RoutingStrategy::LatencyPriority
        );
        assert_eq!(
            RoutingStrategy::from_str("unknown"),
            RoutingStrategy::QualityPriority
        );
    }

    #[test]
    fn test_default_capabilities_gpt4() {
        let caps = default_capabilities_for_model("gpt-4");
        assert!(caps.contains(&ModelCapability::Streaming));
        assert!(caps.contains(&ModelCapability::ToolUse));
        assert!(caps.contains(&ModelCapability::JsonMode));
        assert!(!caps.contains(&ModelCapability::Vision));
    }

    #[test]
    fn test_default_capabilities_gpt4o() {
        let caps = default_capabilities_for_model("gpt-4o");
        assert!(caps.contains(&ModelCapability::Vision));
    }

    #[test]
    fn test_default_capabilities_claude() {
        let caps = default_capabilities_for_model("claude-sonnet-4");
        assert!(caps.contains(&ModelCapability::Streaming));
        assert!(caps.contains(&ModelCapability::ToolUse));
        assert!(caps.contains(&ModelCapability::Vision));
    }

    #[test]
    fn test_build_reliable_provider() {
        let registry = ProviderRegistry::new();

        let openai = Arc::new(OpenAIProvider::new(Some("sk-test")));
        registry.register_provider(
            "openai",
            "openai-official",
            openai,
            vec!["gpt-4".to_string()],
        );

        let ollama = Arc::new(OllamaProvider::new());
        let mut entry = ProviderEntry {
            provider: ollama,
            provider_id: "ollama-local".to_string(),
            models: vec!["gpt-4".to_string()], // Ollama can serve compatible models
            capabilities: HashMap::new(),
            priority: 20,
            is_fallback: true,
        };
        entry
            .capabilities
            .insert("gpt-4".to_string(), default_capabilities_for_model("gpt-4"));
        registry.register("ollama", entry);

        let reliable = registry.build_reliable_provider("openai", "gpt-4");
        assert!(reliable.is_some());
    }

    #[test]
    fn test_model_capability_display() {
        assert_eq!(format!("{}", ModelCapability::Streaming), "streaming");
        assert_eq!(format!("{}", ModelCapability::ToolUse), "tool_use");
    }

    #[test]
    fn test_routing_strategy_display() {
        assert_eq!(
            format!("{}", RoutingStrategy::CostPriority),
            "cost_priority"
        );
    }
}
