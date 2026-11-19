//! Provider ID alias resolution
//!
//! Maps legacy/alternative provider IDs to their canonical models.dev ID.
//! Used by VaultFacade to transparently look up API keys stored under old names
//! after a provider ID migration (e.g. "glm" → "zhipuai").

/// Alias entry: (canonical_id, &[alias_ids])
///
/// The canonical ID is the models.dev provider identifier.
/// Aliases are legacy or alternative names that may still appear in Vault.
const PROVIDER_ALIASES: &[(&str, &[&str])] = &[
    ("zhipuai", &["glm", "zhipu"]),
    ("moonshotai", &["moonshot", "kimi"]),
    ("alibaba", &["qwen", "dashscope"]),
    ("google", &["gemini"]),
    ("xai", &["grok"]),
    ("azure", &["azure_openai"]),
    ("lmstudio", &["lm-studio"]),
];

/// Resolve a provider ID to its canonical form.
///
/// If `id` is already canonical, returns it unchanged.
/// If `id` is a known alias, returns the canonical ID.
/// If `id` is unknown, returns it unchanged (best-effort passthrough).
pub fn canonical_provider_id(id: &str) -> &str {
    // Check if id is a canonical ID
    for (canonical, _) in PROVIDER_ALIASES {
        if *canonical == id {
            return canonical;
        }
    }
    // Check if id is an alias
    for (canonical, aliases) in PROVIDER_ALIASES {
        if aliases.contains(&id) {
            return canonical;
        }
    }
    // Unknown ID — return as-is
    id
}

/// Return all Vault key names that may hold the API key for the given provider.
///
/// The first element is always the canonical ID (preferred).
/// Subsequent elements are aliases in order of priority.
/// Useful for fallback lookups: try each key until one is found.
pub fn vault_key_candidates(provider_id: &str) -> Vec<&str> {
    // First, resolve to canonical
    let canonical = canonical_provider_id(provider_id);

    let mut candidates = vec![canonical];

    for (c, aliases) in PROVIDER_ALIASES {
        if *c == canonical {
            for alias in *aliases {
                candidates.push(alias);
            }
            break;
        }
    }

    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_id_passthrough() {
        assert_eq!(canonical_provider_id("zhipuai"), "zhipuai");
        assert_eq!(canonical_provider_id("moonshotai"), "moonshotai");
        assert_eq!(canonical_provider_id("alibaba"), "alibaba");
        assert_eq!(canonical_provider_id("openai"), "openai");
    }

    #[test]
    fn test_alias_resolution() {
        assert_eq!(canonical_provider_id("glm"), "zhipuai");
        assert_eq!(canonical_provider_id("zhipu"), "zhipuai");
        assert_eq!(canonical_provider_id("moonshot"), "moonshotai");
        assert_eq!(canonical_provider_id("kimi"), "moonshotai");
        assert_eq!(canonical_provider_id("qwen"), "alibaba");
        assert_eq!(canonical_provider_id("dashscope"), "alibaba");
        assert_eq!(canonical_provider_id("gemini"), "google");
        assert_eq!(canonical_provider_id("grok"), "xai");
    }

    #[test]
    fn test_unknown_id_passthrough() {
        assert_eq!(
            canonical_provider_id("some-new-provider"),
            "some-new-provider"
        );
    }

    #[test]
    fn test_vault_key_candidates_canonical() {
        let candidates = vault_key_candidates("zhipuai");
        assert_eq!(candidates, vec!["zhipuai", "glm", "zhipu"]);
    }

    #[test]
    fn test_vault_key_candidates_from_alias() {
        let candidates = vault_key_candidates("glm");
        // "glm" resolves to canonical "zhipuai", then includes all aliases
        assert_eq!(candidates, vec!["zhipuai", "glm", "zhipu"]);
    }

    #[test]
    fn test_vault_key_candidates_no_aliases() {
        let candidates = vault_key_candidates("openai");
        assert_eq!(candidates, vec!["openai"]);
    }

    #[test]
    fn test_vault_key_candidates_moonshotai() {
        let candidates = vault_key_candidates("moonshotai");
        assert_eq!(candidates, vec!["moonshotai", "moonshot", "kimi"]);
    }

    #[test]
    fn test_vault_key_candidates_alibaba() {
        let candidates = vault_key_candidates("alibaba");
        assert_eq!(candidates, vec!["alibaba", "qwen", "dashscope"]);
    }
}
