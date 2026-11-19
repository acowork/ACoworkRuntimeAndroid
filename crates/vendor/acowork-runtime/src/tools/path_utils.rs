//! Shared path utilities for built-in tools.
//!
//! Centralizes cross-platform path handling that is needed by multiple tools
//! (content_search, glob_search, PathGuardedTool, etc.) to avoid duplicated
//! logic and inconsistent Windows behavior.

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use std::borrow::Cow;
use std::path::Path;

/// Expand brace patterns: `*.{ts,tsx}` → `["*.ts", "*.tsx"]`.
///
/// Single-level only — nested braces like `{a,{b,c}}` are not supported
/// (and should not be needed for file-glob includes).
pub fn expand_braces(pattern: &str) -> Vec<String> {
    let open = match pattern.find('{') {
        Some(i) => i,
        None => return vec![pattern.to_string()],
    };
    let close = match pattern[open..].find('}') {
        Some(i) => open + i,
        None => return vec![pattern.to_string()],
    };

    let prefix = &pattern[..open];
    let suffix = &pattern[close + 1..];
    let alternatives: Vec<&str> = pattern[open + 1..close].split(',').collect();

    alternatives
        .iter()
        .map(|alt| format!("{prefix}{alt}{suffix}"))
        .collect()
}

/// Normalize path separators to forward slashes for cross-platform comparison.
pub fn normalize_separators(path: &str) -> String {
    path.replace('\\', "/")
}

/// Compute a relative path from `path` to `base`, handling Windows
/// case-insensitivity and mixed separators.
///
/// Falls back to the file name only if the prefix cannot be stripped,
/// which ensures the include-glob filter still has a chance to match.
pub fn relative_path<'a>(path: &'a Path, base: &Path) -> Cow<'a, str> {
    // Fast path: exact prefix match
    if let Ok(rel) = path.strip_prefix(base) {
        return rel.to_string_lossy();
    }

    // Windows: canonicalize both paths for case-insensitive + separator
    // normalization, then strip prefix.
    #[cfg(target_os = "windows")]
    {
        if let (Ok(canonical_path), Ok(canonical_base)) =
            (std::fs::canonicalize(path), std::fs::canonicalize(base))
            && let Ok(rel) = canonical_path.strip_prefix(&canonical_base)
        {
            return rel.to_string_lossy().into_owned().into();
        }
    }

    // Fallback: use file name only so glob filter can still match
    path.file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| path.to_string_lossy())
}

/// Build a `GlobSet` from a user-provided glob pattern string.
///
/// Handles:
/// - Brace expansion (`*.{ts,tsx}` → two separate globs)
///
/// When `literal_separator` is true, `*` will NOT match path separators,
/// so `*.rs` matches `main.rs` but not `src/main.rs`. This is appropriate
/// for include filters (content_search). For recursive glob patterns
/// (glob_search with `**/*.rs`), pass `false` so `**` can cross `/`.
pub fn build_glob_set(pattern: &str, literal_separator: bool) -> Result<GlobSet, String> {
    let mut builder = GlobSetBuilder::new();
    for expanded in expand_braces(pattern) {
        let glob = GlobBuilder::new(&expanded)
            .literal_separator(literal_separator)
            .build()
            .map_err(|e| format!("Invalid glob '{expanded}': {e}"))?;
        builder.add(glob);
    }
    builder
        .build()
        .map_err(|e| format!("Failed to build glob set: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_braces_no_braces() {
        assert_eq!(expand_braces("*.rs"), vec!["*.rs"]);
    }

    #[test]
    fn test_expand_braces_single_brace() {
        let result = expand_braces("*.{ts,tsx}");
        assert_eq!(result, vec!["*.ts", "*.tsx"]);
    }

    #[test]
    fn test_expand_braces_three_alternatives() {
        let result = expand_braces("*.{js,ts,tsx}");
        assert_eq!(result, vec!["*.js", "*.ts", "*.tsx"]);
    }

    #[test]
    fn test_expand_braces_unmatched_open() {
        assert_eq!(expand_braces("*.{ts"), vec!["*.{ts"]);
    }

    #[test]
    fn test_expand_braces_unmatched_close() {
        assert_eq!(expand_braces("*.ts}"), vec!["*.ts}"]);
    }

    #[test]
    fn test_expand_braces_with_prefix_and_suffix() {
        let result = expand_braces("src/**/*.{rs,toml}");
        assert_eq!(result, vec!["src/**/*.rs", "src/**/*.toml"]);
    }

    #[test]
    fn test_normalize_separators_backslash() {
        assert_eq!(normalize_separators("src\\foo\\bar.rs"), "src/foo/bar.rs");
    }

    #[test]
    fn test_normalize_separators_forward() {
        assert_eq!(normalize_separators("src/foo/bar.rs"), "src/foo/bar.rs");
    }

    #[test]
    fn test_build_glob_set_simple() {
        let gs = build_glob_set("*.rs", true).unwrap();
        assert!(gs.is_match("main.rs"));
        assert!(!gs.is_match("main.ts"));
    }

    #[test]
    fn test_build_glob_set_braces() {
        let gs = build_glob_set("*.{ts,tsx}", true).unwrap();
        assert!(gs.is_match("app.ts"));
        assert!(gs.is_match("app.tsx"));
        assert!(!gs.is_match("app.rs"));
    }

    #[test]
    fn test_build_glob_set_literal_separator() {
        // With literal_separator=true, `*.rs` should NOT match `src/main.rs`
        // because `*` cannot cross `/`
        let gs = build_glob_set("*.rs", true).unwrap();
        assert!(gs.is_match("main.rs"));
        assert!(!gs.is_match("src/main.rs"));
    }

    #[test]
    fn test_build_glob_set_recursive_pattern() {
        // With literal_separator=false, `**/*.rs` should match nested paths
        let gs = build_glob_set("**/*.rs", false).unwrap();
        assert!(gs.is_match("main.rs"));
        assert!(gs.is_match("src/main.rs"));
        assert!(gs.is_match("src/deep/main.rs"));
    }

    #[test]
    fn test_build_glob_set_invalid() {
        assert!(build_glob_set("[invalid", true).is_err());
    }
}
