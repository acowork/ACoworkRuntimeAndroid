//! Skill inspection HTTP routes — ADR-009 §V-A (Gateway Workspace Isolation).
//!
//! The Runtime owns the agent's `skills/` directory (`{package_dir}/skills/`).
//! The Gateway used to re-implement a "minimal SKILL.md parser" against that
//! directory; the two parsers drifted (Gateway lenient, Runtime strict) and the
//! user-visible fallout was a chat skill that showed up in the list but never
//! reached the system prompt. Under ADR-055 the Gateway may not even be on the
//! same machine as the package it was reading — hence these routes: the Gateway
//! reverse-proxies `GET /api/agents/{id}/skills*` here, so there is exactly one
//! parser ([`crate::skills::parser`]) and one authority (this Runtime).
//!
//! | Method | Path                                 | Handler               |
//! |--------|--------------------------------------|-----------------------|
//! | GET    | `/agents/{id}/skills`                | [`list_skills`]       |
//! | GET    | `/agents/{id}/skills/{name}`         | [`get_skill_detail`]  |
//! | GET    | `/agents/{id}/skills/{name}/history` | [`get_skill_history`] |
//!
//! `{name}` is the SKILL.md frontmatter `name`, resolved against the loaded
//! registry — never used to build a filesystem path, so there is no traversal
//! surface to guard.

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};

use crate::http::server::HttpState;
use crate::skills::parser::{SkillDefinition, SkillRegistry};

// ── Wire types ───────────────────────────────────────────────────────
// Field-for-field identical to the shapes the Gateway emitted before the
// reverse-proxy move, so the Desktop client types in
// `apps/acowork-desktop/src/lib/types.ts` need no change.

/// A single skill entry in the list response.
#[derive(Debug, Clone, Serialize)]
pub struct SkillListEntry {
    pub name: String,
    pub description: String,
    pub version: Option<String>,
    pub author: Option<String>,
    pub triggers: Vec<String>,
    pub tool_deps: Vec<String>,
}

/// Paginated list of skills.
#[derive(Debug, Serialize)]
pub struct SkillListResponse {
    pub total: u64,
    pub page: u32,
    pub size: u32,
    pub skills: Vec<SkillListEntry>,
}

/// Detailed skill information (adds the Markdown instructions body).
#[derive(Debug, Serialize)]
pub struct SkillDetailResponse {
    pub name: String,
    pub description: String,
    pub version: Option<String>,
    pub author: Option<String>,
    pub triggers: Vec<String>,
    pub tool_deps: Vec<String>,
    pub instructions: String,
}

/// Skill execution history — still a stub (no execution store yet).
#[derive(Debug, Serialize)]
pub struct SkillExecutionHistoryResponse {
    pub skill_name: String,
    pub total_executions: u64,
    pub page: u32,
    pub size: u32,
    pub executions: Vec<serde_json::Value>,
}

/// Query parameters shared by the list and history endpoints.
#[derive(Debug, Deserialize)]
pub struct SkillListQuery {
    pub page: Option<u32>,
    pub size: Option<u32>,
}

impl SkillListQuery {
    fn effective_page(&self) -> u32 {
        self.page.unwrap_or(1).max(1)
    }

    fn effective_size(&self) -> u32 {
        self.size.unwrap_or(20).clamp(1, 100)
    }
}

// ── Router ───────────────────────────────────────────────────────────

/// The 3 read-only skill routes (see module docs).
pub(crate) fn skills_routes() -> Router<HttpState> {
    Router::new()
        .route("/agents/{id}/skills", get(list_skills))
        .route("/agents/{id}/skills/{name}", get(get_skill_detail))
        .route("/agents/{id}/skills/{name}/history", get(get_skill_history))
}

// ── Handlers ─────────────────────────────────────────────────────────

/// `GET /agents/{id}/skills` — list the agent's skills (paginated).
async fn list_skills(
    State(state): State<HttpState>,
    Path(id): Path<String>,
    Query(query): Query<SkillListQuery>,
) -> Response {
    if !state.instance_matches(&id) {
        return instance_mismatch(&state, &id);
    }
    Json(list_from_registry(
        &load_registry(&state),
        query.effective_page(),
        query.effective_size(),
    ))
    .into_response()
}

/// `GET /agents/{id}/skills/{name}` — one skill's metadata + instructions.
async fn get_skill_detail(
    State(state): State<HttpState>,
    Path((id, name)): Path<(String, String)>,
) -> Response {
    if !state.instance_matches(&id) {
        return instance_mismatch(&state, &id);
    }
    match load_registry(&state).get(&name) {
        Some(skill) => Json(SkillDetailResponse {
            name: skill.name.clone(),
            description: skill.description.clone(),
            version: skill.version.clone(),
            author: skill.author.clone(),
            triggers: skill.triggers.clone(),
            tool_deps: skill.tool_deps.clone(),
            instructions: skill.instructions.clone(),
        })
        .into_response(),
        None => not_found(format!("Skill not found: {name}")),
    }
}

/// `GET /agents/{id}/skills/{name}/history` — execution history stub.
async fn get_skill_history(
    State(state): State<HttpState>,
    Path((id, name)): Path<(String, String)>,
    Query(query): Query<SkillListQuery>,
) -> Response {
    if !state.instance_matches(&id) {
        return instance_mismatch(&state, &id);
    }
    if load_registry(&state).get(&name).is_none() {
        return not_found(format!("Skill not found: {name}"));
    }
    // Execution tracking is not implemented yet (unchanged from the Gateway
    // stub) — always an empty page.
    Json(SkillExecutionHistoryResponse {
        skill_name: name,
        total_executions: 0,
        page: query.effective_page(),
        size: query.effective_size(),
        executions: Vec::new(),
    })
    .into_response()
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Load `{package_dir}/skills/` fresh on every request (rather than reusing the
/// boot-time `AgentCore::skill_registry`) so a newly imported or hand-edited
/// SKILL.md shows up without a Runtime restart. The directory is small and this
/// goes through the one parser, so the cost is negligible next to the round
/// trip.
fn load_registry(state: &HttpState) -> SkillRegistry {
    let skills_dir = state.package_dir.join("skills");
    SkillRegistry::load_from_dir(&skills_dir).unwrap_or_else(|e| {
        tracing::warn!(
            dir = %skills_dir.display(),
            error = %e,
            "Failed to load skill registry for HTTP query"
        );
        SkillRegistry::new()
    })
}

/// Sort by name (stable pagination — the old Gateway version paged a
/// `HashMap`, so page 2 could repeat page 1) and slice out one page.
fn list_from_registry(registry: &SkillRegistry, page: u32, size: u32) -> SkillListResponse {
    let mut all: Vec<&SkillDefinition> = registry.all_skills();
    all.sort_by(|a, b| a.name.cmp(&b.name));

    let total = all.len() as u64;
    let skip = (page as u64 - 1) * size as u64;
    let skills = all
        .into_iter()
        .skip(skip as usize)
        .take(size as usize)
        .map(entry_of)
        .collect();

    SkillListResponse {
        total,
        page,
        size,
        skills,
    }
}

fn entry_of(skill: &SkillDefinition) -> SkillListEntry {
    SkillListEntry {
        name: skill.name.clone(),
        description: skill.description.clone(),
        version: skill.version.clone(),
        author: skill.author.clone(),
        triggers: skill.triggers.clone(),
        tool_deps: skill.tool_deps.clone(),
    }
}

fn instance_mismatch(state: &HttpState, id: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "instance_id_mismatch",
            "message": format!(
                "path '{id}' is not this runtime's instance id '{}'",
                state.instance_id
            ),
        })),
    )
        .into_response()
}

fn not_found(message: String) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "not_found", "message": message })),
    )
        .into_response()
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Write `<dir>/<name>/SKILL.md` with the given `triggers` block, which is
    /// spliced in verbatim so a test can also express `triggers: []`.
    fn write_skill(dir: &std::path::Path, name: &str, triggers_block: &str) {
        let skill_dir = dir.join(name);
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("SKILL.md"),
            format!(
                "---\nname: {name}\ndescription: {name} skill\n{triggers_block}\n---\n\nDo the thing.\n"
            ),
        )
        .unwrap();
    }

    /// The list must come from the Runtime's own parser and be stably ordered,
    /// so `?page=2` cannot repeat `?page=1` (the old HashMap-paged Gateway
    /// version could).
    #[test]
    fn list_is_sorted_and_paginated() {
        let dir = std::env::temp_dir().join(format!("acowork-skills-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Deliberately created out of name order.
        write_skill(&dir, "charlie", "triggers:\n  - c");
        write_skill(&dir, "alpha", "triggers:\n  - a");
        write_skill(&dir, "bravo", "triggers:\n  - b");

        let registry = SkillRegistry::load_from_dir(&dir).unwrap();
        let page1 = list_from_registry(&registry, 1, 2);
        assert_eq!(page1.total, 3);
        assert_eq!(
            page1
                .skills
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "bravo"]
        );
        let page2 = list_from_registry(&registry, 2, 2);
        assert_eq!(
            page2
                .skills
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            vec!["charlie"]
        );

        // Regression guard for the parser relaxation this bug chain produced:
        // a trigger-less skill still loads and is reachable by name.
        write_skill(&dir, "delta", "triggers: []");
        let registry = SkillRegistry::load_from_dir(&dir).unwrap();
        assert!(registry.get("delta").is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
