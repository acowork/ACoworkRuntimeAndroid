//! Debug Protocol HTTP routes (ADR-048 Phase 2).
//!
//! Each handler is a thin wrapper around [`DebugService`](crate::usecases::DebugService).
//! All business logic lives in [`crate::debug::handlers`] — these handlers
//! only do wire-format conversion and slot-resolution.
//!
//! ## Route table
//!
//! See the [`debug_routes()`] builder. Routes mirror the JSON-RPC methods
//! that the legacy WebSocket server exposed 1-to-1:
//!
//! | Method | Path                            | DebugService call         |
//! |--------|---------------------------------|---------------------------|
//! | POST   | `/api/debug/enable`             | (no service call — flips DevMode on at runtime) |
//! | POST   | `/api/debug/disable`            | (no service call — tears DevMode down at runtime) |
//! | POST   | `/api/debug/resume`             | `resume(session_id)`      |
//! | POST   | `/api/debug/pause`              | `pause(session_id)`       |
//! | POST   | `/api/debug/step`               | `step(session_id, …)`     |
//! | POST   | `/api/debug/stop`               | `stop(session_id)`        |
//! | GET    | `/api/debug/state`              | `get_state(session_id)`   |
//! | GET    | `/api/debug/context/{iter}`     | `get_context_snapshot(…)` |
//! | GET    | `/api/debug/context/{iter}/sections/{name}` | `get_section(…)` |
//! | POST   | `/api/debug/context/rewind`     | `rewind(session_id, …)`   |
//! | POST   | `/api/debug/context/patch`      | `patch_context(session_id, …)` |
//! | POST   | `/api/debug/context/re-execute` | `re_execute(session_id)`  |
//!
//! All `session_id` values are taken from the JSON body — there is no
//! implicit "current session" because each session has its own per-session
//! `DebugController`.
//!
//! ## Error mapping
//!
//! [`DebugError`] → HTTP status:
//! - `SessionNotFound` → 404
//! - `InvalidParams`   → 400
//! - `NotFound`        → 404
//! - `InvalidState`    → 409
//! - `Internal`        → 422
//! - (slot empty)      → 503 "DevMode not enabled"

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::debug::handlers::{DebugError, DebugStateSnapshot};
use crate::debug::handlers::{ReExecuteOutcome, StepOutcome};
use crate::debug::protocol::{
    GetContextSnapshotParams, GetContextSnapshotResult, GetSectionParams, GetSectionResult,
    PatchContextParams, RewindParams, RewindResult, StepGranularity,
};
use crate::usecases::DebugService;

// ── Wire format ───────────────────────────────────────────────────────

/// Request body for the RPC endpoints that take a session_id + payload.
///
/// `session_id` is the only field every endpoint needs; specific endpoints
/// add their own optional fields via `Option` so we can keep one body type
/// across all routes (DRY).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct DebugRpcBody {
    pub session_id: String,
    #[serde(default)]
    pub granularity: Option<StepGranularity>,
    #[serde(default)]
    pub to_iteration: Option<u32>,
    #[serde(default)]
    pub patches: Option<PatchContextParams>,
}

impl DebugRpcBody {
    /// Validate the body has a non-empty session_id.
    fn require_session(&self) -> Result<&str, DebugHttpError> {
        if self.session_id.is_empty() {
            Err(DebugHttpError::invalid_params(
                -32602,
                "session_id is required",
            ))
        } else {
            Ok(&self.session_id)
        }
    }
}

/// Response wrapper for every debug endpoint.
///
/// The legacy JSON-RPC envelope is replaced with a flat
/// `{ ok: bool, data?: ..., error?: {...} }` shape so HTTP clients can
/// deserialize uniformly. `data` and `error` are mutually exclusive.
#[derive(Debug, Clone, Serialize)]
pub struct DebugHttpResponse<T: Serialize> {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<DebugHttpErrorBody>,
}

impl<T: Serialize> DebugHttpResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(error: DebugError) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(DebugHttpErrorBody::from(error)),
        }
    }
}

/// Error body embedded in [`DebugHttpResponse::error`].
#[derive(Debug, Clone, Serialize)]
pub struct DebugHttpErrorBody {
    pub code: i32,
    pub message: String,
}

impl From<DebugError> for DebugHttpErrorBody {
    fn from(e: DebugError) -> Self {
        Self {
            code: e.rpc_code(),
            message: e.to_string(),
        }
    }
}

/// HTTP error wrapper — converts into a [`Response`] with a JSON body.
#[derive(Debug)]
pub struct DebugHttpError {
    status: StatusCode,
    body: DebugHttpErrorBody,
}

impl DebugHttpError {
    fn new(status: StatusCode, code: i32, message: impl Into<String>) -> Self {
        Self {
            status,
            body: DebugHttpErrorBody {
                code,
                message: message.into(),
            },
        }
    }

    fn invalid_params(code: i32, msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, msg)
    }
}

impl From<DebugError> for DebugHttpError {
    fn from(e: DebugError) -> Self {
        let status = match &e {
            DebugError::SessionNotFound(_) => StatusCode::NOT_FOUND,
            DebugError::NotFound(_) => StatusCode::NOT_FOUND,
            DebugError::InvalidParams(_) => StatusCode::BAD_REQUEST,
            DebugError::InvalidState(_) => StatusCode::CONFLICT,
            DebugError::Internal(_) => StatusCode::UNPROCESSABLE_ENTITY,
        };
        Self::new(status, e.rpc_code(), e.to_string())
    }
}

impl IntoResponse for DebugHttpError {
    fn into_response(self) -> Response {
        let body = DebugHttpResponse::<()> {
            ok: false,
            data: None,
            error: Some(self.body),
        };
        (self.status, Json(body)).into_response()
    }
}

// ── Slot resolution ───────────────────────────────────────────────────

/// Resolve the late-bound `DebugService` from the HTTP state.
///
/// Returns `DebugHttpError` (which serializes to a 503) when the slot
/// is still empty — same pattern as every other ADR-040 service slot.
/// The HTTP server is started in Phase A before SessionManager wires up
/// the DebugService in Phase B, so this race is expected during boot.
async fn resolve_service(
    state: &super::server::HttpState,
) -> Result<Arc<dyn DebugService>, DebugHttpError> {
    let guard = state.debug_service.lock().await;
    guard.as_ref().cloned().ok_or_else(|| {
        DebugHttpError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            -32000,
            "Debug service not ready (DevMode disabled or Runtime booting)",
        )
    })
}

// ── Route handlers ────────────────────────────────────────────────────

/// `POST /api/debug/resume`
async fn post_resume(
    State(state): State<super::server::HttpState>,
    Json(body): Json<DebugRpcBody>,
) -> Result<Json<DebugHttpResponse<()>>, DebugHttpError> {
    let sid = body.require_session()?;
    let svc = resolve_service(&state).await?;
    svc.resume(sid)
        .await
        .map(|_| Json(DebugHttpResponse::ok(())))
        .map_err(DebugHttpError::from)
}

/// `POST /api/debug/pause`
async fn post_pause(
    State(state): State<super::server::HttpState>,
    Json(body): Json<DebugRpcBody>,
) -> Result<Json<DebugHttpResponse<()>>, DebugHttpError> {
    let sid = body.require_session()?;
    let svc = resolve_service(&state).await?;
    svc.pause(sid)
        .await
        .map(|_| Json(DebugHttpResponse::ok(())))
        .map_err(DebugHttpError::from)
}

/// `POST /api/debug/step`
async fn post_step(
    State(state): State<super::server::HttpState>,
    Json(body): Json<DebugRpcBody>,
) -> Result<Json<DebugHttpResponse<StepOutcome>>, DebugHttpError> {
    let sid = body.require_session()?;
    let granularity = body
        .granularity
        .clone()
        .unwrap_or(StepGranularity::Iteration);
    let svc = resolve_service(&state).await?;
    svc.step(sid, granularity)
        .await
        .map(|o| Json(DebugHttpResponse::ok(o)))
        .map_err(DebugHttpError::from)
}

/// `POST /api/debug/stop`
async fn post_stop(
    State(state): State<super::server::HttpState>,
    Json(body): Json<DebugRpcBody>,
) -> Result<Json<DebugHttpResponse<()>>, DebugHttpError> {
    let sid = body.require_session()?;
    let svc = resolve_service(&state).await?;
    svc.stop(sid)
        .await
        .map(|_| Json(DebugHttpResponse::ok(())))
        .map_err(DebugHttpError::from)
}

/// `GET /api/debug/state?session_id=…`
async fn get_state(
    State(state): State<super::server::HttpState>,
    Query(query): Query<StateQuery>,
) -> Result<Json<DebugHttpResponse<DebugStateSnapshot>>, DebugHttpError> {
    if query.session_id.is_empty() {
        return Err(DebugHttpError::invalid_params(
            -32602,
            "session_id query parameter is required",
        ));
    }
    let svc = resolve_service(&state).await?;
    svc.get_state(&query.session_id)
        .await
        .map(|s| Json(DebugHttpResponse::ok(s)))
        .map_err(DebugHttpError::from)
}

#[derive(Debug, Clone, Deserialize)]
pub struct StateQuery {
    pub session_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SectionQuery {
    pub session_id: String,
}

/// `GET /api/debug/context/{iteration}?session_id=…`
async fn get_context_snapshot(
    State(state): State<super::server::HttpState>,
    Path(iteration): Path<u32>,
    Query(query): Query<SectionQuery>,
) -> Result<Json<DebugHttpResponse<GetContextSnapshotResult>>, DebugHttpError> {
    if query.session_id.is_empty() {
        return Err(DebugHttpError::invalid_params(
            -32602,
            "session_id query parameter is required",
        ));
    }
    let svc = resolve_service(&state).await?;
    svc.get_context_snapshot(&query.session_id, GetContextSnapshotParams { iteration })
        .await
        .map(|r| Json(DebugHttpResponse::ok(r)))
        .map_err(DebugHttpError::from)
}

/// `GET /api/debug/context/{iteration}/sections/{name}?session_id=…`
async fn get_section(
    State(state): State<super::server::HttpState>,
    Path((iteration, section)): Path<(u32, String)>,
    Query(query): Query<SectionQuery>,
) -> Result<Json<DebugHttpResponse<GetSectionResult>>, DebugHttpError> {
    if query.session_id.is_empty() {
        return Err(DebugHttpError::invalid_params(
            -32602,
            "session_id query parameter is required",
        ));
    }
    let svc = resolve_service(&state).await?;
    svc.get_section(&query.session_id, GetSectionParams { iteration, section })
        .await
        .map(|r| Json(DebugHttpResponse::ok(r)))
        .map_err(DebugHttpError::from)
}

/// `POST /api/debug/context/rewind`
async fn post_rewind(
    State(state): State<super::server::HttpState>,
    Json(body): Json<DebugRpcBody>,
) -> Result<Json<DebugHttpResponse<RewindResult>>, DebugHttpError> {
    let sid = body.require_session()?;
    let target = body
        .to_iteration
        .ok_or_else(|| DebugHttpError::invalid_params(-32602, "to_iteration is required"))?;
    let svc = resolve_service(&state).await?;
    svc.rewind(
        sid,
        RewindParams {
            to_iteration: target,
        },
    )
    .await
    .map(|r| Json(DebugHttpResponse::ok(r)))
    .map_err(DebugHttpError::from)
}

/// `POST /api/debug/context/patch`
async fn post_patch_context(
    State(state): State<super::server::HttpState>,
    Json(body): Json<DebugRpcBody>,
) -> Result<Json<DebugHttpResponse<()>>, DebugHttpError> {
    let sid = body.require_session()?;
    let patches = body
        .patches
        .clone()
        .ok_or_else(|| DebugHttpError::invalid_params(-32602, "patches is required"))?;
    let svc = resolve_service(&state).await?;
    svc.patch_context(sid, patches)
        .await
        .map(|_| Json(DebugHttpResponse::ok(())))
        .map_err(DebugHttpError::from)
}

/// `POST /api/debug/context/re-execute`
async fn post_re_execute(
    State(state): State<super::server::HttpState>,
    Json(body): Json<DebugRpcBody>,
) -> Result<Json<DebugHttpResponse<ReExecuteOutcome>>, DebugHttpError> {
    let sid = body.require_session()?;
    let svc = resolve_service(&state).await?;
    svc.re_execute(sid)
        .await
        .map(|r| Json(DebugHttpResponse::ok(r)))
        .map_err(DebugHttpError::from)
}

// `POST /api/debug/prompts/reload` — moved to `POST /agents/{id}/prompts/reload`
// in `http/prompts.rs` (ADR-063 §3.7.7). The old route 503'd outside
// DevMode because it routed through `DebugService::reload_prompts`
// and the `debug_service_slot` is only populated when DevMode is
// active. The new placement is package-level (not debug-session-level)
// and works unconditionally — see ADR-063 §3.7.6 for the L2 reload
// semantics that this comment block previously documented.

// ── Runtime DevMode activation ───────────────────────────────────────

/// JSON body for `POST /api/debug/enable`.
///
/// `session_id` is intentionally absent — DevMode is per-agent, not
/// per-session. `debug_port` is accepted for API parity with the
/// original `--debug-port` config knob (the legacy WS listener was
/// removed in ADR-048; the value is plumbed through but unused at
/// runtime). `None` defaults to 0, which is the same default as
/// `RuntimeConfig::debug_port` fallback.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct EnableDebugBody {
    #[serde(default)]
    pub debug_port: Option<u32>,
}

/// Response payload for `POST /api/debug/enable`.
///
/// `already_enabled` distinguishes a fresh activation from a no-op
/// confirmation so the Desktop can skip the "DevMode just turned on"
/// toast on the second click and refresh the Debug Panel state
/// instead.
#[derive(Debug, Clone, Serialize)]
pub struct EnableDebugResult {
    pub enabled: bool,
    /// `true` when the slot was already populated before this call —
    /// no wiring happened, just a status confirmation.
    pub already_enabled: bool,
    pub debug_port: u32,
}

/// `POST /api/debug/enable` — flip DevMode on at runtime.
///
/// Idempotent: if DevMode is already active (debug service slot is
/// populated) the handler returns `already_enabled: true` and skips
/// the wiring. Otherwise it routes through
/// [`crate::startup::debug_enable::enable_debug_mode_and_fill_slot`]
/// to install the per-session debug controllers, MQTT event
/// publisher, and HTTP debug service in one shot — without restarting
/// the agent or restarting the HTTP server.
///
/// `debug_port` is preserved for API stability but unused at runtime
/// (ADR-048 removed the legacy WebSocket listener). The Desktop
/// always sends the value it has in `agentStore.dev_mode` /
/// `agentStore.debug_port`, so the field still serves as a "the user
/// confirmed the port" sanity check.
async fn post_enable(
    State(state): State<super::server::HttpState>,
    Json(body): Json<EnableDebugBody>,
) -> Result<Json<DebugHttpResponse<EnableDebugResult>>, DebugHttpError> {
    let debug_port = body.debug_port.unwrap_or(0);

    let outcome = crate::startup::debug_enable::enable_debug_mode_and_fill_slot(
        &state.debug_service,
        &state.mqtt_client,
        &state.session_manager_slot,
        debug_port,
    )
    .await;

    match outcome {
        crate::startup::debug_enable::DebugEnableOutcome::AlreadyEnabled => {
            Ok(Json(DebugHttpResponse::ok(EnableDebugResult {
                enabled: true,
                already_enabled: true,
                debug_port,
            })))
        }
        crate::startup::debug_enable::DebugEnableOutcome::NewlyEnabled => {
            tracing::info!(
                debug_port,
                "DevMode enabled at runtime via HTTP — /api/debug/* routes are now live"
            );
            Ok(Json(DebugHttpResponse::ok(EnableDebugResult {
                enabled: true,
                already_enabled: false,
                debug_port,
            })))
        }
        crate::startup::debug_enable::DebugEnableOutcome::SessionManagerUnavailable => {
            // Phase B hasn't finished wiring SessionManager into the
            // slot yet. Same shape as the other "slot not ready" 503s
            // in this file (`resolve_service` returns 503 when the
            // DebugService slot is empty) so the Desktop can handle
            // both with a single retry path.
            Err(DebugHttpError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                -32000,
                "SessionManager not ready (Phase B still running) — retry shortly",
            ))
        }
    }
}

/// `POST /api/debug/disable` — tear DevMode down at runtime.
///
/// Symmetric counterpart to [`post_enable`]. The body is empty
/// (DevMode is per-agent, there is no per-session parameter) and the
/// response carries a single boolean `disabled` flag plus an
/// `already_disabled` no-op confirmation so the Desktop can show
/// "DevMode is off" / "DevMode just turned off" without re-querying
/// agent state.
async fn post_disable(
    State(state): State<super::server::HttpState>,
) -> Result<Json<DebugHttpResponse<DisableDebugResult>>, DebugHttpError> {
    let outcome = crate::startup::debug_enable::disable_debug_mode_and_clear_slot(
        &state.debug_service,
        &state.session_manager_slot,
    )
    .await;

    match outcome {
        crate::startup::debug_enable::DebugDisableOutcome::AlreadyDisabled => {
            Ok(Json(DebugHttpResponse::ok(DisableDebugResult {
                disabled: true,
                already_disabled: true,
            })))
        }
        crate::startup::debug_enable::DebugDisableOutcome::NewlyDisabled => {
            tracing::info!(
                "DevMode disabled at runtime via HTTP — /api/debug/* routes return 503 again"
            );
            Ok(Json(DebugHttpResponse::ok(DisableDebugResult {
                disabled: true,
                already_disabled: false,
            })))
        }
        crate::startup::debug_enable::DebugDisableOutcome::SessionManagerUnavailable => {
            // Same shape as `post_enable` — 503 with a stable
            // -32000 code so the Desktop can reuse its retry path.
            // The service slot stays untouched here; the user can
            // retry once Phase B has wired SessionManager.
            Err(DebugHttpError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                -32000,
                "SessionManager not ready (Phase B still running) — retry shortly",
            ))
        }
    }
}

/// Response payload for `POST /api/debug/disable`.
///
/// `already_disabled: true` means the slot was already empty before
/// the call — no teardown happened, just a status confirmation.
#[derive(Debug, Clone, Serialize)]
pub struct DisableDebugResult {
    pub disabled: bool,
    pub already_disabled: bool,
}

// ── Router ────────────────────────────────────────────────────────────

use axum::extract::Query;

/// Build the debug HTTP router.
///
/// Mount via [`crate::http::server::RuntimeHttpServer::start`] using
/// `.merge(debug::debug_routes())` after the main routes.
pub(crate) fn debug_routes() -> Router<super::server::HttpState> {
    Router::new()
        .route("/api/debug/enable", post(post_enable))
        .route("/api/debug/disable", post(post_disable))
        .route("/api/debug/resume", post(post_resume))
        .route("/api/debug/pause", post(post_pause))
        .route("/api/debug/step", post(post_step))
        .route("/api/debug/stop", post(post_stop))
        .route("/api/debug/state", get(get_state))
        .route("/api/debug/context/{iteration}", get(get_context_snapshot))
        .route(
            "/api/debug/context/{iteration}/sections/{section}",
            get(get_section),
        )
        .route("/api/debug/context/rewind", post(post_rewind))
        .route("/api/debug/context/patch", post(post_patch_context))
        .route("/api/debug/context/re-execute", post(post_re_execute))
}
