//! Android ExecutionBackend bridge (ADR-AND-001).
//!
//! When the Android CLI installs a backend before boot, shell tool calls route
//! through it (capability gate + stdin script) instead of raw `Command`.

use std::sync::{Arc, OnceLock};

use acowork_android::host::ExecutionBackend;

static BACKEND: OnceLock<Arc<dyn ExecutionBackend>> = OnceLock::new();

/// Install the host execution chain for this Runtime process.
///
/// Call once before tool registration / LLM loop. Subsequent calls are ignored.
pub fn install(backend: Arc<dyn ExecutionBackend>) {
    let _ = BACKEND.set(backend);
}

/// The installed backend, if any.
pub fn backend() -> Option<&'static Arc<dyn ExecutionBackend>> {
    BACKEND.get()
}

/// True when an Android backend is driving shell execution.
pub fn is_active() -> bool {
    BACKEND.get().is_some()
}
