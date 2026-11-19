//! Android Runtime role pieces (ADR-AND-003 §2.3).
//!
//! Vendored / adapted from upstream `acowork-runtime` — **no** path or git
//! dependency on that crate. Start with package load; the LLM main loop lands
//! in later slices.

pub mod package;

pub use package::{LoadedPackage, PackageLoadError, list_prompt_files, list_skill_files, load_package};
