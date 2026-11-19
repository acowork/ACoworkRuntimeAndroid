//! Skills module
//!
//! SKILL.md is the static definition layer of the Skill dual-layer model.
//! The dynamic experience layer (Grafeo) is Phase 3.
//!
//! Reference: docs/13-skill-system.md

pub mod parser;

pub use parser::{
    PlatformCompat, SkillDefinition, SkillParseError, SkillRegistry, TestedModel, load_skill_md,
    parse_skill_md,
};
