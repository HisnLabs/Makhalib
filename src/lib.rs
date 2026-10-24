//! Makhalib (مخالب — "claws"): a natural-language-driven LLM red-teaming framework.
//!
//! Architecture: augustus's scanner engine (probe → buff → target → detector → report)
//! fused with PyRIT-style multi-turn orchestration, driven by an LLM "brain" and a
//! semantic memory. Everything an operator would normally write code for — targets,
//! probes, detectors, strategies — is declarative data compiled from a [`plan::ScanPlan`].
//!
//! **For authorized LLM security testing only.** Every [`plan::ScanPlan`] carries an
//! explicit authorization gate that must be satisfied before execution.

pub mod adaptive;
pub mod budget;
pub mod buffs;
pub mod core;
pub mod detectors;
pub mod efficacy;
pub mod generators;
pub mod governance;
pub mod guardrail;
pub mod harden;
pub mod inspect;
pub mod llm;
pub mod plan;
pub mod probes;
pub mod registry;
pub mod report;
pub mod scanner;
pub mod traits;

/// Boxed, thread-safe error used across async trait boundaries.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Crate-wide result alias for fallible trait methods.
pub type Result<T> = std::result::Result<T, BoxError>;
