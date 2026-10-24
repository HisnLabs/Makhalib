//! The plugin contract — the Rust analog of augustus's `Prober`, `Generator`,
//! `Detector`, `Transformer` (buff) and `Harness` interfaces. These are the
//! stable seams every other layer (and every fanned-out module) builds against.
//!
//! All capabilities are `Send + Sync` so the concurrent scanner can share them
//! across worker threads behind `Arc`.

use async_trait::async_trait;
use std::sync::Arc;

use crate::core::{Attempt, Conversation, Message};
use crate::Result;

/// A target under test: wraps an LLM API behind a uniform call. Analog of
/// augustus's `types.Generator`.
#[async_trait]
pub trait Generator: Send + Sync {
    /// Send a conversation and return `n` completions.
    async fn generate(&self, conv: &Conversation, n: usize) -> Result<Vec<Message>>;

    /// Fully-qualified name, e.g. `ollama.Llama3`.
    fn name(&self) -> &str;

    fn description(&self) -> &str {
        ""
    }
}

/// An attack technique: produces one or more [`Attempt`]s by exercising the
/// target. Analog of augustus's `types.Prober`.
#[async_trait]
pub trait Probe: Send + Sync {
    async fn probe(&self, gen: &dyn Generator) -> Result<Vec<Attempt>>;

    /// Fully-qualified name, e.g. `dan.Dan_11_0`.
    fn name(&self) -> &str;

    /// Static attack prompts this probe uses (for listing / reporting).
    fn prompts(&self) -> Vec<String> {
        Vec::new()
    }

    /// Recommended primary detector name.
    fn primary_detector(&self) -> Option<&str> {
        None
    }
}

/// Scores a completed [`Attempt`]'s outputs in `[0.0, 1.0]` (0 = safe,
/// 1 = vulnerable). Analog of augustus's `types.Detector`.
#[async_trait]
pub trait Detector: Send + Sync {
    /// One score per output in `a.outputs`.
    async fn detect(&self, a: &Attempt) -> Result<Vec<f64>>;

    fn name(&self) -> &str;
}

/// Transforms one attempt into zero or more variants (encoding, paraphrase,
/// case, …). Analog of augustus's buff `Transformer`. Synchronous and cheap.
pub trait Buff: Send + Sync {
    fn transform(&self, a: &Attempt) -> Vec<Attempt>;

    fn name(&self) -> &str;
}

/// Orchestrates a scan: runs probes against a target and scores outputs with
/// detectors. Analog of augustus's `harnesses.Harness`. The concurrent scanner
/// is the default implementation.
#[async_trait]
pub trait Harness: Send + Sync {
    async fn run(
        &self,
        gen: Arc<dyn Generator>,
        probes: &[Arc<dyn Probe>],
        detectors: &[Arc<dyn Detector>],
    ) -> Result<Vec<Attempt>>;

    fn name(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Role;

    /// A trivial in-memory generator proving the trait is object-safe and usable
    /// from async tests. Real targets live in the `generators` module (fanned out).
    struct EchoGen;

    #[async_trait]
    impl Generator for EchoGen {
        async fn generate(&self, conv: &Conversation, n: usize) -> Result<Vec<Message>> {
            let last = conv.messages.last().map(|m| m.content.clone()).unwrap_or_default();
            Ok((0..n).map(|_| Message::assistant(format!("echo: {last}"))).collect())
        }
        fn name(&self) -> &str {
            "test.Echo"
        }
    }

    #[tokio::test]
    async fn generator_trait_is_object_safe_and_callable() {
        let gen: Arc<dyn Generator> = Arc::new(EchoGen);
        let conv = Conversation::from_prompt("ping");
        let out = gen.generate(&conv, 2).await.unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].role, Role::Assistant);
        assert_eq!(out[0].content, "echo: ping");
    }
}
