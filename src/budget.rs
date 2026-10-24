//! Token metering & budget (P10) — cost control so a run never burns more than
//! the operator allows.
//!
//! The guardrail `/classify` API does not report token usage, so we **estimate**
//! from text length (~4 characters per token, the common heuristic). For LLM
//! targets that report real usage, record that instead. [`MeteredGenerator`]
//! wraps any [`Generator`] so baseline and adaptive calls are metered uniformly;
//! once the budget is exhausted it refuses further calls (returns an error)
//! without hitting the network, so the run stops gracefully.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;

use crate::core::{Conversation, Message};
use crate::traits::Generator;
use crate::Result;

/// Estimate tokens for `text` at ~4 characters per token (min 1 for non-empty).
pub fn estimate_tokens(text: &str) -> u64 {
    let chars = text.chars().count() as u64;
    if chars == 0 {
        0
    } else {
        chars.div_ceil(4)
    }
}

/// Concurrency-safe running token total against an optional limit (`0` = unlimited).
#[derive(Debug)]
pub struct TokenMeter {
    used: AtomicU64,
    limit: u64,
}

impl TokenMeter {
    pub fn new(limit: u64) -> Self {
        Self { used: AtomicU64::new(0), limit }
    }

    pub fn unlimited() -> Self {
        Self::new(0)
    }

    /// Add `n` tokens; returns true if the budget is now exhausted.
    pub fn add(&self, n: u64) -> bool {
        let used = self.used.fetch_add(n, Ordering::SeqCst) + n;
        self.limit != 0 && used >= self.limit
    }

    pub fn used(&self) -> u64 {
        self.used.load(Ordering::SeqCst)
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// True once a limit is set and reached.
    pub fn exhausted(&self) -> bool {
        self.limit != 0 && self.used() >= self.limit
    }

    /// Tokens left, or `None` when unlimited.
    pub fn remaining(&self) -> Option<u64> {
        if self.limit == 0 {
            None
        } else {
            Some(self.limit.saturating_sub(self.used()))
        }
    }
}

/// Wraps a generator and charges estimated tokens (input + output) to a shared
/// [`TokenMeter`]. Refuses new calls once the budget is exhausted.
pub struct MeteredGenerator {
    inner: Arc<dyn Generator>,
    meter: Arc<TokenMeter>,
    name: String,
}

impl MeteredGenerator {
    pub fn new(inner: Arc<dyn Generator>, meter: Arc<TokenMeter>) -> Self {
        let name = inner.name().to_string();
        Self { inner, meter, name }
    }
}

#[async_trait]
impl Generator for MeteredGenerator {
    async fn generate(&self, conv: &Conversation, n: usize) -> Result<Vec<Message>> {
        if self.meter.exhausted() {
            return Err("token budget exhausted".into());
        }
        let in_tok: u64 = conv.messages.last().map(|m| estimate_tokens(&m.content)).unwrap_or(0);
        let out = self.inner.generate(conv, n).await?;
        let out_tok: u64 = out.iter().map(|m| estimate_tokens(&m.content)).sum();
        self.meter.add(in_tok + out_tok);
        Ok(out)
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        self.inner.description()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_is_chars_over_four() {
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("abcd"), 1);
        assert_eq!(estimate_tokens("abcde"), 2);
        assert_eq!(estimate_tokens(&"x".repeat(40)), 10);
    }

    #[test]
    fn meter_tracks_and_exhausts() {
        let m = TokenMeter::new(10);
        assert!(!m.exhausted());
        assert_eq!(m.remaining(), Some(10));
        assert!(!m.add(4));
        assert_eq!(m.used(), 4);
        assert!(m.add(6)); // reaches 10 -> exhausted
        assert!(m.exhausted());
        assert_eq!(m.remaining(), Some(0));
    }

    #[test]
    fn unlimited_never_exhausts() {
        let m = TokenMeter::unlimited();
        assert!(!m.add(1_000_000));
        assert!(!m.exhausted());
        assert_eq!(m.remaining(), None);
    }

    struct EchoGen;
    #[async_trait]
    impl Generator for EchoGen {
        async fn generate(&self, conv: &Conversation, _n: usize) -> Result<Vec<Message>> {
            let t = conv.messages.last().map(|m| m.content.clone()).unwrap_or_default();
            Ok(vec![Message::assistant(t)])
        }
        fn name(&self) -> &str {
            "echo"
        }
    }

    #[tokio::test]
    async fn metered_generator_charges_and_then_refuses() {
        let meter = Arc::new(TokenMeter::new(5));
        let g = MeteredGenerator::new(Arc::new(EchoGen), meter.clone());
        // "abcdefgh" = 8 chars -> 2 in + 2 out = 4 tokens.
        let conv = Conversation::from_prompt("abcdefgh");
        g.generate(&conv, 1).await.unwrap();
        assert_eq!(meter.used(), 4);
        // Next call pushes to/over 5 -> charged, now exhausted.
        g.generate(&conv, 1).await.unwrap();
        assert!(meter.exhausted());
        // Further calls are refused without touching the inner generator.
        assert!(g.generate(&conv, 1).await.is_err());
    }
}
