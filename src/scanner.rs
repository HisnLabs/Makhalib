//! The default concurrent harness: runs probes, then scores every attempt
//! with detectors on a bounded worker pool.
//!
//! Memory: each `Attempt` is moved by value into its scoring task and handed
//! back out, so nothing is cloned. At most `concurrency` tasks are in flight.

use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::{self, StreamExt};
use tokio::sync::Semaphore;

use crate::core::Attempt;
use crate::traits::{Detector, Generator, Harness, Probe};
use crate::Result;

/// Probe-by-probe harness with bounded-concurrency scoring.
#[derive(Debug, Clone)]
pub struct Probewise {
    concurrency: usize,
}

impl Probewise {
    /// `concurrency` is the max number of attempts scored at once (0 is clamped to 1).
    pub fn new(concurrency: usize) -> Self {
        Self { concurrency: concurrency.max(1) }
    }

    pub fn concurrency(&self) -> usize {
        self.concurrency
    }
}

impl Default for Probewise {
    fn default() -> Self {
        Self::new(8)
    }
}

/// Score one attempt. Never panics or propagates: failures are recorded on the attempt.
async fn score(mut attempt: Attempt, detectors: &[Arc<dyn Detector>]) -> Attempt {
    // An attempt already failed upstream (e.g. probe error) is passed through.
    if attempt.error.is_some() {
        return attempt;
    }
    let chosen = detectors
        .iter()
        .find(|d| !attempt.detector.is_empty() && d.name() == attempt.detector)
        .or_else(|| detectors.first());
    match chosen {
        Some(d) => match d.detect(&attempt).await {
            Ok(scores) => {
                attempt.detector = d.name().to_string();
                attempt.set_scores(scores).complete();
            }
            Err(e) => {
                attempt.detector = d.name().to_string();
                attempt.set_error(e);
            }
        },
        None => {
            attempt.complete();
        }
    }
    attempt
}

#[async_trait]
impl Harness for Probewise {
    async fn run(
        &self,
        gen: Arc<dyn Generator>,
        probes: &[Arc<dyn Probe>],
        detectors: &[Arc<dyn Detector>],
    ) -> Result<Vec<Attempt>> {
        // Phase 1: collect attempts from each probe; a failing probe yields one errored attempt.
        let mut attempts = Vec::new();
        for probe in probes {
            match probe.probe(&*gen).await {
                Ok(batch) => {
                    for mut a in batch {
                        if a.probe.is_empty() {
                            a.probe = probe.name().to_string();
                        }
                        if a.generator.is_empty() {
                            a.generator = gen.name().to_string();
                        }
                        attempts.push(a);
                    }
                }
                Err(e) => {
                    let mut a = Attempt::new("");
                    a.probe = probe.name().to_string();
                    a.generator = gen.name().to_string();
                    a.set_error(e);
                    attempts.push(a);
                }
            }
        }

        // Phase 2: score concurrently; the semaphore is the hard bound on in-flight work.
        let sem = Arc::new(Semaphore::new(self.concurrency));
        let results = stream::iter(attempts)
            .map(|attempt| {
                let sem = Arc::clone(&sem);
                async move {
                    let _permit = sem.acquire_owned().await.expect("semaphore never closed");
                    score(attempt, detectors).await
                }
            })
            .buffer_unordered(self.concurrency)
            .collect::<Vec<_>>()
            .await;
        Ok(results)
    }

    fn name(&self) -> &str {
        "probewise"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Conversation, Message, Status};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    struct MockGen;
    #[async_trait]
    impl Generator for MockGen {
        async fn generate(&self, _c: &Conversation, n: usize) -> Result<Vec<Message>> {
            Ok((0..n).map(|_| Message::assistant("yes")).collect())
        }
        fn name(&self) -> &str {
            "mock.Gen"
        }
    }

    struct MockProbe {
        n: usize,
    }
    #[async_trait]
    impl Probe for MockProbe {
        async fn probe(&self, gen: &dyn Generator) -> Result<Vec<Attempt>> {
            let mut out = Vec::new();
            for i in 0..self.n {
                let mut a = Attempt::new(format!("prompt {i}"));
                let msgs = gen.generate(&a.conversation, 1).await?;
                for m in msgs {
                    a.add_output(m.content);
                }
                out.push(a);
            }
            Ok(out)
        }
        fn name(&self) -> &str {
            "mock.Probe"
        }
    }

    struct FailProbe;
    #[async_trait]
    impl Probe for FailProbe {
        async fn probe(&self, _g: &dyn Generator) -> Result<Vec<Attempt>> {
            Err("probe boom".into())
        }
        fn name(&self) -> &str {
            "mock.Fail"
        }
    }

    struct YesDetector;
    #[async_trait]
    impl Detector for YesDetector {
        async fn detect(&self, a: &Attempt) -> Result<Vec<f64>> {
            Ok(a.outputs.iter().map(|o| if o.contains("yes") { 1.0 } else { 0.0 }).collect())
        }
        fn name(&self) -> &str {
            "mock.Yes"
        }
    }

    struct GaugeDetector {
        cur: AtomicUsize,
        max: AtomicUsize,
    }
    #[async_trait]
    impl Detector for GaugeDetector {
        async fn detect(&self, _a: &Attempt) -> Result<Vec<f64>> {
            let now = self.cur.fetch_add(1, Ordering::SeqCst) + 1;
            self.max.fetch_max(now, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(5)).await;
            self.cur.fetch_sub(1, Ordering::SeqCst);
            Ok(vec![0.0])
        }
        fn name(&self) -> &str {
            "mock.Gauge"
        }
    }

    /// Errors on prompts ending in "7".
    struct FlakyDetector;
    #[async_trait]
    impl Detector for FlakyDetector {
        async fn detect(&self, a: &Attempt) -> Result<Vec<f64>> {
            if a.prompt.ends_with('7') {
                Err("detector boom".into())
            } else {
                Ok(vec![1.0])
            }
        }
        fn name(&self) -> &str {
            "mock.Flaky"
        }
    }

    fn gen() -> Arc<dyn Generator> {
        Arc::new(MockGen)
    }

    #[tokio::test]
    async fn scores_all_attempts() {
        let probes: Vec<Arc<dyn Probe>> = vec![Arc::new(MockProbe { n: 50 })];
        let dets: Vec<Arc<dyn Detector>> = vec![Arc::new(YesDetector)];
        let out = Probewise::new(4).run(gen(), &probes, &dets).await.unwrap();
        assert_eq!(out.len(), 50);
        for a in &out {
            assert_eq!(a.status, Status::Complete);
            assert_eq!(a.scores, vec![1.0]);
            assert_eq!(a.detector, "mock.Yes");
            assert_eq!(a.probe, "mock.Probe");
            assert_eq!(a.generator, "mock.Gen");
        }
    }

    #[tokio::test]
    async fn concurrency_is_bounded() {
        let probes: Vec<Arc<dyn Probe>> = vec![Arc::new(MockProbe { n: 40 })];
        let gauge = Arc::new(GaugeDetector { cur: AtomicUsize::new(0), max: AtomicUsize::new(0) });
        let dets: Vec<Arc<dyn Detector>> = vec![gauge.clone()];
        let out = Probewise::new(3).run(gen(), &probes, &dets).await.unwrap();
        assert_eq!(out.len(), 40);
        let max = gauge.max.load(Ordering::SeqCst);
        assert!(max <= 3, "max in flight {max} exceeded 3");
        assert!(max > 1, "expected real concurrency, saw {max}");
    }

    #[tokio::test]
    async fn zero_concurrency_clamps_to_one() {
        assert_eq!(Probewise::new(0).concurrency(), 1);
        let probes: Vec<Arc<dyn Probe>> = vec![Arc::new(MockProbe { n: 5 })];
        let dets: Vec<Arc<dyn Detector>> = vec![Arc::new(YesDetector)];
        let out = Probewise::new(0).run(gen(), &probes, &dets).await.unwrap();
        assert_eq!(out.len(), 5);
    }

    #[tokio::test]
    async fn detector_error_is_isolated() {
        let probes: Vec<Arc<dyn Probe>> = vec![Arc::new(MockProbe { n: 20 })];
        let dets: Vec<Arc<dyn Detector>> = vec![Arc::new(FlakyDetector)];
        let out = Probewise::new(4).run(gen(), &probes, &dets).await.unwrap();
        assert_eq!(out.len(), 20);
        let errs = out.iter().filter(|a| a.status == Status::Error).count();
        let oks = out.iter().filter(|a| a.status == Status::Complete).count();
        assert_eq!(errs, 2); // prompt 7 and prompt 17
        assert_eq!(oks, 18);
        assert!(out.iter().filter(|a| a.status == Status::Error).all(|a| a.error.is_some()));
    }

    #[tokio::test]
    async fn probe_error_is_isolated() {
        let probes: Vec<Arc<dyn Probe>> = vec![Arc::new(FailProbe), Arc::new(MockProbe { n: 3 })];
        let dets: Vec<Arc<dyn Detector>> = vec![Arc::new(YesDetector)];
        let out = Probewise::new(2).run(gen(), &probes, &dets).await.unwrap();
        assert_eq!(out.len(), 4);
        assert_eq!(out.iter().filter(|a| a.status == Status::Error).count(), 1);
        assert_eq!(out.iter().filter(|a| a.status == Status::Complete).count(), 3);
    }

    #[tokio::test]
    async fn prefers_detector_named_on_attempt() {
        struct Preset;
        #[async_trait]
        impl Probe for Preset {
            async fn probe(&self, _g: &dyn Generator) -> Result<Vec<Attempt>> {
                let mut a = Attempt::new("p");
                a.add_output("no");
                a.detector = "mock.Yes".into();
                Ok(vec![a])
            }
            fn name(&self) -> &str {
                "preset"
            }
        }
        let probes: Vec<Arc<dyn Probe>> = vec![Arc::new(Preset)];
        let dets: Vec<Arc<dyn Detector>> = vec![Arc::new(FlakyDetector), Arc::new(YesDetector)];
        let out = Probewise::new(1).run(gen(), &probes, &dets).await.unwrap();
        assert_eq!(out[0].detector, "mock.Yes");
        assert_eq!(out[0].scores, vec![0.0]);
    }
}
