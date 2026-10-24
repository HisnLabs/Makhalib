//! End-to-end wiring proof: the four independently fanned-out layers
//! (generator → probe → detector → scanner harness) compose into a real scan,
//! and detector verdicts come out correct. Fully offline (MockGenerator).

use std::sync::Arc;

use makhalib::core::Verdict;
use makhalib::detectors::RefusalDetector;
use makhalib::generators::MockGenerator;
use makhalib::probes::{ProbeSpec, StaticProbe};
use makhalib::scanner::Probewise;
use makhalib::traits::{Detector, Generator, Harness, Probe};

/// One probe, one prompt, one detector, through the concurrent harness.
async fn run_once(reply: &str) -> Verdict {
    let gen: Arc<dyn Generator> = Arc::new(MockGenerator::new("mock.Mock", reply));
    let spec = ProbeSpec::from_yaml(
        "name: test.Probe\nprompts:\n  - \"Hello, who are you?\"\n",
    )
    .unwrap();
    let probe: Arc<dyn Probe> = Arc::new(StaticProbe::from_spec(spec));
    let detector: Arc<dyn Detector> = Arc::new(RefusalDetector::default());

    let harness = Probewise::new(4);
    let attempts = harness
        .run(gen, std::slice::from_ref(&probe), std::slice::from_ref(&detector))
        .await
        .unwrap();

    assert_eq!(attempts.len(), 1, "one prompt → one attempt");
    attempts[0].verdict()
}

#[tokio::test]
async fn refusal_is_scored_as_passed() {
    // The target refuses → RefusalDetector scores 0.0 → PASSED (target resisted).
    assert_eq!(run_once("I cannot help with that request.").await, Verdict::Passed);
}

#[tokio::test]
async fn compliance_is_scored_as_vulnerable() {
    // The target complies with no refusal language → score 1.0 → VULNERABLE.
    assert_eq!(run_once("Sure, here is exactly what you asked for.").await, Verdict::Vulnerable);
}
