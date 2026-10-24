//! Data-driven probe framework. A probe is declarative data ([`ProbeSpec`],
//! loadable from YAML/JSON); adding one requires no code. Built-ins here are
//! benign placeholders only — the real attack catalog is loaded from external data.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::core::{Attempt, Conversation};
use crate::registry::Registry;
use crate::traits::{Generator, Probe};
use crate::Result;

/// Declarative, no-code probe definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeSpec {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub goal: String,
    pub prompts: Vec<String>,
    #[serde(default)]
    pub detector: Option<String>,
}

impl ProbeSpec {
    pub fn from_yaml(s: &str) -> Result<Self> {
        Ok(serde_yaml::from_str(s)?)
    }

    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}

/// A probe that sends each prompt of its spec to the target, one attempt per prompt.
#[derive(Debug, Clone)]
pub struct StaticProbe {
    spec: ProbeSpec,
}

impl StaticProbe {
    pub fn from_spec(spec: ProbeSpec) -> Self {
        Self { spec }
    }

    pub fn spec(&self) -> &ProbeSpec {
        &self.spec
    }
}

#[async_trait]
impl Probe for StaticProbe {
    async fn probe(&self, gen: &dyn Generator) -> Result<Vec<Attempt>> {
        let mut attempts = Vec::with_capacity(self.spec.prompts.len());
        for prompt in &self.spec.prompts {
            let mut a = Attempt::new(prompt.clone());
            a.probe = self.spec.name.clone();
            a.generator = gen.name().to_string();
            if let Some(d) = &self.spec.detector {
                a.detector = d.clone();
            }
            match gen.generate(&Conversation::from_prompt(prompt.clone()), 1).await {
                Ok(msgs) => {
                    for m in msgs {
                        a.add_output(m.content);
                    }
                    a.complete();
                }
                Err(e) => {
                    a.set_error(e);
                }
            }
            attempts.push(a);
        }
        Ok(attempts)
    }

    fn name(&self) -> &str {
        &self.spec.name
    }

    fn prompts(&self) -> Vec<String> {
        self.spec.prompts.clone()
    }

    fn primary_detector(&self) -> Option<&str> {
        self.spec.detector.as_deref()
    }
}

fn register_spec(reg: &Registry<Arc<dyn Probe>>, spec: ProbeSpec) {
    let name = spec.name.clone();
    reg.register(name, move |_cfg| {
        Ok(Arc::new(StaticProbe::from_spec(spec.clone())) as Arc<dyn Probe>)
    });
}

/// Registry holding the benign built-in probes (`test.Blank`, `test.Hello`).
pub fn builtin_registry() -> Registry<Arc<dyn Probe>> {
    let reg: Registry<Arc<dyn Probe>> = Registry::new("probes");
    register_spec(
        &reg,
        ProbeSpec {
            name: "test.Blank".into(),
            description: "Sends an empty prompt (framework smoke test).".into(),
            goal: "verify the pipeline end to end".into(),
            prompts: vec![String::new()],
            detector: None,
        },
    );
    register_spec(
        &reg,
        ProbeSpec {
            name: "test.Hello".into(),
            description: "Sends a benign greeting (framework smoke test).".into(),
            goal: "verify the pipeline end to end".into(),
            prompts: vec!["Hello, who are you?".into()],
            detector: None,
        },
    );
    reg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Message, Status};
    use crate::registry::Config;

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

    struct FailOnB;

    #[async_trait]
    impl Generator for FailOnB {
        async fn generate(&self, conv: &Conversation, _n: usize) -> Result<Vec<Message>> {
            let last = conv.messages.last().map(|m| m.content.clone()).unwrap_or_default();
            if last == "b" {
                return Err("boom".into());
            }
            Ok(vec![Message::assistant(last)])
        }
        fn name(&self) -> &str {
            "test.FailOnB"
        }
    }

    fn spec3() -> ProbeSpec {
        ProbeSpec {
            name: "test.Three".into(),
            description: "d".into(),
            goal: "g".into(),
            prompts: vec!["a".into(), "b".into(), "c".into()],
            detector: Some("test.Det".into()),
        }
    }

    #[tokio::test]
    async fn static_probe_yields_one_attempt_per_prompt() {
        let p = StaticProbe::from_spec(spec3());
        let attempts = p.probe(&EchoGen).await.unwrap();
        assert_eq!(attempts.len(), 3);
        for (a, x) in attempts.iter().zip(["a", "b", "c"]) {
            assert_eq!(a.probe, "test.Three");
            assert_eq!(a.detector, "test.Det");
            assert_eq!(a.prompt, x);
            assert_eq!(a.outputs, vec![format!("echo: {x}")]);
            assert_eq!(a.status, Status::Complete);
        }
        assert_eq!(p.name(), "test.Three");
        assert_eq!(p.prompts().len(), 3);
        assert_eq!(p.primary_detector(), Some("test.Det"));
    }

    #[tokio::test]
    async fn generate_error_is_recorded_and_run_continues() {
        let p = StaticProbe::from_spec(spec3());
        let attempts = p.probe(&FailOnB).await.unwrap();
        assert_eq!(attempts.len(), 3);
        assert_eq!(attempts[1].status, Status::Error);
        assert_eq!(attempts[1].error.as_deref(), Some("boom"));
        assert!(attempts[1].outputs.is_empty());
        assert_eq!(attempts[2].outputs, vec!["c"]);
    }

    #[test]
    fn spec_roundtrips_yaml_and_json() {
        let s = spec3();
        let y = serde_yaml::to_string(&s).unwrap();
        assert_eq!(ProbeSpec::from_yaml(&y).unwrap(), s);
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(ProbeSpec::from_json(&j).unwrap(), s);
    }

    #[test]
    fn spec_defaults_and_errors() {
        let s = ProbeSpec::from_yaml("name: x.Y\nprompts: [hi]\n").unwrap();
        assert!(s.description.is_empty() && s.goal.is_empty() && s.detector.is_none());
        assert!(ProbeSpec::from_json("{\"name\":\"x\"}").is_err());
    }

    #[tokio::test]
    async fn builtin_registry_lists_and_runs() {
        let reg = builtin_registry();
        let list = reg.list();
        assert!(list.contains(&"test.Blank".to_string()));
        assert!(list.contains(&"test.Hello".to_string()));
        let p = reg.create("test.Hello", &Config::new()).unwrap();
        let attempts = p.probe(&EchoGen).await.unwrap();
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].outputs, vec!["echo: Hello, who are you?"]);
        let blank = reg.create("test.Blank", &Config::new()).unwrap();
        assert_eq!(blank.probe(&EchoGen).await.unwrap().len(), 1);
    }
}
