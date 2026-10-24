//! Targets (LLM connectors): a deterministic [`MockGenerator`] and a local
//! [`OllamaGenerator`], plus [`builtin_registry`].

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::core::{Conversation, Message, Role};
use crate::registry::{Config, Registry};
use crate::traits::Generator;
use crate::Result;

/// Deterministic offline generator. Scripted replies are cycled across
/// every produced completion.
pub struct MockGenerator {
    name: String,
    replies: Vec<String>,
    echo: bool,
    counter: AtomicUsize,
}

impl MockGenerator {
    pub fn new(name: impl Into<String>, reply: impl Into<String>) -> Self {
        Self::scripted(name, vec![reply.into()])
    }

    pub fn scripted(name: impl Into<String>, replies: Vec<String>) -> Self {
        let replies = if replies.is_empty() { vec![String::new()] } else { replies };
        Self { name: name.into(), replies, echo: false, counter: AtomicUsize::new(0) }
    }

    /// When enabled, each reply is `"echo: {last_user}"` instead of the canned text.
    pub fn with_echo(mut self, echo: bool) -> Self {
        self.echo = echo;
        self
    }
}

#[async_trait]
impl Generator for MockGenerator {
    async fn generate(&self, conv: &Conversation, n: usize) -> Result<Vec<Message>> {
        let last_user = conv
            .messages
            .iter()
            .rev()
            .find(|m| m.role == Role::User)
            .map(|m| m.content.as_str())
            .unwrap_or("");
        Ok((0..n)
            .map(|_| {
                if self.echo {
                    Message::assistant(format!("echo: {last_user}"))
                } else {
                    let i = self.counter.fetch_add(1, Ordering::Relaxed);
                    Message::assistant(self.replies[i % self.replies.len()].clone())
                }
            })
            .collect())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "Deterministic mock generator for offline tests and dry-runs"
    }
}

/// Connector to a local Ollama server (`POST {host}/api/chat`, non-streaming).
/// Ollama returns one message per request, so `n > 1` issues `n` sequential requests.
pub struct OllamaGenerator {
    name: String,
    host: String,
    model: String,
    client: reqwest::Client,
}

impl OllamaGenerator {
    pub const DEFAULT_HOST: &'static str = "http://localhost:11434";

    pub fn new(host: impl Into<String>, model: impl Into<String>, name: Option<String>) -> Result<Self> {
        let model = model.into();
        let name = name.unwrap_or_else(|| format!("ollama.{model}"));
        let client = reqwest::Client::builder().build()?;
        Ok(Self {
            name,
            host: host.into().trim_end_matches('/').to_string(),
            model,
            client,
        })
    }

    fn role_str(r: &Role) -> &'static str {
        match r {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
        }
    }

    async fn one(&self, body: &Value) -> Result<Message> {
        let resp = self.client.post(format!("{}/api/chat", self.host)).json(body).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("ollama returned HTTP {status}: {text}").into());
        }
        let v: Value = resp.json().await?;
        let content = v
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .ok_or("ollama response missing message.content")?;
        Ok(Message::assistant(content))
    }
}

#[async_trait]
impl Generator for OllamaGenerator {
    async fn generate(&self, conv: &Conversation, n: usize) -> Result<Vec<Message>> {
        let messages: Vec<Value> = conv
            .messages
            .iter()
            .map(|m| json!({"role": Self::role_str(&m.role), "content": m.content}))
            .collect();
        let body = json!({"model": self.model, "messages": messages, "stream": false});
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.one(&body).await?);
        }
        Ok(out)
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "Local Ollama chat model"
    }
}

fn str_key<'a>(cfg: &'a Config, k: &str) -> Option<&'a str> {
    cfg.get(k).and_then(|v| v.as_str())
}

/// Registry with `mock.Mock` (keys: `name`, `reply`, `replies`[], `echo`)
/// and `ollama.Ollama` (keys: `host`, `model`, `name`).
pub fn builtin_registry() -> Registry<Arc<dyn Generator>> {
    let reg: Registry<Arc<dyn Generator>> = Registry::new("generators");
    reg.register("mock.Mock", |cfg| {
        let name = str_key(cfg, "name").unwrap_or("mock.Mock");
        let replies: Vec<String> = match cfg.get("replies").and_then(|v| v.as_array()) {
            Some(a) => a.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
            None => vec![str_key(cfg, "reply").unwrap_or("mock reply").to_string()],
        };
        let echo = cfg.get("echo").and_then(|v| v.as_bool()).unwrap_or(false);
        Ok(Arc::new(MockGenerator::scripted(name, replies).with_echo(echo)) as Arc<dyn Generator>)
    });
    reg.register("ollama.Ollama", |cfg| {
        let host = str_key(cfg, "host").unwrap_or(OllamaGenerator::DEFAULT_HOST);
        let model = str_key(cfg, "model").unwrap_or("llama3");
        let g = OllamaGenerator::new(host, model, str_key(cfg, "name").map(String::from))?;
        Ok(Arc::new(g) as Arc<dyn Generator>)
    });
    reg
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn mock_fixed_reply_respects_n() {
        let g = MockGenerator::new("m", "hello");
        let out = g.generate(&Conversation::from_prompt("hi"), 3).await.unwrap();
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|m| m.content == "hello" && m.role == Role::Assistant));
        assert_eq!(g.name(), "m");
    }

    #[tokio::test]
    async fn mock_scripted_cycles_and_echo() {
        let g = MockGenerator::scripted("m", vec!["a".into(), "b".into()]);
        let out = g.generate(&Conversation::from_prompt("x"), 3).await.unwrap();
        let c: Vec<_> = out.iter().map(|m| m.content.as_str()).collect();
        assert_eq!(c, ["a", "b", "a"]);
        let e = MockGenerator::new("e", "z").with_echo(true);
        let out = e.generate(&Conversation::from_prompt("ping"), 1).await.unwrap();
        assert_eq!(out[0].content, "echo: ping");
    }

    #[tokio::test]
    async fn ollama_sends_and_parses() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .and(body_partial_json(json!({
                "model": "llama3",
                "stream": false,
                "messages": [{"role": "user", "content": "secret prompt"}]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "message": {"role": "assistant", "content": "canned answer"}
            })))
            .expect(2)
            .mount(&server)
            .await;
        let g = OllamaGenerator::new(server.uri(), "llama3", None).unwrap();
        let out = g.generate(&Conversation::from_prompt("secret prompt"), 2).await.unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].content, "canned answer");
        assert_eq!(out[0].role, Role::Assistant);
        assert_eq!(g.name(), "ollama.llama3");
    }

    #[tokio::test]
    async fn ollama_500_is_err() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;
        let g = OllamaGenerator::new(server.uri(), "llama3", None).unwrap();
        assert!(g.generate(&Conversation::from_prompt("x"), 1).await.is_err());
    }

    #[tokio::test]
    async fn ollama_bad_body_is_err() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"nope": 1})))
            .mount(&server)
            .await;
        let g = OllamaGenerator::new(server.uri(), "m", None).unwrap();
        assert!(g.generate(&Conversation::from_prompt("x"), 1).await.is_err());
    }

    #[tokio::test]
    async fn registry_builds_mock_and_ollama() {
        let reg = builtin_registry();
        assert_eq!(reg.list(), vec!["mock.Mock", "ollama.Ollama"]);
        let mut cfg = Config::new();
        cfg.insert("reply".into(), json!("canned"));
        let g = reg.create("mock.Mock", &cfg).unwrap();
        let out = g.generate(&Conversation::from_prompt("q"), 1).await.unwrap();
        assert_eq!(out[0].content, "canned");
        let o = reg.create("ollama.Ollama", &Config::new()).unwrap();
        assert_eq!(o.name(), "ollama.llama3");
    }
}
