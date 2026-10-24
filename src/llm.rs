//! Provider-agnostic LLM client for the brain (P2/P6).
//!
//! One [`LlmClient`] trait, several providers — **Ollama, OpenAI, Anthropic
//! (Claude), Google (Gemini), and any OpenAI-compatible endpoint** (OpenRouter,
//! vLLM, LM Studio, …). The provider is chosen by config; API keys come from the
//! environment, never hard-coded. This is the plumbing the NL planner and the
//! attacker/judge roles call; it carries no attack content itself.

use std::sync::Arc;

use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;

use crate::Result;

/// A minimal single-turn chat interface shared by every provider.
#[async_trait]
pub trait LlmClient: Send + Sync {
    /// Send an optional system prompt + a user message, return the assistant text.
    async fn chat(&self, system: Option<&str>, user: &str) -> Result<String>;
    /// Fully-qualified name, e.g. `anthropic.claude-sonnet`.
    fn name(&self) -> &str;
}

fn http() -> Client {
    Client::new()
}

// --- Ollama (local) ---------------------------------------------------------

pub struct OllamaClient {
    http: Client,
    host: String,
    model: String,
    name: String,
}

impl OllamaClient {
    pub fn new(host: impl Into<String>, model: impl Into<String>) -> Self {
        let model = model.into();
        let host = host.into().trim_end_matches('/').to_string();
        Self { http: http(), host, name: format!("ollama.{model}"), model }
    }
}

#[async_trait]
impl LlmClient for OllamaClient {
    async fn chat(&self, system: Option<&str>, user: &str) -> Result<String> {
        let mut messages = Vec::new();
        if let Some(s) = system {
            messages.push(json!({"role": "system", "content": s}));
        }
        messages.push(json!({"role": "user", "content": user}));
        let body = json!({"model": self.model, "messages": messages, "stream": false});
        let resp = self.http.post(format!("{}/api/chat", self.host)).json(&body).send().await?;
        if !resp.status().is_success() {
            return Err(format!("ollama {}", resp.status()).into());
        }
        let v: serde_json::Value = resp.json().await?;
        v["message"]["content"].as_str().map(str::to_string).ok_or_else(|| "ollama: no content".into())
    }
    fn name(&self) -> &str {
        &self.name
    }
}

// --- OpenAI-compatible (OpenAI, OpenRouter, vLLM, LM Studio, …) --------------

pub struct OpenAiClient {
    http: Client,
    base: String, // includes /v1
    model: String,
    api_key: String,
    name: String,
}

impl OpenAiClient {
    pub fn new(base: impl Into<String>, model: impl Into<String>, api_key: impl Into<String>) -> Self {
        let model = model.into();
        let base = base.into().trim_end_matches('/').to_string();
        Self { http: http(), base, name: format!("openai.{model}"), model, api_key: api_key.into() }
    }
}

#[async_trait]
impl LlmClient for OpenAiClient {
    async fn chat(&self, system: Option<&str>, user: &str) -> Result<String> {
        let mut messages = Vec::new();
        if let Some(s) = system {
            messages.push(json!({"role": "system", "content": s}));
        }
        messages.push(json!({"role": "user", "content": user}));
        let body = json!({"model": self.model, "messages": messages});
        let resp = self
            .http
            .post(format!("{}/chat/completions", self.base))
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(format!("openai {}", resp.status()).into());
        }
        let v: serde_json::Value = resp.json().await?;
        v["choices"][0]["message"]["content"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| "openai: no content".into())
    }
    fn name(&self) -> &str {
        &self.name
    }
}

// --- Anthropic (Claude) -----------------------------------------------------

pub struct AnthropicClient {
    http: Client,
    base: String, // includes /v1
    model: String,
    api_key: String,
    max_tokens: u32,
    name: String,
}

impl AnthropicClient {
    pub fn new(base: impl Into<String>, model: impl Into<String>, api_key: impl Into<String>) -> Self {
        let model = model.into();
        let base = base.into().trim_end_matches('/').to_string();
        Self { http: http(), base, name: format!("anthropic.{model}"), model, api_key: api_key.into(), max_tokens: 1024 }
    }
}

#[async_trait]
impl LlmClient for AnthropicClient {
    async fn chat(&self, system: Option<&str>, user: &str) -> Result<String> {
        let mut body = json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": user}],
        });
        if let Some(s) = system {
            body["system"] = json!(s);
        }
        let resp = self
            .http
            .post(format!("{}/messages", self.base))
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(format!("anthropic {}", resp.status()).into());
        }
        let v: serde_json::Value = resp.json().await?;
        v["content"][0]["text"].as_str().map(str::to_string).ok_or_else(|| "anthropic: no content".into())
    }
    fn name(&self) -> &str {
        &self.name
    }
}

// --- Google (Gemini) --------------------------------------------------------

pub struct GeminiClient {
    http: Client,
    base: String, // includes /v1beta
    model: String,
    api_key: String,
    name: String,
}

impl GeminiClient {
    pub fn new(base: impl Into<String>, model: impl Into<String>, api_key: impl Into<String>) -> Self {
        let model = model.into();
        let base = base.into().trim_end_matches('/').to_string();
        Self { http: http(), base, name: format!("gemini.{model}"), model, api_key: api_key.into() }
    }
}

#[async_trait]
impl LlmClient for GeminiClient {
    async fn chat(&self, system: Option<&str>, user: &str) -> Result<String> {
        let mut body = json!({
            "contents": [{"role": "user", "parts": [{"text": user}]}],
        });
        if let Some(s) = system {
            body["systemInstruction"] = json!({"parts": [{"text": s}]});
        }
        let url = format!("{}/models/{}:generateContent?key={}", self.base, self.model, self.api_key);
        let resp = self.http.post(url).json(&body).send().await?;
        if !resp.status().is_success() {
            return Err(format!("gemini {}", resp.status()).into());
        }
        let v: serde_json::Value = resp.json().await?;
        v["candidates"][0]["content"]["parts"][0]["text"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| "gemini: no content".into())
    }
    fn name(&self) -> &str {
        &self.name
    }
}

// --- Factory ----------------------------------------------------------------

/// Declarative LLM config. `provider` is one of `ollama|openai|anthropic|gemini|
/// openai-compatible`. The key is taken from `api_key`, else the env var in
/// `api_key_env`, else the provider's default env var.
#[derive(Debug, Clone, Default)]
pub struct LlmConfig {
    pub provider: String,
    pub model: String,
    pub base_url: Option<String>,
    pub host: Option<String>,
    pub api_key: Option<String>,
    pub api_key_env: Option<String>,
}

fn key_for(cfg: &LlmConfig, default_env: &str) -> Result<String> {
    if let Some(k) = &cfg.api_key {
        return Ok(k.clone());
    }
    let env = cfg.api_key_env.as_deref().unwrap_or(default_env);
    std::env::var(env).map_err(|_| format!("missing API key: set ${env}").into())
}

/// Build a client from config, resolving keys from the environment.
pub fn build(cfg: &LlmConfig) -> Result<Arc<dyn LlmClient>> {
    let model = cfg.model.clone();
    match cfg.provider.as_str() {
        "ollama" => {
            let host = cfg.host.clone().or_else(|| cfg.base_url.clone()).unwrap_or_else(|| "http://localhost:11434".into());
            Ok(Arc::new(OllamaClient::new(host, model)))
        }
        "openai" | "openai-compatible" => {
            let base = cfg.base_url.clone().unwrap_or_else(|| "https://api.openai.com/v1".into());
            Ok(Arc::new(OpenAiClient::new(base, model, key_for(cfg, "OPENAI_API_KEY")?)))
        }
        "anthropic" | "claude" => {
            let base = cfg.base_url.clone().unwrap_or_else(|| "https://api.anthropic.com/v1".into());
            Ok(Arc::new(AnthropicClient::new(base, model, key_for(cfg, "ANTHROPIC_API_KEY")?)))
        }
        "gemini" | "google" => {
            let base = cfg.base_url.clone().unwrap_or_else(|| "https://generativelanguage.googleapis.com/v1beta".into());
            let key = key_for(cfg, "GEMINI_API_KEY").or_else(|_| key_for(cfg, "GOOGLE_API_KEY"))?;
            Ok(Arc::new(GeminiClient::new(base, model, key)))
        }
        other => Err(format!("unknown LLM provider: {other}").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn ollama_chat() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"message": {"role": "assistant", "content": "hi"}})))
            .mount(&s)
            .await;
        let c = OllamaClient::new(s.uri(), "llama3");
        assert_eq!(c.chat(Some("sys"), "hello").await.unwrap(), "hi");
        assert_eq!(c.name(), "ollama.llama3");
    }

    #[tokio::test]
    async fn openai_chat() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("authorization", "Bearer sk-test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"choices": [{"message": {"content": "hi"}}]})))
            .mount(&s)
            .await;
        let c = OpenAiClient::new(format!("{}/v1", s.uri()), "gpt-4o", "sk-test");
        assert_eq!(c.chat(None, "hello").await.unwrap(), "hi");
    }

    #[tokio::test]
    async fn anthropic_chat() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(header("x-api-key", "k"))
            .and(header("anthropic-version", "2023-06-01"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"content": [{"type": "text", "text": "hi"}]})))
            .mount(&s)
            .await;
        let c = AnthropicClient::new(format!("{}/v1", s.uri()), "claude-sonnet", "k");
        assert_eq!(c.chat(Some("sys"), "hello").await.unwrap(), "hi");
    }

    #[tokio::test]
    async fn gemini_chat() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1beta/models/gemini-1.5-flash:generateContent"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"candidates": [{"content": {"parts": [{"text": "hi"}]}}]})))
            .mount(&s)
            .await;
        let c = GeminiClient::new(format!("{}/v1beta", s.uri()), "gemini-1.5-flash", "k");
        assert_eq!(c.chat(None, "hello").await.unwrap(), "hi");
    }

    #[tokio::test]
    async fn error_status_is_err() {
        let s = MockServer::start().await;
        Mock::given(method("POST")).respond_with(ResponseTemplate::new(500)).mount(&s).await;
        let c = OllamaClient::new(s.uri(), "m");
        assert!(c.chat(None, "x").await.is_err());
    }

    #[test]
    fn factory_selects_provider_and_resolves_key() {
        let ollama = build(&LlmConfig { provider: "ollama".into(), model: "llama3".into(), ..Default::default() }).unwrap();
        assert_eq!(ollama.name(), "ollama.llama3");

        let openai = build(&LlmConfig {
            provider: "openai".into(),
            model: "gpt-4o".into(),
            api_key: Some("sk".into()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(openai.name(), "openai.gpt-4o");

        // Missing key for a hosted provider is an error.
        let missing = build(&LlmConfig {
            provider: "anthropic".into(),
            model: "claude".into(),
            api_key_env: Some("DEFINITELY_UNSET_KEY_XYZ".into()),
            ..Default::default()
        });
        assert!(missing.is_err());

        assert!(build(&LlmConfig { provider: "nope".into(), ..Default::default() }).is_err());
    }
}
