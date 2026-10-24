//! Typed, thread-safe capability registry — the equivalent of augustus's
//! generic `pkg/registry`. Targets, probes, detectors, buffs and harnesses each
//! own a `Registry<T>` and self-register factories by name. Instantiation is
//! driven by a [`Config`] map so the whole catalog is data-configurable.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use crate::BoxError;

/// Free-form configuration passed to a factory (parsed from a plan's spec).
pub type Config = serde_json::Map<String, serde_json::Value>;

/// Factory that builds a capability instance from config.
pub type Factory<T> = Arc<dyn Fn(&Config) -> Result<T, BoxError> + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("{kind}: capability not found: {name}")]
    NotFound { kind: String, name: String },
}

/// A named set of factories for one capability type `T`. Safe for concurrent use.
pub struct Registry<T> {
    kind: String,
    factories: RwLock<BTreeMap<String, Factory<T>>>,
}

impl<T> Registry<T> {
    pub fn new(kind: impl Into<String>) -> Self {
        Self { kind: kind.into(), factories: RwLock::new(BTreeMap::new()) }
    }

    /// Register (or replace) a factory under `name`.
    pub fn register<F>(&self, name: impl Into<String>, factory: F)
    where
        F: Fn(&Config) -> Result<T, BoxError> + Send + Sync + 'static,
    {
        self.factories
            .write()
            .expect("registry lock poisoned")
            .insert(name.into(), Arc::new(factory));
    }

    /// Fully-qualified names, sorted (BTreeMap keeps them ordered).
    pub fn list(&self) -> Vec<String> {
        self.factories.read().expect("registry lock poisoned").keys().cloned().collect()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.factories.read().expect("registry lock poisoned").contains_key(name)
    }

    /// Instantiate the capability registered under `name`.
    pub fn create(&self, name: &str, cfg: &Config) -> Result<T, BoxError> {
        let factory = {
            let map = self.factories.read().expect("registry lock poisoned");
            map.get(name).cloned()
        };
        match factory {
            Some(f) => f(cfg),
            None => Err(Box::new(RegistryError::NotFound {
                kind: self.kind.clone(),
                name: name.to_string(),
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty() -> Config {
        Config::new()
    }

    #[test]
    fn register_create_roundtrip() {
        let reg: Registry<String> = Registry::new("probes");
        reg.register("test.Echo", |cfg| {
            Ok(cfg.get("msg").and_then(|v| v.as_str()).unwrap_or("default").to_string())
        });
        assert_eq!(reg.create("test.Echo", &empty()).unwrap(), "default");

        let mut cfg = Config::new();
        cfg.insert("msg".into(), serde_json::json!("hi"));
        assert_eq!(reg.create("test.Echo", &cfg).unwrap(), "hi");
    }

    #[test]
    fn list_is_sorted() {
        let reg: Registry<u8> = Registry::new("x");
        reg.register("b.Two", |_| Ok(2));
        reg.register("a.One", |_| Ok(1));
        reg.register("c.Three", |_| Ok(3));
        assert_eq!(reg.list(), vec!["a.One", "b.Two", "c.Three"]);
    }

    #[test]
    fn unknown_name_is_not_found() {
        let reg: Registry<u8> = Registry::new("detectors");
        let err = reg.create("nope.Nope", &empty()).unwrap_err();
        assert!(err.to_string().contains("detectors"));
        assert!(err.to_string().contains("nope.Nope"));
    }

    #[test]
    fn contains_reflects_registration() {
        let reg: Registry<u8> = Registry::new("x");
        assert!(!reg.contains("a"));
        reg.register("a", |_| Ok(0));
        assert!(reg.contains("a"));
    }
}
