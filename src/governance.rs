//! Governance (P8): target allowlist and a tamper-evident audit log.
//!
//! - **Allowlist**: a run may only target hosts the operator has listed. Any other
//!   endpoint is refused before a single request is sent.
//! - **Audit log**: every run appends one JSON line recording who ran it, the scope,
//!   the target and the outcome. Each entry carries the SHA-256 of the previous
//!   entry, so editing or deleting an earlier line breaks the chain and
//!   [`verify_chain`] reports it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Returns the host of `url` (lowercased), or `None` if it has no host.
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next()?;
    // Strip userinfo and port.
    let host_port = authority.rsplit('@').next()?;
    let host = if let Some(stripped) = host_port.strip_prefix('[') {
        stripped.split(']').next()?
    } else {
        host_port.split(':').next()?
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Checks that `endpoint`'s host is on the allowlist. An empty allowlist refuses
/// everything, so governance is never silently disabled.
pub fn check_allowlist(endpoint: &str, allowlist: &[String]) -> Result<(), String> {
    let host = host_of(endpoint).ok_or_else(|| format!("cannot read a host from {endpoint}"))?;
    if allowlist.is_empty() {
        return Err("target allowlist is empty: add the host to allow it".into());
    }
    if allowlist.iter().any(|a| a.trim().eq_ignore_ascii_case(&host)) {
        Ok(())
    } else {
        Err(format!("host '{host}' is not on the target allowlist"))
    }
}

/// One audit record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub seq: u64,
    pub timestamp: String,
    pub actor: String,
    pub scope: String,
    pub endpoint: String,
    pub outcome: String,
    /// Estimated tokens consumed by the run (see `budget`).
    pub tokens_used: u64,
    /// Token budget the run was started with; 0 = unlimited.
    pub token_limit: u64,
    pub prev_hash: String,
    pub hash: String,
}

#[allow(clippy::too_many_arguments)]
fn digest(seq: u64, timestamp: &str, actor: &str, scope: &str, endpoint: &str, outcome: &str, used: u64, limit: u64, prev: &str) -> String {
    let mut h = Sha256::new();
    let (used_s, limit_s) = (used.to_string(), limit.to_string());
    for part in [seq.to_string().as_str(), timestamp, actor, scope, endpoint, outcome, used_s.as_str(), limit_s.as_str(), prev] {
        h.update(part.as_bytes());
        h.update([0x1f]); // unit separator, so fields cannot run together
    }
    format!("{:x}", h.finalize())
}

/// Builds the next entry on top of `prev` (`None` for the first entry).
#[allow(clippy::too_many_arguments)]
pub fn next_entry(prev: Option<&AuditEntry>, timestamp: &str, actor: &str, scope: &str, endpoint: &str, outcome: &str, tokens_used: u64, token_limit: u64) -> AuditEntry {
    let (seq, prev_hash) = match prev {
        Some(p) => (p.seq + 1, p.hash.clone()),
        None => (0, "genesis".to_string()),
    };
    let hash = digest(seq, timestamp, actor, scope, endpoint, outcome, tokens_used, token_limit, &prev_hash);
    AuditEntry {
        seq,
        timestamp: timestamp.into(),
        actor: actor.into(),
        scope: scope.into(),
        endpoint: endpoint.into(),
        outcome: outcome.into(),
        tokens_used,
        token_limit,
        prev_hash,
        hash,
    }
}

/// Verifies every entry's hash and link. Returns the first broken `seq`, or `Ok(())`.
pub fn verify_chain(entries: &[AuditEntry]) -> Result<(), u64> {
    let mut prev: Option<&AuditEntry> = None;
    for e in entries {
        let expected_prev = prev.map(|p| p.hash.clone()).unwrap_or_else(|| "genesis".into());
        let expected_seq = prev.map(|p| p.seq + 1).unwrap_or(0);
        let recomputed = digest(e.seq, &e.timestamp, &e.actor, &e.scope, &e.endpoint, &e.outcome, e.tokens_used, e.token_limit, &e.prev_hash);
        if e.seq != expected_seq || e.prev_hash != expected_prev || e.hash != recomputed {
            return Err(e.seq);
        }
        prev = Some(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_extraction() {
        assert_eq!(host_of("http://localhost:8787/v1/inspect").as_deref(), Some("localhost"));
        assert_eq!(host_of("https://API.Example.com/x?q=1").as_deref(), Some("api.example.com"));
        assert_eq!(host_of("http://user:pw@10.0.0.5:8080/").as_deref(), Some("10.0.0.5"));
        assert_eq!(host_of("http://[::1]:9000/a").as_deref(), Some("::1"));
        assert_eq!(host_of("http:///nohost"), None);
    }

    #[test]
    fn allowlist_gates_hosts() {
        let list = vec!["localhost".to_string()];
        assert!(check_allowlist("http://localhost:8787/v1/inspect", &list).is_ok());
        assert!(check_allowlist("http://evil.example.com/x", &list).is_err());
    }

    #[test]
    fn empty_allowlist_refuses_everything() {
        assert!(check_allowlist("http://localhost:8787", &[]).is_err());
    }

    #[test]
    fn audit_chain_verifies_and_detects_tampering() {
        let a = next_entry(None, "t0", "alice", "scope", "http://localhost", "ok", 0, 0);
        let b = next_entry(Some(&a), "t1", "alice", "scope", "http://localhost", "ok", 0, 0);
        let c = next_entry(Some(&b), "t2", "bob", "scope", "http://localhost", "refused", 0, 0);
        let mut chain = vec![a.clone(), b.clone(), c.clone()];
        assert!(verify_chain(&chain).is_ok());

        // Editing an earlier record breaks the chain at that record.
        chain[1].outcome = "tampered".into();
        assert_eq!(verify_chain(&chain), Err(1));
    }

    #[test]
    fn token_usage_is_covered_by_the_chain() {
        let a = next_entry(None, "t0", "alice", "s", "e", "ok", 1200, 5000);
        let mut chain = vec![a];
        assert!(verify_chain(&chain).is_ok());
        // Under-reporting token usage after the fact must be detected.
        chain[0].tokens_used = 10;
        assert_eq!(verify_chain(&chain), Err(0));
    }

    #[test]
    fn deleting_a_record_is_detected() {
        let a = next_entry(None, "t0", "alice", "s", "e", "ok", 0, 0);
        let b = next_entry(Some(&a), "t1", "alice", "s", "e", "ok", 0, 0);
        let c = next_entry(Some(&b), "t2", "alice", "s", "e", "ok", 0, 0);
        let chain = vec![a, c]; // b removed
        assert!(verify_chain(&chain).is_err());
    }
}
