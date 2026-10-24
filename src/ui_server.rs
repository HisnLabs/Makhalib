//! Read-only results server for the Makhalib dashboard (`makhalib ui --port <n>`).
//!
//! It serves the built dashboard from `ui/dist` and exposes the exported run
//! reports from a reports directory. It never starts a scan: it only reads
//! files that a previous `redteam` run already wrote.
//!
//! Routes:
//! - `GET /api/runs` → list of runs (name, has_scorecard, started, bypass rate)
//! - `GET /api/runs/<name>` → that run's `results.json` plus `scorecard.md`
//! - anything else → static file from the dist directory (SPA fallback to index.html)

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

/// A run directory name is safe only if it is a single plain segment.
pub fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Lists run directories (those containing `results.json`), newest name first.
pub fn list_runs(reports: &Path) -> Vec<Value> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(reports) else {
        return out;
    };
    for e in entries.flatten() {
        let dir = e.path();
        let results = dir.join("results.json");
        let Ok(text) = fs::read_to_string(&results) else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let name = e.file_name().to_string_lossy().to_string();
        out.push(json!({
            "name": name,
            "has_scorecard": dir.join("scorecard.md").exists(),
            "started": v["meta"]["started"].clone(),
            "endpoint": v["meta"]["endpoint"].clone(),
            "total": v["total"].clone(),
            "bypassed": v["bypassed"].clone(),
            "bypass_rate": v["bypass_rate"].clone(),
        }));
    }
    out.sort_by(|a, b| b["name"].as_str().cmp(&a["name"].as_str()));
    out
}

/// Returns one run's report and scorecard, or `None` if the name is unsafe or missing.
pub fn load_run(reports: &Path, name: &str) -> Option<Value> {
    if !safe_name(name) {
        return None;
    }
    let dir = reports.join(name);
    let report: Value = serde_json::from_str(&fs::read_to_string(dir.join("results.json")).ok()?).ok()?;
    let scorecard = fs::read_to_string(dir.join("scorecard.md")).unwrap_or_default();
    Some(json!({ "name": name, "report": report, "scorecard": scorecard }))
}

/// Progress events for a run after index `since`, and whether the run has finished
/// (its `results.json` exists). Returns `None` for an unsafe or unknown run name.
pub fn live_events(reports: &Path, name: &str, since: usize) -> Option<Value> {
    if !safe_name(name) {
        return None;
    }
    let dir = reports.join(name);
    if !dir.is_dir() {
        return None;
    }
    let lines: Vec<Value> = fs::read_to_string(dir.join("progress.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect();
    let total = lines.len();
    let events: Vec<Value> = lines.into_iter().skip(since).collect();
    Some(json!({
        "name": name,
        "total": total,
        "since": since,
        "events": events,
        "done": dir.join("results.json").exists(),
    }))
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        _ => "application/octet-stream",
    }
}

fn respond(stream: &mut TcpStream, status: &str, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)
}

/// Resolves a request path to a file inside `dist`, refusing any traversal.
pub fn static_path(dist: &Path, url_path: &str) -> Option<PathBuf> {
    let clean = url_path.split('?').next()?.trim_start_matches('/');
    if clean.split('/').any(|seg| seg == ".." || seg.contains('\\')) {
        return None;
    }
    let candidate = if clean.is_empty() { dist.join("index.html") } else { dist.join(clean) };
    let canon = candidate.canonicalize().ok()?;
    let root = dist.canonicalize().ok()?;
    if canon.starts_with(&root) && canon.is_file() {
        Some(canon)
    } else {
        None
    }
}

fn handle(mut stream: TcpStream, reports: &Path, dist: &Path) -> std::io::Result<()> {
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf)?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let line = req.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");

    if method != "GET" {
        return respond(&mut stream, "405 Method Not Allowed", "text/plain", b"read-only");
    }
    if path == "/api/runs" {
        let body = serde_json::to_vec(&list_runs(reports)).unwrap_or_default();
        return respond(&mut stream, "200 OK", "application/json", &body);
    }
    if let Some(rest) = path.strip_prefix("/api/live/") {
        let (name, query) = rest.split_once('?').unwrap_or((rest, ""));
        let since = query
            .split('&')
            .find_map(|kv| kv.strip_prefix("since="))
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        return match live_events(reports, name, since) {
            Some(v) => respond(&mut stream, "200 OK", "application/json", &serde_json::to_vec(&v).unwrap_or_default()),
            None => respond(&mut stream, "404 Not Found", "text/plain", b"no such run"),
        };
    }
    if let Some(name) = path.strip_prefix("/api/runs/") {
        return match load_run(reports, name) {
            Some(v) => respond(&mut stream, "200 OK", "application/json", &serde_json::to_vec(&v).unwrap_or_default()),
            None => respond(&mut stream, "404 Not Found", "text/plain", b"no such run"),
        };
    }
    match static_path(dist, path).or_else(|| static_path(dist, "/index.html")) {
        Some(file) => {
            let body = fs::read(&file).unwrap_or_default();
            respond(&mut stream, "200 OK", content_type(&file), &body)
        }
        None => respond(&mut stream, "404 Not Found", "text/plain", b"build the UI first: cd ui && npm run build"),
    }
}

/// Serves the dashboard on `127.0.0.1:<port>` until the process is stopped.
pub fn serve(port: u16, reports: &Path, dist: &Path) -> std::io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!("makhalib ui · http://127.0.0.1:{port} · reports: {}", reports.display());
    for stream in listener.incoming().flatten() {
        let _ = handle(stream, reports, dist);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_name_rejects_traversal() {
        assert!(safe_name("gateway-20261024"));
        assert!(!safe_name(".."));
        assert!(!safe_name("a/b"));
        assert!(!safe_name(""));
        assert!(!safe_name("a\\b"));
    }

    #[test]
    fn list_and_load_runs_from_disk() {
        let root = std::env::temp_dir().join(format!("mkb-ui-{}", std::process::id()));
        let run = root.join("run-a");
        fs::create_dir_all(&run).unwrap();
        fs::write(
            run.join("results.json"),
            r#"{"total":3,"bypassed":1,"bypass_rate":0.33,"meta":{"started":"t","endpoint":"e"}}"#,
        )
        .unwrap();
        fs::write(run.join("scorecard.md"), "# card").unwrap();

        let runs = list_runs(&root);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0]["name"], "run-a");
        assert_eq!(runs[0]["has_scorecard"], true);

        let loaded = load_run(&root, "run-a").unwrap();
        assert_eq!(loaded["report"]["bypassed"], 1);
        assert!(load_run(&root, "../etc").is_none());
        assert!(load_run(&root, "missing").is_none());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn live_events_return_only_new_lines() {
        let root = std::env::temp_dir().join(format!("mkb-live-{}", std::process::id()));
        let run = root.join("run-x");
        fs::create_dir_all(&run).unwrap();
        fs::write(run.join("progress.jsonl"), "{\"score\":0.1}\n{\"score\":0.9}\n{\"score\":0.4}\n").unwrap();
        let all = live_events(&root, "run-x", 0).unwrap();
        assert_eq!(all["total"], 3);
        assert_eq!(all["events"].as_array().unwrap().len(), 3);
        assert_eq!(all["done"], false);
        let tail = live_events(&root, "run-x", 2).unwrap();
        assert_eq!(tail["events"].as_array().unwrap().len(), 1);
        assert!(live_events(&root, "../x", 0).is_none());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn static_path_stays_inside_dist() {
        let dist = std::env::temp_dir().join(format!("mkb-dist-{}", std::process::id()));
        fs::create_dir_all(&dist).unwrap();
        fs::write(dist.join("index.html"), "<html>").unwrap();
        assert!(static_path(&dist, "/").is_some());
        assert!(static_path(&dist, "/index.html").is_some());
        assert!(static_path(&dist, "/../secret").is_none());
        assert!(static_path(&dist, "/a/../../secret").is_none());
        let _ = fs::remove_dir_all(&dist);
    }
}
