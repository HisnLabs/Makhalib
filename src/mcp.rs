//! Read-only Model Context Protocol (MCP) server over stdio.
//!
//! Speaks JSON-RPC 2.0, one message per line, and exposes existing run reports
//! (`results.json`, `scorecard.md`, `remediation.csv`) to any MCP client. The
//! server never starts scans and never writes to disk.

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;

use serde_json::{json, Value};

use crate::ui_server::{list_runs, load_run, safe_name};

/// MCP protocol revision this server implements.
const PROTOCOL_VERSION: &str = "2024-11-05";

fn ok(id: Value, result: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string()
}

fn err(id: Value, code: i64, message: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}).to_string()
}

fn run_schema() -> Value {
    json!({
        "type": "object",
        "properties": {"run": {"type": "string", "description": "Run directory name"}},
        "required": ["run"]
    })
}

fn tools() -> Value {
    json!([
        {"name": "list_runs", "description": "List available scan runs with summary statistics.",
         "inputSchema": {"type": "object", "properties": {}}},
        {"name": "get_run", "description": "Get a run's full report and scorecard.",
         "inputSchema": run_schema()},
        {"name": "get_findings", "description": "Get the confirmed findings from a run's report.",
         "inputSchema": run_schema()},
        {"name": "get_remediation", "description": "Get a run's remediation.csv as text, if present.",
         "inputSchema": run_schema()}
    ])
}

/// Dispatches a tool by name; `Err` carries a message for an `isError` result.
fn call_tool(reports: &Path, name: &str, args: &Value) -> Result<Value, String> {
    if name == "list_runs" {
        return Ok(Value::Array(list_runs(reports)));
    }
    if !matches!(name, "get_run" | "get_findings" | "get_remediation") {
        return Err(format!("unknown tool: {name}"));
    }
    let run = args.get("run").and_then(Value::as_str).ok_or("missing required argument: run")?;
    if !safe_name(run) {
        return Err(format!("unsafe run name: {run}"));
    }
    match name {
        "get_run" => load_run(reports, run).ok_or_else(|| format!("run not found: {run}")),
        "get_findings" => {
            let v = load_run(reports, run).ok_or_else(|| format!("run not found: {run}"))?;
            Ok(v["report"]["findings"].clone())
        }
        _ => fs::read_to_string(reports.join(run).join("remediation.csv"))
            .map(Value::String)
            .map_err(|_| format!("no remediation.csv for run: {run}")),
    }
}

/// Handles one JSON-RPC request line and returns the response line, or `None`
/// for notifications (requests without an `id`).
pub fn handle_message(reports: &Path, line: &str) -> Option<String> {
    let Ok(msg) = serde_json::from_str::<Value>(line) else {
        return Some(err(Value::Null, -32700, "parse error"));
    };
    let id = msg.get("id").cloned()?;
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    Some(match method {
        "initialize" => ok(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "makhalib", "version": env!("CARGO_PKG_VERSION")}
            }),
        ),
        "ping" => ok(id, json!({})),
        "tools/list" => ok(id, json!({"tools": tools()})),
        "tools/call" => {
            let params = msg.get("params").cloned().unwrap_or(Value::Null);
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(Value::Null);
            let (text, is_error) = match call_tool(reports, name, &args) {
                Ok(Value::String(s)) => (s, false),
                Ok(v) => (v.to_string(), false),
                Err(e) => (e, true),
            };
            ok(id, json!({"content": [{"type": "text", "text": text}], "isError": is_error}))
        }
        _ => err(id, -32601, "method not found"),
    })
}

/// Serves MCP over stdin/stdout until stdin closes, flushing after every response.
pub fn serve(reports: &Path) -> io::Result<()> {
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(resp) = handle_message(reports, &line) {
            writeln!(out, "{resp}")?;
            out.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("mcp-{tag}-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn rpc(dir: &Path, req: Value) -> Value {
        serde_json::from_str(&handle_message(dir, &req.to_string()).unwrap()).unwrap()
    }

    fn make_run(dir: &Path) {
        let run = dir.join("run1");
        fs::create_dir_all(&run).unwrap();
        fs::write(
            run.join("results.json"),
            r#"{"total":2,"bypassed":1,"bypass_rate":0.5,"meta":{"endpoint":"e"},"findings":[{"id":"f1"}]}"#,
        )
        .unwrap();
        fs::write(run.join("remediation.csv"), "a,b\n1,2\n").unwrap();
    }

    #[test]
    fn initialize_reports_server_info() {
        let d = tmp("init");
        let r = rpc(&d, json!({"jsonrpc":"2.0","id":1,"method":"initialize"}));
        assert_eq!(r["result"]["serverInfo"]["name"], "makhalib");
        assert_eq!(r["result"]["protocolVersion"], "2024-11-05");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn tools_list_has_four_tools() {
        let d = tmp("list");
        let r = rpc(&d, json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}));
        let names: Vec<&str> = r["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        for n in ["list_runs", "get_run", "get_findings", "get_remediation"] {
            assert!(names.contains(&n), "missing {n}");
        }
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn call_list_runs_returns_run() {
        let d = tmp("runs");
        make_run(&d);
        let r = rpc(&d, json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_runs"}}));
        assert_eq!(r["result"]["isError"], false);
        assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("run1"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn findings_and_remediation_read() {
        let d = tmp("find");
        make_run(&d);
        let call = |n: &str| rpc(&d, json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":n,"arguments":{"run":"run1"}}}));
        assert!(call("get_findings")["result"]["content"][0]["text"].as_str().unwrap().contains("f1"));
        assert_eq!(call("get_remediation")["result"]["content"][0]["text"], "a,b\n1,2\n");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn unsafe_name_is_error() {
        let d = tmp("unsafe");
        let r = rpc(&d, json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_findings","arguments":{"run":"../etc"}}}));
        assert_eq!(r["result"]["isError"], true);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn unknown_tool_is_error() {
        let d = tmp("tool");
        let r = rpc(&d, json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope"}}));
        assert_eq!(r["result"]["isError"], true);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn malformed_json_is_parse_error() {
        let d = tmp("bad");
        let r: Value = serde_json::from_str(&handle_message(&d, "{not json").unwrap()).unwrap();
        assert_eq!(r["error"]["code"], -32700);
        assert!(r["id"].is_null());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn notification_has_no_response() {
        let d = tmp("note");
        assert!(handle_message(&d, r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).is_none());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn unknown_method_is_32601() {
        let d = tmp("meth");
        let r = rpc(&d, json!({"jsonrpc":"2.0","id":7,"method":"bogus"}));
        assert_eq!(r["error"]["code"], -32601);
        let _ = fs::remove_dir_all(&d);
    }
}
