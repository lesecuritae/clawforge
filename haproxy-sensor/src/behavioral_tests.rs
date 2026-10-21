//! Reviewed parser vectors and raw-journal fixtures; no production traffic.
use super::*;
use serde_json::{json, Value};

#[test]
fn reviewed_free_model_parser_vectors() {
    let data: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/behavior-validation/parser-vectors.json"
    ))
    .unwrap();
    for case in data["http"].as_array().unwrap() {
        let metrics = Metrics::default();
        let line = json!({"__CURSOR":case["id"],"MESSAGE":case["message"],
            "__REALTIME_TIMESTAMP":"1767268800000000","_HOSTNAME":"isolated-fixture"});
        let parsed = parse_journal_line(&line.to_string(), &metrics);
        let status = parsed.map(|r| match r.envelope.evidence {
            SecurityEventEvidence::HttpAnomaly(e) => i64::from(e.status_code),
            _ => panic!("incorrect event type"),
        });
        assert_eq!(
            status,
            case["expected_envelope_status"].as_i64(),
            "{}",
            case["id"]
        );
    }
}

#[test]
#[ignore = "exports real parser envelopes into an explicitly selected isolated report directory"]
fn export_behavioral_scenarios() -> anyhow::Result<()> {
    let out = std::path::PathBuf::from(std::env::var("CLAWFORGE_BEHAVIOR_REPORT_DIR")?);
    let plan: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/behavior-validation/scenarios.json"
    ))?;
    for (index, case) in plan["cases"].as_array().unwrap().iter().enumerate() {
        if case["kind"] != "http" {
            continue;
        }
        let metrics = Metrics::default();
        let mut events = Vec::new();
        for (n, offset) in case["offsets"].as_array().unwrap().iter().enumerate() {
            let ip = format!("203.0.113.{}", index + 1);
            let path = format!(
                "/fixture-{}",
                n % case["distinct_paths"].as_u64().unwrap() as usize
            );
            let message = format!("{ip}:54321 [01/Jan/2026:12:00:00.000] fe be/srv 0/0/0/1/1 {} 123 - - ---- 1/1/1/1/0 0/0 \"GET {path} HTTP/1.1\"",case["status"]);
            let line = json!({"__CURSOR":format!("behavior:{}:{n}",case["id"].as_str().unwrap()),
                "MESSAGE":message,"__REALTIME_TIMESTAMP":((1767268800_i64+offset.as_i64().unwrap())*1_000_000).to_string(),
                "_HOSTNAME":"isolated-fixture"});
            if let Some(parsed) = parse_journal_line(&line.to_string(), &metrics) {
                events.push(serde_json::to_value(parsed.envelope)?);
            }
        }
        let artifact = json!({"case":case,"events":events,"input_lines":case["event_count"],
            "parser_drops":metrics.dropped_total.load(Ordering::Relaxed),"scope":"actual HAProxy journal parser"});
        std::fs::write(
            out.join(format!("{}.json", case["id"].as_str().unwrap())),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    Ok(())
}
