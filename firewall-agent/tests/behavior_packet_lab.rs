//! Actual adapter and TCP packet tests. Refuses to run in the invoking host's netns.
use clawforge_firewall_agent::{
    FirewallAction, FirewallAdapter, FirewallTarget, NftablesAdapter, VerificationResult,
};
use serde_json::json;
use std::{
    net::SocketAddr,
    process::Command,
    time::{Duration, Instant},
};
use tokio::net::{TcpListener, TcpSocket};

async fn connects(source: &str, destination: SocketAddr) -> bool {
    let sock = if destination.is_ipv4() {
        TcpSocket::new_v4().unwrap()
    } else {
        TcpSocket::new_v6().unwrap()
    };
    sock.bind(SocketAddr::new(source.parse().unwrap(), 0))
        .unwrap();
    matches!(
        tokio::time::timeout(Duration::from_millis(180), sock.connect(destination)).await,
        Ok(Ok(_))
    )
}

#[tokio::test]
#[ignore = "root in freshly unshared network namespace with explicit parent namespace identity"]
async fn isolated_adapter_packets_ttl_and_rollback() -> anyhow::Result<()> {
    let parent = std::env::var("CLAWFORGE_BEHAVIOR_HOST_NETNS")?;
    let current = std::fs::read_link("/proc/self/ns/net")?
        .to_string_lossy()
        .to_string();
    anyhow::ensure!(
        parent.starts_with("net:[") && parent != current,
        "refusing any host-network mutation"
    );
    let out = std::path::PathBuf::from(std::env::var("CLAWFORGE_BEHAVIOR_REPORT_DIR")?);
    let ip = |args: &[&str]| assert!(Command::new("ip").args(args).status().unwrap().success());
    ip(&["link", "set", "lo", "up"]);
    for address in ["203.0.113.18/32", "203.0.113.19/32", "192.0.2.1/32"] {
        ip(&["addr", "add", address, "dev", "lo"]);
    }
    for address in ["2001:db8::18/128", "2001:db8::19/128", "2001:db8::1/128"] {
        ip(&["-6", "addr", "add", address, "dev", "lo", "nodad"]);
    }
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../scripts/nftables-clawforge-provision.sh"
    );
    anyhow::ensure!(
        Command::new("sh").arg(script).status()?.success(),
        "isolated provisioning failed"
    );
    let mut results = Vec::new();
    for (source, legitimate, destination) in [
        ("203.0.113.18", "203.0.113.19", "192.0.2.1:0"),
        ("2001:db8::18", "2001:db8::19", "[2001:db8::1]:0"),
    ] {
        let listener = TcpListener::bind(destination).await?;
        let target = listener.local_addr()?;
        for repeat in 0..4 {
            let adapter = NftablesAdapter::new();
            let action = FirewallAction {
                target: FirewallTarget::ThreatIntelIndicator {
                    cidr: source.to_string(),
                    source: "controlled-isolated-fixture".into(),
                },
                ttl_seconds: 2,
                reason: "actual packet/TTL acceptance".into(),
            };
            anyhow::ensure!(
                connects(source, target).await && connects(legitimate, target).await,
                "baseline TCP"
            );
            let start = Instant::now();
            adapter.apply(&action, false).await?;
            anyhow::ensure!(
                adapter.verify(&action.target).await? == VerificationResult::Verified,
                "membership missing"
            );
            anyhow::ensure!(
                !connects(source, target).await,
                "blocked source TCP still passes"
            );
            anyhow::ensure!(
                connects(legitimate, target).await,
                "legitimate traffic was blocked"
            );
            // No rollback or sweep is run here: the kernel alone must expire the element.
            let deadline = Instant::now() + Duration::from_secs(4);
            while adapter.verify(&action.target).await? != VerificationResult::NotPresent {
                anyhow::ensure!(Instant::now() < deadline, "kernel expiry deadline");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            anyhow::ensure!(connects(source, target).await, "TCP not restored after TTL");
            results.push(json!({"source_family":if target.is_ipv4(){"ipv4"}else{"ipv6"},"repeat":repeat,"ttl_seconds":2,"restore_observed_seconds":start.elapsed().as_secs_f64(),"blocked_packet":true,"legitimate_packet_passed":true,"restored_packet":true}));
        }
        let adapter = NftablesAdapter::new();
        let action = FirewallAction {
            target: FirewallTarget::ThreatIntelIndicator {
                cidr: source.to_string(),
                source: "controlled-isolated-fixture".into(),
            },
            ttl_seconds: 60,
            reason: "explicit rollback acceptance".into(),
        };
        adapter.apply(&action, false).await?;
        anyhow::ensure!(!connects(source, target).await, "rollback baseline block");
        let start = Instant::now();
        adapter.rollback(&action).await?;
        anyhow::ensure!(
            connects(source, target).await,
            "explicit rollback failed to restore actual TCP"
        );
        results.push(json!({"explicit_adapter_rollback_seconds":start.elapsed().as_secs_f64(),"family":if target.is_ipv4(){"ipv4"}else{"ipv6"}}));
        let protected = FirewallAction {
            target: FirewallTarget::ThreatIntelIndicator {
                cidr: "127.0.0.1".into(),
                source: "fixture".into(),
            },
            ttl_seconds: 2,
            reason: "must reject protected address".into(),
        };
        anyhow::ensure!(
            adapter.apply(&protected, false).await.is_err(),
            "loopback protection bypassed"
        );
    }
    let mut observations: Vec<f64> = results
        .iter()
        .filter_map(|r| r["restore_observed_seconds"].as_f64())
        .collect();
    observations.sort_by(f64::total_cmp);
    let report = json!({"scope":"actual production nftables adapter and TCP packets in fresh private network namespace","parent_namespace":parent,"test_namespace":current,"same_namespace":false,"ttl_samples":observations.len(),"ttl_restore_observed_seconds_p95":observations[(observations.len()*95).div_ceil(100)-1],"ttl_restore_observed_seconds_max":observations.last(),"results":results,"limits":{"small_fixture_only":true,"production_network_slo":false,"executor_crash_recovery":"not covered by this adapter packet test","native_operator_kill_switch":"not covered; explicit adapter rollback only"}});
    std::fs::write(
        out.join("packet-report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    println!("PACKET_REPORT {}", report);
    Ok(())
}
