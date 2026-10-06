//! Native quarantine generations: committed snapshots precede mutation and row
//! locks fence recovery. Unknown remote completion never triggers automatic replay.
use crate::quarantine_gate::{self, QuarantineIdentity, QuarantineKind};
use anyhow::{bail, Context, Result};
use clawforge_firewall_agent::{
    docker::DockerAdapter, proxmox::ProxmoxAdapter, quarantine::QuarantineTarget,
    VerificationResult,
};
use clawforge_storage::{
    ClaimedExecutionRequest, FirewallActionReceiptInput, PostgresStore, QuarantineIntent,
};
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RecoveryOutcome {
    Restored,
    Resolved,
    Busy,
    ManualReview,
}

/// Snapshot metadata can enrich only the rollback call, never the approved target.
fn restore_target(intent: &QuarantineIntent) -> Result<Value> {
    let context =
        quarantine_gate::validate_context(&intent.action_name, &intent.target_json, true)?;
    let (adapter, fingerprint, field) = match context.target {
        QuarantineIdentity::Docker { container_id } => ("docker", container_id, "networks"),
        QuarantineIdentity::Proxmox { node, vmid } => {
            ("proxmox", format!("{node}/{vmid}"), "original_net0")
        }
        QuarantineIdentity::Tailscale { .. } => {
            bail!("Tailscale exact reversible snapshot and policy evidence require manual review")
        }
    };
    if adapter != intent.adapter || fingerprint != intent.target_fingerprint {
        bail!("quarantine generation identity mismatch");
    }
    let snapshot = intent
        .rollback_plan
        .get(field)
        .context("quarantine restore snapshot missing")?;
    let mut target = intent.target_json.clone();
    target
        .as_object_mut()
        .context("invalid quarantine target")?
        .insert(field.into(), snapshot.clone());
    Ok(target)
}

/// Called with an exact generation ID. A resolved old ID cannot restore a newer
/// generation at the same target. The lock remains held through remote readback
/// and the atomic rollback receipt; a competing sweep must retry later.
pub(crate) async fn recover(store: &PostgresStore, id: Uuid) -> Result<RecoveryOutcome> {
    let Some(guard) = store.acquire_quarantine_guard(id).await? else {
        return match store.quarantine_intent(id).await? {
            Some(intent) if matches!(intent.status.as_str(), "rolled_back" | "not_applied") => {
                Ok(RecoveryOutcome::Resolved)
            }
            Some(_) => Ok(RecoveryOutcome::Busy),
            None => bail!("quarantine generation not found"),
        };
    };
    if guard.intent().status != "completed" {
        // Prepared may have crashed before IO OR after submitting an async task.
        // Neither snapshot equality nor a retry proves that task cannot still run.
        if guard.intent().status == "prepared" {
            guard.recovery_required().await?;
        }
        return Ok(RecoveryOutcome::ManualReview);
    }
    let target = match restore_target(guard.intent()) {
        Ok(target) => target,
        Err(_) => {
            guard.recovery_required().await?;
            return Ok(RecoveryOutcome::ManualReview);
        }
    };
    let Some(inflight_id) = crate::try_begin_inflight(store, &guard.intent().adapter)
        .await
        .map_err(|_| anyhow::anyhow!("quarantine recovery concurrency lease unavailable"))?
    else {
        return Ok(RecoveryOutcome::Busy);
    };
    let result = crate::rollback_target(
        &guard.intent().adapter,
        &target,
        format!("quarantine generation {id} rollback"),
    )
    .await;
    if store
        .end_firewall_inflight_operation(inflight_id)
        .await
        .is_err()
    {
        tracing::warn!(intent_id=%id, "quarantine recovery concurrency lease could not be released");
    }
    if result.is_err() {
        guard.recovery_required().await?;
        return Ok(RecoveryOutcome::ManualReview);
    }
    guard.resolve_rollback().await?;
    Ok(RecoveryOutcome::Restored)
}

pub(crate) async fn sweep(store: &PostgresStore) {
    let intents = match store.recoverable_quarantine_intents().await {
        Ok(intents) => intents,
        Err(_) => {
            tracing::warn!("quarantine recovery lookup failed");
            return;
        }
    };
    for intent in intents {
        // Durable recovery_required is deliberately not retried every tick.
        if intent.status == "recovery_required" {
            continue;
        }
        match recover(store, intent.id).await {
            Ok(RecoveryOutcome::Restored) => {
                tracing::info!(intent_id=%intent.id, "quarantine snapshot restored and generation resolved")
            }
            Ok(RecoveryOutcome::ManualReview) => {
                tracing::warn!(intent_id=%intent.id, "quarantine completion unknown; ownership retained for manual reconciliation")
            }
            Ok(_) => {}
            Err(_) => {
                tracing::warn!(intent_id=%intent.id, "quarantine recovery failed; generation retained")
            }
        }
    }
}

/// Production entry point deliberately retains the hard gate. No configuration
/// switch can activate the inner write-ahead pipeline without a reviewed change.
pub(crate) async fn dispatch(
    store: &PostgresStore,
    claimed: &ClaimedExecutionRequest,
) -> (
    bool,
    Option<String>,
    Option<String>,
    Vec<crate::FirewallDispatchReceipt>,
) {
    if QuarantineKind::from_action_name(&claimed.action_name).is_none()
        || crate::dispatch_dry_run(claimed)
    {
        return crate::dispatch(claimed).await;
    }
    let result = async {
        quarantine_gate::ensure_live_dispatch_disabled(false)?;
        apply_prepared(store, claimed).await
    }
    .await;
    match result {
        Ok(()) => (
            true,
            Some("verified native quarantine generation committed".into()),
            None,
            vec![],
        ),
        Err(_) => (
            false,
            None,
            Some("live quarantine refused or requires verified recovery".into()),
            vec![],
        ),
    }
}

/// Inner pipeline is unreachable from live production dispatch while the gate is
/// closed. Complete authoritative preflight, commit intent, acquire generation
/// lock, compare fresh snapshot, mutate, verify, atomically finish. No best-effort
/// receipt and no automatic retry of ambiguous remote mutation.
async fn apply_prepared(store: &PostgresStore, claimed: &ClaimedExecutionRequest) -> Result<()> {
    apply_prepared_observed(store, claimed, |_| async { Ok(()) }).await
}

async fn apply_prepared_observed<F, Fut>(
    store: &PostgresStore,
    claimed: &ClaimedExecutionRequest,
    observer: F,
) -> Result<()>
where
    F: FnOnce(Uuid) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let target = claimed
        .target
        .as_ref()
        .context("quarantine target missing")?;
    let context = quarantine_gate::validate_context(&claimed.action_name, target, false)?;
    let (adapter_name, fingerprint, preflight, plan, qtarget) = match context.target {
        QuarantineIdentity::Docker { container_id } => {
            let qtarget = QuarantineTarget::Docker {
                container_id: container_id.clone(),
            };
            let pf = DockerAdapter::new().preflight(&qtarget).await?;
            if pf.protected || pf.currently_quarantined || pf.networks.is_empty() {
                bail!("Docker preflight refused");
            }
            (
                "docker",
                container_id,
                json!({"container_id":pf.container_id,"networks":pf.networks,"protected":false,"currently_quarantined":false}),
                json!({"networks":pf.networks}),
                qtarget,
            )
        }
        QuarantineIdentity::Proxmox { node, vmid } => {
            let qtarget = QuarantineTarget::Proxmox {
                node: node.clone(),
                vmid,
            };
            let pf = ProxmoxAdapter::new().preflight(&qtarget).await?;
            if pf.protected || pf.currently_quarantined {
                bail!("Proxmox preflight refused");
            }
            (
                "proxmox",
                format!("{node}/{vmid}"),
                json!({"node":pf.node,"vmid":pf.vmid,"net0":pf.net0,"protected":false,"currently_quarantined":false}),
                json!({"original_net0":pf.net0}),
                qtarget,
            )
        }
        QuarantineIdentity::Tailscale { .. } => {
            bail!("Tailscale reversible snapshot and policy proof unavailable")
        }
    };
    let id = store
        .prepare_quarantine_intent(
            claimed.id,
            adapter_name,
            &fingerprint,
            target,
            &preflight,
            &plan,
            context.ttl_seconds,
        )
        .await?;
    let mut guard = store
        .acquire_quarantine_guard(id)
        .await?
        .context("prepared generation busy")?;
    if guard.intent().status != "prepared" {
        bail!("prepared generation was already assigned to recovery; mutation refused");
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    if guard.intent().expires_at.timestamp() <= i64::try_from(now)? {
        bail!("prepared generation expired before mutation; recovery required");
    }
    guard.validate_approval().await?;
    observer(id).await?;
    let outcome: Result<Value> = async {
        if adapter_name == "docker" {
            let networks: Vec<clawforge_firewall_agent::docker::NetworkAttachment> =
                serde_json::from_value(plan["networks"].clone())?;
            let adapter = DockerAdapter::new();
            let applied = adapter.apply_prepared(&qtarget, &networks).await?;
            if adapter.verify(&qtarget).await? != VerificationResult::Verified {
                bail!("Docker verification failed");
            }
            Ok(json!({"disconnected_networks":applied}))
        } else {
            let adapter = ProxmoxAdapter::new();
            adapter
                .apply_prepared(
                    &qtarget,
                    plan["original_net0"]
                        .as_str()
                        .context("NIC snapshot missing")?,
                )
                .await?;
            if adapter.verify(&qtarget).await? != VerificationResult::Verified {
                bail!("Proxmox verification failed");
            }
            Ok(json!({"isolated":true}))
        }
    }
    .await;
    let observed = match outcome {
        Ok(value) => value,
        Err(_) => {
            guard.recovery_required().await?;
            bail!("quarantine mutation or verification uncertain; recovery required");
        }
    };
    guard
        .finish(&FirewallActionReceiptInput {
            execution_id: Some(claimed.id),
            adapter: adapter_name,
            action_name: &claimed.action_name,
            preflight_state: preflight,
            rendered_commands: json!([]),
            observed_state: Some(observed),
            verification_result: Some("verified"),
            ttl_seconds: context.ttl_seconds,
            rollback_plan: plan,
            is_dry_run: false,
            receipt_kind: "apply",
            target_fingerprint: Some(&fingerprint),
            target_json: Some(target.clone()),
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn intent(
        adapter: &str,
        action: &str,
        target: Value,
        plan: Value,
        fp: &str,
    ) -> QuarantineIntent {
        // Reuse a deserialized timestamp through the production row type without
        // introducing an executor-only clock dependency.
        QuarantineIntent {
            id: Uuid::new_v4(),
            execution_id: Uuid::new_v4(),
            adapter: adapter.into(),
            action_name: action.into(),
            target_fingerprint: fp.into(),
            target_json: target,
            preflight_state: json!({}),
            rollback_plan: plan,
            ttl_seconds: 60,
            expires_at: serde_json::from_value(json!("2026-01-01T00:00:00Z")).unwrap(),
            status: "completed".into(),
        }
    }
    #[test]
    fn exact_restore_snapshot_is_separate_from_approved_target() {
        let id = "a".repeat(64);
        let target = json!({"kind":"docker","container_id":id});
        let item = intent(
            "docker",
            "docker.quarantine_container",
            target.clone(),
            json!({"networks":[{"alias":"immutable"}]}),
            &id,
        );
        let restored = restore_target(&item).unwrap();
        assert_eq!(restored["networks"], item.rollback_plan["networks"]);
        assert_eq!(item.target_json, target);
        assert!(item.target_json.get("networks").is_none());
    }
    #[test]
    fn mismatched_generation_or_missing_snapshot_never_restores() {
        let mut item = intent(
            "proxmox",
            "proxmox.quarantine_vm",
            json!({"node":"pve","vmid":9000}),
            json!({"original_net0":"virtio=aa,link_down=0"}),
            "pve/9001",
        );
        assert!(restore_target(&item).is_err());
        item.target_fingerprint = "pve/9000".into();
        assert_eq!(
            restore_target(&item).unwrap()["original_net0"],
            "virtio=aa,link_down=0"
        );
        item.rollback_plan = json!({});
        assert!(restore_target(&item).is_err());
    }
    #[test]
    fn tailscale_tag_presence_is_not_reversible_isolation_evidence() {
        let item = intent(
            "tailscale",
            "tailscale.quarantine_device",
            json!({"device_id":"123"}),
            json!({"tags":[]}),
            "123",
        );
        assert!(restore_target(&item).is_err());
    }
    struct DockerLab {
        container: String,
        networks: Vec<String>,
        previous_guard: Option<String>,
    }
    impl Drop for DockerLab {
        fn drop(&mut self) {
            let _ = std::process::Command::new("docker")
                .args(["rm", "-f", &self.container])
                .output();
            for network in &self.networks {
                let _ = std::process::Command::new("docker")
                    .args(["network", "rm", network])
                    .output();
            }
            match &self.previous_guard {
                Some(v) => std::env::set_var("CLAWFORGE_DOCKER_NEVER_QUARANTINE", v),
                None => std::env::remove_var("CLAWFORGE_DOCKER_NEVER_QUARANTINE"),
            }
        }
    }
    fn docker(args: &[&str]) -> Result<String> {
        let output = std::process::Command::new("docker").args(args).output()?;
        if !output.status.success() {
            bail!(
                "disposable Docker fixture command failed ({})",
                output.status
            );
        }
        Ok(String::from_utf8(output.stdout)?.trim().into())
    }
    async fn approved(store: &PostgresStore, target: &Value) -> Result<ClaimedExecutionRequest> {
        let action:Uuid=sqlx::query_scalar("UPDATE actions SET enabled=TRUE,risk_level='critical',requires_approval=TRUE WHERE name='docker.quarantine_container' RETURNING id").fetch_one(store.pool()).await?;
        let suffix = Uuid::new_v4();
        let name = format!("native-lab-requester-{suffix}");
        let requester = store
            .create_admin_user(&name, "Administrator", "fixture-hash")
            .await?;
        let id = store
            .create_execution_request(&clawforge_storage::ExecutionRequestInput {
                action_id: action,
                workflow_run_id: None,
                decision_id: None,
                requested_by: name,
                requested_by_id: Some(requester),
                idempotency_key: None,
                target: Some(target.clone()),
            })
            .await?;
        for index in [1, 2] {
            let name = format!("native-lab-approver-{suffix}-{index}");
            let user = store
                .create_admin_user(&name, "Approver", "fixture-hash")
                .await?;
            store.approve_execution_request(id, user, &name).await?;
        }
        sqlx::query("UPDATE execution_requests SET status='starting' WHERE id=$1")
            .bind(id)
            .execute(store.pool())
            .await?;
        Ok(ClaimedExecutionRequest {
            id,
            action_name: "docker.quarantine_container".into(),
            target: Some(target.clone()),
        })
    }
    #[tokio::test]
    #[ignore = "own Docker container/networks and explicit disposable schema-54 PostgreSQL; run alone"]
    async fn native_controller_writeahead_recovery_and_stale_generation_lab() -> Result<()> {
        let url = std::env::var("CLAWFORGE_TEST_QUARANTINE_DATABASE_URL")?;
        // Restrict the explicit fixture URL to dedicated local test ports and
        // database names; never print credentials on connection failures.
        let authority = url
            .rsplit_once('@')
            .map(|(_, tail)| tail)
            .context("explicit fixture URL must have credentials")?;
        let (host, database) = authority
            .split_once('/')
            .context("explicit fixture database missing")?;
        let database = database.split('?').next().unwrap_or_default();
        if !matches!(host, "127.0.0.1:55432" | "127.0.0.1:55436")
            || !database.starts_with("clawforge_test")
        {
            bail!(
                "controller lab requires dedicated loopback test port and clawforge_test database"
            );
        }
        let store = PostgresStore::connect_runtime(&url)
            .await
            .map_err(|_| anyhow::anyhow!("fixture DB unavailable"))?;
        let suffix = Uuid::new_v4().simple().to_string();
        let mut lab = DockerLab {
            container: format!("clawforge-native-{}", &suffix[..12]),
            networks: vec![],
            previous_guard: std::env::var("CLAWFORGE_DOCKER_NEVER_QUARANTINE").ok(),
        };
        let octet = u8::from_str_radix(&suffix[..2], 16)?.max(1);
        for index in [0, 1] {
            let name = format!("clawforge-native-{}-{index}", &suffix[..12]);
            let subnet = format!("10.{}.{}.0/24", 240 + index, octet);
            docker(&[
                "network",
                "create",
                "--label",
                "clawforge.disposable=native-controller",
                "--subnet",
                &subnet,
                &name,
            ])?;
            lab.networks.push(name);
        }
        let first_ip = format!("10.240.{octet}.23");
        let second_ip = format!("10.241.{octet}.23");
        let cid = docker(&[
            "run",
            "-d",
            "--label",
            "clawforge.disposable=native-controller",
            "--name",
            &lab.container,
            "--network",
            &lab.networks[0],
            "--network-alias",
            "native-first",
            "--ip",
            &first_ip,
            "alpine:latest",
            "sleep",
            "600",
        ])?;
        docker(&[
            "network",
            "connect",
            "--alias",
            "native-second",
            "--ip",
            &second_ip,
            &lab.networks[1],
            &cid,
        ])?;
        std::env::set_var(
            "CLAWFORGE_DOCKER_NEVER_QUARANTINE",
            format!("docker:{}", "f".repeat(64)),
        );
        let qtarget = QuarantineTarget::Docker {
            container_id: cid.clone(),
        };
        let original = DockerAdapter::new().preflight(&qtarget).await?.networks;
        assert_eq!(original.len(), 2);
        let target = json!({"kind":"docker","container_id":cid,"ttl_seconds":60,"data_owner":"disposable test fixture","snapshot_restore_reference":"own immutable Docker networks","management_network_plan":"host and production containers protected; fixture only"});
        let request = approved(&store, &target).await?;
        let observer_store = &store;
        let observer_target = &target;
        let observer_original = &original;
        let observer_qtarget = &qtarget;
        apply_prepared_observed(&store, &request, |id| async move {
            let (store, target, original, qtarget) = (
                observer_store,
                observer_target,
                observer_original,
                observer_qtarget,
            );
            let intent = store
                .quarantine_intent(id)
                .await?
                .context("writeahead generation absent")?;
            assert_eq!(intent.status, "prepared");
            assert_eq!(&intent.target_json, target);
            assert_eq!(intent.rollback_plan["networks"], json!(original));
            assert_eq!(
                DockerAdapter::new().preflight(qtarget).await?.networks,
                *original,
                "snapshot committed before network mutation"
            );
            let receipts: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM firewall_action_receipts WHERE intent_id=$1",
            )
            .bind(id)
            .fetch_one(store.pool())
            .await?;
            assert_eq!(receipts, 0);
            Ok(())
        })
        .await?;
        let first: Uuid =
            sqlx::query_scalar("SELECT id FROM firewall_action_intents WHERE execution_id=$1")
                .bind(request.id)
                .fetch_one(store.pool())
                .await?;
        assert_eq!(
            store.quarantine_intent(first).await?.unwrap().status,
            "completed"
        );
        assert!(DockerAdapter::new()
            .preflight(&qtarget)
            .await?
            .networks
            .is_empty());
        let delayed_kill = store
            .create_firewall_kill_switch_request(
                "docker",
                &cid,
                &target,
                Some("disposable delayed generation test"),
                "fixture",
                None,
            )
            .await?;
        let pending = store.pending_firewall_kill_switch_requests().await?;
        let bound = pending
            .iter()
            .find(|row| row.request_id == delayed_kill)
            .context("bound kill request missing")?;
        assert_eq!(bound.quarantine_intent_id, Some(first));
        // Real TTL scheduling path: before expiry no restore, after expiry the
        // normal sweep must resolve exactly this generation without direct IO calls.
        sweep(&store).await;
        assert_eq!(
            store.quarantine_intent(first).await?.unwrap().status,
            "completed"
        );
        tokio::time::sleep(std::time::Duration::from_secs(61)).await;
        sweep(&store).await;
        assert_eq!(
            store.quarantine_intent(first).await?.unwrap().status,
            "rolled_back"
        );
        assert_eq!(
            DockerAdapter::new().preflight(&qtarget).await?.networks,
            original
        );
        assert_eq!(recover(&store, first).await?, RecoveryOutcome::Resolved);
        let request2 = approved(&store, &target).await?;
        apply_prepared(&store, &request2).await?;
        assert_eq!(
            recover(&store, first).await?,
            RecoveryOutcome::Resolved,
            "stale generation must not touch newer quarantine"
        );
        let pending = store.pending_firewall_kill_switch_requests().await?;
        let bound = pending
            .iter()
            .find(|row| row.request_id == delayed_kill)
            .context("delayed kill request lost")?;
        assert_eq!(
            recover(&store, bound.quarantine_intent_id.unwrap()).await?,
            RecoveryOutcome::Resolved
        );
        store
            .mark_firewall_kill_switch_request_processed(delayed_kill)
            .await?;
        assert!(DockerAdapter::new()
            .preflight(&qtarget)
            .await?
            .networks
            .is_empty());
        let second: Uuid =
            sqlx::query_scalar("SELECT id FROM firewall_action_intents WHERE execution_id=$1")
                .bind(request2.id)
                .fetch_one(store.pool())
                .await?;
        assert_eq!(recover(&store, second).await?, RecoveryOutcome::Restored);
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM firewall_action_receipts WHERE intent_id IN ($1,$2)",
        )
        .bind(first)
        .bind(second)
        .fetch_one(store.pool())
        .await?;
        assert_eq!(
            count, 4,
            "exactly one apply and rollback receipt per generation"
        );
        assert_eq!(
            DockerAdapter::new().preflight(&qtarget).await?.networks,
            original
        );
        // Real INSERT failure after successful mutation must leave durable
        // prepared ownership, never success or an automatic mutation replay.
        let request3 = approved(&store, &target).await?;
        let constraint = format!("native_fixture_fault_{}", &suffix[..12]);
        sqlx::query(&format!("ALTER TABLE firewall_action_receipts ADD CONSTRAINT {constraint} CHECK(execution_id <> '{}'::uuid OR receipt_kind <> 'apply')",request3.id)).execute(store.pool()).await?;
        let result = apply_prepared(&store, &request3).await;
        sqlx::query(&format!(
            "ALTER TABLE firewall_action_receipts DROP CONSTRAINT {constraint}"
        ))
        .execute(store.pool())
        .await?;
        assert!(result.is_err(), "receipt failure must not return success");
        let failed: Uuid =
            sqlx::query_scalar("SELECT id FROM firewall_action_intents WHERE execution_id=$1")
                .bind(request3.id)
                .fetch_one(store.pool())
                .await?;
        assert_eq!(
            store.quarantine_intent(failed).await?.unwrap().status,
            "prepared"
        );
        assert_eq!(
            recover(&store, failed).await?,
            RecoveryOutcome::ManualReview
        );
        assert!(
            DockerAdapter::new()
                .preflight(&qtarget)
                .await?
                .networks
                .is_empty(),
            "unknown completion recovery must not replay or reconnect"
        );
        // Explicit lab operator reconciliation with authoritative readback.
        let guard = store
            .acquire_quarantine_guard(failed)
            .await?
            .context("fault generation ownership missing")?;
        DockerAdapter::new().rollback(&qtarget, &original).await?;
        guard.resolve_rollback().await?;
        assert_eq!(
            DockerAdapter::new().preflight(&qtarget).await?.networks,
            original
        );
        Ok(())
    }
}
