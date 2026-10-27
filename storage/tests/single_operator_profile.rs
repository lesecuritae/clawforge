//! Isolated PostgreSQL tests of the explicit single-operator approval profile (migration 0071).
//! Default stays multi-person; the profile is deployment configuration (owner-role table), never a request field.
use clawforge_storage::{ExecutionRequestInput, PostgresStore};
use serde_json::json;
use sqlx::{postgres::PgConnectOptions, ConnectOptions, PgPool, Row};
use std::str::FromStr;
use uuid::Uuid;

const ACTION: &str = "nftables.block_incident_source";
const OTHER_ACTION: &str = "haproxy.block_incident_source";

#[tokio::test]
#[ignore = "requires an isolated CLAWFORGE_TEST_DATABASE_URL"]
async fn single_operator_profile_is_explicit_bounded_and_fails_closed() -> anyhow::Result<()> {
    let base = std::env::var("CLAWFORGE_TEST_DATABASE_URL")?;
    let admin = PgPool::connect(&base).await?;
    let database = format!("single_operator_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {database}"))
        .execute(&admin)
        .await?;
    let url = PgConnectOptions::from_str(&base)?
        .database(&database)
        .to_url_lossy()
        .to_string();
    let result = tokio::spawn(async move { checks(&url).await }).await;
    let cleanup = sqlx::query(&format!("DROP DATABASE {database} WITH (FORCE)"))
        .execute(&admin)
        .await;
    admin.close().await;
    cleanup?;
    result??;
    Ok(())
}

struct Env {
    store: PostgresStore,
}

impl Env {
    async fn user(&self, label: &str, role: &str) -> anyhow::Result<(Uuid, String)> {
        let name = format!("{label}-{}", Uuid::new_v4().simple());
        let id = self
            .store
            .create_admin_user(&name, role, "test-hash")
            .await?;
        Ok((id, name))
    }
    async fn action(&self, name: &str) -> anyhow::Result<Uuid> {
        sqlx::query("UPDATE actions SET enabled=TRUE, requires_approval=TRUE WHERE name=$1")
            .bind(name)
            .execute(self.store.pool())
            .await?;
        Ok(sqlx::query_scalar("SELECT id FROM actions WHERE name=$1")
            .bind(name)
            .fetch_one(self.store.pool())
            .await?)
    }
    async fn request(
        &self,
        action: Uuid,
        requester: (Uuid, &str),
        ip: &str,
    ) -> anyhow::Result<(Uuid, String)> {
        let id = self
            .store
            .create_execution_request(&ExecutionRequestInput {
                action_id: action,
                workflow_run_id: None,
                decision_id: None,
                requested_by: requester.1.to_string(),
                requested_by_id: Some(requester.0),
                idempotency_key: None,
                target: Some(
                    json!({"kind":"threat_intel_indicator","cidr":ip,"source":"profile-test"}),
                ),
            })
            .await?;
        let hash: String =
            sqlx::query_scalar("SELECT approval_context_hash FROM execution_requests WHERE id=$1")
                .bind(id)
                .fetch_one(self.store.pool())
                .await?;
        Ok((id, hash))
    }
    async fn profile(&self, sql: &str) -> anyhow::Result<()> {
        sqlx::query(sql).execute(self.store.pool()).await?;
        Ok(())
    }
    async fn status(&self, id: Uuid) -> anyhow::Result<String> {
        Ok(
            sqlx::query_scalar("SELECT status FROM execution_requests WHERE id=$1")
                .bind(id)
                .fetch_one(self.store.pool())
                .await?,
        )
    }
    async fn required(&self, id: Uuid) -> anyhow::Result<i32> {
        Ok(
            sqlx::query_scalar("SELECT required_approvals FROM execution_requests WHERE id=$1")
                .bind(id)
                .fetch_one(self.store.pool())
                .await?,
        )
    }
}

fn refused<T: std::fmt::Debug, E: std::fmt::Debug>(r: Result<T, E>, why: &str) {
    assert!(r.is_err(), "{why}: expected refusal, got {r:?}");
}

async fn checks(url: &str) -> anyhow::Result<()> {
    let env = Env {
        store: PostgresStore::connect(url).await?,
    };
    let nft = env.action(ACTION).await?;
    let hap = env.action(OTHER_ACTION).await?;
    let (op, op_name) = env.user("solo-operator", "Administrator").await?;
    let (other_admin, other_admin_name) = env.user("other-admin", "Administrator").await?;
    let (req, req_name) = env.user("requester", "Operator").await?;
    let set_single = |actions: &str, operator: Uuid| {
        format!("UPDATE approval_profile SET mode='single_operator', operator_user_id='{operator}', allowed_actions=ARRAY[{actions}]::TEXT[]")
    };

    // 1. Default: multi-person, nothing lowered, no marker, single confirmation unavailable.
    assert_eq!(env.store.approval_profile().await?.mode, "multi_person");
    let (r1, h1) = env.request(nft, (req, &req_name), "203.0.113.141").await?;
    assert_eq!(
        env.required(r1).await?,
        2,
        "default: the critical policy's two approvals"
    );
    let marker: bool = sqlx::query_scalar(
        "SELECT approval_context ? 'approval_profile' FROM execution_requests WHERE id=$1",
    )
    .bind(r1)
    .fetch_one(env.store.pool())
    .await?;
    assert!(!marker);
    refused(
        env.store
            .confirm_single_operator_execution(r1, op, &op_name, &h1)
            .await,
        "single confirmation under the default profile",
    );
    let first = env
        .store
        .approve_execution_request(r1, op, &op_name)
        .await?;
    assert_eq!(
        first["status"], "waiting_approval",
        "one distinct approval is not enough by default"
    );
    refused(
        env.store.approve_execution_request(r1, op, &op_name).await,
        "same identity twice",
    );
    refused(
        env.store
            .approve_execution_request(r1, req, &req_name)
            .await,
        "requester approving by default",
    );

    // 2. Profile table: constraints and ownership.
    refused(
        env.profile("UPDATE approval_profile SET mode='single_operator'")
            .await,
        "single_operator without operator and actions",
    );
    refused(
        env.profile("UPDATE approval_profile SET mode='surprise'")
            .await,
        "unknown mode",
    );
    refused(
        env.profile(&set_single("'docker.quarantine_container'", op))
            .await,
        "quarantine action in the allow list",
    );
    refused(
        env.profile(&set_single(
            "'nftables.block_incident_source','something.else'",
            op,
        ))
        .await,
        "arbitrary action in the allow list",
    );
    refused(
        env.profile(
            "INSERT INTO approval_profile (singleton, mode) VALUES (FALSE, 'multi_person')",
        )
        .await,
        "a second profile row",
    );
    assert_eq!(
        env.store.approval_profile().await?.mode,
        "multi_person",
        "refused changes leave the default"
    );

    // 3. Opt in (owner-role configuration): only the one account and the one action.
    env.profile(&set_single("'nftables.block_incident_source'", op))
        .await?;
    let p = env.store.approval_profile().await?;
    assert_eq!(
        (
            p.mode.as_str(),
            p.operator_user_id,
            p.allowed_actions.clone()
        ),
        ("single_operator", Some(op), vec![ACTION.to_string()])
    );
    let audited: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action='approval_profile_changed' AND details->>'mode'='single_operator'").fetch_one(env.store.pool()).await?;
    assert!(audited >= 1, "the profile change is audited");

    // 3a. Self-initiated and self-confirmed, explicit and context-bound.
    let (r2, h2) = env.request(nft, (op, &op_name), "203.0.113.142").await?;
    assert_eq!(env.required(r2).await?, 1);
    let ctx: serde_json::Value =
        sqlx::query_scalar("SELECT approval_context FROM execution_requests WHERE id=$1")
            .bind(r2)
            .fetch_one(env.store.pool())
            .await?;
    assert_eq!(ctx["approval_profile"]["mode"], "single_operator");
    assert_eq!(
        ctx["approval_profile"]["policy_required_approvals"], 2,
        "the lowered requirement is recorded, not hidden"
    );
    assert_eq!(ctx["required_approvals"], 1);
    assert!(
        !env.store.firewall_request_live_authorized(r2).await?,
        "not authorized before the confirmation"
    );
    refused(
        env.store
            .approve_execution_request(r2, other_admin, &other_admin_name)
            .await,
        "ordinary approval of a profile request by another administrator",
    );
    refused(
        env.store.approve_execution_request(r2, op, &op_name).await,
        "ordinary approval path used for the self-confirmation",
    );
    refused(
        env.store
            .confirm_single_operator_execution(r2, other_admin, &other_admin_name, &h2)
            .await,
        "confirmation by an administrator who is not the designated operator",
    );
    refused(
        env.store
            .confirm_single_operator_execution(r2, op, &op_name, &"0".repeat(64))
            .await,
        "wrong context hash",
    );
    assert_eq!(env.status(r2).await?, "waiting_approval");
    let done = env
        .store
        .confirm_single_operator_execution(r2, op, &op_name, &h2)
        .await?;
    assert_eq!(done["status"], "approved");
    assert!(
        env.store.firewall_request_live_authorized(r2).await?,
        "authorized by the confirmation under the active profile"
    );
    refused(
        env.store
            .confirm_single_operator_execution(r2, op, &op_name, &h2)
            .await,
        "replayed confirmation",
    );
    // Revocation: leaving the profile withdraws the lowered authorization immediately.
    env.profile("UPDATE approval_profile SET mode='multi_person', operator_user_id=NULL, allowed_actions='{}'").await?;
    assert!(
        !env.store.firewall_request_live_authorized(r2).await?,
        "profile off: the single confirmation no longer authorizes"
    );
    env.profile(&set_single("'nftables.block_incident_source'", op))
        .await?;

    // 3b. Separate requester and operator also works; an agent identity is not an administrator account at all.
    let (r3, h3) = env.request(nft, (req, &req_name), "203.0.113.143").await?;
    env.store
        .confirm_single_operator_execution(r3, op, &op_name, &h3)
        .await?;
    assert!(env.store.firewall_request_live_authorized(r3).await?);

    // 3c. Expired window, cancelled request, other action, non-Administrator operator.
    let (r4, h4) = env.request(nft, (op, &op_name), "203.0.113.144").await?;
    let mut tx = env.store.pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE execution_requests SET approval_expires_at = NOW() - INTERVAL '1 minute' WHERE id=$1").bind(r4).execute(&mut *tx).await?;
    tx.commit().await?;
    refused(
        env.store
            .confirm_single_operator_execution(r4, op, &op_name, &h4)
            .await,
        "expired window",
    );
    let (r5, h5) = env.request(nft, (op, &op_name), "203.0.113.145").await?;
    sqlx::query("UPDATE execution_requests SET status='cancelled' WHERE id=$1")
        .bind(r5)
        .execute(env.store.pool())
        .await?;
    refused(
        env.store
            .confirm_single_operator_execution(r5, op, &op_name, &h5)
            .await,
        "cancelled request",
    );
    let (r6, h6) = env.request(hap, (op, &op_name), "203.0.113.146").await?;
    assert_eq!(
        env.required(r6).await?,
        2,
        "an action outside the allow list keeps the policy's two approvals"
    );
    refused(
        env.store
            .confirm_single_operator_execution(r6, op, &op_name, &h6)
            .await,
        "action outside the allow list",
    );

    // 4. Direct database paths cannot bypass the profile.
    let direct = |required: i32, context: serde_json::Value| {
        let pool = env.store.pool().clone();
        async move {
            let hash = "a".repeat(64);
            sqlx::query("INSERT INTO execution_requests (id,action_id,requested_by,requested_by_id,status,required_approvals,approval_expires_at,approval_context,approval_context_hash,max_retries,timeout_seconds) VALUES ($1,$2,'direct',$3,'waiting_approval',$4,NOW()+INTERVAL '1 hour',$5,$6,0,60)")
                .bind(Uuid::new_v4()).bind(nft).bind(req).bind(required).bind(context).bind(hash).execute(&pool).await
        }
    };
    refused(
        direct(1, json!({})).await,
        "lowered requirement without the marker (profile active)",
    );
    refused(
        direct(
            1,
            json!({"approval_profile": {"mode":"single_operator","operator_user_id": other_admin}}),
        )
        .await,
        "marker naming another operator",
    );
    refused(
        direct(1, json!({"approval_profile": {"mode":"multi_person"}})).await,
        "marker with a different mode",
    );
    direct(
        1,
        json!({"approval_profile": {"mode":"single_operator","operator_user_id": op}}),
    )
    .await?; // the legitimate shape is accepted
    env.profile("UPDATE approval_profile SET mode='multi_person', operator_user_id=NULL, allowed_actions='{}'").await?;
    refused(
        direct(
            1,
            json!({"approval_profile": {"mode":"single_operator","operator_user_id": op}}),
        )
        .await,
        "marker accepted while the profile is off",
    );
    let direct_approval = sqlx::query("INSERT INTO execution_approvals (id,execution_id,approver_id,approver_name,context_hash,approval_mode) VALUES ($1,$2,$3,$4,$5,'single_operator_confirmation')")
        .bind(Uuid::new_v4()).bind(r1).bind(op).bind(&op_name).bind(&h1).execute(env.store.pool()).await;
    refused(
        direct_approval,
        "single-operator approval row while the profile is off",
    );

    // 5. Missing row and a disabled operator read as the default (fail closed).
    env.profile(&set_single("'nftables.block_incident_source'", op))
        .await?;
    sqlx::query("UPDATE admin_users SET enabled=FALSE WHERE id=$1")
        .bind(op)
        .execute(env.store.pool())
        .await?;
    assert_eq!(
        env.store.approval_profile().await?.mode,
        "multi_person",
        "disabled operator account: default"
    );
    sqlx::query("UPDATE admin_users SET enabled=TRUE WHERE id=$1")
        .bind(op)
        .execute(env.store.pool())
        .await?;
    assert_eq!(env.store.approval_profile().await?.mode, "single_operator");
    sqlx::query("DELETE FROM approval_profile")
        .execute(env.store.pool())
        .await?;
    assert_eq!(
        env.store.approval_profile().await?.mode,
        "multi_person",
        "missing row: default"
    );
    let n: i64 = sqlx::query("SELECT count(*) AS n FROM clawforge_approval_profile()")
        .fetch_one(env.store.pool())
        .await?
        .get("n");
    assert_eq!(n, 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires the provisioned fixture with CLAWFORGE_TEST_API_DATABASE_URL"]
async fn runtime_roles_cannot_change_the_profile() -> anyhow::Result<()> {
    let api = PgPool::connect(&std::env::var("CLAWFORGE_TEST_API_DATABASE_URL")?).await?;
    let denied = sqlx::query("UPDATE approval_profile SET note='changed by the api role'")
        .execute(&api)
        .await;
    assert!(
        denied.is_err(),
        "the API role must have no write privilege on the profile"
    );
    let denied = sqlx::query("SELECT mode FROM approval_profile")
        .fetch_all(&api)
        .await;
    assert!(
        denied.is_err(),
        "the API role reads the profile only through the function"
    );
    let mode: String = sqlx::query_scalar("SELECT mode FROM clawforge_approval_profile()")
        .fetch_one(&api)
        .await?;
    assert_eq!(mode, "multi_person");
    Ok(())
}
