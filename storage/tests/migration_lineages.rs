//! Real SQLx history convergence; isolated database only, no ledger rewriting.
use clawforge_storage::PostgresStore;
use sqlx::{migrate::Migrator, PgPool};
use std::path::PathBuf;

#[tokio::test]
#[ignore = "requires CLAWFORGE_TEST_MIGRATION_URL on an isolated PostgreSQL instance"]
async fn both_historical_lineages_converge_without_rewriting_history() -> anyhow::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let base = std::env::var("CLAWFORGE_TEST_MIGRATION_URL")?;
    let admin = PgPool::connect(&base).await?;
    for production in [false, true] {
        let db = format!("phase11_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE {db}"))
            .execute(&admin)
            .await?;
        let url = format!("{}/{db}", base.rsplit_once('/').unwrap().0);
        let pool = PgPool::connect(&url).await?;
        let dir = std::env::temp_dir().join(&db);
        std::fs::create_dir(&dir)?;
        for entry in std::fs::read_dir(root.join("migrations"))? {
            let file = entry?.path();
            let name = file.file_name().unwrap().to_str().unwrap();
            let version: i64 = name.split('_').next().unwrap().parse()?;
            if version <= 46 || (production && version == 47) {
                if production && version == 46 {
                    std::fs::copy(
                        root.join("migration-history/0046_goaway_challenge_adapter.sql"),
                        dir.join("0046_goaway_challenge_adapter.sql"),
                    )?;
                } else {
                    std::fs::copy(&file, dir.join(name))?;
                }
            }
        }
        Migrator::new(dir.as_path()).await?.run(&pool).await?;
        let before: Vec<(i64, Vec<u8>, bool)> = sqlx::query_as(
            "SELECT version,checksum,success FROM _sqlx_migrations ORDER BY version",
        )
        .fetch_all(&pool)
        .await?;
        let legacy_name: String = sqlx::query_scalar(
            "SELECT name FROM actions WHERE id='00000000-0000-4000-8000-0000000000a9'",
        )
        .fetch_one(&pool)
        .await?;
        // Seed approved work against the lineage-specific legacy action.
        // Its enabled flag and immutable audit rows must survive convergence.
        sqlx::query(
            "UPDATE actions SET enabled=TRUE WHERE id='00000000-0000-4000-8000-0000000000a9'",
        )
        .execute(&pool)
        .await?;
        let requester = uuid::Uuid::new_v4();
        let one = uuid::Uuid::new_v4();
        let two = uuid::Uuid::new_v4();
        for (id, name, role) in [
            (requester, "legacy-requester", "Administrator"),
            (one, "legacy-approver1", "Approver"),
            (two, "legacy-approver2", "Approver"),
        ] {
            sqlx::query("INSERT INTO admin_users(id,username,role,password_hash) VALUES ($1,$2,$3,'test-only-not-a-login-hash')")
                .bind(id).bind(name).bind(role).execute(&pool).await?;
        }
        let request_id = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO execution_requests(id,action_id,requested_by,requested_by_id,status,required_approvals,approval_expires_at,approval_context,approval_context_hash) VALUES ($1,'00000000-0000-4000-8000-0000000000a9','legacy-requester',$2,'waiting_approval',2,NOW()+INTERVAL '1 hour','{\"legacy\":true}',repeat('11',32))")
            .bind(request_id).bind(requester).execute(&pool).await?;
        for (approver, name) in [(one, "legacy-approver1"), (two, "legacy-approver2")] {
            sqlx::query("INSERT INTO execution_approvals(id,execution_id,approver_id,approver_name,context_hash) VALUES ($1,$2,$3,$4,repeat('11',32))")
                .bind(uuid::Uuid::new_v4()).bind(request_id).bind(approver).bind(name).execute(&pool).await?;
        }
        sqlx::query("UPDATE execution_requests SET status='approved' WHERE id=$1")
            .bind(request_id)
            .execute(&pool)
            .await?;
        let action_before: serde_json::Value = sqlx::query_scalar(
            "SELECT to_jsonb(a) FROM actions a WHERE id='00000000-0000-4000-8000-0000000000a9'",
        )
        .fetch_one(&pool)
        .await?;
        let request_before: serde_json::Value =
            sqlx::query_scalar("SELECT to_jsonb(e) FROM execution_requests e WHERE id=$1")
                .bind(request_id)
                .fetch_one(&pool)
                .await?;
        let approvals_before: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(a) FROM execution_approvals a WHERE execution_id=$1 ORDER BY id",
        )
        .bind(request_id)
        .fetch_all(&pool)
        .await?;
        let store = PostgresStore::connect(&url).await?;
        let action_after: serde_json::Value = sqlx::query_scalar(
            "SELECT to_jsonb(a) FROM actions a WHERE id='00000000-0000-4000-8000-0000000000a9'",
        )
        .fetch_one(&pool)
        .await?;
        let request_after: serde_json::Value =
            sqlx::query_scalar("SELECT to_jsonb(e) FROM execution_requests e WHERE id=$1")
                .bind(request_id)
                .fetch_one(&pool)
                .await?;
        let approvals_after: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT to_jsonb(a) FROM execution_approvals a WHERE execution_id=$1 ORDER BY id",
        )
        .bind(request_id)
        .fetch_all(&pool)
        .await?;
        assert_eq!(
            action_before, action_after,
            "legacy action flags and metadata are preserved"
        );
        assert_eq!(request_before, request_after, "approved work is preserved");
        assert_eq!(
            approvals_before, approvals_after,
            "immutable approvals are preserved"
        );
        assert!(store.readiness().await?.current);
        assert_eq!(store.readiness().await?.latest, 54);
        let after: Vec<(i64, Vec<u8>, bool)> = sqlx::query_as("SELECT version,checksum,success FROM _sqlx_migrations WHERE version <= $1 ORDER BY version")
            .bind(if production { 47_i64 } else { 46 }).fetch_all(&pool).await?;
        assert_eq!(
            before, after,
            "historical checksums and rows must be unchanged"
        );
        let preserved: String = sqlx::query_scalar(
            "SELECT name FROM actions WHERE id='00000000-0000-4000-8000-0000000000a9'",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(
            legacy_name, preserved,
            "existing action identity must not be renamed"
        );
        let goaway: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM actions WHERE name IN ('goaway.challenge_indicator','goaway.challenge_incident_source')").fetch_one(&pool).await?;
        assert_eq!(goaway, 2);
        let quarantines: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM actions WHERE name IN ('docker.quarantine_container','proxmox.quarantine_vm','tailscale.quarantine_device') AND risk_level='critical' AND requires_approval AND NOT enabled").fetch_one(&pool).await?;
        assert_eq!(quarantines, 3);
        assert!(
            PostgresStore::connect_runtime(&url)
                .await?
                .readiness()
                .await?
                .current
        );
        assert!(
            PostgresStore::connect(&url)
                .await?
                .readiness()
                .await?
                .current
        );
        // Equal count/version can never disguise an unknown checksum.
        sqlx::query(
            "UPDATE _sqlx_migrations SET checksum=decode(repeat('00',48),'hex') WHERE version=46",
        )
        .execute(&pool)
        .await?;
        assert!(PostgresStore::connect_runtime(&url).await.is_err());
        assert!(PostgresStore::connect(&url).await.is_err());
        pool.close().await;
        store.pool().close().await;
        sqlx::query(&format!("DROP DATABASE {db} WITH (FORCE)"))
            .execute(&admin)
            .await?;
        std::fs::remove_dir_all(dir)?;
    }
    admin.close().await;
    Ok(())
}
