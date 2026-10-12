use clawforge_storage::{
    LearningEvidence, LearningLessonInput, LearningQuery, LearningReview, PostgresStore,
};
use serde_json::json;
use uuid::Uuid;
fn lesson(key: &str) -> LearningLessonInput {
    LearningLessonInput {
        idempotency_key: key.into(),
        context: Default::default(),
        repository: "fixture-repository".into(),
        component: "learning".into(),
        title: "checked fix".into(),
        symptoms: "fixture failure".into(),
        cause: "race".into(),
        fix: "transaction".into(),
        rule: "check durable state".into(),
        validity: json!({"platform":"linux","framework":"rust"}),
        tags: vec!["fixture".into()],
        evidence: LearningEvidence {
            commit: "960f4d567e9968394bd4a43d736089583e9d0d46".into(),
            test: "learning::lifecycle".into(),
            artifact_sha256: "0".repeat(64),
            passed: true,
        },
    }
}
#[test]
fn malformed_or_secret_payload_rejected() {
    let mut x = lesson("key");
    assert!(x.validate().is_ok());
    x.evidence.commit = "0".repeat(64);
    assert!(x.validate().is_ok());
    x.evidence.commit = "0".repeat(41);
    assert!(x.validate().is_err());
    x = lesson("key");
    x.validity = json!({"password":"not-allowed"});
    assert!(x.validate().is_err());
    x = lesson("key");
    x.tags = vec!["nvapi-".into()];
    assert!(x.validate().is_err());
    x = lesson("key");
    x.context.confidence = Some(1.1);
    assert!(x.validate().is_err());
    x = lesson("key");
    x.context
        .versions
        .insert("secret".into(), "discard-me".into());
    assert!(x.validate().is_err());
}
#[tokio::test]
#[ignore = "requires isolated PostgreSQL learning fixture"]
async fn learning_lifecycle_and_isolation() -> anyhow::Result<()> {
    let store =
        PostgresStore::connect(&std::env::var("CLAWFORGE_LEARNING_TEST_DATABASE_URL")?).await?;
    let owner = Uuid::new_v4();
    let stranger = Uuid::new_v4();
    let curator = Uuid::new_v4();
    let mut input = lesson("first");
    input.context.language = Some("rust".into());
    input.context.framework = Some("axum".into());
    input.context.platform = Some("linux".into());
    input.context.provider = Some("fixture-provider".into());
    input.context.model = Some("fixture-model".into());
    input.context.project = Some("fixture-project".into());
    input.context.error_class = Some("race".into());
    input.context.files = vec!["storage/src/learning.rs".into()];
    input
        .context
        .versions
        .insert("clawforge".into(), "1.0.0".into());
    input.context.confidence = Some(0.9);
    let (a, b) = tokio::join!(
        store.propose_learning(owner, &input),
        store.propose_learning(owner, &input)
    );
    let first = a?;
    assert_eq!(first, b?);
    assert_eq!(first, store.propose_learning(owner, &input).await?);
    let id: Uuid = serde_json::from_value(first["id"].clone())?;
    let rid: Uuid = serde_json::from_value(first["revision_id"].clone())?;
    assert!(store
        .query_learning(owner, &LearningQuery::default())
        .await?["data"]
        .as_array()
        .unwrap()
        .is_empty());
    let pending = LearningQuery {
        status: Some("pending".into()),
        ..Default::default()
    };
    let data = store.query_learning(owner, &pending).await?;
    assert_eq!(
        data["data"][0]["payload"]["evidence"]["commit"],
        input.evidence.commit
    );
    assert!(store.query_learning(stranger, &pending).await?["data"]
        .as_array()
        .unwrap()
        .is_empty());
    let mut mismatch = input.clone();
    mismatch.title = "different".into();
    assert!(store.propose_learning(owner, &mismatch).await.is_err());
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE actor=$1")
        .bind(owner.to_string())
        .fetch_one(store.pool())
        .await?;
    let review = LearningReview {
        idempotency_key: "review".into(),
        status: "active".into(),
        reason: "independently checked fixture".into(),
        evidence: input.evidence.clone(),
    };
    assert!(store.review_learning(owner, rid, &review).await.is_err());
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE actor=$1")
        .bind(owner.to_string())
        .fetch_one(store.pool())
        .await?;
    assert_eq!(
        before, after,
        "rejected review must not commit audit or status"
    );
    let mut wrong = LearningReview {
        idempotency_key: "review".into(),
        status: "active".into(),
        reason: "wrong".into(),
        evidence: input.evidence.clone(),
    };
    wrong.evidence.passed = false;
    assert!(store.review_learning(curator, rid, &wrong).await.is_err());
    assert!(store.review_learning(curator, rid, &review).await.is_err());
    store.grant_learning_curator(owner, curator).await?;
    assert!(store.review_learning(curator, rid, &review).await.is_err());
    store
        .attest_learning_evidence(owner, &input.repository, curator, &input.evidence)
        .await?;
    let receipt = store.review_learning(curator, rid, &review).await?;
    assert_eq!(receipt, store.review_learning(curator, rid, &review).await?);
    let last: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT last_verified FROM learning_revisions WHERE id=$1")
            .bind(rid)
            .fetch_one(store.pool())
            .await?;
    let attested: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "SELECT verified_at FROM learning_verified_evidence WHERE owner_id=$1 LIMIT 1",
    )
    .bind(owner)
    .fetch_one(store.pool())
    .await?;
    assert_eq!(last, attested);
    let matching = LearningQuery {
        language: Some("rust".into()),
        framework: Some("axum".into()),
        platform: Some("linux".into()),
        provider: Some("fixture-provider".into()),
        model: Some("fixture-model".into()),
        project: Some("fixture-project".into()),
        error_class: Some("race".into()),
        file_path: Some("storage/src/learning.rs".into()),
        tag: Some("fixture".into()),
        version_key: Some("clawforge".into()),
        version: Some("1.0.0".into()),
        ..Default::default()
    };
    let matched = store.query_learning(owner, &matching).await?;
    assert_eq!(matched["data"].as_array().unwrap().len(), 1);
    assert!(matched["data"][0]["created_at"].is_string());
    assert!(matched["data"][0]["updated_at"].is_string());
    let mut mismatch = matching.clone();
    mismatch.version = Some("2.0.0".into());
    assert!(store.query_learning(owner, &mismatch).await?["data"]
        .as_array()
        .unwrap()
        .is_empty());
    mismatch = matching.clone();
    mismatch.platform = Some("windows".into());
    assert!(store.query_learning(owner, &mismatch).await?["data"]
        .as_array()
        .unwrap()
        .is_empty());
    mismatch = matching.clone();
    mismatch.file_path = Some("foreign.rs".into());
    assert!(store.query_learning(owner, &mismatch).await?["data"]
        .as_array()
        .unwrap()
        .is_empty());
    mismatch = matching.clone();
    mismatch.tag = Some("wrong-tag".into());
    assert!(store.query_learning(owner, &mismatch).await?["data"]
        .as_array()
        .unwrap()
        .is_empty());

    assert_eq!(
        store
            .query_learning(owner, &LearningQuery::default())
            .await?["data"][0]["status"],
        "active"
    );
    for kind in ["decision", "routing", "escalation"] {
        store
            .attach_learning_record(
                owner,
                rid,
                kind,
                kind,
                &json!({"task":"fixture","reason":"checked evidence"}),
            )
            .await?;
    }
    assert_eq!(
        store.learning_records(owner, rid, None, None).await?["data"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    assert!(store
        .learning_records(stranger, rid, None, None)
        .await
        .is_err());
    assert!(store
        .attach_learning_record(
            stranger,
            rid,
            "decision",
            "foreign",
            &json!({"reason":"foreign"})
        )
        .await
        .is_err());
    assert!(store
        .attach_learning_record(owner, rid, "routing", "bad", &json!({"token":"bad"}))
        .await
        .is_err());
    let mut next = input.clone();
    next.idempotency_key = "revision-two".into();
    next.fix = "improved transaction".into();
    let revised = store.revise_learning(owner, id, &next).await?;
    assert_eq!(revised, store.revise_learning(owner, id, &next).await?);
    assert!(store.revise_learning(stranger, id, &next).await.is_err());
    let nextid = serde_json::from_value(revised["revision_id"].clone())?;
    store.review_learning(curator, nextid, &review).await?;
    let active = store
        .query_learning(owner, &LearningQuery::default())
        .await?;
    assert_eq!(active["data"].as_array().unwrap().len(), 1);
    assert_eq!(active["data"][0]["revision"], 2);
    assert_eq!(receipt, store.review_learning(curator, rid, &review).await?);
    let new_attempt = LearningReview {
        idempotency_key: "reactivate-old".into(),
        ..review.clone()
    };
    assert!(store
        .review_learning(curator, rid, &new_attempt)
        .await
        .is_err());
    let retired = LearningReview {
        idempotency_key: "deprecate".into(),
        status: "deprecated".into(),
        reason: "version no longer valid".into(),
        evidence: input.evidence.clone(),
    };
    let deprecated = store.review_learning(curator, nextid, &retired).await?;
    assert_eq!(
        deprecated,
        store.review_learning(curator, nextid, &retired).await?
    );
    assert!(store
        .query_learning(owner, &LearningQuery::default())
        .await?["data"]
        .as_array()
        .unwrap()
        .is_empty());
    let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM audit_events WHERE actor IN ($1,$2) AND action LIKE 'lesson%' OR actor=$1 AND action='learning_record_created'").bind(owner.to_string()).bind(curator.to_string()).fetch_one(store.pool()).await?;
    assert_eq!(count, 8);
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL owner fixture"]
async fn learning_api_role_cannot_modify_trust_roots() -> anyhow::Result<()> {
    let store =
        PostgresStore::connect(&std::env::var("CLAWFORGE_LEARNING_TEST_DATABASE_URL")?).await?;
    let role = format!("learning_role_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} NOLOGIN NOSUPERUSER NOBYPASSRLS"
    ))
    .execute(store.pool())
    .await?;
    sqlx::query(&format!("GRANT USAGE ON SCHEMA public TO {role}"))
        .execute(store.pool())
        .await?;
    sqlx::query(&format!(
        "GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO {role}"
    ))
    .execute(store.pool())
    .await?;
    sqlx::query(&format!("REVOKE INSERT,UPDATE,DELETE ON learning_actor_tokens,learning_curator_grants,learning_verified_evidence FROM {role}")).execute(store.pool()).await?;
    sqlx::query(&format!(
        "REVOKE UPDATE,DELETE ON learning_lessons,learning_records,learning_revisions FROM {role}"
    ))
    .execute(store.pool())
    .await?;
    sqlx::query(&format!(
        "GRANT UPDATE(status,last_verified) ON learning_revisions TO {role}"
    ))
    .execute(store.pool())
    .await?;
    for table in [
        "learning_actor_tokens",
        "learning_curator_grants",
        "learning_verified_evidence",
    ] {
        for operation in [
            format!("INSERT INTO {table} DEFAULT VALUES"),
            format!(
                "UPDATE {table} SET {}={} WHERE false",
                if table == "learning_actor_tokens" {
                    "actor_id"
                } else {
                    "owner_id"
                },
                if table == "learning_actor_tokens" {
                    "actor_id"
                } else {
                    "owner_id"
                }
            ),
            format!("DELETE FROM {table} WHERE false"),
        ] {
            let mut tx = store.pool().begin().await?;
            sqlx::query(&format!("SET LOCAL ROLE {role}"))
                .execute(&mut *tx)
                .await?;
            let error = sqlx::query(&operation)
                .execute(&mut *tx)
                .await
                .expect_err("trust root mutation must be rejected");
            assert_eq!(
                error.as_database_error().unwrap().code().as_deref(),
                Some("42501")
            );
            tx.rollback().await?;
        }
    }
    for operation in [
        "DELETE FROM learning_records WHERE false",
        "UPDATE learning_revisions SET payload='{}'::jsonb WHERE false",
    ] {
        let mut tx = store.pool().begin().await?;
        sqlx::query(&format!("SET LOCAL ROLE {role}"))
            .execute(&mut *tx)
            .await?;
        assert_eq!(
            sqlx::query(operation)
                .execute(&mut *tx)
                .await
                .unwrap_err()
                .as_database_error()
                .unwrap()
                .code()
                .as_deref(),
            Some("42501")
        );
        tx.rollback().await?;
    }
    sqlx::query(&format!("DROP OWNED BY {role}"))
        .execute(store.pool())
        .await?;
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(store.pool())
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL learning fixture"]
async fn learning_context_ranking_and_terminal_exclusion() -> anyhow::Result<()> {
    let store =
        PostgresStore::connect(&std::env::var("CLAWFORGE_LEARNING_TEST_DATABASE_URL")?).await?;
    let owner = Uuid::new_v4();
    let curator = Uuid::new_v4();
    store.grant_learning_curator(owner, curator).await?;
    let mut ids = Vec::new();
    for (key, confidence) in [("low", 0.2), ("high", 0.95)] {
        let mut input = lesson(key);
        input.context.confidence = Some(confidence);
        input.context.language = Some("rust".into());
        input.context.framework = Some("axum".into());
        store
            .attest_learning_evidence(owner, &input.repository, curator, &input.evidence)
            .await?;
        let proposed = store.propose_learning(owner, &input).await?;
        let rid: Uuid = serde_json::from_value(proposed["revision_id"].clone())?;
        let review = LearningReview {
            idempotency_key: "review".into(),
            status: "active".into(),
            reason: "independent fixture validation".into(),
            evidence: input.evidence.clone(),
        };
        store.review_learning(curator, rid, &review).await?;
        ids.push((rid, review));
    }
    let query = LearningQuery {
        language: Some("rust".into()),
        framework: Some("axum".into()),
        ..Default::default()
    };
    let data = store.query_learning(owner, &query).await?;
    assert_eq!(data["data"][0]["payload"]["idempotency_key"], "high");
    let mut mismatch = query.clone();
    mismatch.language = Some("kotlin".into());
    assert!(store.query_learning(owner, &mismatch).await?["data"]
        .as_array()
        .unwrap()
        .is_empty());
    let (rid, mut review) = ids.pop().unwrap();
    review.status = "deprecated".into();
    review.idempotency_key = "deprecate".into();
    store.review_learning(curator, rid, &review).await?;
    let active = store.query_learning(owner, &query).await?;
    assert_eq!(active["data"].as_array().unwrap().len(), 1);
    assert_eq!(active["data"][0]["payload"]["idempotency_key"], "low");
    assert!(store
        .review_learning(
            curator,
            rid,
            &LearningReview {
                status: "active".into(),
                ..review
            }
        )
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL learning fixture"]
async fn generic_applicability_specificity_and_record_pagination() -> anyhow::Result<()> {
    let store =
        PostgresStore::connect(&std::env::var("CLAWFORGE_LEARNING_TEST_DATABASE_URL")?).await?;
    let owner = Uuid::new_v4();
    let curator = Uuid::new_v4();
    store.grant_learning_curator(owner, curator).await?;
    let mut specific_rid = Uuid::nil();
    for generic in [false, true] {
        let mut input = lesson(if generic { "generic" } else { "specific" });
        input.context.generic = generic;
        input.context.confidence = Some(if generic { 1.0 } else { 0.1 });
        if generic {
            input.repository = "*".into();
            input.component = "*".into();
            input.context.versions.insert("*".into(), "*".into());
            input.tags = vec!["*".into()];
        } else {
            input.context.language = Some("rust".into());
            input
                .context
                .versions
                .insert("framework".into(), "1".into());
        }
        store
            .attest_learning_evidence(owner, &input.repository, curator, &input.evidence)
            .await?;
        let p = store.propose_learning(owner, &input).await?;
        let rid = serde_json::from_value(p["revision_id"].clone())?;
        store
            .review_learning(
                curator,
                rid,
                &LearningReview {
                    idempotency_key: "activate".into(),
                    status: "active".into(),
                    reason: "fixture independent check".into(),
                    evidence: input.evidence,
                },
            )
            .await?;
        if !generic {
            specific_rid = rid;
        }
    }
    let query = LearningQuery {
        repository: Some("fixture-repository".into()),
        component: Some("learning".into()),
        language: Some("rust".into()),
        version_key: Some("framework".into()),
        version: Some("1".into()),
        ..Default::default()
    };
    let rows = store.query_learning(owner, &query).await?;
    assert_eq!(rows["data"].as_array().unwrap().len(), 2);
    assert_eq!(rows["data"][0]["payload"]["idempotency_key"], "specific");
    let mismatch = LearningQuery {
        version: Some("2".into()),
        ..query.clone()
    };
    let rows = store.query_learning(owner, &mismatch).await?;
    assert_eq!(rows["data"].as_array().unwrap().len(), 1);
    assert_eq!(rows["data"][0]["payload"]["idempotency_key"], "generic");
    for n in 0..105 {
        let key = format!("record-{n}");
        let payload = json!({"sequence":n});
        let first = store
            .attach_learning_record(owner, specific_rid, "decision", &key, &payload)
            .await?;
        assert_eq!(
            first,
            store
                .attach_learning_record(owner, specific_rid, "decision", &key, &payload)
                .await?
        );
        assert!(store
            .attach_learning_record(
                owner,
                specific_rid,
                "decision",
                &key,
                &json!({"sequence":-1})
            )
            .await
            .is_err());
    }
    let page = store
        .learning_records(owner, specific_rid, Some(100), None)
        .await?;
    assert_eq!(page["data"].as_array().unwrap().len(), 100);
    assert_eq!(page["data"][0]["payload"]["sequence"], 104);
    let cursor = serde_json::from_value(page["next_cursor"].clone())?;
    let next = store
        .learning_records(owner, specific_rid, Some(100), Some(cursor))
        .await?;
    assert_eq!(next["data"].as_array().unwrap().len(), 6);
    assert!(next["next_cursor"].is_null());
    let mut ids = std::collections::HashSet::new();
    for row in page["data"]
        .as_array()
        .unwrap()
        .iter()
        .chain(next["data"].as_array().unwrap())
    {
        assert!(ids.insert(row["id"].as_str().unwrap()));
    }
    Ok(())
}
