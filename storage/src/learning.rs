//! Structured, actor-owned learning. Proposals are never trusted without an
//! independent scoped curator and matching objective evidence. All transitions
//! share a transaction with the existing audit outbox.
use super::PostgresStore;
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use uuid::Uuid;

/// Operator-approved binding for the trusted offline importer; never an agent API.
#[derive(Clone)]
pub struct LearningTrustBinding {
    pub token_id: Uuid,
    pub actor_id: Uuid,
    pub rotation_from: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LearningEvidence {
    pub commit: String,
    pub test: String,
    pub artifact_sha256: String,
    pub passed: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct LearningContext {
    pub generic: bool,
    pub project: Option<String>,
    pub task: Option<String>,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub language: Option<String>,
    pub framework: Option<String>,
    pub platform: Option<String>,
    pub error_class: Option<String>,
    pub origin: Option<String>,
    pub pull_request: Option<String>,
    pub files: Vec<String>,
    pub versions: std::collections::BTreeMap<String, String>,
    pub confidence: Option<f64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearningLessonInput {
    pub idempotency_key: String,
    pub repository: String,
    pub component: String,
    pub title: String,
    pub symptoms: String,
    pub cause: String,
    pub fix: String,
    pub rule: String,
    pub validity: Value,
    pub tags: Vec<String>,
    pub evidence: LearningEvidence,
    #[serde(default)]
    pub context: LearningContext,
}
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct LearningQuery {
    pub repository: Option<String>,
    pub component: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub project: Option<String>,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub language: Option<String>,
    pub framework: Option<String>,
    pub platform: Option<String>,
    pub error_class: Option<String>,
    pub file_path: Option<String>,
    pub tag: Option<String>,
    pub version_key: Option<String>,
    pub version: Option<String>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearningReview {
    pub idempotency_key: String,
    pub status: String,
    pub reason: String,
    pub evidence: LearningEvidence,
}
fn bounded(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.len() <= max
}
fn hex(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn safe_json(v: &Value, depth: usize) -> bool {
    if depth > 8 {
        return false;
    }
    match v {
        Value::String(s) => {
            let t = s.to_ascii_lowercase();
            s.len() <= 10000
                && ![
                    "nvapi-",
                    "ghp_",
                    "sk-or-v1-",
                    "bearer ",
                    "-----begin private key",
                ]
                .iter()
                .any(|x| t.contains(x))
        }
        Value::Object(o) => {
            o.len() <= 64
                && o.iter().all(|(k, v)| {
                    ![
                        "password",
                        "secret",
                        "token",
                        "authorization",
                        "api_key",
                        "apikey",
                        "request_body",
                    ]
                    .contains(&k.to_ascii_lowercase().as_str())
                        && safe_json(v, depth + 1)
                })
        }
        Value::Array(a) => a.len() <= 64 && a.iter().all(|v| safe_json(v, depth + 1)),
        _ => true,
    }
}
impl LearningEvidence {
    fn validate(&self) -> Result<()> {
        ensure!(
            (hex(&self.commit, 40, 40) || hex(&self.commit, 64, 64))
                && hex(&self.artifact_sha256, 64, 64)
                && bounded(&self.test, 512),
            "invalid objective evidence"
        );
        Ok(())
    }
}
impl LearningLessonInput {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            bounded(&self.idempotency_key, 128)
                && bounded(&self.repository, 512)
                && bounded(&self.component, 240)
                && bounded(&self.title, 240),
            "invalid learning identity"
        );
        ensure!(
            [&self.symptoms, &self.cause, &self.fix, &self.rule]
                .iter()
                .all(|v| bounded(v, 10000)),
            "invalid lesson text"
        );
        self.evidence.validate()?;
        ensure!(
            (self.repository != "*" && self.component != "*") || self.context.generic,
            "wildcard scope requires explicit generic applicability"
        );
        ensure!(
            [
                &self.context.project,
                &self.context.task,
                &self.context.agent,
                &self.context.model,
                &self.context.provider,
                &self.context.language,
                &self.context.framework,
                &self.context.platform,
                &self.context.error_class,
                &self.context.origin,
                &self.context.pull_request
            ]
            .iter()
            .all(|v| v.as_ref().is_none_or(|s| bounded(s, 512))),
            "invalid learning context"
        );
        ensure!(
            self.context.files.len() <= 64
                && self.context.files.iter().all(|s| bounded(s, 1024))
                && self.context.versions.len() <= 32
                && self
                    .context
                    .versions
                    .iter()
                    .all(|(k, v)| bounded(k, 80) && bounded(v, 128))
                && self
                    .context
                    .confidence
                    .is_none_or(|x| x.is_finite() && (0.0..=1.0).contains(&x)),
            "invalid learning applicability"
        );
        ensure!(
            self.tags.len() <= 32 && self.tags.iter().all(|v| bounded(v, 80)),
            "invalid lesson tags"
        );
        ensure!(
            self.validity.is_object() && safe_json(&serde_json::to_value(self)?, 0),
            "unsafe learning payload"
        );
        Ok(())
    }
}
impl PostgresStore {
    /// Resolve a stable learning actor while retaining legacy token identity for
    /// unrelated API contracts. Missing links initially use the token UUID.
    pub async fn learning_actor(&self, token: Uuid) -> Result<Uuid> {
        sqlx::query_scalar("SELECT actor_id FROM learning_actor_tokens WHERE token_id=$1")
            .bind(token)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| anyhow::anyhow!("learning credential is not onboarded"))
    }
    /// Trusted onboarding before a newly issued credential may use learning.
    pub async fn onboard_learning_actor(&self, token: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        self.onboard_learning_actor_tx(&mut tx, token).await?;
        tx.commit().await?;
        Ok(())
    }
    async fn onboard_learning_actor_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        token: Uuid,
    ) -> Result<()> {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("learning-rotation:{token}"))
            .execute(&mut **tx)
            .await?;
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agent_tokens WHERE id=$1)")
                .bind(token)
                .fetch_one(&mut **tx)
                .await?;
        ensure!(exists, "credential missing");
        let inserted=sqlx::query("INSERT INTO learning_actor_tokens(token_id,actor_id) VALUES($1,$1) ON CONFLICT DO NOTHING").bind(token).execute(&mut **tx).await?;
        if inserted.rows_affected() > 0 {
            Self::insert_audit_outbox(
                tx,
                "learning-trust-admin",
                "learning_actor_onboarded",
                &token.to_string(),
                &json!({"actor_id":token}),
            )
            .await?;
        }
        Ok(())
    }
    /// Trusted credential-management integration only: a replacement inherits
    /// the original credential's actor. Never expose this as an agent endpoint.
    pub async fn link_learning_rotation(&self, old: Uuid, new: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        self.link_learning_rotation_tx(&mut tx, old, new).await?;
        tx.commit().await?;
        Ok(())
    }
    async fn link_learning_rotation_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        old: Uuid,
        new: Uuid,
    ) -> Result<()> {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("learning-rotation:{new}"))
            .execute(&mut **tx)
            .await?;
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agent_tokens WHERE id=$1)")
                .bind(old)
                .fetch_one(&mut **tx)
                .await?;
        ensure!(exists, "original credential missing");
        let actor: Uuid =
            sqlx::query_scalar("SELECT actor_id FROM learning_actor_tokens WHERE token_id=$1")
                .bind(old)
                .fetch_one(&mut **tx)
                .await?;
        let prior: Option<Uuid> = sqlx::query_scalar(
            "SELECT actor_id FROM learning_actor_tokens WHERE token_id=$1 FOR UPDATE",
        )
        .bind(new)
        .fetch_optional(&mut **tx)
        .await?;
        ensure!(
            prior.is_none() || prior == Some(actor),
            "replacement already belongs to another actor"
        );
        let owns: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM learning_lessons WHERE owner_id=$1)")
                .bind(new)
                .fetch_one(&mut **tx)
                .await?;
        ensure!(
            new == actor || !owns,
            "replacement already owns unlinked learning data"
        );
        let inserted=sqlx::query("INSERT INTO learning_actor_tokens(token_id,actor_id) VALUES($1,$2) ON CONFLICT(token_id) DO NOTHING")
            .bind(new).bind(actor).execute(&mut **tx).await?;
        if inserted.rows_affected() > 0 {
            Self::insert_audit_outbox(
                tx,
                "learning-trust-admin",
                "learning_actor_linked",
                &new.to_string(),
                &json!({"actor_id":actor,"original_token_id":old}),
            )
            .await?;
        }
        Ok(())
    }
    /// Trusted admin onboarding, not a proposal/curation capability.
    pub async fn grant_learning_curator(&self, owner: Uuid, reviewer: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        self.grant_learning_curator_tx(&mut tx, owner, reviewer)
            .await?;
        tx.commit().await?;
        Ok(())
    }
    async fn grant_learning_curator_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        owner: Uuid,
        reviewer: Uuid,
    ) -> Result<()> {
        ensure!(owner != reviewer, "self curation grant prohibited");
        let inserted =
            sqlx::query("INSERT INTO learning_curator_grants VALUES($1,$2) ON CONFLICT DO NOTHING")
                .bind(owner)
                .bind(reviewer)
                .execute(&mut **tx)
                .await?;
        if inserted.rows_affected() > 0 {
            Self::insert_audit_outbox(
                tx,
                "learning-trust-admin",
                "learning_curator_granted",
                &owner.to_string(),
                &json!({"reviewer_id":reviewer}),
            )
            .await?;
        }
        Ok(())
    }
    /// Trusted CI importer must verify the artifact/test externally before this
    /// call. This records that verification; it does not execute arbitrary tests.
    pub async fn attest_learning_evidence(
        &self,
        owner: Uuid,
        repository: &str,
        verifier: Uuid,
        evidence: &LearningEvidence,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        self.attest_learning_evidence_tx(&mut tx, owner, repository, verifier, evidence)
            .await?;
        tx.commit().await?;
        Ok(())
    }
    async fn attest_learning_evidence_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        owner: Uuid,
        repository: &str,
        verifier: Uuid,
        evidence: &LearningEvidence,
    ) -> Result<()> {
        evidence.validate()?;
        ensure!(
            bounded(repository, 512)
                && safe_json(&json!({"repository":repository,"evidence":evidence}), 0),
            "unsafe evidence attestation"
        );
        ensure!(
            evidence.passed && owner != verifier,
            "independent passing evidence required"
        );
        let inserted=sqlx::query("INSERT INTO learning_verified_evidence(owner_id,repository,commit_hash,test_name,artifact_sha256,verifier_id) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING")
            .bind(owner).bind(repository).bind(&evidence.commit).bind(&evidence.test).bind(&evidence.artifact_sha256).bind(verifier).execute(&mut **tx).await?;
        if inserted.rows_affected() > 0 {
            Self::insert_audit_outbox(
                tx,
                "learning-trust-import",
                "learning_evidence_attested",
                &owner.to_string(),
                &json!({"repository":repository,"verifier_id":verifier,"evidence":evidence}),
            )
            .await?;
        }
        Ok(())
    }
    /// Atomically validate active scoped credentials and import authenticated evidence.
    /// Row locks serialize token revocation/scope changes with the complete import.
    pub async fn import_learning_evidence(
        &self,
        bindings: &[LearningTrustBinding],
        owner: Uuid,
        curator: Uuid,
        repository: &str,
        evidence: &[LearningEvidence],
    ) -> Result<()> {
        ensure!(
            owner != curator && bindings.len() == 2,
            "independent identities required"
        );
        ensure!(
            bindings.iter().any(|b| b.actor_id == owner)
                && bindings.iter().any(|b| b.actor_id == curator),
            "independent role pair missing"
        );
        let mut ordered: Vec<_> = bindings.iter().collect();
        ordered.sort_by_key(|b| b.token_id);
        ensure!(
            ordered[0].token_id != ordered[1].token_id,
            "distinct credentials required"
        );
        let mut tx = self.pool.begin().await?;
        // Match the rotation/onboarding lock order, before taking credential row locks.
        for b in &ordered {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                .bind(format!("learning-rotation:{}", b.token_id))
                .execute(&mut *tx)
                .await?;
        }
        for b in &ordered {
            let row = sqlx::query(
                "SELECT scopes,revoked_at,expires_at FROM agent_tokens WHERE id=$1 FOR UPDATE",
            )
            .bind(b.token_id)
            .fetch_one(&mut *tx)
            .await?;
            ensure!(
                row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("revoked_at")
                    .is_none()
                    && row.get::<chrono::DateTime<chrono::Utc>, _>("expires_at")
                        > chrono::Utc::now(),
                "credential inactive"
            );
            let scopes: Vec<String> = serde_json::from_value(row.get("scopes"))?;
            let required = if b.actor_id == owner {
                vec!["agent:learning:read", "agent:learning:propose"]
            } else {
                ensure!(b.actor_id == curator, "binding outside approved actors");
                vec!["agent:learning:curate"]
            };
            ensure!(
                required.len() == scopes.len()
                    && required.iter().all(|s| scopes.iter().any(|x| x == s)),
                "credential scope mismatch"
            );
            let prior: Option<Uuid> =
                sqlx::query_scalar("SELECT actor_id FROM learning_actor_tokens WHERE token_id=$1")
                    .bind(b.token_id)
                    .fetch_optional(&mut *tx)
                    .await?;
            if let Some(actual) = prior {
                ensure!(actual == b.actor_id, "existing actor mismatch");
            } else if let Some(old) = b.rotation_from {
                let actual: Uuid = sqlx::query_scalar(
                    "SELECT actor_id FROM learning_actor_tokens WHERE token_id=$1",
                )
                .bind(old)
                .fetch_one(&mut *tx)
                .await?;
                ensure!(actual == b.actor_id, "rotation source mismatch");
                self.link_learning_rotation_tx(&mut tx, old, b.token_id)
                    .await?;
            } else {
                ensure!(
                    b.token_id == b.actor_id,
                    "explicit onboarding actor mismatch"
                );
                self.onboard_learning_actor_tx(&mut tx, b.token_id).await?;
            }
        }
        self.grant_learning_curator_tx(&mut tx, owner, curator)
            .await?;
        for item in evidence {
            self.attest_learning_evidence_tx(&mut tx, owner, repository, curator, item)
                .await?;
        }
        // Expiry advances without an UPDATE and therefore needs a fresh final check.
        for b in &ordered {
            let active: bool = sqlx::query_scalar("SELECT revoked_at IS NULL AND expires_at > clock_timestamp() FROM agent_tokens WHERE id=$1")
                .bind(b.token_id).fetch_one(&mut *tx).await?;
            ensure!(active, "credential inactive before import commit");
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn propose_learning(
        &self,
        owner: Uuid,
        input: &LearningLessonInput,
    ) -> Result<Value> {
        input.validate()?;
        let payload = serde_json::to_value(input)?;
        let mut tx = self.pool.begin().await?;
        // Lock by owner+idempotency key, including concurrent first insertion.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("learning:{owner}:{}", input.idempotency_key))
            .execute(&mut *tx)
            .await?;
        if let Some(row)=sqlx::query("SELECT l.id,r.id AS revision_id,r.payload FROM learning_lessons l JOIN learning_revisions r ON r.lesson_id=l.id AND r.revision=1 WHERE owner_id=$1 AND idempotency_key=$2").bind(owner).bind(&input.idempotency_key).fetch_optional(&mut *tx).await? {
 ensure!(row.get::<Value,_>("payload")==payload,"idempotency payload mismatch");return Ok(json!({"schema_version":1,"id":row.get::<Uuid,_>("id"),"revision_id":row.get::<Uuid,_>("revision_id")})); }
        let id = Uuid::new_v4();
        let revision_id = Uuid::new_v4();
        sqlx::query("INSERT INTO learning_lessons(id,owner_id,repository,component,idempotency_key) VALUES($1,$2,$3,$4,$5)").bind(id).bind(owner).bind(&input.repository).bind(&input.component).bind(&input.idempotency_key).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO learning_revisions(id,lesson_id,revision,status,payload) VALUES($1,$2,1,'pending',$3)").bind(revision_id).bind(id).bind(payload).execute(&mut *tx).await?;
        Self::insert_audit_outbox(
            &mut tx,
            &owner.to_string(),
            "lesson_proposed",
            &revision_id.to_string(),
            &json!({"schema_version":1,"lesson_id":id}),
        )
        .await?;
        tx.commit().await?;
        Ok(json!({"schema_version":1,"id":id,"revision_id":revision_id}))
    }
    pub async fn revise_learning(
        &self,
        owner: Uuid,
        id: Uuid,
        input: &LearningLessonInput,
    ) -> Result<Value> {
        input.validate()?;
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT owner_id,repository,component FROM learning_lessons WHERE id=$1 FOR UPDATE",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        ensure!(
            row.get::<Uuid, _>("owner_id") == owner,
            "learning owner mismatch"
        );
        ensure!(
            row.get::<String, _>("repository") == input.repository
                && row.get::<String, _>("component") == input.component,
            "revision context mismatch"
        );
        // Idempotent revision retry keyed by submitted input identity inside this lesson.
        let existing=sqlx::query("SELECT id,payload FROM learning_revisions WHERE lesson_id=$1 AND payload->>'idempotency_key'=$2").bind(id).bind(&input.idempotency_key).fetch_optional(&mut *tx).await?;
        let payload = serde_json::to_value(input)?;
        if let Some(r) = existing {
            ensure!(
                r.get::<Value, _>("payload") == payload,
                "idempotency payload mismatch"
            );
            return Ok(json!({"schema_version":1,"revision_id":r.get::<Uuid,_>("id")}));
        }
        let revision: i32 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(revision),0)+1 FROM learning_revisions WHERE lesson_id=$1",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        let rid = Uuid::new_v4();
        sqlx::query("INSERT INTO learning_revisions(id,lesson_id,revision,status,payload) VALUES($1,$2,$3,'pending',$4)").bind(rid).bind(id).bind(revision).bind(payload).execute(&mut *tx).await?;
        Self::insert_audit_outbox(
            &mut tx,
            &owner.to_string(),
            "lesson_revision_proposed",
            &rid.to_string(),
            &json!({"lesson_id":id,"revision":revision}),
        )
        .await?;
        tx.commit().await?;
        Ok(json!({"schema_version":1,"revision_id":rid}))
    }
    pub async fn query_learning(&self, owner: Uuid, query: &LearningQuery) -> Result<Value> {
        let status = query.status.as_deref().unwrap_or("active");
        ensure!(
            ["pending", "active", "superseded", "deprecated"].contains(&status),
            "invalid learning status"
        );
        let mut context = serde_json::Map::new();
        for (key, value) in [
            ("project", &query.project),
            ("agent", &query.agent),
            ("model", &query.model),
            ("provider", &query.provider),
            ("language", &query.language),
            ("framework", &query.framework),
            ("platform", &query.platform),
            ("error_class", &query.error_class),
        ] {
            if let Some(value) = value {
                ensure!(bounded(value, 512), "invalid context filter");
                context.insert(key.into(), json!(value));
            }
        }
        if let Some(path) = &query.file_path {
            ensure!(bounded(path, 1024), "invalid file filter");
            context.insert("files".into(), json!([path]));
        }
        match (&query.version_key, &query.version) {
            (Some(key), Some(version)) => {
                ensure!(
                    bounded(key, 80) && bounded(version, 128),
                    "invalid version filter"
                );
                context.insert("versions".into(), json!({key:version}));
            }
            (None, None) => {}
            _ => anyhow::bail!("version key and value must be paired"),
        }
        let tags = match &query.tag {
            Some(tag) => {
                ensure!(bounded(tag, 80), "invalid tag filter");
                json!([tag])
            }
            None => json!([]),
        };
        let rows=sqlx::query("SELECT l.id,l.repository,l.component,l.created_at AS lesson_created_at,r.id AS revision_id,r.revision,r.status,r.payload,r.created_at,r.updated_at,r.last_verified FROM learning_lessons l JOIN learning_revisions r ON r.lesson_id=l.id WHERE l.owner_id=$1 AND ($2::text IS NULL OR l.repository=$2 OR l.repository='*') AND ($3::text IS NULL OR l.component=$3 OR l.component='*') AND r.status=$4 AND clawforge_learning_context_matches(COALESCE(r.payload->'context','{}'::jsonb),$6::jsonb) AND (COALESCE(r.payload->'tags','[]'::jsonb) @> $7::jsonb OR (r.payload->'context'->>'generic'='true' AND r.payload->'tags' @> '[\"*\"]'::jsonb)) ORDER BY CASE WHEN $2::text IS NOT NULL AND l.repository=$2 THEN 1 ELSE 0 END DESC,CASE WHEN $3::text IS NOT NULL AND l.component=$3 THEN 1 ELSE 0 END DESC,(SELECT COUNT(*) FROM jsonb_each($6::jsonb) q WHERE (r.payload->'context'->q.key) @> q.value) DESC,COALESCE((r.payload->'context'->>'confidence')::double precision,0) DESC,r.last_verified DESC NULLS LAST,r.updated_at DESC LIMIT $5").bind(owner).bind(&query.repository).bind(&query.component).bind(status).bind(query.limit.unwrap_or(20).clamp(1,100)).bind(Value::Object(context)).bind(tags).fetch_all(&self.pool).await?;
        let data:Vec<Value>=rows.iter().map(|r|json!({"id":r.get::<Uuid,_>("id"),"revision_id":r.get::<Uuid,_>("revision_id"),"revision":r.get::<i32,_>("revision"),"status":r.get::<String,_>("status"),"payload":r.get::<Value,_>("payload"),"created_at":r.get::<chrono::DateTime<chrono::Utc>,_>("lesson_created_at"),"revision_created_at":r.get::<chrono::DateTime<chrono::Utc>,_>("created_at"),"updated_at":r.get::<chrono::DateTime<chrono::Utc>,_>("updated_at"),"last_verified":r.get::<Option<chrono::DateTime<chrono::Utc>>,_>("last_verified")})).collect();
        Ok(json!({"schema_version":1,"data":data}))
    }
    pub async fn review_learning(
        &self,
        reviewer: Uuid,
        rid: Uuid,
        review: &LearningReview,
    ) -> Result<Value> {
        ensure!(
            ["active", "deprecated"].contains(&review.status.as_str())
                && bounded(&review.reason, 2000)
                && bounded(&review.idempotency_key, 128),
            "invalid review"
        );
        review.evidence.validate()?;
        ensure!(
            safe_json(
                &json!({"idempotency_key":review.idempotency_key,"reason":review.reason,"evidence":review.evidence}),
                0
            ),
            "unsafe review"
        );
        let mut tx = self.pool.begin().await?;
        // Serialize every transition of the lesson before locking its revision.
        let lid: Uuid = sqlx::query_scalar("SELECT lesson_id FROM learning_revisions WHERE id=$1")
            .bind(rid)
            .fetch_one(&mut *tx)
            .await?;
        let owner: Uuid =
            sqlx::query_scalar("SELECT owner_id FROM learning_lessons WHERE id=$1 FOR UPDATE")
                .bind(lid)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(owner != reviewer, "self validation is prohibited");
        let authorized: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM learning_curator_grants WHERE owner_id=$1 AND reviewer_id=$2)").bind(owner).bind(reviewer).fetch_one(&mut *tx).await?;
        ensure!(authorized, "curator is not assigned to this owner");
        let requested =
            json!({"status":review.status,"reason":review.reason,"evidence":review.evidence});
        if let Some(existing)=sqlx::query("SELECT id,kind,payload FROM learning_records WHERE revision_id=$1 AND actor_id=$2 AND idempotency_key=$3").bind(rid).bind(reviewer).bind(&review.idempotency_key).fetch_optional(&mut *tx).await? {
            ensure!(existing.get::<String,_>("kind")=="review" && existing.get::<Value,_>("payload")==requested,"review idempotency mismatch");
            return Ok(json!({"schema_version":1,"revision_id":rid,"status":review.status,"review_id":existing.get::<Uuid,_>("id")}));
        }

        let row = sqlx::query(
            "SELECT status,payload,revision FROM learning_revisions WHERE id=$1 FOR UPDATE",
        )
        .bind(rid)
        .fetch_one(&mut *tx)
        .await?;
        let old: String = row.get("status");
        ensure!(
            old == "pending" || old == "active",
            "terminal revision cannot be reactivated"
        );
        let input: LearningLessonInput = serde_json::from_value(row.get("payload"))?;
        let attested: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar("SELECT verified_at FROM learning_verified_evidence WHERE owner_id=$1 AND repository=$2 AND commit_hash=$3 AND test_name=$4 AND artifact_sha256=$5 AND verifier_id<>$1")
            .bind(owner).bind(&input.repository).bind(&review.evidence.commit).bind(&review.evidence.test).bind(&review.evidence.artifact_sha256).fetch_optional(&mut *tx).await?;
        let verified_at = attested
            .ok_or_else(|| anyhow::anyhow!("evidence has no independent trusted attestation"))?;
        ensure!(
            review.evidence == input.evidence && review.evidence.passed,
            "review must match passing objective evidence"
        );
        if review.status == "active" {
            let newer:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM learning_revisions WHERE lesson_id=$1 AND revision>$2 AND status='active')").bind(lid).bind(row.get::<i32,_>("revision")).fetch_one(&mut *tx).await?;
            ensure!(!newer, "cannot supersede a newer active revision");
            sqlx::query("UPDATE learning_revisions SET status='superseded' WHERE lesson_id=$1 AND id<>$2 AND status='active'").bind(lid).bind(rid).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE learning_revisions SET status=$2,last_verified=$3 WHERE id=$1")
            .bind(rid)
            .bind(&review.status)
            .bind(verified_at)
            .execute(&mut *tx)
            .await?;
        let record = Uuid::new_v4();
        sqlx::query("INSERT INTO learning_records(id,revision_id,actor_id,kind,payload,idempotency_key) VALUES($1,$2,$3,'review',$4,$5)").bind(record).bind(rid).bind(reviewer).bind(requested).bind(&review.idempotency_key).execute(&mut *tx).await?;
        Self::insert_audit_outbox(
            &mut tx,
            &reviewer.to_string(),
            "lesson_reviewed",
            &rid.to_string(),
            &json!({"status":review.status,"review_id":record,"evidence":review.evidence}),
        )
        .await?;
        tx.commit().await?;
        Ok(json!({"schema_version":1,"revision_id":rid,"status":review.status,"review_id":record}))
    }
    pub async fn attach_learning_record(
        &self,
        owner: Uuid,
        rid: Uuid,
        kind: &str,
        idempotency_key: &str,
        payload: &Value,
    ) -> Result<Value> {
        ensure!(
            ["decision", "routing", "escalation"].contains(&kind)
                && bounded(idempotency_key, 128)
                && safe_json(&json!(idempotency_key), 0)
                && payload.is_object()
                && safe_json(payload, 0)
                && serde_json::to_vec(payload)?.len() <= 20000,
            "invalid learning record"
        );
        let mut tx = self.pool.begin().await?;
        let actual:Uuid=sqlx::query_scalar("SELECT l.owner_id FROM learning_lessons l JOIN learning_revisions r ON r.lesson_id=l.id WHERE r.id=$1 FOR UPDATE OF l").bind(rid).fetch_one(&mut *tx).await?;
        ensure!(actual == owner, "learning owner mismatch");
        if let Some(existing)=sqlx::query("SELECT id,kind,payload FROM learning_records WHERE revision_id=$1 AND actor_id=$2 AND idempotency_key=$3").bind(rid).bind(owner).bind(idempotency_key).fetch_optional(&mut *tx).await? {
            ensure!(existing.get::<String,_>("kind")==kind && existing.get::<Value,_>("payload")==*payload,"record idempotency mismatch");
            return Ok(json!({"schema_version":1,"id":existing.get::<Uuid,_>("id")}));
        }

        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO learning_records(id,revision_id,actor_id,kind,payload,idempotency_key) VALUES($1,$2,$3,$4,$5,$6)").bind(id).bind(rid).bind(owner).bind(kind).bind(payload).bind(idempotency_key).execute(&mut *tx).await?;
        Self::insert_audit_outbox(
            &mut tx,
            &owner.to_string(),
            "learning_record_created",
            &id.to_string(),
            &json!({"kind":kind,"revision_id":rid}),
        )
        .await?;
        tx.commit().await?;
        Ok(json!({"schema_version":1,"id":id}))
    }
    pub async fn learning_records(
        &self,
        owner: Uuid,
        rid: Uuid,
        limit: Option<i64>,
        before: Option<Uuid>,
    ) -> Result<Value> {
        let owns:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM learning_lessons l JOIN learning_revisions r ON r.lesson_id=l.id WHERE r.id=$1 AND l.owner_id=$2)").bind(rid).bind(owner).fetch_one(&self.pool).await?;
        ensure!(owns, "learning owner mismatch");
        if let Some(cursor) = before {
            let valid: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM learning_records WHERE id=$1 AND revision_id=$2)",
            )
            .bind(cursor)
            .bind(rid)
            .fetch_one(&self.pool)
            .await?;
            ensure!(valid, "invalid records cursor");
        }
        let limit = limit.unwrap_or(20).clamp(1, 100);
        let rows=sqlx::query("SELECT id,actor_id,kind,payload,created_at FROM learning_records WHERE revision_id=$1 AND ($2::uuid IS NULL OR (created_at,id)<(SELECT created_at,id FROM learning_records WHERE id=$2 AND revision_id=$1)) ORDER BY created_at DESC,id DESC LIMIT $3").bind(rid).bind(before).bind(limit+1).fetch_all(&self.pool).await?;
        let more = rows.len() > limit as usize;
        let data:Vec<Value>=rows.iter().take(limit as usize).map(|r|json!({"id":r.get::<Uuid,_>("id"),"actor_id":r.get::<Uuid,_>("actor_id"),"kind":r.get::<String,_>("kind"),"payload":r.get::<Value,_>("payload"),"created_at":r.get::<chrono::DateTime<chrono::Utc>,_>("created_at")})).collect();
        let next = if more {
            data.last().map(|r| r["id"].clone())
        } else {
            None
        };
        Ok(json!({"schema_version":1,"data":data,"next_cursor":next}))
    }
}
