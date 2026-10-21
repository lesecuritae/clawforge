//! Actor-scoped learning API; read wildcard never grants proposal/curation writes.
use super::*;
use clawforge_storage::{LearningLessonInput, LearningQuery, LearningReview};
use serde_json::{json, Value};
const READ: &str = "agent:learning:read";
const PROPOSE: &str = "agent:learning:propose";
const CURATE: &str = "agent:learning:curate";
fn exact_scope(p: &AgentPrincipal, s: &str) -> ApiResult<()> {
    if p.scopes.iter().any(|v| v == s) {
        Ok(())
    } else {
        Err(api_error(
            StatusCode::FORBIDDEN,
            "learning scope is not granted",
        ))
    }
}
async fn principal(
    state: &AppState,
    headers: &HeaderMap,
    scope: &str,
) -> ApiResult<AgentPrincipal> {
    if !state.config.learning_enabled {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "learning feature disabled",
        ));
    }
    let mut p = authenticate_agent(state, headers).await?;
    exact_scope(&p, scope)?;
    p.id = state.store.learning_actor(p.id).await.map_err(|_| {
        api_error(
            StatusCode::FORBIDDEN,
            "learning credential is not onboarded",
        )
    })?;
    Ok(p)
}
fn bad() -> (StatusCode, Json<ApiError>) {
    api_error(StatusCode::BAD_REQUEST, "learning operation rejected")
}
pub(super) async fn capabilities(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiEnvelope<Value>>> {
    let p = principal(&state, &headers, READ).await?;
    // Probe the actual tables, fail closed when migration 0056 is missing.
    state
        .store
        .query_learning(
            p.id,
            &LearningQuery {
                limit: Some(1),
                ..Default::default()
            },
        )
        .await
        .map_err(|_| bad())?;
    let migration = state.store.readiness().await.map_err(|_| bad())?;
    if !migration.current || migration.latest < 56 {
        return Err(bad());
    }
    audit_agent_read(&state, &p, "/api/v1/learning/capabilities", READ).await;
    Ok(envelope(
        json!({"schema_version":1,"api_version":1,"migration_version":migration.latest,"required_migration_version":56,"features":["actor_owned_lessons","pending_proposals","immutable_revisions","independent_attested_curation","append_only_records"],"retrieval_fields":["repository","component","project","agent","model","provider","language","framework","platform","error_class","file_path","tag","version_key","version","status"],"ranking":"exact applicability and explicit generic compatibility; repository/component/context specificity; confidence; verified recency; revision update recency","required_scopes":{"read":READ,"propose":PROPOSE,"curate":CURATE}}),
        None,
    ))
}
pub(super) async fn query(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<LearningQuery>,
) -> ApiResult<Json<ApiEnvelope<Value>>> {
    let p = principal(&state, &headers, READ).await?;
    let v = state
        .store
        .query_learning(p.id, &q)
        .await
        .map_err(|_| bad())?;
    audit_agent_read(&state, &p, "/api/v1/learning/lessons", READ).await;
    Ok(envelope(v, None))
}
pub(super) async fn propose(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(v): Json<LearningLessonInput>,
) -> ApiResult<Json<ApiEnvelope<Value>>> {
    let p = principal(&state, &headers, PROPOSE).await?;
    Ok(envelope(
        state
            .store
            .propose_learning(p.id, &v)
            .await
            .map_err(|_| bad())?,
        None,
    ))
}
pub(super) async fn revise(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(v): Json<LearningLessonInput>,
) -> ApiResult<Json<ApiEnvelope<Value>>> {
    let p = principal(&state, &headers, PROPOSE).await?;
    Ok(envelope(
        state
            .store
            .revise_learning(p.id, id, &v)
            .await
            .map_err(|_| bad())?,
        None,
    ))
}
pub(super) async fn review(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(v): Json<LearningReview>,
) -> ApiResult<Json<ApiEnvelope<Value>>> {
    let p = principal(&state, &headers, CURATE).await?;
    Ok(envelope(
        state
            .store
            .review_learning(p.id, id, &v)
            .await
            .map_err(|_| bad())?,
        None,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordInput {
    idempotency_key: String,
    kind: String,
    payload: Value,
}
pub(super) async fn attach(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(v): Json<RecordInput>,
) -> ApiResult<Json<ApiEnvelope<Value>>> {
    let p = principal(&state, &headers, PROPOSE).await?;
    Ok(envelope(
        state
            .store
            .attach_learning_record(p.id, id, &v.kind, &v.idempotency_key, &v.payload)
            .await
            .map_err(|_| bad())?,
        None,
    ))
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordsQuery {
    limit: Option<i64>,
    before: Option<Uuid>,
}
pub(super) async fn records(
    Query(q): Query<RecordsQuery>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApiEnvelope<Value>>> {
    let p = principal(&state, &headers, READ).await?;
    let v = state
        .store
        .learning_records(p.id, id, q.limit, q.before)
        .await
        .map_err(|_| bad())?;
    audit_agent_read(&state, &p, "/api/v1/learning/records", READ).await;
    Ok(envelope(v, None))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wildcard_cannot_write_or_read_learning() {
        let p = AgentPrincipal {
            id: Uuid::new_v4(),
            name: "readonly".into(),
            scopes: vec![AGENT_SCOPE_ALL_READ.into()],
        };
        assert!(exact_scope(&p, PROPOSE).is_err());
        assert!(exact_scope(&p, CURATE).is_err());
        assert!(exact_scope(&p, READ).is_err());
    }
}

#[cfg(test)]
mod postgres_tests {
    use super::*;
    use tower::ServiceExt;
    #[tokio::test]
    #[ignore = "requires isolated PostgreSQL learning fixture"]
    async fn learning_routes_enforce_scope_owner_and_curator() -> anyhow::Result<()> {
        let store =
            PostgresStore::connect(&std::env::var("CLAWFORGE_LEARNING_TEST_DATABASE_URL")?).await?;
        let full = new_secret();
        let read = new_secret();
        let curator = new_secret();
        let foreign = new_secret();
        let unique = Uuid::new_v4();
        for (name, token, scopes) in [
            (
                "owner",
                &full,
                vec![READ.into(), PROPOSE.into(), CURATE.into()],
            ),
            ("read", &read, vec![AGENT_SCOPE_ALL_READ.into()]),
            ("foreign", &foreign, vec![READ.into(), PROPOSE.into()]),
            ("curator", &curator, vec![CURATE.into()]),
        ] {
            let token_id = store
                .create_agent_token(
                    &format!("learning-{name}-{unique}"),
                    &digest(token),
                    &token[..8],
                    &scopes,
                    chrono::Utc::now() + chrono::Duration::hours(1),
                    None,
                )
                .await?;
            store.onboard_learning_actor(token_id).await?;
        }
        let app = build_router(super::super::tests::test_app_state(store.clone()));
        let body = json!({"idempotency_key":"fixture","repository":"fixture-repo","component":"api","title":"verified","symptoms":"race","cause":"missing lock","fix":"lock","rule":"lock writes","validity":{"platform":"linux"},"tags":[],"evidence":{"commit":"960f4d567e9968394bd4a43d736089583e9d0d46","test":"learning_routes_enforce_scope_owner_and_curator","artifact_sha256":"0".repeat(64),"passed":true}});
        let req = |method: &str, path: &str, token: &str, body: &Value| {
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap()
        };
        assert_eq!(
            app.clone()
                .oneshot(req("POST", "/api/v1/learning/lessons", &read, &body))
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );
        let response = app
            .clone()
            .oneshot(req("POST", "/api/v1/learning/lessons", &full, &body))
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let value: Value = serde_json::from_slice(&to_bytes(response.into_body(), 100000).await?)?;
        let rid = value["data"]["revision_id"].as_str().unwrap();
        let foreign_read = app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v1/learning/lessons?status=pending",
                &foreign,
                &json!(null),
            ))
            .await?;
        assert_eq!(foreign_read.status(), StatusCode::OK);
        let foreign_value: Value =
            serde_json::from_slice(&to_bytes(foreign_read.into_body(), 100000).await?)?;
        assert!(foreign_value["data"]["data"].as_array().unwrap().is_empty());
        assert_eq!(
            app.clone()
                .oneshot(req(
                    "GET",
                    &format!("/api/v1/learning/revisions/{rid}/records"),
                    &foreign,
                    &json!(null)
                ))
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            app.clone()
                .oneshot(req(
                    "POST",
                    "/api/v1/learning/lessons",
                    &full,
                    &json!({"password":"discard-me"})
                ))
                .await?
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let missing = Request::builder()
            .uri("/api/v1/learning/lessons")
            .body(Body::empty())?;
        assert_eq!(
            app.clone().oneshot(missing).await?.status(),
            StatusCode::UNAUTHORIZED
        );
        let cap = app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v1/learning/capabilities",
                &full,
                &json!(null),
            ))
            .await?;
        assert_eq!(cap.status(), StatusCode::OK);
        let cap_value: Value = serde_json::from_slice(&to_bytes(cap.into_body(), 100000).await?)?;
        assert_eq!(cap_value["data"]["migration_version"], 60);

        let review = json!({"idempotency_key":"activate-fixture","status":"active","reason":"objective fixture assertion","evidence":body["evidence"]});
        let path = format!("/api/v1/learning/revisions/{rid}/review");
        assert_eq!(
            app.clone()
                .oneshot(req("POST", &path, &read, &review))
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            app.clone()
                .oneshot(req("POST", &path, &full, &review))
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
        let owner_id = store
            .authenticate_agent_token(&digest(&full))
            .await?
            .unwrap()
            .id;
        let curator_id = store
            .authenticate_agent_token(&digest(&curator))
            .await?
            .unwrap()
            .id;
        assert_eq!(
            app.clone()
                .oneshot(req("POST", &path, &curator, &review))
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
        store.grant_learning_curator(owner_id, curator_id).await?;
        let evidence: clawforge_storage::LearningEvidence =
            serde_json::from_value(body["evidence"].clone())?;
        assert_eq!(
            app.clone()
                .oneshot(req("POST", &path, &curator, &review))
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
        store
            .attest_learning_evidence(owner_id, "fixture-repo", curator_id, &evidence)
            .await?;
        assert_eq!(
            app.clone()
                .oneshot(req("POST", &path, &curator, &review))
                .await?
                .status(),
            StatusCode::OK
        );
        let response = app
            .clone()
            .oneshot(req("GET", "/api/v1/learning/lessons", &full, &json!(null)))
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let value: Value = serde_json::from_slice(&to_bytes(response.into_body(), 100000).await?)?;
        assert_eq!(value["data"]["data"][0]["status"], "active");
        let mut disabled_state = super::super::tests::test_app_state(
            PostgresStore::connect_runtime(&std::env::var("CLAWFORGE_LEARNING_TEST_DATABASE_URL")?)
                .await?,
        );
        disabled_state.config.learning_enabled = false;
        let disabled = build_router(disabled_state);
        assert_eq!(
            disabled
                .oneshot(req("POST", "/api/v1/learning/lessons", &full, &body))
                .await?
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(store.readiness().await?.current);
        assert_eq!(
            store
                .query_learning(owner_id, &LearningQuery::default())
                .await?["data"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let rotated = new_secret();
        let rotated_id = store
            .create_agent_token(
                &format!("rotated-{unique}"),
                &digest(&rotated),
                &rotated[..8],
                &[READ.into(), PROPOSE.into(), CURATE.into()],
                chrono::Utc::now() + chrono::Duration::hours(1),
                None,
            )
            .await?;
        assert_eq!(
            app.clone()
                .oneshot(req(
                    "GET",
                    "/api/v1/learning/lessons",
                    &rotated,
                    &json!(null)
                ))
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );
        store.link_learning_rotation(owner_id, rotated_id).await?;
        store.revoke_agent_token(owner_id).await?;
        assert_eq!(
            app.clone()
                .oneshot(req("GET", "/api/v1/learning/lessons", &full, &json!(null)))
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let rotated_response = app
            .clone()
            .oneshot(req(
                "GET",
                "/api/v1/learning/lessons",
                &rotated,
                &json!(null),
            ))
            .await?;
        assert_eq!(rotated_response.status(), StatusCode::OK);
        let rotated_value: Value =
            serde_json::from_slice(&to_bytes(rotated_response.into_body(), 100000).await?)?;
        assert_eq!(rotated_value["data"]["data"][0]["status"], "active");
        assert_eq!(
            app.clone()
                .oneshot(req("POST", &path, &rotated, &review))
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );

        assert_eq!(
            app.clone()
                .oneshot(req("GET", "/api/v1/learning/lessons", &read, &json!(null)))
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );
        Ok(())
    }
}
