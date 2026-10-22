//! Behaviour counts of one assessment (migration 0067). Numbers only: the policy engine never
//! sees usernames or request paths.
use crate::PostgresStore;
use anyhow::Result;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AssessmentShape {
    /// Member events read (at most 1000).
    pub events: i64,
    /// Different account names tried by the failed SSH logins among them.
    pub distinct_usernames: i64,
    /// Distinct request paths among the HTTP anomalies that match a supplied expression.
    pub signature_paths: i64,
}

impl PostgresStore {
    pub async fn assessment_shape(
        &self,
        assessment_id: Uuid,
        path_patterns: &[String],
    ) -> Result<AssessmentShape> {
        let value: serde_json::Value =
            sqlx::query_scalar("SELECT clawforge_assessment_shape($1, $2)")
                .bind(assessment_id)
                .bind(path_patterns)
                .fetch_one(self.pool())
                .await?;
        let number = |key: &str| {
            value
                .get(key)
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0)
        };
        Ok(AssessmentShape {
            events: number("events"),
            distinct_usernames: number("distinct_usernames"),
            signature_paths: number("signature_paths"),
        })
    }
}
