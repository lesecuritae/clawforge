use async_trait::async_trait;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRequest {
    pub incident_id: Uuid,
    pub input: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisOutput {
    pub provider: String,
    pub model: String,
    pub confidence: f32,
    pub summary: String,
    pub observations: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error("provider request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("provider returned HTTP {status}: {message}")]
    ProviderHttp { status: StatusCode, message: String },
    #[error("provider response was invalid: {0}")]
    InvalidResponse(String),
}

#[async_trait]
pub trait AnalysisProvider: Send + Sync {
    async fn analyze(&self, input: &Value) -> Result<AnalysisOutput, AnalysisError>;
}

#[derive(Debug, Clone)]
pub struct MockProvider {
    pub model: String,
}

#[async_trait]
impl AnalysisProvider for MockProvider {
    async fn analyze(&self, input: &Value) -> Result<AnalysisOutput, AnalysisError> {
        let event_count = input
            .get("events")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        let incident_id = input
            .get("incident")
            .and_then(|value| value.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        Ok(AnalysisOutput {
            provider: "mock".to_string(),
            model: self.model.clone(),
            confidence: 0.5,
            summary: format!(
                "Mock analysis for incident {incident_id}; {event_count} correlated event(s)."
            ),
            observations: vec![
                "This result was produced by the offline analysis provider.".to_string(),
                "The analyzer only explains stored, sanitized incident context.".to_string(),
            ],
            recommendations: vec![
                "Review the correlated events and confirm the incident context.".to_string(),
            ],
        })
    }
}

#[derive(Debug, Clone)]
pub struct OpenAiCompatibleProvider {
    pub client: reqwest::Client,
    pub base_url: String,
    pub api_key: Option<String>,
    pub model: String,
    pub provider: String,
}

#[async_trait]
impl AnalysisProvider for OpenAiCompatibleProvider {
    async fn analyze(&self, input: &Value) -> Result<AnalysisOutput, AnalysisError> {
        let mut request = self
            .client
            .post(format!("{}/chat/completions", self.base_url.trim_end_matches('/')))
            .json(&json!({
                "model": self.model,
                "temperature": 0,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": "You are an incident analysis assistant. Return only JSON with confidence (0..1), summary, observations (array of strings), and recommendations (array of strings). Explain context only. Never block, grant trust, change policies, activate providers, or change permissions."},
                    {"role": "user", "content": serde_json::to_string(input).map_err(|error| AnalysisError::InvalidResponse(error.to_string()))?}
                ]
            }));
        if let Some(api_key) = &self.api_key {
            request = request.bearer_auth(api_key);
        }
        let response = request.send().await?;
        let status = response.status();
        let body: Value = response.json().await?;
        if !status.is_success() {
            return Err(AnalysisError::ProviderHttp {
                status,
                message: body
                    .get("error")
                    .and_then(|value| value.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("provider error")
                    .to_string(),
            });
        }
        let content = body
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|choices| choices.first())
            .and_then(|choice| choice.get("message"))
            .and_then(|message| message.get("content"))
            .and_then(Value::as_str)
            .ok_or_else(|| AnalysisError::InvalidResponse("missing message content".into()))?;
        let content = content
            .trim()
            .strip_prefix("```json")
            .and_then(|value| value.strip_suffix("```"))
            .unwrap_or(content)
            .trim();
        let parsed: ProviderPayload = serde_json::from_str(content)
            .map_err(|error| AnalysisError::InvalidResponse(error.to_string()))?;
        parsed.into_output(&self.provider, &self.model)
    }
}

#[derive(Debug, Deserialize)]
struct ProviderPayload {
    confidence: f32,
    summary: String,
    #[serde(default)]
    observations: Vec<String>,
    #[serde(default)]
    recommendations: Vec<String>,
}

impl ProviderPayload {
    fn into_output(self, provider: &str, model: &str) -> Result<AnalysisOutput, AnalysisError> {
        if !(0.0..=1.0).contains(&self.confidence)
            || self.summary.trim().is_empty()
            || self.summary.len() > 4_000
            || self.observations.len() > 32
            || self.recommendations.len() > 32
            || self
                .observations
                .iter()
                .chain(self.recommendations.iter())
                .any(|value| value.len() > 1_000)
        {
            return Err(AnalysisError::InvalidResponse(
                "analysis fields failed validation".into(),
            ));
        }
        Ok(AnalysisOutput {
            provider: provider.to_string(),
            model: model.to_string(),
            confidence: self.confidence,
            summary: self.summary,
            observations: self.observations,
            recommendations: self.recommendations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn offline_mock_returns_structured_analysis() {
        let output = MockProvider {
            model: "offline".into(),
        }
        .analyze(&json!({"incident":{"id":"abc"},"events":[{}]}))
        .await
        .expect("mock analysis");
        assert_eq!(output.provider, "mock");
        assert_eq!(output.observations.len(), 2);
        assert!((0.0..=1.0).contains(&output.confidence));
    }

    #[test]
    fn provider_payload_rejects_invalid_confidence_and_empty_summary() {
        let invalid = ProviderPayload {
            confidence: 2.0,
            summary: String::new(),
            observations: vec![],
            recommendations: vec![],
        };
        assert!(invalid.into_output("mock", "test").is_err());
    }

    #[test]
    fn provider_payload_accepts_structured_output() {
        let valid = ProviderPayload {
            confidence: 0.8,
            summary: "context".into(),
            observations: vec!["observation".into()],
            recommendations: vec!["review".into()],
        };
        assert_eq!(valid.into_output("local", "model").unwrap().model, "model");
    }

    #[tokio::test]
    async fn provider_http_error_is_reported_without_provider_details() {
        use axum::{routing::post, Json, Router};
        use std::net::SocketAddr;

        async fn unavailable() -> (StatusCode, Json<Value>) {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":{"message":"offline"}})),
            )
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                Router::new().route("/chat/completions", post(unavailable)),
            )
            .await;
        });
        let provider = OpenAiCompatibleProvider {
            client: reqwest::Client::new(),
            base_url: format!("http://{address}"),
            api_key: None,
            model: "test".into(),
            provider: "test".into(),
        };
        let error = provider.analyze(&json!({"events":[]})).await.unwrap_err();
        assert!(matches!(
            error,
            AnalysisError::ProviderHttp {
                status: StatusCode::SERVICE_UNAVAILABLE,
                ..
            }
        ));
        task.abort();
    }

    #[tokio::test]
    async fn provider_timeout_is_reported() {
        use axum::{routing::post, Json, Router};
        use std::net::SocketAddr;
        use tokio::time::{sleep, Duration};

        async fn slow() -> Json<Value> {
            sleep(Duration::from_millis(100)).await;
            Json(json!({}))
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                Router::new().route("/chat/completions", post(slow)),
            )
            .await;
        });
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(10))
            .build()
            .unwrap();
        let provider = OpenAiCompatibleProvider {
            client,
            base_url: format!("http://{address}"),
            api_key: None,
            model: "test".into(),
            provider: "test".into(),
        };
        let error = provider.analyze(&json!({"events":[]})).await.unwrap_err();
        assert!(matches!(error, AnalysisError::Request(_)));
        task.abort();
    }
}
