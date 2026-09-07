use anyhow::{Context, Result};
use lettre::{
    message::Mailbox, transport::smtp::authentication::Credentials, AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{env, fs, time::Duration};
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct Envelope<T> {
    data: T,
}

#[derive(Debug, Deserialize)]
struct Event {
    id: Uuid,
    event_type: String,
    severity: String,
    #[serde(rename = "resource")]
    _resource: String,
    target: String,
    channel_type: String,
    payload: Value,
    retry_count: i32,
    secret_ref: Option<String>,
    config: Value,
}

#[derive(Debug, Serialize)]
struct ResultRequest<'a> {
    success: bool,
    error: Option<&'a str>,
}

#[derive(Clone)]
struct Config {
    api_url: String,
    token: String,
    poll: Duration,
    timeout: Duration,
}

fn retry_delay(attempt: i32) -> Duration {
    Duration::from_secs(2_u64.saturating_pow(attempt.max(0) as u32).min(3600))
}

fn matrix_payload(event: &Event) -> Value {
    serde_json::json!({
        "msgtype": "m.text",
        "body": format!("{} [{}] {}", event.event_type, event.severity, serde_json::to_string(&event.payload).unwrap_or_default())
    })
}

fn secret_value(reference: Option<&str>) -> Option<String> {
    let name = reference?;
    if let Ok(path) = env::var(format!("{name}_FILE")) {
        if let Ok(value) = fs::read_to_string(path) {
            if !value.trim().is_empty() {
                return Some(value.trim().to_string());
            }
        }
    }
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn configured_token() -> Result<String> {
    if let Ok(path) = env::var("CLAWFORGE_NOTIFIER_TOKEN_FILE") {
        if let Ok(value) = fs::read_to_string(path) {
            if !value.trim().is_empty() {
                return Ok(value.trim().to_string());
            }
        }
    }
    env::var("CLAWFORGE_NOTIFIER_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .context("CLAWFORGE_NOTIFIER_TOKEN_FILE or CLAWFORGE_NOTIFIER_TOKEN must be configured")
}

async fn deliver_webhook(client: &Client, event: &Event, token: Option<String>) -> Result<()> {
    let mut request = client.post(&event.target).json(&event.payload);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request
        .header("X-Clawforge-Event", &event.event_type)
        .send()
        .await?;
    if !response.status().is_success() {
        anyhow::bail!("webhook returned {}", response.status());
    }
    Ok(())
}

async fn deliver_smtp(event: &Event, password: Option<String>) -> Result<()> {
    let message = build_smtp_message(event)?;
    let host = event
        .config
        .get("host")
        .and_then(Value::as_str)
        .context("smtp config.host missing")?;
    let user = event.config.get("username").and_then(Value::as_str);
    let builder = AsyncSmtpTransport::<Tokio1Executor>::relay(host)?;
    let builder = if let (Some(user), Some(password)) = (user, password) {
        builder.credentials(Credentials::new(user.to_string(), password))
    } else {
        builder
    };
    builder.build().send(message).await?;
    Ok(())
}

fn build_smtp_message(event: &Event) -> Result<Message> {
    let from = event
        .config
        .get("from")
        .and_then(Value::as_str)
        .context("smtp config.from missing")?;
    let to = event
        .target
        .parse::<Mailbox>()
        .context("invalid SMTP recipient")?;
    let from = from.parse::<Mailbox>().context("invalid SMTP sender")?;
    let body = serde_json::to_string_pretty(&event.payload)?;
    Ok(Message::builder()
        .from(from)
        .to(to)
        .subject(format!(
            "Clawforge {} ({})",
            event.event_type, event.severity
        ))
        .body(body)?)
}

async fn deliver(client: &Client, event: &Event) -> Result<()> {
    let secret = secret_value(event.secret_ref.as_deref());
    match event.channel_type.as_str() {
        "webhook" => deliver_webhook(client, event, secret).await,
        "matrix" => {
            let body = matrix_payload(event);
            let mut request = client.post(&event.target).json(&body);
            if let Some(token) = secret {
                request = request.bearer_auth(token);
            }
            let response = request.send().await?;
            if !response.status().is_success() {
                anyhow::bail!("Matrix webhook returned {}", response.status());
            }
            Ok(())
        }
        "smtp" => deliver_smtp(event, secret).await,
        other => anyhow::bail!("unsupported notification channel {other}"),
    }
}

async fn poll_once(client: &Client, config: &Config) -> Result<()> {
    let events_response = client
        .get(format!(
            "{}/internal/events/consume?consumer=notifier&limit=25",
            config.api_url.trim_end_matches('/')
        ))
        .bearer_auth(&config.token)
        .send()
        .await?
        .error_for_status()?;
    let events: Envelope<Vec<Value>> = events_response.json().await?;
    for event in events.data {
        if let Some(delivery_id) = event.get("delivery_id").and_then(Value::as_str) {
            client
                .post(format!(
                    "{}/internal/events/{}/result",
                    config.api_url.trim_end_matches('/'),
                    delivery_id
                ))
                .bearer_auth(&config.token)
                .json(&ResultRequest {
                    success: true,
                    error: None,
                })
                .send()
                .await?
                .error_for_status()?;
        }
    }
    let response = client
        .get(format!(
            "{}/internal/notifier/events?limit=25",
            config.api_url.trim_end_matches('/')
        ))
        .bearer_auth(&config.token)
        .send()
        .await?
        .error_for_status()?;
    let envelope: Envelope<Vec<Event>> = response.json().await?;
    for event in envelope.data {
        let result = deliver(client, &event).await;
        let (success, error) = match &result {
            Ok(()) => (true, None),
            Err(error) => (false, Some(error.to_string())),
        };
        if let Err(error) = client
            .post(format!(
                "{}/internal/notifier/events/{}/result",
                config.api_url.trim_end_matches('/'),
                event.id
            ))
            .bearer_auth(&config.token)
            .json(&ResultRequest {
                success,
                error: error.as_deref(),
            })
            .send()
            .await?
            .error_for_status()
        {
            warn!(event_id=%event.id, %error, "could not persist notification result");
        }
        if let Err(error) = result {
            let next_retry = retry_delay(event.retry_count);
            warn!(event_id=%event.id, retry_count=event.retry_count, retry_after_seconds=next_retry.as_secs(), %error, "notification delivery failed");
        }
    }
    Ok(())
}

fn config() -> Result<Config> {
    let token = configured_token()?;
    Ok(Config {
        api_url: env::var("CLAWFORGE_CORE_API_URL")
            .unwrap_or_else(|_| "http://clawforge-api:8080".into()),
        token,
        poll: Duration::from_secs(
            env::var("CLAWFORGE_NOTIFIER_POLL_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
        ),
        timeout: Duration::from_secs(
            env::var("CLAWFORGE_NOTIFIER_TIMEOUT_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(15),
        ),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let config = config()?;
    let client = Client::builder().timeout(config.timeout).build()?;
    info!(api_url=%config.api_url, "Clawforge notifier started");
    let mut interval = tokio::time::interval(config.poll);
    loop {
        tokio::select! {
            _ = interval.tick() => if let Err(error) = poll_once(&client, &config).await { warn!(%error, "notifier poll failed"); },
            _ = shutdown_signal() => { info!("Clawforge notifier shutting down"); break; }
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secret_values_are_loaded_from_environment_only() {
        std::env::set_var("CLAWFORGE_NOTIFICATION_TEST_SECRET", "value");
        assert_eq!(
            secret_value(Some("CLAWFORGE_NOTIFICATION_TEST_SECRET")).as_deref(),
            Some("value")
        );
    }

    #[test]
    fn retry_backoff_is_bounded_and_exponential() {
        assert_eq!(retry_delay(0), Duration::from_secs(1));
        assert_eq!(retry_delay(3), Duration::from_secs(8));
        assert_eq!(retry_delay(99), Duration::from_secs(3600));
    }

    #[test]
    fn matrix_payload_is_structured() {
        let event = Event {
            id: Uuid::new_v4(),
            event_type: "rpki_invalid".into(),
            severity: "high".into(),
            _resource: "prefix".into(),
            target: "https://matrix.invalid".into(),
            channel_type: "matrix".into(),
            payload: serde_json::json!({"source":"test"}),
            retry_count: 1,
            secret_ref: None,
            config: serde_json::json!({}),
        };
        assert_eq!(matrix_payload(&event)["msgtype"], "m.text");
        assert!(matrix_payload(&event)["body"]
            .as_str()
            .unwrap()
            .contains("rpki_invalid"));
    }

    #[test]
    fn smtp_message_is_built_without_network_access() {
        let event = Event {
            id: Uuid::new_v4(),
            event_type: "incident_created".into(),
            severity: "high".into(),
            _resource: "incident".into(),
            target: "ops@example.test".into(),
            channel_type: "smtp".into(),
            payload: serde_json::json!({"risk_score":80}),
            retry_count: 0,
            secret_ref: Some("SMTP_PASSWORD".into()),
            config: serde_json::json!({"from":"clawforge@example.test","host":"smtp.example.test"}),
        };
        let message = build_smtp_message(&event).expect("valid mock SMTP message");
        assert_eq!(
            message
                .headers()
                .get::<lettre::message::header::Subject>()
                .unwrap()
                .as_ref(),
            "Clawforge incident_created (high)"
        );
    }

    #[tokio::test]
    async fn webhook_mock_receives_structured_payload() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 4096];
            let size = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..size]);
            assert!(request.contains("incident_created"));
            assert!(request.contains("risk_score"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let event = Event {
            id: Uuid::new_v4(),
            event_type: "incident_created".into(),
            severity: "high".into(),
            _resource: "incident".into(),
            target: format!("http://{address}"),
            channel_type: "webhook".into(),
            payload: serde_json::json!({"risk_score":80}),
            retry_count: 0,
            secret_ref: None,
            config: serde_json::json!({}),
        };
        let client = Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        deliver_webhook(&client, &event, None).await.unwrap();
        task.await.unwrap();
    }
}
