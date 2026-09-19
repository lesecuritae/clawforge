use anyhow::{Context, Result};
use clawforge_notification::{
    allowed_hosts, is_public_destination, validate_channel, ValidatedChannel, MATRIX_SECRET_ID,
    SMTP_SECRET_ID, WEBHOOK_SECRET_ID,
};
use clawforge_secret::{load_optional, load_required_token};
use lettre::{
    message::Mailbox, transport::smtp::authentication::Credentials, AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};
use reqwest::{redirect::Policy, Client};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashSet, env, net::SocketAddr, time::Duration};
use tracing::{info, warn};
use url::Url;
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
    allowed_hosts: HashSet<String>,
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

fn secret_value(channel_type: &str, reference: Option<&str>) -> Result<Option<String>> {
    let Some(reference) = reference else {
        return Ok(None);
    };
    let (expected, file_key, value_key) = match channel_type {
        "webhook" => (
            WEBHOOK_SECRET_ID,
            "CLAWFORGE_NOTIFIER_WEBHOOK_SECRET_FILE",
            "CLAWFORGE_NOTIFIER_WEBHOOK_SECRET",
        ),
        "matrix" => (
            MATRIX_SECRET_ID,
            "CLAWFORGE_NOTIFIER_MATRIX_SECRET_FILE",
            "CLAWFORGE_NOTIFIER_MATRIX_SECRET",
        ),
        "smtp" => (
            SMTP_SECRET_ID,
            "CLAWFORGE_NOTIFIER_SMTP_SECRET_FILE",
            "CLAWFORGE_NOTIFIER_SMTP_SECRET",
        ),
        _ => anyhow::bail!("unsupported notification channel"),
    };
    if reference != expected {
        anyhow::bail!("notification secret is not bound to this channel type");
    }
    load_optional(file_key, value_key)
}

fn configured_token() -> Result<String> {
    load_required_token("CLAWFORGE_NOTIFIER_TOKEN_FILE", "CLAWFORGE_NOTIFIER_TOKEN")
}

async fn deliver_webhook(
    client: &Client,
    url: Url,
    event: &Event,
    token: Option<String>,
) -> Result<()> {
    let mut request = client.post(url).json(&event.payload);
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

async fn deliver_smtp(event: &Event, host: &str, password: Option<String>) -> Result<()> {
    let message = build_smtp_message(event)?;
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

async fn resolve_public(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .context("notification host lookup failed")?
        .collect::<Vec<_>>();
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| !is_public_destination(address.ip()))
    {
        anyhow::bail!("notification host resolved to a forbidden address");
    }
    Ok(addresses)
}

async fn web_client(host: &str, port: u16, timeout: Duration) -> Result<Client> {
    let addresses = resolve_public(host, port).await?;
    Client::builder()
        .timeout(timeout)
        .redirect(Policy::none())
        .resolve_to_addrs(host, &addresses)
        .build()
        .context("build pinned notification client")
}

async fn deliver(event: &Event, config: &Config) -> Result<()> {
    let destination = validate_channel(
        &event.channel_type,
        &event.target,
        event.secret_ref.as_deref(),
        &event.config,
        &config.allowed_hosts,
    )?;
    let secret = secret_value(&event.channel_type, event.secret_ref.as_deref())?;
    match (event.channel_type.as_str(), destination) {
        ("webhook", ValidatedChannel::Web { url, host, port }) => {
            let client = web_client(&host, port, config.timeout).await?;
            deliver_webhook(&client, url, event, secret).await
        }
        ("matrix", ValidatedChannel::Web { url, host, port }) => {
            let client = web_client(&host, port, config.timeout).await?;
            let body = matrix_payload(event);
            let mut request = client.post(url).json(&body);
            if let Some(token) = secret {
                request = request.bearer_auth(token);
            }
            let response = request.send().await?;
            if !response.status().is_success() {
                anyhow::bail!("Matrix webhook returned {}", response.status());
            }
            Ok(())
        }
        ("smtp", ValidatedChannel::Smtp { host, port }) => {
            resolve_public(&host, port).await?;
            deliver_smtp(event, &host, secret).await
        }
        _ => anyhow::bail!("notification channel validation mismatch"),
    }
}

async fn poll_once(client: &Client, config: &Config) -> Result<()> {
    let events_response = client
        .get(format!(
            "{}/internal/events/consume?limit=25",
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
        let result = deliver(&event, config).await;
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
        allowed_hosts: allowed_hosts(
            &env::var("CLAWFORGE_NOTIFIER_ALLOWED_HOSTS").unwrap_or_default(),
        )?,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let config = config()?;
    let client = Client::builder()
        .timeout(config.timeout)
        .redirect(Policy::none())
        .build()?;
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
    fn channel_secret_ids_are_fixed_and_cannot_select_arbitrary_environment_values() {
        std::env::set_var("CLAWFORGE_NOTIFIER_WEBHOOK_SECRET", "value");
        std::env::set_var("CLAWFORGE_NOTIFICATION_TEST_SECRET", "must-not-be-readable");
        assert_eq!(
            secret_value("webhook", Some(WEBHOOK_SECRET_ID))
                .unwrap()
                .as_deref(),
            Some("value")
        );
        assert!(secret_value("webhook", Some("CLAWFORGE_NOTIFICATION_TEST_SECRET")).is_err());
        std::env::remove_var("CLAWFORGE_NOTIFIER_WEBHOOK_SECRET");
        std::env::remove_var("CLAWFORGE_NOTIFICATION_TEST_SECRET");
    }

    #[test]
    fn retry_backoff_is_bounded_and_exponential() {
        assert_eq!(retry_delay(0), Duration::from_secs(1));
        assert_eq!(retry_delay(3), Duration::from_secs(8));
        assert_eq!(retry_delay(99), Duration::from_secs(3600));
    }

    #[tokio::test]
    async fn dns_resolution_rejects_loopback_destinations() {
        assert!(resolve_public("localhost", 443).await.is_err());
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
            secret_ref: Some(SMTP_SECRET_ID.into()),
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
        deliver_webhook(&client, Url::parse(&event.target).unwrap(), &event, None)
            .await
            .unwrap();
        task.await.unwrap();
    }
}
