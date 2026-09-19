//! Shared validation for notification credentials and outbound destinations.

use anyhow::{anyhow, bail, Result};
use serde_json::Value;
use std::{collections::HashSet, net::IpAddr};
use url::Url;

pub const WEBHOOK_SECRET_ID: &str = "webhook_auth";
pub const MATRIX_SECRET_ID: &str = "matrix_auth";
pub const SMTP_SECRET_ID: &str = "smtp_password";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidatedChannel {
    Web { url: Url, host: String, port: u16 },
    Smtp { host: String, port: u16 },
}

pub fn allowed_hosts(value: &str) -> Result<HashSet<String>> {
    let mut hosts = HashSet::new();
    for item in value.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let host = normalized_host(item)?;
        if host.parse::<IpAddr>().is_ok() || item.contains('/') || item.contains('*') {
            bail!("notification host allowlist accepts exact DNS names only");
        }
        hosts.insert(host);
    }
    Ok(hosts)
}

pub fn validate_channel(
    channel_type: &str,
    target: &str,
    secret_ref: Option<&str>,
    config: &Value,
    allowed: &HashSet<String>,
) -> Result<ValidatedChannel> {
    validate_secret_binding(channel_type, secret_ref)?;
    match channel_type {
        "webhook" | "matrix" => validate_web_target(target, config, allowed),
        "smtp" => validate_smtp_target(target, config, allowed),
        _ => bail!("unsupported notification channel"),
    }
}

fn validate_secret_binding(channel_type: &str, secret_ref: Option<&str>) -> Result<()> {
    let Some(reference) = secret_ref else {
        return Ok(());
    };
    let expected = match channel_type {
        "webhook" => WEBHOOK_SECRET_ID,
        "matrix" => MATRIX_SECRET_ID,
        "smtp" => SMTP_SECRET_ID,
        _ => bail!("unsupported notification channel"),
    };
    if reference != expected {
        bail!("notification secret is not bound to this channel type");
    }
    Ok(())
}

fn validate_web_target(
    target: &str,
    config: &Value,
    allowed: &HashSet<String>,
) -> Result<ValidatedChannel> {
    if config.as_object().is_none_or(|value| !value.is_empty()) {
        bail!("webhook and matrix channel configuration must be empty");
    }
    let url = Url::parse(target).map_err(|_| anyhow!("invalid notification URL"))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("notification URL must be credential-free HTTPS");
    }
    let host = normalized_host(url.host_str().ok_or_else(|| anyhow!("URL host missing"))?)?;
    require_allowed_dns_host(&host, allowed)?;
    let port = url.port_or_known_default().unwrap_or(443);
    if port != 443 {
        bail!("notification HTTPS target must use port 443");
    }
    Ok(ValidatedChannel::Web { url, host, port })
}

fn validate_smtp_target(
    target: &str,
    config: &Value,
    allowed: &HashSet<String>,
) -> Result<ValidatedChannel> {
    if target.len() > 320
        || target
            .chars()
            .any(|character| matches!(character, '\r' | '\n'))
        || !target.contains('@')
        || target.starts_with('@')
        || target.ends_with('@')
    {
        bail!("invalid SMTP recipient");
    }
    let object = config
        .as_object()
        .ok_or_else(|| anyhow!("SMTP configuration must be an object"))?;
    if object.keys().any(|key| {
        !matches!(key.as_str(), "host" | "username" | "from")
            || matches!(
                key.to_ascii_lowercase().as_str(),
                "secret" | "password" | "token" | "api_key"
            )
    }) {
        bail!("SMTP configuration contains an unsupported field");
    }
    for value in object.values() {
        let text = value
            .as_str()
            .ok_or_else(|| anyhow!("SMTP configuration values must be strings"))?;
        if text.len() > 320
            || text
                .chars()
                .any(|character| matches!(character, '\r' | '\n'))
        {
            bail!("invalid SMTP configuration value");
        }
    }
    let host = normalized_host(
        object
            .get("host")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("SMTP host missing"))?,
    )?;
    require_allowed_dns_host(&host, allowed)?;
    let from = object
        .get("from")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("SMTP sender missing"))?;
    if !from.contains('@') || from.starts_with('@') || from.ends_with('@') {
        bail!("invalid SMTP sender");
    }
    Ok(ValidatedChannel::Smtp { host, port: 465 })
}

fn normalized_host(host: &str) -> Result<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || host
            .chars()
            .any(|character| matches!(character, '/' | '\\' | '@' | ':' | '\r' | '\n'))
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
    {
        bail!("invalid notification host");
    }
    Ok(host)
}

fn require_allowed_dns_host(host: &str, allowed: &HashSet<String>) -> Result<()> {
    if host.parse::<IpAddr>().is_ok() {
        bail!("literal IP notification targets are forbidden");
    }
    if !allowed.contains(host) {
        bail!("notification host is not allowlisted");
    }
    Ok(())
}

pub fn is_public_destination(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [first, second, ..] = address.octets();
            let special_use = first == 0
                || first == 10
                || first == 127
                || (first == 100 && (64..=127).contains(&second))
                || (first == 169 && second == 254)
                || (first == 172 && (16..=31).contains(&second))
                || (first == 192 && second == 0)
                || (first == 192 && second == 168)
                || (first == 198 && (18..=19).contains(&second))
                || first >= 224;
            !(special_use || address.is_documentation())
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_public_destination(IpAddr::V4(mapped));
            }
            let octets = address.octets();
            let ipv4_compatible = octets[..12] == [0; 12];
            let well_known_nat64 = octets[..12] == [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];
            let local_nat64 = octets[..6] == [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01];
            let discard_only = octets[..8] == [0x01, 0x00, 0, 0, 0, 0, 0, 0];
            let ietf_protocol_assignments =
                octets[0] == 0x20 && octets[1] == 0x01 && octets[2] <= 0x01;
            let six_to_four = octets[0] == 0x20 && octets[1] == 0x02;
            let documentation = octets[..4] == [0x20, 0x01, 0x0d, 0xb8];
            let unique_local = octets[0] & 0xfe == 0xfc;
            let link_local = octets[0] == 0xfe && octets[1] & 0xc0 == 0x80;
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || ipv4_compatible
                || well_known_nat64
                || local_nat64
                || discard_only
                || ietf_protocol_assignments
                || six_to_four
                || documentation
                || unique_local
                || link_local)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts() -> HashSet<String> {
        allowed_hosts("hooks.example.test, matrix.example.test, smtp.example.test").unwrap()
    }

    #[test]
    fn accepts_only_exact_allowlisted_https_targets() {
        let valid = validate_channel(
            "webhook",
            "https://hooks.example.test/events",
            Some(WEBHOOK_SECRET_ID),
            &serde_json::json!({}),
            &hosts(),
        );
        assert!(valid.is_ok());
        for target in [
            "http://hooks.example.test/events",
            "https://user@hooks.example.test/events",
            "https://hooks.example.test:8443/events",
            "https://hooks.example.test/events?token=secret",
            "https://127.0.0.1/events",
            "https://other.example.test/events",
        ] {
            assert!(
                validate_channel(
                    "webhook",
                    target,
                    Some(WEBHOOK_SECRET_ID),
                    &serde_json::json!({}),
                    &hosts(),
                )
                .is_err(),
                "accepted {target}"
            );
        }
    }

    #[test]
    fn binds_fixed_secret_ids_to_channel_types() {
        assert!(validate_channel(
            "matrix",
            "https://matrix.example.test/send",
            Some(WEBHOOK_SECRET_ID),
            &serde_json::json!({}),
            &hosts(),
        )
        .is_err());
        assert!(validate_channel(
            "matrix",
            "https://matrix.example.test/send",
            Some(MATRIX_SECRET_ID),
            &serde_json::json!({}),
            &hosts(),
        )
        .is_ok());
    }

    #[test]
    fn rejects_private_link_local_and_documentation_addresses() {
        for address in [
            "0.1.2.3",
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "192.0.0.9",
            "192.0.2.10",
            "198.18.0.1",
            "240.0.0.1",
            "::1",
            "64:ff9b::7f00:1",
            "100::1",
            "2001::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "2002:7f00:1::",
        ] {
            assert!(
                !is_public_destination(address.parse().unwrap()),
                "accepted {address}"
            );
        }
        assert!(is_public_destination("1.1.1.1".parse().unwrap()));
        assert!(is_public_destination(
            "2606:4700:4700::1111".parse().unwrap()
        ));
    }

    #[test]
    fn validates_smtp_host_and_configuration_shape() {
        assert!(validate_channel(
            "smtp",
            "ops@example.test",
            Some(SMTP_SECRET_ID),
            &serde_json::json!({"host":"smtp.example.test","from":"clawforge@example.test"}),
            &hosts(),
        )
        .is_ok());
        assert!(validate_channel(
            "smtp",
            "ops@example.test",
            Some(SMTP_SECRET_ID),
            &serde_json::json!({"host":"smtp.example.test","from":"clawforge@example.test","password":"stored"}),
            &hosts(),
        )
        .is_err());
    }
}
