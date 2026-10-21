//! Routing context for one source address: the announced prefix, its origin
//! ASN(s) and the RPKI validity of that announcement, from RIPEstat's public,
//! keyless Data API (`network-info`, `rpki-validation`).
//!
//! This is *context*, not a verdict. An unrouted prefix, a multi-origin
//! announcement or an RPKI-invalid route is a fact about routing hygiene that
//! legitimate networks also produce; nothing here decides to block anything. The
//! consumers only use the origin ASN to look it up in reputation lists, and show
//! the rest to a human approver.
//!
//! Everything fetched is untrusted input: the response size is capped while
//! streaming, redirects are refused, the JSON envelope must say `ok`/200, the
//! announced prefix must actually contain the queried address and must not be
//! implausibly wide, and ASNs must be plain numbers. A malformed or hostile
//! answer is an error, never a partial result.

use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use reqwest::{redirect::Policy, Client, StatusCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SOURCE: &str = "ripestat";
const BASE_URL: &str = "https://stat.ripe.net/data";
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_ASNS: usize = 16;
const MIN_V4_PREFIX_LEN: u8 = 8;
const MIN_V6_PREFIX_LEN: u8 = 16;
/// Upper bound honoured for a server-supplied `Retry-After`.
pub const MAX_RETRY_AFTER_SECONDS: u64 = 3600;

#[derive(Debug, Error)]
pub enum IpContextError {
    /// HTTP 429 (or an equivalent refusal); the caller must wait at least this long.
    #[error("rate limited, retry after {retry_after_seconds}s")]
    RateLimited { retry_after_seconds: u64 },
    #[error("upstream HTTP status {0}")]
    Upstream(u16),
    #[error("request failed or timed out")]
    Transport,
    #[error("response rejected: {0}")]
    Rejected(&'static str),
}

impl IpContextError {
    /// Whether retrying later can help (transport/upstream/rate limit) as opposed
    /// to a response that was refused as malformed or hostile.
    pub fn is_transient(&self) -> bool {
        !matches!(self, Self::Rejected(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpkiSummary {
    Valid,
    Invalid,
    /// Several origins whose validity differs.
    Mixed,
    Unknown,
    /// The validity call failed or was not attempted.
    NotChecked,
}

impl RpkiSummary {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Mixed => "mixed",
            Self::Unknown => "unknown",
            Self::NotChecked => "not_checked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpNetworkContext {
    /// `None` for an address with no announced route.
    pub prefix: Option<IpNet>,
    pub origin_asns: Vec<u32>,
    pub rpki: RpkiSummary,
    pub source: String,
    pub fetched_at: DateTime<Utc>,
}

impl IpNetworkContext {
    /// More than one announced origin for the prefix (multi-origin AS): context only.
    pub fn multi_origin(&self) -> bool {
        self.origin_asns.len() > 1
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RpkiState {
    Valid,
    Invalid,
    Unknown,
}

fn envelope(body: &[u8]) -> Result<serde_json::Value, IpContextError> {
    if body.is_empty() || body.len() > MAX_BODY_BYTES {
        return Err(IpContextError::Rejected(
            "body size outside the accepted range",
        ));
    }
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| IpContextError::Rejected("not JSON"))?;
    if value.get("status").and_then(serde_json::Value::as_str) != Some("ok")
        || value.get("status_code").and_then(serde_json::Value::as_u64) != Some(200)
    {
        return Err(IpContextError::Rejected("envelope is not status ok / 200"));
    }
    Ok(value)
}

fn asn_number(text: &str) -> Option<u32> {
    if text.is_empty() || text.len() > 10 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u32>().ok().filter(|asn| *asn != 0)
}

/// `Ok(None)`: a well-formed answer saying the address has no announced route.
pub fn parse_network_info(
    body: &[u8],
    ip: IpAddr,
) -> Result<Option<(IpNet, Vec<u32>)>, IpContextError> {
    let value = envelope(body)?;
    let data = value
        .get("data")
        .and_then(serde_json::Value::as_object)
        .ok_or(IpContextError::Rejected("data is not an object"))?;
    let prefix = data
        .get("prefix")
        .and_then(serde_json::Value::as_str)
        .ok_or(IpContextError::Rejected("prefix missing"))?;
    let asns = data
        .get("asns")
        .and_then(serde_json::Value::as_array)
        .ok_or(IpContextError::Rejected("asns missing"))?;
    if prefix.is_empty() {
        return if asns.is_empty() {
            Ok(None)
        } else {
            Err(IpContextError::Rejected("origin ASNs without a prefix"))
        };
    }
    let net: IpNet = prefix
        .parse()
        .map_err(|_| IpContextError::Rejected("prefix is not a CIDR"))?;
    let min = match net {
        IpNet::V4(_) => MIN_V4_PREFIX_LEN,
        IpNet::V6(_) => MIN_V6_PREFIX_LEN,
    };
    if net.prefix_len() < min {
        return Err(IpContextError::Rejected(
            "announced prefix implausibly wide",
        ));
    }
    if !net.contains(&ip) {
        return Err(IpContextError::Rejected(
            "prefix does not contain the queried address",
        ));
    }
    if asns.is_empty() || asns.len() > MAX_ASNS {
        return Err(IpContextError::Rejected(
            "origin ASN count outside the accepted range",
        ));
    }
    let mut origins = Vec::with_capacity(asns.len());
    for item in asns {
        let number = item
            .as_str()
            .and_then(asn_number)
            .or_else(|| {
                item.as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .filter(|n| *n != 0)
            })
            .ok_or(IpContextError::Rejected("origin ASN is not a plain number"))?;
        origins.push(number);
    }
    origins.sort_unstable();
    origins.dedup();
    Ok(Some((net, origins)))
}

fn parse_rpki(body: &[u8], prefix: &IpNet, asn: u32) -> Result<RpkiState, IpContextError> {
    let value = envelope(body)?;
    let data = value
        .get("data")
        .and_then(serde_json::Value::as_object)
        .ok_or(IpContextError::Rejected("data is not an object"))?;
    // The answer must be about what was asked.
    let echoed_prefix = data.get("prefix").and_then(serde_json::Value::as_str);
    if echoed_prefix.and_then(|p| p.parse::<IpNet>().ok()) != Some(*prefix) {
        return Err(IpContextError::Rejected(
            "RPKI answer is about a different prefix",
        ));
    }
    let echoed_asn = match data.get("resource") {
        Some(serde_json::Value::String(text)) => asn_number(text.trim_start_matches("AS")),
        Some(serde_json::Value::Number(number)) => {
            number.as_u64().and_then(|n| u32::try_from(n).ok())
        }
        _ => None,
    };
    if echoed_asn != Some(asn) {
        return Err(IpContextError::Rejected(
            "RPKI answer is about a different origin",
        ));
    }
    match data.get("status").and_then(serde_json::Value::as_str) {
        Some("valid") => Ok(RpkiState::Valid),
        Some(status) if status.starts_with("invalid") => Ok(RpkiState::Invalid),
        Some("unknown") | Some("not-found") | Some("unverified") => Ok(RpkiState::Unknown),
        _ => Err(IpContextError::Rejected(
            "RPKI status is not a recognised value",
        )),
    }
}

fn summarize(states: &[RpkiState]) -> RpkiSummary {
    if states.is_empty() {
        return RpkiSummary::NotChecked;
    }
    if states.iter().all(|s| *s == RpkiState::Valid) {
        RpkiSummary::Valid
    } else if states.iter().all(|s| *s == RpkiState::Invalid) {
        RpkiSummary::Invalid
    } else if states.iter().all(|s| *s == RpkiState::Unknown) {
        RpkiSummary::Unknown
    } else {
        RpkiSummary::Mixed
    }
}

/// Parse both answers into one context. `rpki_bodies` holds one answer per origin
/// ASN in the same (sorted) order; a missing or refused answer degrades to
/// `NotChecked` rather than failing the routing facts that were verified.
pub fn assemble(
    network_info: &[u8],
    ip: IpAddr,
    rpki_bodies: &[Option<Vec<u8>>],
    fetched_at: DateTime<Utc>,
) -> Result<IpNetworkContext, IpContextError> {
    let Some((prefix, origins)) = parse_network_info(network_info, ip)? else {
        return Ok(IpNetworkContext {
            prefix: None,
            origin_asns: Vec::new(),
            rpki: RpkiSummary::NotChecked,
            source: SOURCE.into(),
            fetched_at,
        });
    };
    let mut states = Vec::new();
    let mut complete = rpki_bodies.len() == origins.len();
    for (asn, body) in origins.iter().zip(rpki_bodies) {
        match body
            .as_deref()
            .map(|bytes| parse_rpki(bytes, &prefix, *asn))
        {
            Some(Ok(state)) => states.push(state),
            _ => complete = false,
        }
    }
    Ok(IpNetworkContext {
        prefix: Some(prefix),
        origin_asns: origins,
        rpki: if complete {
            summarize(&states)
        } else {
            RpkiSummary::NotChecked
        },
        source: SOURCE.into(),
        fetched_at,
    })
}

/// Only publicly routable unicast addresses are ever sent to the third party:
/// never loopback, private, link-local, CGNAT/shared, documentation-adjacent
/// special ranges, multicast or unspecified addresses (our own and management
/// networks live there).
pub fn is_queryable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1])) // 100.64.0.0/10 (CGNAT, Tailscale)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local
                || (s[0] & 0xffc0) == 0xfe80 // link local
                || v6.to_ipv4_mapped().is_some()
                || (s[0] & 0xe000) != 0x2000) // outside global unicast 2000::/3
        }
    }
}

#[derive(Clone)]
pub struct RipeStatIpContext {
    client: Client,
    base_url: String,
    sourceapp: String,
}

impl RipeStatIpContext {
    pub fn new(sourceapp: &str) -> Result<Self, IpContextError> {
        Self::with_base(BASE_URL, sourceapp)
    }

    /// For tests against a local fixture server.
    pub fn with_base(base_url: &str, sourceapp: &str) -> Result<Self, IpContextError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(Policy::none())
            .user_agent("clawforge-ip-context/0.1")
            .build()
            .map_err(|_| IpContextError::Transport)?;
        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            sourceapp: sourceapp.to_string(),
        })
    }

    async fn get(&self, call: &str, query: &[(&str, &str)]) -> Result<Vec<u8>, IpContextError> {
        let url = format!("{}/{call}/data.json", self.base_url);
        let mut response = self
            .client
            .get(&url)
            .query(query)
            .query(&[("sourceapp", self.sourceapp.as_str())])
            .send()
            .await
            .map_err(|_| IpContextError::Transport)?;
        let status = response.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            let seconds = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse::<u64>().ok())
                .unwrap_or(60)
                .clamp(1, MAX_RETRY_AFTER_SECONDS);
            return Err(IpContextError::RateLimited {
                retry_after_seconds: seconds,
            });
        }
        if !status.is_success() {
            return Err(IpContextError::Upstream(status.as_u16()));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| IpContextError::Transport)?
        {
            if body.len() + chunk.len() > MAX_BODY_BYTES {
                return Err(IpContextError::Rejected("body exceeds the size cap"));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// Routing context for one address. The caller guarantees `is_queryable`.
    pub async fn lookup(&self, ip: IpAddr) -> Result<IpNetworkContext, IpContextError> {
        if !is_queryable(ip) {
            return Err(IpContextError::Rejected(
                "address is not publicly routable unicast",
            ));
        }
        let info = self
            .get("network-info", &[("resource", &ip.to_string())])
            .await?;
        let Some((prefix, origins)) = parse_network_info(&info, ip)? else {
            return assemble(&info, ip, &[], Utc::now());
        };
        let mut bodies = Vec::with_capacity(origins.len());
        for asn in &origins {
            // The validity call is best-effort: a failure leaves it "not checked".
            let body = self
                .get(
                    "rpki-validation",
                    &[
                        ("resource", &format!("AS{asn}")),
                        ("prefix", &prefix.to_string()),
                    ],
                )
                .await;
            match body {
                Ok(bytes) => bodies.push(Some(bytes)),
                Err(error @ IpContextError::RateLimited { .. }) => return Err(error),
                Err(_) => bodies.push(None),
            }
        }
        assemble(&info, ip, &bodies, Utc::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(data: &str) -> Vec<u8> {
        format!(r#"{{"status":"ok","status_code":200,"data":{data}}}"#).into_bytes()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn a_well_formed_announcement_parses() {
        let body = ok(r#"{"asns":["15169"],"prefix":"8.8.8.0/24"}"#);
        let (net, asns) = parse_network_info(&body, ip("8.8.8.8")).unwrap().unwrap();
        assert_eq!(net.to_string(), "8.8.8.0/24");
        assert_eq!(asns, vec![15169]);
    }

    #[test]
    fn an_unrouted_address_is_a_valid_empty_answer() {
        let body = ok(r#"{"asns":[],"prefix":""}"#);
        assert_eq!(parse_network_info(&body, ip("8.8.8.8")).unwrap(), None);
        let ctx = assemble(&body, ip("8.8.8.8"), &[], Utc::now()).unwrap();
        assert_eq!(ctx.prefix, None);
        assert_eq!(ctx.rpki, RpkiSummary::NotChecked);
    }

    #[test]
    fn hostile_or_malformed_answers_are_rejected_not_partially_used() {
        let target = ip("8.8.8.8");
        for body in [
            b"".to_vec(),
            b"not json".to_vec(),
            vec![b'a'; MAX_BODY_BYTES + 1],
            br#"{"status":"error","status_code":500,"data":{}}"#.to_vec(),
            br#"{"status":"ok","status_code":200}"#.to_vec(),
            ok(r#"{"asns":["15169"]}"#),
            ok(r#"{"asns":"15169","prefix":"8.8.8.0/24"}"#),
            // prefix that does not contain the queried address
            ok(r#"{"asns":["15169"],"prefix":"9.9.9.0/24"}"#),
            // "everything" prefixes
            ok(r#"{"asns":["15169"],"prefix":"0.0.0.0/0"}"#),
            ok(r#"{"asns":["15169"],"prefix":"8.0.0.0/7"}"#),
            ok(r#"{"asns":["15169"],"prefix":"::/0"}"#),
            // origin without prefix, empty origin list with prefix
            ok(r#"{"asns":["15169"],"prefix":""}"#),
            ok(r#"{"asns":[],"prefix":"8.8.8.0/24"}"#),
            // non-numeric, signed, oversized, zero and absurdly many origins
            ok(r#"{"asns":["AS15169"],"prefix":"8.8.8.0/24"}"#),
            ok(r#"{"asns":["-5"],"prefix":"8.8.8.0/24"}"#),
            ok(r#"{"asns":["99999999999"],"prefix":"8.8.8.0/24"}"#),
            ok(r#"{"asns":["0"],"prefix":"8.8.8.0/24"}"#),
            ok(&format!(
                r#"{{"asns":[{}],"prefix":"8.8.8.0/24"}}"#,
                (1..40)
                    .map(|n| format!("\"{n}\""))
                    .collect::<Vec<_>>()
                    .join(",")
            )),
            ok(r#"{"asns":[{"x":1}],"prefix":"8.8.8.0/24"}"#),
        ] {
            assert!(
                parse_network_info(&body, target).is_err(),
                "must reject {:?}",
                String::from_utf8_lossy(&body)
                    .chars()
                    .take(80)
                    .collect::<String>()
            );
        }
    }

    #[test]
    fn duplicate_and_unsorted_origins_are_normalised() {
        let body = ok(r#"{"asns":["64500","64496","64500"],"prefix":"203.0.113.0/24"}"#);
        let (_, asns) = parse_network_info(&body, ip("203.0.113.9"))
            .unwrap()
            .unwrap();
        assert_eq!(asns, vec![64496, 64500]);
    }

    fn rpki_body(resource: &str, prefix: &str, status: &str) -> Option<Vec<u8>> {
        Some(ok(&format!(
            r#"{{"resource":"{resource}","prefix":"{prefix}","status":"{status}","validating_roas":[]}}"#
        )))
    }

    #[test]
    fn rpki_states_are_summarised_per_origin() {
        let info = ok(r#"{"asns":["64496"],"prefix":"203.0.113.0/24"}"#);
        let at = Utc::now();
        for (status, expected) in [
            ("valid", RpkiSummary::Valid),
            ("invalid_asn", RpkiSummary::Invalid),
            ("invalid_length", RpkiSummary::Invalid),
            ("unknown", RpkiSummary::Unknown),
        ] {
            let ctx = assemble(
                &info,
                ip("203.0.113.9"),
                &[rpki_body("64496", "203.0.113.0/24", status)],
                at,
            )
            .unwrap();
            assert_eq!(ctx.rpki, expected, "{status}");
        }
        // multi-origin with differing validity is "mixed", never silently one of them
        let info = ok(r#"{"asns":["64496","64500"],"prefix":"203.0.113.0/24"}"#);
        let ctx = assemble(
            &info,
            ip("203.0.113.9"),
            &[
                rpki_body("64496", "203.0.113.0/24", "valid"),
                rpki_body("64500", "203.0.113.0/24", "invalid_asn"),
            ],
            at,
        )
        .unwrap();
        assert_eq!(ctx.rpki, RpkiSummary::Mixed);
        assert!(ctx.multi_origin());
    }

    #[test]
    fn a_wrong_or_missing_rpki_answer_degrades_to_not_checked_never_to_valid() {
        let info = ok(r#"{"asns":["64496"],"prefix":"203.0.113.0/24"}"#);
        let at = Utc::now();
        let wrong_prefix = rpki_body("64496", "198.51.100.0/24", "valid");
        let wrong_origin = rpki_body("65000", "203.0.113.0/24", "valid");
        let garbage_status = rpki_body("64496", "203.0.113.0/24", "definitely-fine");
        for answer in [
            wrong_prefix,
            wrong_origin,
            garbage_status,
            None,
            Some(b"{".to_vec()),
        ] {
            let ctx = assemble(&info, ip("203.0.113.9"), &[answer], at).unwrap();
            assert_eq!(ctx.rpki, RpkiSummary::NotChecked);
            assert_eq!(
                ctx.origin_asns,
                vec![64496],
                "verified routing facts are kept"
            );
        }
        // fewer answers than origins is also incomplete
        let two = ok(r#"{"asns":["64496","64500"],"prefix":"203.0.113.0/24"}"#);
        let ctx = assemble(
            &two,
            ip("203.0.113.9"),
            &[rpki_body("64496", "203.0.113.0/24", "valid")],
            at,
        )
        .unwrap();
        assert_eq!(ctx.rpki, RpkiSummary::NotChecked);
    }

    #[test]
    fn only_public_unicast_addresses_are_ever_queried() {
        for yes in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ] {
            assert!(is_queryable(ip(yes)), "{yes}");
        }
        for no in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.9",
            "192.168.0.8",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.254",
            "224.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
            "192.0.0.5",
            "198.18.0.1",
            "240.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
            "::ffff:10.0.0.1",
            "100::1",
        ] {
            assert!(!is_queryable(ip(no)), "{no}");
        }
    }

    #[test]
    fn transient_versus_rejected_errors_are_distinguished() {
        assert!(IpContextError::RateLimited {
            retry_after_seconds: 5
        }
        .is_transient());
        assert!(IpContextError::Upstream(503).is_transient());
        assert!(IpContextError::Transport.is_transient());
        assert!(!IpContextError::Rejected("x").is_transient());
    }
}

#[cfg(test)]
mod http_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// One-shot local HTTP server answering every request with `respond(path)`.
    fn serve(
        respond: impl Fn(&str) -> Vec<u8> + Send + 'static,
    ) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut buffer = [0_u8; 4096];
                let n = stream.read(&mut buffer).unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..n]).to_string();
                let path = request.split_whitespace().nth(1).unwrap_or("").to_string();
                log.lock().unwrap().push(path.clone());
                let _ = stream.write_all(&respond(&path));
            }
        });
        (base, seen)
    }

    fn response(status: &str, headers: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn client(base: &str) -> RipeStatIpContext {
        RipeStatIpContext::with_base(base, "clawforge-test").unwrap()
    }

    #[tokio::test]
    async fn a_normal_lookup_assembles_routing_and_validity() {
        let (base, seen) = serve(|path| {
            if path.starts_with("/network-info") {
                response(
                    "200 OK",
                    "",
                    r#"{"status":"ok","status_code":200,"data":{"asns":["64496"],"prefix":"93.184.216.0/24"}}"#,
                )
            } else {
                response(
                    "200 OK",
                    "",
                    r#"{"status":"ok","status_code":200,"data":{"resource":"64496","prefix":"93.184.216.0/24","status":"valid"}}"#,
                )
            }
        });
        let context = client(&base).lookup(ip("93.184.216.34")).await.unwrap();
        assert_eq!(context.origin_asns, vec![64496]);
        assert_eq!(context.rpki, RpkiSummary::Valid);
        assert_eq!(context.prefix.unwrap().to_string(), "93.184.216.0/24");
        assert_eq!(
            seen.lock().unwrap().len(),
            2,
            "one routing call, one validity call per origin"
        );
    }

    #[tokio::test]
    async fn requests_carry_the_source_application_identifier() {
        let (base, seen) = serve(|_| {
            response(
                "200 OK",
                "",
                r#"{"status":"ok","status_code":200,"data":{"asns":[],"prefix":""}}"#,
            )
        });
        let context = client(&base).lookup(ip("93.184.216.34")).await.unwrap();
        assert_eq!(context.prefix, None);
        let paths = seen.lock().unwrap().clone();
        assert_eq!(paths.len(), 1, "an unrouted address needs no validity call");
        assert!(
            paths[0].contains("sourceapp=clawforge-test")
                && paths[0].contains("resource=93.184.216.34"),
            "{paths:?}"
        );
    }

    #[tokio::test]
    async fn rate_limiting_is_surfaced_with_a_bounded_retry_after() {
        for (header, expected) in [
            ("Retry-After: 7\r\n", 7),
            ("Retry-After: 99999\r\n", 3600),
            ("", 60),
            ("Retry-After: soon\r\n", 60),
            ("Retry-After: 0\r\n", 1),
        ] {
            let (base, _) = serve(move |_| response("429 Too Many Requests", header, "{}"));
            match client(&base).lookup(ip("93.184.216.34")).await {
                Err(IpContextError::RateLimited {
                    retry_after_seconds,
                }) => {
                    assert_eq!(retry_after_seconds, expected, "{header:?}");
                }
                other => panic!("expected RateLimited for {header:?}, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn redirects_upstream_errors_and_oversized_bodies_are_refused() {
        let (base, seen) = serve(|_| {
            response(
                "302 Found",
                "Location: http://127.0.0.1:1/elsewhere\r\n",
                "",
            )
        });
        assert!(matches!(
            client(&base).lookup(ip("93.184.216.34")).await,
            Err(IpContextError::Upstream(302))
        ));
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "the redirect target must never be requested"
        );
        let (base, _) = serve(|_| response("503 Service Unavailable", "", "down"));
        assert!(matches!(
            client(&base).lookup(ip("93.184.216.34")).await,
            Err(IpContextError::Upstream(503))
        ));
        let big = "x".repeat(MAX_BODY_BYTES + 10);
        let (base, _) = serve(move |_| response("200 OK", "", &big));
        assert!(matches!(
            client(&base).lookup(ip("93.184.216.34")).await,
            Err(IpContextError::Rejected(_))
        ));
    }

    #[tokio::test]
    async fn non_public_addresses_never_leave_the_host() {
        let (base, seen) = serve(|_| response("200 OK", "", "{}"));
        for address in ["10.0.0.5", "127.0.0.1", "100.64.1.1", "fe80::1"] {
            assert!(client(&base).lookup(ip(address)).await.is_err());
        }
        assert!(
            seen.lock().unwrap().is_empty(),
            "no request may be made for non-public addresses"
        );
    }

    #[tokio::test]
    async fn a_failed_validity_call_keeps_the_verified_routing_facts() {
        let (base, _) = serve(|path| {
            if path.starts_with("/network-info") {
                response(
                    "200 OK",
                    "",
                    r#"{"status":"ok","status_code":200,"data":{"asns":["64496"],"prefix":"93.184.216.0/24"}}"#,
                )
            } else {
                response("500 Internal Server Error", "", "oops")
            }
        });
        let context = client(&base).lookup(ip("93.184.216.34")).await.unwrap();
        assert_eq!(context.origin_asns, vec![64496]);
        assert_eq!(context.rpki, RpkiSummary::NotChecked);
    }
}
