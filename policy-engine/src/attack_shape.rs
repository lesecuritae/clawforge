//! Attack shape: behaviour that a plain event count cannot express, derived from the member
//! events of one assessment as counts (`clawforge_assessment_shape`, migration 0067).
//!
//! * `account_enumeration` - a source whose failed SSH logins tried many different account
//!   names. Users behind a shared NAT mistype a few valid accounts; dictionary attacks walk
//!   through dozens of names.
//! * `invalid_account_probe` - a source that tried several different account names which sshd
//!   itself reported as nonexistent. A user mistypes their OWN name once or twice; guessing walks
//!   through names no one has. Needs a sensor that reports sshd's verdict (migration 0069);
//!   events without it never count.
//! * `secret_path_probe` - a source asking for several distinct paths that no legitimate client
//!   requests (`/.env*`, `/.git/...`, `/.aws/...`, SSH keys, ...). A broken asset release or a
//!   missing favicon produces many 404s too, but for application paths.
//!
//! These are properties of the events themselves, not of how many there are, so they are an
//! additional, content-based observation rather than a lower threshold. They corroborate an
//! assessment (evidence basis `attack_shape`) and never replace reputation: the policy -> execution
//! bridge still requires a counting threat-intel listing (`REQUIRE_THREAT_INTEL`, mandatory for
//! `automatic`), and routing/ASN/RPKI context stays context.
use clawforge_storage::AssessmentShape;
use std::env;

pub const DEFAULT_MIN_USERNAMES: i64 = 8;
pub const DEFAULT_MIN_INVALID_USERNAMES: i64 = 4;
pub const DEFAULT_MIN_SIGNATURE_PATHS: i64 = 3;

/// POSIX extended expressions (matched case-insensitively in SQL) for paths a legitimate client
/// never requests on a server that does not publish these files. Deliberately narrow: secrets,
/// dot-directories and key files only. Appliance/CMS exploit paths are NOT built in because a
/// site may legitimately run them; add them with `CLAWFORGE_ATTACK_SHAPE_PATH_PATTERNS`.
pub const DEFAULT_PATH_PATTERNS: &[&str] = &[
    r"(^|/)\.env([._-][a-z0-9._-]*)?(\?.*)?$",
    r"(^|/)\.git(/|$|\?)",
    r"(^|/)\.(aws|ssh|docker|svn|hg|kube)(/|$|\?)",
    r"(^|/)\.(npmrc|pypirc|htpasswd|htaccess|netrc|bash_history)(\?.*)?$",
    r"(^|/)aws/(credentials|config)(\?.*)?$",
    r"(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)(\.pub)?(\?.*)?$",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeConfig {
    pub enabled: bool,
    pub min_usernames: i64,
    pub min_invalid_usernames: i64,
    pub min_signature_paths: i64,
    pub path_patterns: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapeKind {
    AccountEnumeration,
    InvalidAccountProbe,
    SecretPathProbe,
}

impl ShapeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ShapeKind::AccountEnumeration => "account_enumeration",
            ShapeKind::InvalidAccountProbe => "invalid_account_probe",
            ShapeKind::SecretPathProbe => "secret_path_probe",
        }
    }
}

impl ShapeConfig {
    pub fn from_env() -> Self {
        let number = |name: &str, default: i64| {
            env::var(name)
                .ok()
                .and_then(|value| value.trim().parse::<i64>().ok())
                .filter(|value| *value >= 2)
                .unwrap_or(default)
        };
        let mut path_patterns: Vec<String> = DEFAULT_PATH_PATTERNS
            .iter()
            .map(|p| p.to_string())
            .collect();
        if let Ok(extra) = env::var("CLAWFORGE_ATTACK_SHAPE_PATH_PATTERNS") {
            path_patterns.extend(
                extra
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty() && line.len() <= 200)
                    .take(40)
                    .map(str::to_string),
            );
        }
        Self {
            enabled: !matches!(
                env::var("CLAWFORGE_ATTACK_SHAPE")
                    .ok()
                    .as_deref()
                    .map(str::trim),
                Some("off" | "false" | "0")
            ),
            min_usernames: number(
                "CLAWFORGE_ATTACK_SHAPE_MIN_USERNAMES",
                DEFAULT_MIN_USERNAMES,
            ),
            min_invalid_usernames: number(
                "CLAWFORGE_ATTACK_SHAPE_MIN_INVALID_USERNAMES",
                DEFAULT_MIN_INVALID_USERNAMES,
            ),
            min_signature_paths: number(
                "CLAWFORGE_ATTACK_SHAPE_MIN_SIGNATURE_PATHS",
                DEFAULT_MIN_SIGNATURE_PATHS,
            ),
            path_patterns,
        }
    }

    /// Which shape, if any, the counts show. Enumeration is checked first: both can only arise
    /// from different event families, so at most one applies to a single assessment.
    pub fn classify(&self, shape: &AssessmentShape) -> Option<ShapeKind> {
        if !self.enabled {
            return None;
        }
        if shape.distinct_usernames >= self.min_usernames {
            return Some(ShapeKind::AccountEnumeration);
        }
        if shape.distinct_invalid_usernames >= self.min_invalid_usernames {
            return Some(ShapeKind::InvalidAccountProbe);
        }
        if shape.signature_paths >= self.min_signature_paths {
            return Some(ShapeKind::SecretPathProbe);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(users: i64, paths: i64) -> AssessmentShape {
        AssessmentShape {
            events: 20,
            distinct_usernames: users,
            distinct_invalid_usernames: 0,
            signature_paths: paths,
        }
    }

    fn invalid(users: i64, invalid: i64) -> AssessmentShape {
        AssessmentShape {
            distinct_invalid_usernames: invalid,
            ..shape(users, 0)
        }
    }

    fn config() -> ShapeConfig {
        ShapeConfig {
            enabled: true,
            min_usernames: DEFAULT_MIN_USERNAMES,
            min_invalid_usernames: DEFAULT_MIN_INVALID_USERNAMES,
            min_signature_paths: DEFAULT_MIN_SIGNATURE_PATHS,
            path_patterns: Vec::new(),
        }
    }

    #[test]
    fn a_shared_nat_with_few_accounts_is_not_enumeration() {
        let c = config();
        for users in [0, 1, 2, 3, 5, 7] {
            assert_eq!(c.classify(&shape(users, 0)), None, "{users} accounts");
        }
        assert_eq!(
            c.classify(&shape(8, 0)),
            Some(ShapeKind::AccountEnumeration)
        );
        assert_eq!(
            c.classify(&shape(40, 0)),
            Some(ShapeKind::AccountEnumeration)
        );
    }

    #[test]
    fn a_few_mistyped_own_names_are_not_an_invalid_account_probe() {
        let c = config();
        // users behind a NAT with valid accounts: nothing invalid at all
        assert_eq!(c.classify(&invalid(5, 0)), None);
        // a forgetful user mistyping their own name two or three ways
        assert_eq!(c.classify(&invalid(3, 2)), None);
        assert_eq!(c.classify(&invalid(4, 3)), None);
        assert_eq!(
            c.classify(&invalid(5, 4)),
            Some(ShapeKind::InvalidAccountProbe)
        );
        // enumeration (many names in total) is checked first
        assert_eq!(
            c.classify(&invalid(30, 29)),
            Some(ShapeKind::AccountEnumeration)
        );
    }

    #[test]
    fn one_or_two_odd_paths_are_not_a_secret_probe() {
        let c = config();
        assert_eq!(c.classify(&shape(0, 0)), None);
        assert_eq!(c.classify(&shape(0, 1)), None);
        assert_eq!(c.classify(&shape(0, 2)), None);
        assert_eq!(c.classify(&shape(0, 3)), Some(ShapeKind::SecretPathProbe));
    }

    #[test]
    fn disabled_means_no_shape() {
        let mut c = config();
        c.enabled = false;
        assert_eq!(c.classify(&shape(50, 50)), None);
    }

    #[test]
    fn defaults_come_from_the_environment_but_never_below_two() {
        // process-wide environment: touch only this test's variables, restore afterwards
        env::set_var("CLAWFORGE_ATTACK_SHAPE_MIN_USERNAMES", "1");
        env::set_var("CLAWFORGE_ATTACK_SHAPE_MIN_SIGNATURE_PATHS", "5");
        env::set_var(
            "CLAWFORGE_ATTACK_SHAPE_PATH_PATTERNS",
            "^/extra-probe\n\n   ^/another  \n",
        );
        let c = ShapeConfig::from_env();
        assert_eq!(
            c.min_usernames, DEFAULT_MIN_USERNAMES,
            "1 is refused, default kept"
        );
        assert_eq!(c.min_signature_paths, 5);
        assert!(c.path_patterns.iter().any(|p| p == "^/extra-probe"));
        assert!(c.path_patterns.iter().any(|p| p == "^/another"));
        assert_eq!(c.path_patterns.len(), DEFAULT_PATH_PATTERNS.len() + 2);
        for name in [
            "CLAWFORGE_ATTACK_SHAPE_MIN_USERNAMES",
            "CLAWFORGE_ATTACK_SHAPE_MIN_SIGNATURE_PATHS",
            "CLAWFORGE_ATTACK_SHAPE_PATH_PATTERNS",
        ] {
            env::remove_var(name);
        }
    }
}
