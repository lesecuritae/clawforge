//! Fail-closed loading and validation for Clawforge service credentials.

use anyhow::{anyhow, Context, Result};
use std::{collections::HashSet, env, fs};

pub const MIN_TOKEN_LENGTH: usize = 32;

const PLACEHOLDER_MARKERS: &[&str] = &[
    "change-me",
    "changeme",
    "replace-this",
    "replace-with",
    "placeholder",
    "example-token",
];

/// Load a required secret. Once the file variable is configured, file errors
/// are fatal and never fall back to an environment value.
pub fn load_required(file_key: &str, value_key: &str) -> Result<String> {
    let value = match env::var(file_key) {
        Ok(path) if path.trim().is_empty() => {
            return Err(anyhow!("{file_key} cannot be empty"));
        }
        Ok(path) => fs::read_to_string(&path)
            .with_context(|| format!("could not read secret configured by {file_key}"))?,
        Err(env::VarError::NotPresent) => {
            env::var(value_key).with_context(|| format!("{file_key} or {value_key} required"))?
        }
        Err(error) => return Err(error).with_context(|| format!("invalid {file_key}")),
    };
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(anyhow!("secret configured by {file_key} cannot be empty"));
    }
    Ok(value)
}

/// Load an optional secret without hiding a configured but broken file.
pub fn load_optional(file_key: &str, value_key: &str) -> Result<Option<String>> {
    match (env::var(file_key), env::var(value_key)) {
        (Err(env::VarError::NotPresent), Err(env::VarError::NotPresent)) => Ok(None),
        _ => load_required(file_key, value_key).map(Some),
    }
}

/// Reject checked-in placeholders and obviously weak service credentials.
/// This is a deployment guard, not an entropy estimator; operators should use
/// a cryptographically secure generator.
pub fn validate_token(label: &str, value: &str) -> Result<()> {
    let normalized = value.to_ascii_lowercase();
    if value.len() < MIN_TOKEN_LENGTH {
        return Err(anyhow!(
            "{label} must contain at least {MIN_TOKEN_LENGTH} characters"
        ));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(anyhow!("{label} must not contain whitespace"));
    }
    if PLACEHOLDER_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker))
    {
        return Err(anyhow!("{label} contains a known placeholder"));
    }
    if value.chars().collect::<HashSet<_>>().len() < 8 {
        return Err(anyhow!("{label} has insufficient character diversity"));
    }
    Ok(())
}

pub fn load_required_token(file_key: &str, value_key: &str) -> Result<String> {
    let value = load_required(file_key, value_key)?;
    validate_token(value_key, &value)?;
    Ok(value)
}

pub fn ensure_distinct(values: &[(&str, &str)]) -> Result<()> {
    for (index, (left_name, left)) in values.iter().enumerate() {
        for (right_name, right) in values.iter().skip(index + 1) {
            if left == right {
                return Err(anyhow!(
                    "{left_name} and {right_name} must use different credentials"
                ));
            }
        }
    }
    Ok(())
}

pub fn contains_placeholder(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    PLACEHOLDER_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_known_placeholders_short_and_repeated_values() {
        assert!(validate_token(
            "bootstrap token",
            "replace-this-bootstrap-token-before-production"
        )
        .is_err());
        assert!(validate_token("service token", "too-short").is_err());
        assert!(validate_token("service token", &"a".repeat(64)).is_err());
    }

    #[test]
    fn accepts_generated_style_tokens_and_requires_separation() {
        let first = "11111111-2222-4333-8444-555555555555-abcdefghi";
        let second = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee-123456789";
        validate_token("first", first).unwrap();
        validate_token("second", second).unwrap();
        ensure_distinct(&[("first", first), ("second", second)]).unwrap();
        assert!(ensure_distinct(&[("first", first), ("second", first)]).is_err());
    }

    #[test]
    fn placeholder_detection_is_case_insensitive() {
        assert!(contains_placeholder("prefix-CHANGE-ME-suffix"));
        assert!(!contains_placeholder("8Fcd1b09a7eE4f3C92bd6a51"));
    }

    #[test]
    fn configured_file_is_fail_closed_and_takes_precedence() {
        let file_key = "CLAWFORGE_TEST_SECRET_FILE_UNIQUE";
        let value_key = "CLAWFORGE_TEST_SECRET_VALUE_UNIQUE";
        let path =
            std::env::temp_dir().join(format!("clawforge-secret-test-{}", std::process::id()));
        std::env::set_var(value_key, "environment-fallback-value");
        std::env::set_var(file_key, &path);
        assert!(load_required(file_key, value_key).is_err());
        assert!(load_optional(file_key, value_key).is_err());

        std::fs::write(&path, "file-value\n").unwrap();
        assert_eq!(load_required(file_key, value_key).unwrap(), "file-value");

        std::fs::write(&path, "\n").unwrap();
        assert!(load_required(file_key, value_key).is_err());

        std::env::remove_var(file_key);
        assert_eq!(
            load_required(file_key, value_key).unwrap(),
            "environment-fallback-value"
        );
        std::env::remove_var(value_key);
        assert_eq!(load_optional(file_key, value_key).unwrap(), None);
        std::fs::remove_file(path).unwrap();
    }
}
