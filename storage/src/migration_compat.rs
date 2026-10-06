//! Reviewed historical SQL sources, never checksum or migration-ledger rewrites.
use anyhow::{bail, Result};
use sqlx::migrate::{Migration, MigrationSource, MigrationType, Migrator};
use std::{borrow::Cow, future::Future, pin::Pin};

fn production_46() -> Migration {
    Migration::new(
        46,
        Cow::Borrowed("goaway challenge adapter"),
        MigrationType::Simple,
        Cow::Borrowed(include_str!(
            "../../migration-history/0046_goaway_challenge_adapter.sql"
        )),
        false,
    )
}

pub(crate) fn resolve_history(applied: &[(i64, Vec<u8>, bool)]) -> Result<Vec<Migration>> {
    let mut migrations: Vec<_> = super::MIGRATOR.iter().cloned().collect();
    for (version, checksum, success) in applied {
        if !success {
            bail!("unfinished migration {version}; operator recovery required");
        }
        let expected = migrations
            .iter_mut()
            .find(|m| m.version == *version)
            .ok_or_else(|| {
                anyhow::anyhow!("unknown applied migration {version}; refusing downgrade")
            })?;
        if expected.checksum.as_ref() == checksum {
            continue;
        }
        let historical = production_46();
        if *version == 46 && historical.checksum.as_ref() == checksum {
            *expected = historical;
        } else {
            bail!("unrecognized checksum for migration {version}");
        }
    }
    Ok(migrations)
}

#[derive(Debug)]
struct ReviewedSources(Vec<Migration>);
impl<'s> MigrationSource<'s> for ReviewedSources {
    fn resolve(
        self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Migration>, sqlx::error::BoxDynError>> + Send + 's>>
    {
        Box::pin(async move { Ok(self.0) })
    }
}

pub(crate) async fn migrator(applied: &[(i64, Vec<u8>, bool)]) -> Result<Migrator> {
    Ok(Migrator::new(ReviewedSources(resolve_history(applied)?)).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_only_the_exact_archived_production_sql() {
        let legacy = production_46();
        let resolved = resolve_history(&[(46, legacy.checksum.to_vec(), true)]).unwrap();
        assert_eq!(
            resolved.iter().find(|m| m.version == 46).unwrap().sql,
            legacy.sql
        );
        assert!(resolve_history(&[(46, vec![0; 48], true)]).is_err());
        assert!(resolve_history(&[(46, legacy.checksum.to_vec(), false)]).is_err());
    }
    #[test]
    fn canonical_history_stays_unchanged_and_other_mismatches_fail() {
        let history: Vec<_> = super::super::MIGRATOR
            .iter()
            .map(|m| (m.version, m.checksum.to_vec(), true))
            .collect();
        let resolved = resolve_history(&history).unwrap();
        assert_eq!(resolved.len(), history.len());
        assert!(resolve_history(&[(45, vec![0; 48], true)]).is_err());
        assert!(resolve_history(&[(999, vec![0; 48], true)]).is_err());
    }
}
