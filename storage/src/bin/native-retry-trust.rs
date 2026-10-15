//! Fixed, independently rerun Retry-After acceptance. Existing Cargo proof CLI is unchanged.
//! No arbitrary commands, network access for tested code, or agent trust-write endpoint.
use anyhow::{ensure, Context, Result};
use clawforge_storage::{
    LearningEvidence, LearningImportAuthorization, LearningTrustBinding, PostgresStore,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
const DOMAIN: &[u8] = b"clawforge-native-retry-after-verification-v1\0";
const COMMIT: &str = "34416282cad05e6a31d0d9e6e3722e6721fd6def";
const SOLUTION: &str = "bab3b84afc998aeadd86fce7d048198d763ae946da2f77dee03f7d93317ef4d6";
const TESTS: &str = "ec718a945cd755975d38e82fb853a15559c9c7d0cb463c4b38990577e3dfeab3";
const HOLDOUT: &str = "e675e3ead6ec1b6c755a349838063215d0aa88ce195c339495a76b4eef007365";
const OLD_RESULT: &str = "0495077b955e9bbae3dcfa220c9f37267683b97e6e4914f094f33c6b675f0157";
const TEST_NAME: &str = "native-retry-after-original-5-and-independent-259";
const UNIT_DRIVER: &str = r#"import sys,unittest,json,os
sys.path.insert(0,sys.argv[1])
assert os.getuid()==994 and os.getgroups()==[984]
suite=unittest.defaultTestLoader.discover(sys.argv[1],pattern='test_solution.py')
r=unittest.TextTestRunner(verbosity=2).run(suite)
assert r.testsRun==5 and r.wasSuccessful() and not r.skipped
print(json.dumps({'unit_passed':5,'failed':0,'uid':os.getuid()}))
"#;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    version: u32,
    expires_at: u64,
    repository: String,
    commit: String,
    workspace: PathBuf,
    artifacts: PathBuf,
    python: PathBuf,
    runtime_sha256: BTreeMap<String, String>,
    delivery: PathBuf,
    delivery_sha256: String,
    database_host: String,
    database_port: u16,
    database_name: String,
    cluster_system_identifier: String,
    database_oid: i64,
    runtime_image_digest: String,
    importer_sha256: String,
    owner_token: Uuid,
    owner_actor: Uuid,
    curator_token: Uuid,
    curator_actor: Uuid,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    version: u32,
    created_at: u64,
    policy_sha256: String,
    commit: String,
    artifact: String,
    artifact_sha256: String,
    old_result_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sealed {
    proof: Proof,
    mac: String,
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn hash(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn protected(p: &Path, private: bool) -> Result<()> {
    ensure!(
        p.is_absolute()
            && p.components()
                .all(|c| !matches!(c, std::path::Component::ParentDir)),
        "absolute canonical path required"
    );
    for ancestor in p.ancestors() {
        let m = fs::symlink_metadata(ancestor)?;
        ensure!(
            !m.file_type().is_symlink() && matches!(m.uid(), 0 | 10001) && m.mode() & 0o022 == 0,
            "root/operator-owned protected admission path required"
        );
    }
    let m = fs::metadata(p)?;
    ensure!(m.is_file(), "regular file required");
    if private {
        ensure!(m.mode() & 0o077 == 0, "private operator secret required");
    }
    Ok(())
}
fn pinned(p: &Path, sha: &str) -> Result<()> {
    protected(p, false)?;
    ensure!(hash(&fs::read(p)?) == sha, "pinned input changed");
    Ok(())
}
fn fresh_write(p: &Path, b: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(p)?;
    use std::io::Write;
    f.write_all(b)?;
    f.sync_all()?;
    Ok(())
}
fn delivery(p: &Policy) -> Result<()> {
    pinned(&p.delivery, &p.delivery_sha256)?;
    let d: Value = serde_json::from_slice(&fs::read(&p.delivery)?)?;
    validate_delivery(p, &d)
}
fn validate_delivery(p: &Policy, d: &Value) -> Result<()> {
    ensure!(
        d["kind"] == "isolated-native-retry"
            && d["network_internal"] == true
            && d["published_ports"] == false,
        "isolated delivery required"
    );
    ensure!(
        d["network"]
            .as_str()
            .is_some_and(|n| n.starts_with("hermes-learning-"))
            && d["network_id"].as_str().is_some_and(|s| s.len() == 64),
        "specific fixture network required"
    );
    ensure!(
        d["database_host"] == p.database_host
            && d["database_port"] == p.database_port
            && d["database_name"] == p.database_name
            && d["runtime_image_digest"] == p.runtime_image_digest
            && d["importer_sha256"] == p.importer_sha256,
        "delivery target mismatch"
    );
    ensure!(
        p.database_port == 5432
            && p.database_name == "hermes_learning_fixture"
            && p.database_host
                .parse::<std::net::Ipv4Addr>()
                .is_ok_and(|ip| ip.is_private()),
        "native fixture target required"
    );
    ensure!(
        d["cluster_system_identifier"] == p.cluster_system_identifier
            && d["database_oid"] == p.database_oid
            && p.database_oid > 0,
        "instance identity missing"
    );
    Ok(())
}
fn load(path: &Path) -> Result<(Policy, String)> {
    protected(path, false)?;
    let bytes = fs::read(path)?;
    let p: Policy = serde_json::from_slice(&bytes)?;
    ensure!(
        p.version == 1 && p.commit == COMMIT && p.repository == "hermes-native-acceptance-fixtures",
        "fixed native case required"
    );
    ensure!(
        p.expires_at > now()? && p.expires_at - now()? <= 86400,
        "policy expired/unbounded"
    );
    ensure!(
        p.owner_actor != p.curator_actor && p.owner_token != p.curator_token,
        "independent identities required"
    );
    delivery(&p)?;
    source(&p)?;
    runtime(&p)?;
    Ok((p, hash(&bytes)))
}
fn source(p: &Policy) -> Result<()> {
    let names = [
        ("solution.py", SOLUTION),
        ("test_solution.py", TESTS),
        ("heldout.py", HOLDOUT),
        ("provenance.json", OLD_RESULT),
    ];
    for directory in [&p.workspace, &p.artifacts] {
        ensure!(
            directory.is_absolute() && directory.is_dir(),
            "protected source/artifact directory required"
        );
        for ancestor in directory.ancestors() {
            let m = fs::symlink_metadata(ancestor)?;
            ensure!(
                !m.file_type().is_symlink()
                    && matches!(m.uid(), 0 | 10001)
                    && m.mode() & 0o022 == 0,
                "unsafe source/artifact ancestor"
            );
        }
    }
    ensure!(
        p.workspace != p.artifacts
            && !p.workspace.starts_with(&p.artifacts)
            && !p.artifacts.starts_with(&p.workspace),
        "source/artifact overlap denied"
    );
    let present: std::collections::BTreeSet<_> = fs::read_dir(&p.workspace)?
        .map(|r| Ok(r?.file_name().to_string_lossy().to_string()))
        .collect::<Result<_>>()?;
    ensure!(
        present == names.iter().map(|(name, _)| name.to_string()).collect(),
        "unexpected source file or shadow module"
    );
    for (name, sha) in names {
        pinned(&p.workspace.join(name), sha)?;
    }
    Ok(())
}
fn runtime(p: &Policy) -> Result<()> {
    ensure!(
        p.runtime_sha256
            .contains_key(p.python.to_str().context("invalid interpreter path")?)
            && p.runtime_sha256.contains_key("/usr/bin/unshare")
            && p.runtime_sha256.contains_key("/usr/bin/setpriv")
            && p.runtime_sha256.contains_key("/usr/bin/timeout"),
        "interpreter/isolation runtime pins required"
    );
    ensure!(
        p.runtime_sha256
            .keys()
            .any(|s| s.ends_with("/unittest/runner.py")),
        "stdlib runtime pins required"
    );
    for (name, sha) in &p.runtime_sha256 {
        let path = Path::new(name);
        if fs::symlink_metadata(path)?.file_type().is_symlink() {
            ensure!(
                ["/usr/bin/timeout", "/usr/bin/setpriv", "/usr/bin/unshare"]
                    .contains(&name.as_str())
                    && fs::symlink_metadata(path)?.uid() == 0,
                "runtime alias denied"
            );
            let parent = path.parent().context("runtime alias parent")?;
            for ancestor in parent.ancestors() {
                let m = fs::symlink_metadata(ancestor)?;
                ensure!(
                    !m.file_type().is_symlink() && m.uid() == 0 && m.mode() & 0o022 == 0,
                    "runtime alias parent unsafe"
                );
            }
            let target = fs::canonicalize(path)?;
            ensure!(
                p.runtime_sha256
                    .get(target.to_str().context("runtime target encoding")?)
                    == Some(sha),
                "runtime alias target not pinned"
            );
            pinned(&target, sha)?;
        } else {
            pinned(path, sha)?;
        }
    }
    Ok(())
}
fn key(path: &Path) -> Result<Vec<u8>> {
    protected(path, true)?;
    let b = fs::read(path)?;
    ensure!(b.len() >= 32, "strong signing key required");
    Ok(b)
}
fn child(p: &Policy, args: &[&str]) -> Result<Value> {
    let out = Command::new("/usr/bin/timeout")
        .args([
            "-k",
            "2",
            "30",
            "/usr/bin/unshare",
            "--net",
            "--",
            "/usr/bin/setpriv",
            "--reuid=994",
            "--regid=984",
            "--groups=984",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--bounding-set=-all",
            "--no-new-privs",
        ])
        .arg(&p.python)
        .args(["-I", "-B"])
        .args(args)
        .current_dir(&p.workspace)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .output()?;
    ensure!(
        out.status.success(),
        "independent native test process failed"
    );
    let text = std::str::from_utf8(&out.stdout)?;
    let rows: Vec<_> = text.lines().filter(|s| !s.trim().is_empty()).collect();
    ensure!(rows.len() == 1, "ambiguous native test output");
    Ok(serde_json::from_str(rows[0])?)
}
fn validate_result(v: &Value) -> Result<()> {
    ensure!(
        v["schema_version"] == 1
            && v["commit"] == COMMIT
            && v["passed"] == true
            && v["unit_passed"] == 5
            && v["heldout_passed"] == 259
            && v["test_uid"] == 994
            && v["network_isolated"] == true
            && v["old_result_sha256"] == OLD_RESULT,
        "native coverage/result mismatch"
    );
    Ok(())
}
fn produce(policy: &Path, key_path: &Path, bundle: &Path) -> Result<()> {
    ensure!(
        unsafe { getuid() } == 0,
        "producer requires root to create no-network unprivileged tests"
    );
    let (p, digest) = load(policy)?;
    let signing = key(key_path)?;
    let before = now()?;
    let workspace = p.workspace.to_str().context("workspace encoding")?;
    let unit = child(&p, &["-c", UNIT_DRIVER, workspace])?;
    ensure!(
        unit["unit_passed"] == 5 && unit["failed"] == 0 && unit["uid"] == 994,
        "original five tests failed"
    );
    let heldout = p.workspace.join("heldout.py");
    let held = child(
        &p,
        &[heldout.to_str().context("holdout encoding")?, workspace],
    )?;
    ensure!(
        held["heldout_passed"] == true
            && held["checks"] == 259
            && held["original_tests_modified"] == false,
        "independent 259 holdout failed"
    );
    source(&p)?;
    runtime(&p)?;
    ensure!(now()? < p.expires_at, "policy expired during tests");
    let result = json!({"schema_version":1,"commit":COMMIT,"passed":true,"unit_passed":5,"heldout_passed":259,"test_uid":994,"network_isolated":true,"old_result_sha256":OLD_RESULT,"started_at":before,"completed_at":now()?});
    validate_result(&result)?;
    let artifact = "independent-native-retry.json";
    let bytes = serde_json::to_vec_pretty(&result)?;
    fresh_write(&p.artifacts.join(artifact), &bytes)?;
    let proof = Proof {
        version: 1,
        created_at: now()?,
        policy_sha256: digest,
        commit: COMMIT.into(),
        artifact: artifact.into(),
        artifact_sha256: hash(&bytes),
        old_result_sha256: OLD_RESULT.into(),
    };
    ensure!(
        bundle.parent() == Some(p.artifacts.as_path()),
        "proof outside artifacts denied"
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(&signing)?;
    mac.update(DOMAIN);
    mac.update(&serde_json::to_vec(&proof)?);
    fresh_write(
        bundle,
        &serde_json::to_vec_pretty(&Sealed {
            proof,
            mac: format!("{:x}", mac.finalize().into_bytes()),
        })?,
    )?;
    Ok(())
}
unsafe extern "C" {
    fn getuid() -> u32;
}
fn verify(policy: &Path, key_path: &Path, bundle: &Path) -> Result<(Policy, Proof)> {
    let (p, digest) = load(policy)?;
    protected(bundle, false)?;
    ensure!(
        bundle.parent() == Some(p.artifacts.as_path()),
        "proof location mismatch"
    );
    let sealed: Sealed = serde_json::from_slice(&fs::read(bundle)?)?;
    let bytes = sealed.mac.as_bytes();
    ensure!(bytes.len() == 64, "invalid MAC");
    let signature: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(std::str::from_utf8(&bytes[i..i + 2]).unwrap_or(""), 16))
        .collect::<std::result::Result<_, _>>()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key(key_path)?)?;
    mac.update(DOMAIN);
    mac.update(&serde_json::to_vec(&sealed.proof)?);
    mac.verify_slice(&signature)?;
    let pr = sealed.proof;
    ensure!(
        pr.version == 1
            && pr.policy_sha256 == digest
            && pr.commit == COMMIT
            && pr.old_result_sha256 == OLD_RESULT
            && pr.created_at <= now()?
            && now()? - pr.created_at <= 86400
            && pr.created_at < p.expires_at,
        "proof policy/expiry mismatch"
    );
    ensure!(
        pr.artifact == "independent-native-retry.json",
        "fixed artifact required"
    );
    let artifact = p.artifacts.join(&pr.artifact);
    pinned(&artifact, &pr.artifact_sha256)?;
    validate_result(&serde_json::from_slice(&fs::read(artifact)?)?)?;
    Ok((p, pr))
}
async fn import(policy: &Path, key_path: &Path, bundle: &Path, database: &Path) -> Result<()> {
    let (p, proof) = verify(policy, key_path, bundle)?;
    protected(database, true)?;
    ensure!(
        hash(&fs::read(std::env::current_exe()?)?) == p.importer_sha256,
        "importer binary mismatch"
    );
    let url = fs::read_to_string(database)?.trim().to_owned();
    use std::str::FromStr;
    let opt = sqlx::postgres::PgConnectOptions::from_str(&url)
        .map_err(|_| anyhow::anyhow!("private database URL invalid"))?;
    ensure!(
        opt.get_host() == p.database_host
            && opt.get_port() == p.database_port
            && opt.get_database() == Some(p.database_name.as_str()),
        "database URL retarget denied"
    );
    let store = PostgresStore::connect_runtime(&url)
        .await
        .map_err(|_| anyhow::anyhow!("private database connection rejected"))?;
    let bindings = [
        LearningTrustBinding {
            token_id: p.owner_token,
            actor_id: p.owner_actor,
            rotation_from: None,
        },
        LearningTrustBinding {
            token_id: p.curator_token,
            actor_id: p.curator_actor,
            rotation_from: None,
        },
    ];
    let evidence = [LearningEvidence {
        commit: COMMIT.into(),
        test: TEST_NAME.into(),
        artifact_sha256: proof.artifact_sha256,
        passed: true,
    }];
    let auth = LearningImportAuthorization {
        cluster_system_identifier: p.cluster_system_identifier,
        database_oid: p.database_oid,
        expires_at: i64::try_from(p.expires_at.min(proof.created_at + 86400))?,
    };
    store
        .import_learning_evidence_authorized(
            &bindings,
            p.owner_actor,
            p.curator_actor,
            &p.repository,
            &evidence,
            Some(&auth),
        )
        .await?;
    store.pool().close().await;
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        a.len() == 5 || a.len() == 6,
        "usage: native-retry-trust produce|verify|import POLICY KEY PROOF [DB_URL_FILE]"
    );
    let (p, k, b) = (Path::new(&a[2]), Path::new(&a[3]), Path::new(&a[4]));
    match a[1].as_str() {
        "produce" if a.len() == 5 => produce(p, k, b)?,
        "verify" if a.len() == 5 => {
            verify(p, k, b)?;
        }
        "import" if a.len() == 6 => import(p, k, b, Path::new(&a[5])).await?,
        _ => anyhow::bail!("unsupported fixed native operation"),
    }
    println!(
        "{}",
        json!({"status":"passed","operation":a[1],"provider_calls":0})
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn false_success_and_wrong_coverage_denied() {
        let good = json!({"schema_version":1,"commit":COMMIT,"passed":true,"unit_passed":5,"heldout_passed":259,"test_uid":994,"network_isolated":true,"old_result_sha256":OLD_RESULT});
        assert!(validate_result(&good).is_ok());
        for (k, v) in [
            ("passed", json!(false)),
            ("unit_passed", json!(4)),
            ("heldout_passed", json!(258)),
            ("test_uid", json!(0)),
            ("network_isolated", json!(false)),
            ("commit", json!("0".repeat(40))),
        ] {
            let mut bad = good.clone();
            bad[k] = v;
            assert!(validate_result(&bad).is_err());
        }
    }
    #[test]
    fn domain_separates_native_from_cargo() {
        let key = [7u8; 32];
        let bytes = b"same proof bytes";
        let mut native = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        native.update(DOMAIN);
        native.update(bytes);
        let mut cargo = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        cargo.update(b"clawforge-learning-trust-v2-split-targets\0");
        cargo.update(bytes);
        assert!(cargo.verify_slice(&native.finalize().into_bytes()).is_err());
    }
    #[test]
    fn retargeting_and_external_delivery_denied() {
        let p = Policy {
            version: 1,
            expires_at: 1,
            repository: "hermes-native-acceptance-fixtures".into(),
            commit: COMMIT.into(),
            workspace: "/opt/source".into(),
            artifacts: "/opt/artifacts".into(),
            python: "/usr/bin/python3.14".into(),
            runtime_sha256: BTreeMap::new(),
            delivery: "/opt/delivery".into(),
            delivery_sha256: "a".repeat(64),
            database_host: "192.168.160.2".into(),
            database_port: 5432,
            database_name: "hermes_learning_fixture".into(),
            cluster_system_identifier: "1234".into(),
            database_oid: 16384,
            runtime_image_digest: format!("sha256:{}", "a".repeat(64)),
            importer_sha256: "b".repeat(64),
            owner_token: Uuid::new_v4(),
            owner_actor: Uuid::new_v4(),
            curator_token: Uuid::new_v4(),
            curator_actor: Uuid::new_v4(),
        };
        let good = json!({"kind":"isolated-native-retry","network_internal":true,"published_ports":false,"network":"hermes-learning-review-fixture","network_id":"a".repeat(64),"database_host":p.database_host,"database_port":p.database_port,"database_name":p.database_name,"runtime_image_digest":p.runtime_image_digest,"importer_sha256":p.importer_sha256,"cluster_system_identifier":p.cluster_system_identifier,"database_oid":p.database_oid});
        assert!(validate_delivery(&p, &good).is_ok());
        for (key, value) in [
            ("database_host", json!("192.168.160.3")),
            ("database_oid", json!(16385)),
            ("cluster_system_identifier", json!("9876")),
            ("network_internal", json!(false)),
            ("published_ports", json!(true)),
            ("runtime_image_digest", json!("sha256:wrong")),
            ("importer_sha256", json!("c".repeat(64))),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(validate_delivery(&p, &bad).is_err());
        }
    }
}
