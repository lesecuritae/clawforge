//! Trusted, offline CI proof producer/importer. No agent endpoint or arbitrary
//! commands; signing keys, operator policy and owner DB URL remain outside Git.
use anyhow::{ensure, Context, Result};
use clawforge_storage::{LearningEvidence, LearningTrustBinding, PostgresStore};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgConnectOptions, Row};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    process::Command,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    token_id: Uuid,
    actor_id: Uuid,
    rotation_from: Option<Uuid>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    version: u32,
    expires_at: u64,
    repository: String,
    commit: String,
    workspace: PathBuf,
    artifacts: PathBuf,
    source_sha256: BTreeMap<String, String>,
    toolchain: PathBuf,
    toolchain_sha256: BTreeMap<String, String>,
    cargo_home: PathBuf,
    bindings: Vec<Binding>,
    owner_actor: Uuid,
    curator_actor: Uuid,
    database_host: String,
    database_port: u16,
    database_name: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    name: String,
    artifact: String,
    sha256: String,
    exit_code: i32,
    tests: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    version: u32,
    id: Uuid,
    created_at: u64,
    policy_sha256: String,
    commit: String,
    source_sha256: BTreeMap<String, String>,
    toolchain_sha256: BTreeMap<String, String>,
    checks: Vec<Check>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedProof {
    proof: Proof,
    mac: String,
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{x:02x}")).collect()
}
fn sha(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
fn unhex(s: &str) -> Result<Vec<u8>> {
    ensure!(
        s.len() == 64 && s.bytes().all(|x| x.is_ascii_hexdigit()),
        "invalid signature"
    );
    (0..s.len())
        .step_by(2)
        .map(|n| u8::from_str_radix(&s[n..n + 2], 16).map_err(Into::into))
        .collect()
}
fn uid() -> Result<u32> {
    fs::read_to_string("/proc/self/status")?
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|s| s.split_whitespace().nth(1))
        .context("effective identity missing")?
        .parse()
        .map_err(Into::into)
}
fn ancestors(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "canonical absolute path required"
    );
    let trusted = uid()?;
    for ancestor in path.ancestors() {
        let m = fs::symlink_metadata(ancestor).context("protected path missing")?;
        ensure!(!m.file_type().is_symlink(), "symlink path denied");
        ensure!(m.uid() == 0 || m.uid() == trusted, "untrusted path owner");
        ensure!(m.mode() & 0o022 == 0, "writable ancestor denied");
    }
    Ok(())
}
fn protected(path: &Path, private: bool) -> Result<()> {
    ancestors(path)?;
    let m = fs::symlink_metadata(path)?;
    ensure!(m.is_file(), "regular file required");
    if private {
        ensure!(m.mode() & 0o077 == 0, "private file permissions required");
    }
    Ok(())
}
fn relative(root: &Path, name: &str) -> Result<PathBuf> {
    let p = Path::new(name);
    ensure!(
        !p.as_os_str().is_empty() && p.components().all(|c| matches!(c, Component::Normal(_))),
        "unsafe relative path"
    );
    Ok(root.join(p))
}
fn load_policy(path: &Path) -> Result<(Policy, String)> {
    protected(path, true)?;
    let b = fs::read(path)?;
    let p: Policy = serde_json::from_slice(&b)?;
    ensure!(
        p.version == 1 && now()? <= p.expires_at,
        "expired/incompatible operator policy"
    );
    ensure!(
        p.owner_actor != p.curator_actor && p.bindings.len() == 2,
        "independent identities required"
    );
    ensure!(
        (p.commit.len() == 40 || p.commit.len() == 64)
            && p.commit.bytes().all(|b| b.is_ascii_hexdigit()),
        "exact Git commit required"
    );
    ensure!(
        !p.source_sha256.is_empty() && p.repository.len() <= 512 && !p.repository.trim().is_empty(),
        "source policy missing"
    );
    Ok((p, sha(&b)))
}
fn key(path: &Path) -> Result<Vec<u8>> {
    protected(path, true)?;
    let b = fs::read(path)?;
    ensure!(
        b.len() >= 32 && b.len() <= 4096,
        "signing key length invalid"
    );
    Ok(b)
}
fn git_bytes(workspace: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let o = Command::new("/usr/bin/git")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.attributesFile=/dev/null",
        ])
        .args(args)
        .current_dir(workspace)
        .output()?;
    ensure!(o.status.success(), "Git verification failed");
    Ok(o.stdout)
}
fn git(workspace: &Path, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8(git_bytes(workspace, args)?)?
        .trim()
        .into())
}
fn source(p: &Policy) -> Result<()> {
    ancestors(&p.workspace)?;
    ensure!(p.workspace.is_dir(), "workspace directory required");
    ensure!(
        !p.artifacts.starts_with(&p.workspace) && !p.workspace.starts_with(&p.artifacts),
        "source/artifacts overlap denied"
    );
    let config = git(
        &p.workspace,
        &[
            "config",
            "--local",
            "--no-includes",
            "--name-only",
            "--list",
        ],
    )?;
    for name in config.lines() {
        let name = name.to_ascii_lowercase();
        ensure!(
            !name.starts_with("include")
                && !name.starts_with("filter.")
                && name != "diff.external"
                && !name.starts_with("core.fsmonitor"),
            "executable Git configuration denied"
        );
    }
    ensure!(
        git(&p.workspace, &["rev-parse", "HEAD"])? == p.commit,
        "commit mismatch"
    );
    // Read raw committed blobs: index flags cannot hide changed build inputs.
    let tree = git_bytes(&p.workspace, &["ls-tree", "-r", "-z", "HEAD"])?;
    for entry in tree.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        let entry = std::str::from_utf8(entry)?;
        let (metadata, name) = entry.split_once('\t').context("invalid Git tree")?;
        let fields: Vec<_> = metadata.split_whitespace().collect();
        ensure!(
            fields.len() == 3 && fields[1] == "blob" && matches!(fields[0], "100644" | "100755"),
            "non-regular tracked source denied"
        );
        let file = relative(&p.workspace, name)?;
        protected(&file, false)?;
        ensure!(
            fs::read(file)? == git_bytes(&p.workspace, &["cat-file", "blob", fields[2]])?,
            "tracked bytes differ from commit"
        );
    }
    ensure!(
        git(
            &p.workspace,
            &[
                "status",
                "--porcelain",
                "--untracked-files=all",
                "--ignored"
            ]
        )?
        .is_empty(),
        "uncommitted or ignored source denied"
    );
    for (name, digest) in &p.source_sha256 {
        let file = relative(&p.workspace, name)?;
        protected(&file, false)?;
        git(&p.workspace, &["ls-files", "--error-unmatch", name])?;
        ensure!(sha(&fs::read(file)?) == *digest, "source hash mismatch");
    }
    Ok(())
}
fn verify_toolchain(p: &Policy) -> Result<()> {
    ancestors(&p.toolchain)?;
    ancestors(&p.cargo_home)?;
    ensure!(
        p.toolchain.is_dir() && p.cargo_home.is_dir(),
        "private toolchain/home required"
    );
    ensure!(
        !p.toolchain.starts_with(&p.workspace) && !p.cargo_home.starts_with(&p.workspace),
        "toolchain/build input overlap denied"
    );
    ensure!(
        p.toolchain_sha256.contains_key("bin/cargo")
            && p.toolchain_sha256.contains_key("bin/rustc")
            && p.toolchain_sha256.contains_key("bin/rustdoc"),
        "absolute toolchain binaries required"
    );
    fn walk(root: &Path, dir: &Path, hashes: &BTreeMap<String, String>) -> Result<()> {
        ancestors(dir)?;
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                !metadata.file_type().is_symlink(),
                "toolchain symlink denied"
            );
            if metadata.is_dir() {
                walk(root, &path, hashes)?;
            } else {
                protected(&path, false)?;
                let name = path
                    .strip_prefix(root)?
                    .to_str()
                    .context("toolchain path")?;
                ensure!(
                    hashes.get(name) == Some(&sha(&fs::read(&path)?)),
                    "toolchain bytes differ from policy"
                );
            }
        }
        Ok(())
    }
    walk(&p.toolchain, &p.toolchain, &p.toolchain_sha256)?;
    for name in p.toolchain_sha256.keys() {
        protected(&relative(&p.toolchain, name)?, false)?;
    }
    ensure!(
        !p.cargo_home.join("config").exists() && !p.cargo_home.join("config.toml").exists(),
        "mutable Cargo home config denied"
    );
    Ok(())
}
fn cargo_command(p: &Policy, args: &[&str]) -> Result<Command> {
    verify_toolchain(p)?;
    let mut command = Command::new(p.toolchain.join("bin/cargo"));
    command
        .env_clear()
        .args(args)
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &p.cargo_home)
        .env("CARGO_HOME", &p.cargo_home)
        .env("RUSTC", p.toolchain.join("bin/rustc"))
        .env("RUSTDOC", p.toolchain.join("bin/rustdoc"));
    Ok(command)
}
fn cases() -> Vec<(&'static str, Vec<&'static str>, Vec<&'static str>)> {
    vec![
        (
            "storage-learning",
            vec![
                "cargo",
                "test",
                "-p",
                "clawforge-storage",
                "--test",
                "learning",
                "--",
                "--include-ignored",
                "--test-threads=1",
            ],
            vec![
                "learning_api_role_cannot_modify_trust_roots",
                "learning_lifecycle_and_isolation",
                "generic_applicability_specificity_and_record_pagination",
            ],
        ),
        (
            "api-learning",
            vec![
                "cargo",
                "test",
                "-p",
                "clawforge-api",
                "--bin",
                "clawforge-api",
                "learning::",
                "--",
                "--include-ignored",
                "--test-threads=1",
            ],
            vec!["learning::postgres_tests::learning_routes_enforce_scope_owner_and_curator"],
        ),
        (
            "mcp-learning",
            vec!["cargo", "test", "-p", "clawforge-mcp", "learning_"],
            vec![
                "tests::learning_discovery_requires_separate_token_and_exact_scopes",
                "tests::learning_upstream_uses_separate_token_and_checks_schema",
            ],
        ),
    ]
}
fn log_passed(bytes: &[u8], required: &[&str]) -> Result<()> {
    let log = std::str::from_utf8(bytes)?;
    ensure!(
        log.contains("test result: ok.")
            && !log.contains("test result: FAILED")
            && !log.contains("... FAILED"),
        "test artifact not successful"
    );
    for test in required {
        ensure!(
            log.lines().any(|l| l == format!("test {test} ... ok")),
            "required test missing"
        );
    }
    Ok(())
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
async fn produce(
    policy_path: &Path,
    key_path: &Path,
    bundle: &Path,
    database_path: &Path,
) -> Result<()> {
    let (p, digest) = load_policy(policy_path)?;
    source(&p)?;
    let target = PathBuf::from(
        std::env::var_os("CARGO_TARGET_DIR").context("external CARGO_TARGET_DIR required")?,
    );
    ancestors(&target)?;
    ensure!(
        target.is_dir()
            && !target.starts_with(&p.workspace)
            && !p.workspace.starts_with(&target)
            && !target.starts_with(&p.artifacts)
            && !p.artifacts.starts_with(&target),
        "build target/source/artifacts overlap denied"
    );
    verify_toolchain(&p)?;
    let signing = key(key_path)?;
    let url = database(database_path, &p)?;
    let store = PostgresStore::connect_runtime(&url).await?;
    check_bindings(&store, &p).await?;
    store.pool().close().await;
    let parent = bundle.parent().context("proof directory missing")?;
    ensure!(
        parent == p.artifacts,
        "proof outside protected artifact directory"
    );
    ancestors(parent)?;
    ensure!(
        parent.is_dir(),
        "operator must precreate artifact directory"
    );
    let marker = parent.join(format!(".permission-check-{}", Uuid::new_v4()));
    write_new(&marker, b"check")?;
    protected(&marker, true)?;
    fs::remove_file(marker)?;
    let mut proof = Proof {
        version: 1,
        id: Uuid::new_v4(),
        created_at: now()?,
        policy_sha256: digest,
        commit: p.commit.clone(),
        source_sha256: p.source_sha256.clone(),
        toolchain_sha256: p.toolchain_sha256.clone(),
        checks: vec![],
    };
    for (name, args, tests) in cases() {
        source(&p)?;
        verify_toolchain(&p)?;
        let mut command = cargo_command(&p, &args[1..])?;
        command
            .current_dir(&p.workspace)
            .env("CARGO_TARGET_DIR", &target);
        let output = command
            .env("CARGO_NET_OFFLINE", "true")
            .env("CLAWFORGE_LEARNING_TEST_DATABASE_URL", &url)
            .output()?;
        let mut bytes = output.stdout;
        bytes.extend_from_slice(&output.stderr);
        ensure!(output.status.success(), "trusted CI command failed");
        log_passed(&bytes, &tests)?;
        let artifact = format!("{}-{name}.log", proof.id);
        write_new(&parent.join(&artifact), &bytes)?;
        proof.checks.push(Check {
            name: name.into(),
            artifact,
            sha256: sha(&bytes),
            exit_code: output.status.code().context("terminated CI command")?,
            tests: tests.iter().map(|s| (*s).into()).collect(),
        });
    }
    source(&p)?;
    verify_toolchain(&p)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&signing)?;
    mac.update(&serde_json::to_vec(&proof)?);
    let sealed = SealedProof {
        proof,
        mac: hex(&mac.finalize().into_bytes()),
    };
    write_new(bundle, &serde_json::to_vec_pretty(&sealed)?)?;
    Ok(())
}
fn verify(policy_path: &Path, key_path: &Path, bundle: &Path) -> Result<(Policy, Proof)> {
    let (p, digest) = load_policy(policy_path)?;
    source(&p)?;
    protected(bundle, true)?;
    ensure!(
        bundle.parent() == Some(p.artifacts.as_path()),
        "proof directory mismatch"
    );
    let sealed: SealedProof = serde_json::from_slice(&fs::read(bundle)?)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key(key_path)?)?;
    mac.update(&serde_json::to_vec(&sealed.proof)?);
    mac.verify_slice(&unhex(&sealed.mac)?)
        .map_err(|_| anyhow::anyhow!("proof authentication failed"))?;
    let proof = sealed.proof;
    let t = now()?;
    ensure!(
        proof.version == 1
            && proof.created_at <= t
            && t - proof.created_at <= 86400
            && proof.created_at <= p.expires_at,
        "stale/incompatible proof"
    );
    ensure!(
        proof.policy_sha256 == digest
            && proof.commit == p.commit
            && proof.source_sha256 == p.source_sha256
            && proof.toolchain_sha256 == p.toolchain_sha256,
        "proof policy/source mismatch"
    );
    let required = cases();
    ensure!(
        proof.checks.len() == required.len(),
        "proof coverage incomplete"
    );
    for (check, (name, _, tests)) in proof.checks.iter().zip(required) {
        ensure!(
            check.name == name && check.exit_code == 0 && check.tests == tests,
            "proof command/coverage mismatch"
        );
        let artifact = relative(&p.artifacts, &check.artifact)?;
        protected(&artifact, true)?;
        let bytes = fs::read(artifact)?;
        ensure!(sha(&bytes) == check.sha256, "artifact hash mismatch");
        log_passed(&bytes, &tests)?;
    }
    Ok((p, proof))
}
fn database(path: &Path, p: &Policy) -> Result<String> {
    protected(path, true)?;
    let url = fs::read_to_string(path)?;
    let url = url.trim().to_string();
    let opt = PgConnectOptions::from_str(&url)
        .map_err(|_| anyhow::anyhow!("database configuration invalid"))?;
    ensure!(
        opt.get_host() == p.database_host
            && opt.get_port() == p.database_port
            && opt.get_database() == Some(p.database_name.as_str()),
        "database identity mismatch"
    );
    ensure!(
        p.database_host == "127.0.0.1"
            && p.database_name.starts_with("learning_")
            && (55430..=55439).contains(&p.database_port),
        "isolated target required; production import is not enabled"
    );
    Ok(url)
}
async fn check_bindings(store: &PostgresStore, p: &Policy) -> Result<()> {
    // Check actual active token rows/scopes before privileged identity mutations.
    for b in &p.bindings {
        let row = sqlx::query("SELECT scopes,revoked_at,expires_at FROM agent_tokens WHERE id=$1")
            .bind(b.token_id)
            .fetch_one(store.pool())
            .await?;
        ensure!(
            row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("revoked_at")
                .is_none()
                && row.get::<chrono::DateTime<chrono::Utc>, _>("expires_at") > chrono::Utc::now(),
            "credential inactive"
        );
        let scopes: Vec<String> = serde_json::from_value(row.get("scopes"))?;
        let required: Vec<&str> = if b.actor_id == p.owner_actor {
            vec!["agent:learning:read", "agent:learning:propose"]
        } else if b.actor_id == p.curator_actor {
            vec!["agent:learning:curate"]
        } else {
            anyhow::bail!("binding outside approved actors")
        };
        ensure!(
            required.len() == scopes.len()
                && required.iter().all(|s| scopes.iter().any(|x| x == s)),
            "credential scope mismatch"
        );
        if let Ok(actual) = store.learning_actor(b.token_id).await {
            ensure!(actual == b.actor_id, "existing actor mismatch");
        } else if let Some(old) = b.rotation_from {
            ensure!(
                store.learning_actor(old).await? == b.actor_id,
                "rotation source mismatch"
            );
        } else {
            ensure!(
                b.token_id == b.actor_id,
                "explicit onboarding actor mismatch"
            );
        }
    }
    ensure!(
        p.bindings.iter().any(|b| b.actor_id == p.owner_actor)
            && p.bindings.iter().any(|b| b.actor_id == p.curator_actor),
        "independent role pair missing"
    );
    Ok(())
}
async fn import(
    policy_path: &Path,
    key_path: &Path,
    bundle: &Path,
    database_path: &Path,
) -> Result<()> {
    let (p, proof) = verify(policy_path, key_path, bundle)?;
    let store = PostgresStore::connect_runtime(&database(database_path, &p)?).await?;
    ensure!(
        store.readiness().await?.current,
        "database schema not current"
    );
    let bindings: Vec<_> = p
        .bindings
        .iter()
        .map(|b| LearningTrustBinding {
            token_id: b.token_id,
            actor_id: b.actor_id,
            rotation_from: b.rotation_from,
        })
        .collect();
    let evidence: Vec<_> = proof
        .checks
        .into_iter()
        .map(|check| LearningEvidence {
            commit: proof.commit.clone(),
            test: check.name,
            artifact_sha256: check.sha256,
            passed: true,
        })
        .collect();
    store
        .import_learning_evidence(
            &bindings,
            p.owner_actor,
            p.curator_actor,
            &p.repository,
            &evidence,
        )
        .await?;
    println!("{{\"schema_version\":1,\"proof_id\":\"{}\",\"authenticated_checks\":3,\"status\":\"imported\"}}",proof.id);
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    ensure!(
        args.len() == 6,
        "usage: learning-trust produce|import POLICY_FILE KEY_FILE BUNDLE_FILE DATABASE_URL_FILE"
    );
    let paths: Vec<&Path> = args[2..].iter().map(Path::new).collect();
    match args[1].as_str() {
        "produce" => produce(paths[0], paths[1], paths[2], paths[3]).await,
        "import" => import(paths[0], paths[1], paths[2], paths[3]).await,
        _ => anyhow::bail!("unknown trusted operation"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    struct Fixture {
        root: PathBuf,
        policy: PathBuf,
        key: PathBuf,
        bundle: PathBuf,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    impl Fixture {
        fn new() -> Result<Self> {
            let root = PathBuf::from(std::env::var("HOME")?)
                .join(format!(".learning-trust-fixture-{}", Uuid::new_v4()));
            fs::create_dir_all(&root)?;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
            let repo = root.join("repo");
            fs::create_dir(&repo)?;
            fs::set_permissions(&repo, fs::Permissions::from_mode(0o700))?;
            write_new(&repo.join("source.rs"), b"// reviewed fixture source\n")?;
            for args in [
                vec!["init", "-q"],
                vec!["add", "source.rs"],
                vec![
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@local.invalid",
                    "commit",
                    "-qm",
                    "fixture",
                ],
            ] {
                ensure!(
                    Command::new("git")
                        .args(args)
                        .current_dir(&repo)
                        .status()?
                        .success(),
                    "fixture Git failed"
                );
            }
            let commit = git(&repo, &["rev-parse", "HEAD"])?;
            let artifacts = root.join("artifacts");
            fs::create_dir(&artifacts)?;
            fs::set_permissions(&artifacts, fs::Permissions::from_mode(0o700))?;
            let owner = Uuid::new_v4();
            let curator = Uuid::new_v4();
            let policy = Policy {
                version: 1,
                expires_at: now()? + 3600,
                repository: "fixture".into(),
                commit,
                workspace: repo,
                artifacts,
                source_sha256: BTreeMap::from([(
                    "source.rs".into(),
                    sha(b"// reviewed fixture source\n"),
                )]),
                toolchain: root.join("toolchain"),
                toolchain_sha256: BTreeMap::new(),
                cargo_home: root.join("cargo-home"),
                bindings: vec![
                    Binding {
                        token_id: owner,
                        actor_id: owner,
                        rotation_from: None,
                    },
                    Binding {
                        token_id: curator,
                        actor_id: curator,
                        rotation_from: None,
                    },
                ],
                owner_actor: owner,
                curator_actor: curator,
                database_host: "127.0.0.1".into(),
                database_port: 55436,
                database_name: "learning_trust_test".into(),
            };
            let path = root.join("policy.json");
            write_new(&path, &serde_json::to_vec(&policy)?)?;
            let keypath = root.join("signing-key");
            write_new(&keypath, b"fixture-only non-production signing material")?;
            let bundle = policy.artifacts.join("proof.json");
            let f = Self {
                root,
                policy: path,
                key: keypath,
                bundle,
            };
            f.seal()?;
            Ok(f)
        }
        // Synthetic logs exercise verification negatives, NOT claimed CI execution.
        fn seal(&self) -> Result<()> {
            let (p, digest) = load_policy(&self.policy)?;
            let mut proof = Proof {
                version: 1,
                id: Uuid::new_v4(),
                created_at: now()?,
                policy_sha256: digest,
                commit: p.commit,
                source_sha256: p.source_sha256,
                toolchain_sha256: p.toolchain_sha256,
                checks: vec![],
            };
            for (name, _, tests) in cases() {
                let text = tests
                    .iter()
                    .map(|s| format!("test {s} ... ok\n"))
                    .collect::<String>()
                    + "test result: ok. 1 passed; 0 failed; 0 ignored;\n";
                let namefile = format!("{name}.log");
                let path = p.artifacts.join(&namefile);
                if path.exists() {
                    fs::remove_file(&path)?;
                }
                write_new(&path, text.as_bytes())?;
                proof.checks.push(Check {
                    name: name.into(),
                    artifact: namefile,
                    sha256: sha(text.as_bytes()),
                    exit_code: 0,
                    tests: tests.into_iter().map(str::to_string).collect(),
                });
            }
            let mut mac = Hmac::<Sha256>::new_from_slice(&key(&self.key)?)?;
            mac.update(&serde_json::to_vec(&proof)?);
            if self.bundle.exists() {
                fs::remove_file(&self.bundle)?;
            }
            write_new(
                &self.bundle,
                &serde_json::to_vec(&SealedProof {
                    proof,
                    mac: hex(&mac.finalize().into_bytes()),
                })?,
            )?;
            Ok(())
        }
    }
    #[test]
    fn authentic_proof_and_tampered_artifact() -> Result<()> {
        let f = Fixture::new()?;
        verify(&f.policy, &f.key, &f.bundle)?;
        fs::write(
            f.bundle.parent().unwrap().join("storage-learning.log"),
            b"changed",
        )?;
        assert!(verify(&f.policy, &f.key, &f.bundle).is_err());
        Ok(())
    }
    #[test]
    fn signature_stale_version_commit_and_scope() -> Result<()> {
        let f = Fixture::new()?;
        let bytes = fs::read(&f.bundle)?;
        for change in ["mac", "version", "stale", "commit"] {
            let mut p: SealedProof = serde_json::from_slice(&bytes)?;
            match change {
                "mac" => p.mac = "0".repeat(64),
                "version" => p.proof.version = 2,
                "stale" => p.proof.created_at = 0,
                _ => p.proof.commit = "f".repeat(40),
            };
            if change != "mac" {
                let mut m = Hmac::<Sha256>::new_from_slice(&key(&f.key)?)?;
                m.update(&serde_json::to_vec(&p.proof)?);
                p.mac = hex(&m.finalize().into_bytes());
            }
            fs::write(&f.bundle, serde_json::to_vec(&p)?)?;
            assert!(verify(&f.policy, &f.key, &f.bundle).is_err());
        }
        Ok(())
    }
    #[test]
    fn source_changes_untracked_and_symlink_paths_denied() -> Result<()> {
        let f = Fixture::new()?;
        let p = load_policy(&f.policy)?.0;
        write_new(&p.workspace.join("unreviewed.rs"), b"unreviewed")?;
        assert!(source(&p).is_err());
        fs::remove_file(p.workspace.join("unreviewed.rs"))?;
        fs::write(p.workspace.join("source.rs"), b"changed")?;
        assert!(source(&p).is_err());
        let link = f.root.join("key-link");
        std::os::unix::fs::symlink(&f.key, &link)?;
        assert!(key(&link).is_err());
        fs::set_permissions(&f.root, fs::Permissions::from_mode(0o770))?;
        assert!(key(&f.key).is_err());
        Ok(())
    }
    #[test]
    fn hidden_index_flags_and_ignored_build_config_denied() -> Result<()> {
        for flag in ["--assume-unchanged", "--skip-worktree"] {
            let f = Fixture::new()?;
            let p = load_policy(&f.policy)?.0;
            git(&p.workspace, &["update-index", flag, "source.rs"])?;
            fs::write(p.workspace.join("source.rs"), b"hidden changed source")?;
            assert!(source(&p).is_err());
        }
        let f = Fixture::new()?;
        let mut p = load_policy(&f.policy)?.0;
        write_new(&p.workspace.join(".gitignore"), b".cargo/\n")?;
        git(&p.workspace, &["add", ".gitignore"])?;
        git(
            &p.workspace,
            &[
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@local.invalid",
                "commit",
                "-qm",
                "ignore",
            ],
        )?;
        p.commit = git(&p.workspace, &["rev-parse", "HEAD"])?;
        fs::create_dir(p.workspace.join(".cargo"))?;
        write_new(
            &p.workspace.join(".cargo/config.toml"),
            b"[build]\nrustflags=[]\n",
        )?;
        assert!(source(&p).is_err());
        Ok(())
    }
    #[test]
    fn configured_fsmonitor_never_executes() -> Result<()> {
        let f = Fixture::new()?;
        let p = load_policy(&f.policy)?.0;
        let marker = f.root.join("executed");
        let hook = f.root.join("monitor");
        write_new(
            &hook,
            format!("#!/bin/sh\ntouch '{}'\n", marker.display()).as_bytes(),
        )?;
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o700))?;
        git(
            &p.workspace,
            &["config", "core.fsmonitor", hook.to_str().context("path")?],
        )?;
        git(&p.workspace, &["status", "--porcelain"])?;
        assert!(source(&p).is_err());
        assert!(!marker.exists());
        Ok(())
    }
    #[test]
    fn absolute_toolchain_ignores_path_and_rejects_changed_binary() -> Result<()> {
        let f = Fixture::new()?;
        let mut p = load_policy(&f.policy)?.0;
        fs::create_dir(&p.toolchain)?;
        fs::create_dir(p.toolchain.join("bin"))?;
        fs::create_dir(&p.cargo_home)?;
        for dir in [&p.toolchain, &p.toolchain.join("bin"), &p.cargo_home] {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        for name in ["cargo", "rustc", "rustdoc"] {
            let bytes = b"#!/bin/sh\nprintf reviewed\n";
            let path = p.toolchain.join("bin").join(name);
            write_new(&path, bytes)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            p.toolchain_sha256.insert(format!("bin/{name}"), sha(bytes));
        }
        let fake_dir = f.root.join("fake");
        fs::create_dir(&fake_dir)?;
        let fake = fake_dir.join("cargo");
        write_new(&fake, b"#!/bin/sh\nprintf FAKE\n")?;
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o700))?;
        // Caller PATH is irrelevant: the configured absolute program is retained.
        let mut command = cargo_command(&p, &[])?;
        command.env("PATH", &fake_dir);
        assert_eq!(command.output()?.stdout, b"reviewed");
        fs::write(p.toolchain.join("bin/rustc"), b"changed")?;
        assert!(cargo_command(&p, &[]).is_err());
        Ok(())
    }
    #[test]
    fn missing_failed_or_ignored_required_tests_denied() {
        for b in [
            b"test result: ok. 0 passed;".as_slice(),
            b"test actual ... ignored\ntest result: ok. 0 passed;".as_slice(),
            b"test actual ... FAILED\ntest result: FAILED".as_slice(),
        ] {
            assert!(log_passed(b, &["actual"]).is_err());
        }
    }
    async fn wait_for_locked_query(pool: &sqlx::PgPool, pattern: &str) -> Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE $1)")
                    .bind(pattern).fetch_one(pool).await?;
                if waiting { return Ok::<(), anyhow::Error>(()); }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }).await.context("concurrent import/revocation did not reach expected row lock")??;
        Ok(())
    }
    #[tokio::test]
    #[ignore = "requires isolated owner PostgreSQL fixture; synthetic signed verifier proof, not claimed producer execution"]
    async fn isolated_import_scope_ownership_audit_and_replay() -> Result<()> {
        let base = std::env::var("CLAWFORGE_LEARNING_TEST_DATABASE_URL")?;
        let options = PgConnectOptions::from_str(&base)?;
        ensure!(
            options.get_host() == "127.0.0.1" && (55430..=55439).contains(&options.get_port()),
            "isolated fixture required"
        );
        let admin = sqlx::PgPool::connect(&base).await?;
        let db = format!("learning_trust_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE {db}"))
            .execute(&admin)
            .await?;
        let url = format!(
            "{}/{db}",
            base.rsplit_once('/').context("fixture URL invalid")?.0
        );
        let store = PostgresStore::connect(&url).await?;
        let f = Fixture::new()?;
        let mut p = load_policy(&f.policy)?.0;
        p.database_port = options.get_port();
        p.database_name = db.clone();
        let owner = store
            .create_agent_token(
                "fixture-owner",
                &sha(Uuid::new_v4().as_bytes()),
                "fixture",
                &[
                    "agent:learning:read".into(),
                    "agent:learning:propose".into(),
                ],
                chrono::Utc::now() + chrono::Duration::hours(1),
                None,
            )
            .await?;
        let curator = store
            .create_agent_token(
                "fixture-curator",
                &sha(Uuid::new_v4().as_bytes()),
                "fixture",
                &["agent:learning:curate".into()],
                chrono::Utc::now() + chrono::Duration::hours(1),
                None,
            )
            .await?;
        p.owner_actor = owner;
        p.curator_actor = curator;
        p.bindings = vec![
            Binding {
                token_id: owner,
                actor_id: owner,
                rotation_from: None,
            },
            Binding {
                token_id: curator,
                actor_id: curator,
                rotation_from: None,
            },
        ];
        fs::write(&f.policy, serde_json::to_vec(&p)?)?;
        f.seal()?;
        let urlfile = f.root.join("database-url");
        write_new(&urlfile, url.as_bytes())?;
        check_bindings(&store, &p).await?;
        assert!(store.learning_actor(owner).await.is_err());
        sqlx::query(r#"UPDATE agent_tokens SET scopes='["agent:read"]'::jsonb WHERE id=$1"#)
            .bind(curator)
            .execute(store.pool())
            .await?;
        assert!(import(&f.policy, &f.key, &f.bundle, &urlfile)
            .await
            .is_err());
        assert!(store.learning_actor(owner).await.is_err());
        sqlx::query(
            r#"UPDATE agent_tokens SET scopes='["agent:learning:curate"]'::jsonb WHERE id=$1"#,
        )
        .bind(curator)
        .execute(store.pool())
        .await?;
        // Revocation wins the credential row lock: importer waits, then rejects
        // the newly revoked row with no onboarding/grant/evidence/audit mutations.
        let mut revoke = store.pool().begin().await?;
        sqlx::query("UPDATE agent_tokens SET revoked_at=NOW() WHERE id=$1")
            .bind(curator)
            .execute(&mut *revoke)
            .await?;
        let paths = (
            f.policy.clone(),
            f.key.clone(),
            f.bundle.clone(),
            urlfile.clone(),
        );
        let pending =
            tokio::spawn(async move { import(&paths.0, &paths.1, &paths.2, &paths.3).await });
        wait_for_locked_query(
            store.pool(),
            "SELECT scopes,revoked_at,expires_at FROM agent_tokens%",
        )
        .await?;
        revoke.commit().await?;
        assert!(pending.await?.is_err());
        let unchanged: i64 = sqlx::query_scalar("SELECT (SELECT count(*) FROM learning_actor_tokens)+(SELECT count(*) FROM learning_curator_grants)+(SELECT count(*) FROM learning_verified_evidence)+(SELECT count(*) FROM audit_events)")
            .fetch_one(store.pool()).await?;
        assert_eq!(unchanged, 0);
        sqlx::query("UPDATE agent_tokens SET revoked_at=NULL WHERE id=$1")
            .bind(curator)
            .execute(store.pool())
            .await?;

        // Import wins the credential locks. Hold its grant INSERT in a trigger
        // while revocation attempts UPDATE; it must wait until the whole import
        // (including all evidence and audit rows) commits.
        let gate = 91377423_i64;
        sqlx::query("CREATE FUNCTION learning_import_test_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(91377423); RETURN NEW; END $$")
            .execute(store.pool()).await?;
        sqlx::query("CREATE TRIGGER learning_import_test_gate BEFORE INSERT ON learning_curator_grants FOR EACH ROW EXECUTE FUNCTION learning_import_test_gate()")
            .execute(store.pool()).await?;
        let mut barrier = store.pool().begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(gate)
            .execute(&mut *barrier)
            .await?;
        let paths = (
            f.policy.clone(),
            f.key.clone(),
            f.bundle.clone(),
            urlfile.clone(),
        );
        let pending =
            tokio::spawn(async move { import(&paths.0, &paths.1, &paths.2, &paths.3).await });
        wait_for_locked_query(store.pool(), "INSERT INTO learning_curator_grants%").await?;
        let pool = store.pool().clone();
        let revocation = tokio::spawn(async move {
            sqlx::query("UPDATE agent_tokens SET revoked_at=NOW() WHERE id=$1")
                .bind(curator)
                .execute(&pool)
                .await
        });
        wait_for_locked_query(store.pool(), "UPDATE agent_tokens SET revoked_at=NOW()%").await?;
        barrier.commit().await?;
        pending.await??;
        revocation.await??;
        sqlx::query("DROP TRIGGER learning_import_test_gate ON learning_curator_grants")
            .execute(store.pool())
            .await?;
        sqlx::query("DROP FUNCTION learning_import_test_gate()")
            .execute(store.pool())
            .await?;
        sqlx::query("UPDATE agent_tokens SET revoked_at=NULL WHERE id=$1")
            .bind(curator)
            .execute(store.pool())
            .await?;
        assert_eq!(store.learning_actor(owner).await?, owner);
        assert_eq!(store.learning_actor(curator).await?, curator);
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM learning_verified_evidence WHERE owner_id=$1")
                .bind(owner)
                .fetch_one(store.pool())
                .await?;
        assert_eq!(count, 3);
        let audit:i64=sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action IN ('learning_actor_onboarded','learning_curator_granted','learning_evidence_attested')").fetch_one(store.pool()).await?;
        assert_eq!(audit, 6);
        import(&f.policy, &f.key, &f.bundle, &urlfile).await?;
        let repeated:i64=sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action IN ('learning_actor_onboarded','learning_curator_granted','learning_evidence_attested')").fetch_one(store.pool()).await?;
        assert_eq!(audit, repeated);
        store.pool().close().await;
        sqlx::query(&format!("DROP DATABASE {db} WITH(FORCE)"))
            .execute(&admin)
            .await?;
        admin.close().await;
        Ok(())
    }
}
