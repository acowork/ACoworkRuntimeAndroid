//! Getting evidence off a device and into a file someone can open.
//!
//! §4.6 item 6 lists six sources — `logcat -d`, `screencap`, `dumpsys <service>`, `/data/anr`,
//! `/data/tombstones`, `bugreportz` — and calls them the real value of the root tier. Measured
//! on the BLA-AL00 (probe items 13 / 13b, and again for this module) they are six different
//! permission questions, so this module treats "capture it" as a claim that has to be checked
//! per source rather than per tier:
//!
//! | source | shell uid on a `user` build | measured |
//! |---|---|---|
//! | `screencap -p` | works | 1 378 048-byte PNG |
//! | `logcat -d` | works, and reads the **whole** buffer | 878 395 bytes, other apps' lines included |
//! | `dumpsys <service>` | varies per service | listing works; a single dump is not verified here |
//! | `/data/anr` | lists names, reads nothing | `cat: /data/anr/trace_00: Permission denied` on a `-rw-r----- tombstoned system` file |
//! | `/data/tombstones` | cannot even list | `ls: /data/tombstones: Permission denied` |
//! | `bugreportz` | works — and it is a **write**, not a read | 1 m 44 s, 4 093 129-byte zip under `/data/user_de/0/com.android.shell/…`, `-rw------- shell shell`; `-s`/`-p` progress is **not** supported on API 29 (`usage: bugreportz [-h | -v]`) |
//!
//! The tier consequence of that table is worth stating plainly: on a `user` build with no root,
//! four of the six sources are reachable and two are not, and the two that are not
//! (`/data/anr`, `/data/tombstones`) fail at *read* time, after listing succeeded — which is
//! why [`Source::DeviceFile`] reports the device's own `Permission denied` rather than an empty
//! artifact.
//!
//! Two facts shape the transport, and both are the reason this module exists next to
//! [`rollback`](super::rollback) instead of on top of `exec`:
//!
//! - The exec channel decodes stdout with `from_utf8_lossy`, so **reading a binary through it
//!   is not reading it**. Every artifact is base64 on the wire and decoded here.
//! - Output is capped ([`DEFAULT_OUTPUT_CAP`](super::DEFAULT_OUTPUT_CAP) = 1 MiB) and a
//!   screenshot's base64 is 1.8 MiB, so an artifact arrives in chunks. Chunking is also what
//!   bounds memory: the alternative is a per-source output cap that has to be bigger than the
//!   biggest thing a user might ask for.
//!
//! The chunk arithmetic is the risky part, so it is not trusted: the device reports the
//! `sha256sum` of the bytes **it** wrote, and the artifact is kept only if the bytes that
//! arrived hash to the same value. A dropped chunk, a line mangled in transit, or a cap that
//! clipped the tail all become a reported failure with the two digests in it — never a PNG that
//! opens halfway.
//!
//! Reads use `dd bs=<chunk> skip=<n> count=1`, not `bs=1 skip=<byte>`: measured on device, the
//! byte-at-a-time form costs 0.82 s for one 256 KiB chunk at a 1 MB offset and the block form
//! 0.02 s. A capture that reads 29 chunks would otherwise spend half its time inside `dd`.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use acowork_platform_contract::Budget;
use base64::Engine as _;
use sha2::{Digest as _, Sha256};

use crate::host::{
    ApprovalToken, Capability, ExecRecord, ExecRequest, ExecutionBackend, classify_script,
    next_nonce, quote_posix,
};

/// How large an artifact may be before it needs to be asked for on purpose.
///
/// Four megabytes is not a round number: it is the measured size of a `bugreportz` zip on this
/// device (4 093 129 bytes), so the default covers every source the ADR lists without a caller
/// having to know sizes in advance.
pub const DEFAULT_EVIDENCE_BUDGET: u64 = 4 * 1024 * 1024;

/// Raw bytes per read. The limit in this direction is the output cap (1 MiB of *text* coming
/// back), not the `printf` argument ceiling that sizes [`SNAPSHOT_CHUNK_BYTES`]
/// (super::SNAPSHOT_CHUNK_BYTES) on the write path: 256 KiB of bytes is ~342 KiB of base64,
/// which fits with room for the identity prologue's own output.
pub const EVIDENCE_CHUNK_BYTES: u64 = 256 * 1024;

/// Where a capture puts bytes it has to stage before reading them.
pub const EVIDENCE_STAGING_DIR: &str = "/data/local/tmp";

/// How long to wait for each source. `bugreportz` is the reason this is per source: measured
/// at 1 m 44 s on this device, it exceeds every other budget in the crate, and a capture that
/// timed out at the default 30 s would leave a partially built report on the device.
pub const BUGREPORT_TIMEOUT: Duration = Duration::from_secs(300);
/// A screenshot and a logcat dump are sub-second operations on the device.
pub const QUICK_TIMEOUT: Duration = Duration::from_secs(30);

/// What to capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// `screencap -p` — the current display as a PNG.
    Screenshot,
    /// `logcat -d`, optionally one buffer and optionally only the last N lines.
    Logcat {
        /// `main` / `system` / `crash` / `radio` / `events` / `kernel`, or `None` for the
        /// default set.
        buffer: Option<String>,
        /// `-t <n>`: the last n lines. `None` is the whole buffer, which on the measured device
        /// was 878 KiB.
        tail: Option<u32>,
    },
    /// `dumpsys <service>` — one service's dump, not the 246-service list.
    Dumpsys {
        /// The service name, validated against [`safe_name`] before it reaches a command line.
        service: String,
    },
    /// A file already on the device, read without going through a staging copy. This is the
    /// shape `/data/anr/*` would need, and the shape that answers honestly when the device
    /// will not open it.
    DeviceFile {
        /// An absolute path on the device.
        path: String,
    },
    /// `bugreportz`: the device builds a zip and prints where it put it.
    Bugreport,
}

impl Source {
    /// A short, filesystem-safe slug for the artifact name.
    fn slug(&self) -> String {
        match self {
            Source::Screenshot => "screenshot".to_string(),
            Source::Logcat { buffer, tail } => match (buffer, tail) {
                (Some(b), Some(n)) => format!("logcat-{b}-{n}"),
                (Some(b), None) => format!("logcat-{b}"),
                (None, Some(n)) => format!("logcat-{n}"),
                (None, None) => "logcat".to_string(),
            },
            Source::Dumpsys { service } => format!("dumpsys-{}", sanitize_slug(service)),
            Source::DeviceFile { path } => {
                format!(
                    "file-{}",
                    sanitize_slug(
                        Path::new(path)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("anonymous")
                    )
                )
            }
            Source::Bugreport => "bugreport".to_string(),
        }
    }

    /// What the artifact should be opened as.
    fn extension(&self) -> &'static str {
        match self {
            Source::Screenshot => "png",
            Source::Bugreport => "zip",
            _ => "txt",
        }
    }

    /// How long the producing command gets.
    fn timeout(&self) -> Duration {
        match self {
            Source::Bugreport => BUGREPORT_TIMEOUT,
            _ => QUICK_TIMEOUT,
        }
    }

    /// The command that puts the bytes somewhere readable, if the source does not already
    /// live in a file.
    fn stage_script(&self, stage: &str) -> Result<String, CaptureError> {
        match self {
            Source::Screenshot => Ok(format!("screencap -p > {}", quote_posix(stage))),
            Source::Logcat { buffer, tail } => {
                let mut script = String::from("logcat -d");
                if let Some(b) = buffer {
                    let b = safe_name(b, "logcat buffer")?;
                    script.push_str(&format!(" -b {b}"));
                }
                if let Some(n) = tail {
                    script.push_str(&format!(" -t {n}"));
                }
                script.push_str(&format!(" > {}", quote_posix(stage)));
                Ok(script)
            }
            Source::Dumpsys { service } => {
                let service = safe_name(service, "dumpsys service")?;
                Ok(format!("dumpsys {service} > {}", quote_posix(stage)))
            }
            // Read in place: copying a file the caller cannot read would fail the same way,
            // with a worse error message.
            Source::DeviceFile { .. } | Source::Bugreport => Ok(String::new()),
        }
    }

    /// Human-readable, for the artifact record and the audit-facing summary.
    pub fn describe(&self) -> String {
        match self {
            Source::Screenshot => "screencap -p".to_string(),
            Source::Logcat { buffer, tail } => format!(
                "logcat -d{}{}",
                buffer
                    .as_ref()
                    .map(|b| format!(" -b {b}"))
                    .unwrap_or_default(),
                tail.map(|n| format!(" -t {n}")).unwrap_or_default()
            ),
            Source::Dumpsys { service } => format!("dumpsys {service}"),
            Source::DeviceFile { path } => format!("read {path}"),
            Source::Bugreport => "bugreportz".to_string(),
        }
    }
}

/// A capture that produced bytes and proved they were the device's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    /// What was asked for, as the command the device ran.
    pub source: String,
    /// Where the bytes landed on the host.
    pub host_path: PathBuf,
    /// How many.
    pub bytes: u64,
    /// The digest the **device** reported, which the host copy reproduced.
    pub digest: String,
    /// Round trips spent carrying it, so a slow capture is at least explainable.
    pub reads: usize,
}

/// Why nothing was captured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    /// A name the caller supplied could not be used safely — refused before anything ran.
    UnsafeName {
        /// What the caller supplied.
        value: String,
        /// Which parameter it was rejected as.
        what: String,
    },
    /// The device could not produce the artifact.
    CommandFailed {
        /// The script that produced nothing.
        script: String,
        /// Its exit code, when there was one.
        exit: Option<i32>,
        /// Its stderr, which is the part worth reading.
        stderr: String,
    },
    /// The device would not open the file. The reason is its own words (`Permission denied`),
    /// not this module's guess.
    Unreadable {
        /// The file that would not open.
        path: String,
        /// The device's own words, e.g. `Permission denied`.
        reason: String,
    },
    /// `bugreportz` exited 0 without the `OK:<path>` line its protocol promises.
    NoReportPath(
        /// The first 200 characters of what it printed instead.
        String,
    ),
    /// Bigger than the budget, so nothing was read. The bytes stay on the device rather than
    /// arriving incomplete.
    OverBudget {
        /// What the device says the artifact weighs.
        bytes: u64,
        /// What the caller was willing to carry.
        budget: u64,
    },
    /// The chunks did not add up to the size the device reported.
    ShortRead {
        /// The size the device reported.
        expected: u64,
        /// The size that actually arrived.
        got: u64,
    },
    /// The host copy is not the device's bytes. The artifact was deleted.
    DigestMismatch {
        /// The device's digest of the bytes it wrote.
        expected: String,
        /// The host's digest of the bytes that arrived.
        got: String,
    },
    /// The backend refused or failed. Carries its own text.
    Backend(String),
    /// Could not write the host file.
    Host(String),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaptureError::UnsafeName { value, what } => write!(
                f,
                "`{value}` is not a usable {what}: a name that carries a shell metacharacter \
                 would become part of the command line, and the guard that catches it after \
                 that is the same guard that has to catch everything else"
            ),
            CaptureError::CommandFailed {
                script,
                exit,
                stderr,
            } => write!(
                f,
                "`{script}` did not produce anything (exit {exit:?}): {}",
                stderr.trim()
            ),
            CaptureError::Unreadable { path, reason } => write!(
                f,
                "the device will not open {path}: {reason} — listing it and reading it are \
                 different permissions on Android, and this is the difference"
            ),
            CaptureError::NoReportPath(out) => write!(
                f,
                "bugreportz did not report where it put the report (got `{out}`); the report \
                 may still exist on the device, so this is not a reason to run it again \
                 blindly — it costs 1m44s per attempt here"
            ),
            CaptureError::OverBudget { bytes, budget } => write!(
                f,
                "{bytes} bytes is over the {budget}-byte evidence budget; raise the budget for \
                 this one capture rather than for every capture"
            ),
            CaptureError::ShortRead { expected, got } => write!(
                f,
                "the device said {expected} bytes and {got} arrived; a chunk was lost"
            ),
            CaptureError::DigestMismatch { expected, got } => write!(
                f,
                "the artifact hashes to {got} but the device reported {expected}; the bytes \
                 that came back are not the bytes that were there, and the incomplete file \
                 has been deleted"
            ),
            CaptureError::Backend(e) => write!(f, "the backend refused or failed: {e}"),
            CaptureError::Host(e) => write!(f, "cannot write the artifact on the host: {e}"),
        }
    }
}

impl std::error::Error for CaptureError {}

/// Only names that cannot change the shape of a command line.
///
/// `dumpsys`, `logcat -b` and a device path all arrive from a caller — a model, in production —
/// and are pasted into a script that will be run as shell. The classifier would catch `x; rm -rf
/// /data` as a second command, but catching injection after it is already in a command line is
/// a worse place to decide than refusing the character.
fn safe_name(value: &str, what: &str) -> Result<String, CaptureError> {
    let ok = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':'));
    if ok {
        Ok(value.to_string())
    } else {
        Err(CaptureError::UnsafeName {
            value: value.to_string(),
            what: what.to_string(),
        })
    }
}

/// File names are for the host filesystem, where `/` is a separator, not a character.
fn sanitize_slug(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .take(64)
        .collect()
}

/// Run one script, claiming what the classifier says it does.
///
/// Same rule as everywhere else in this crate: the capability comes from the content, and a
/// redirect is an `fs:outside-app` write even when the command that produced it is a read.
async fn run(
    backend: &Arc<dyn ExecutionBackend>,
    script: &str,
    session: &str,
    token: Option<&ApprovalToken>,
    timeout: Duration,
) -> Result<ExecRecord, CaptureError> {
    let capability = classify_script(script)
        .strongest()
        .capability()
        .unwrap_or(Capability::ShellRead);
    let mut request = ExecRequest::new(capability, script, session);
    request.budget = Budget {
        timeout: Some(timeout),
        output_cap: crate::host::DEFAULT_OUTPUT_CAP,
    };
    request.approval_token = token.cloned();
    backend
        .exec(request)
        .await
        .map_err(|e| CaptureError::Backend(e.to_string()))
}

/// Size and digest, as the device sees them.
async fn measure(
    backend: &Arc<dyn ExecutionBackend>,
    path: &str,
    session: &str,
) -> Result<(u64, String), CaptureError> {
    let quoted = quote_posix(path);
    let sized = run(
        backend,
        &format!("wc -c < {quoted}"),
        session,
        None,
        QUICK_TIMEOUT,
    )
    .await?;
    if sized.exit_code != Some(0) {
        return Err(CaptureError::Unreadable {
            path: path.to_string(),
            reason: sized.stderr.trim().to_string(),
        });
    }
    let bytes: u64 = sized
        .stdout
        .trim()
        .parse()
        .map_err(|_| CaptureError::Unreadable {
            path: path.to_string(),
            reason: format!("`wc -c` answered {:?}", sized.stdout.trim()),
        })?;

    let digested = run(
        backend,
        &format!("sha256sum < {quoted}"),
        session,
        None,
        QUICK_TIMEOUT,
    )
    .await?;
    if digested.exit_code != Some(0) {
        return Err(CaptureError::Unreadable {
            path: path.to_string(),
            reason: digested.stderr.trim().to_string(),
        });
    }
    let digest = digested
        .stdout
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();
    Ok((bytes, digest))
}

/// Carry the bytes across a text channel, in pieces the channel can hold.
async fn read_chunks(
    backend: &Arc<dyn ExecutionBackend>,
    path: &str,
    bytes: u64,
    session: &str,
) -> Result<Vec<u8>, CaptureError> {
    let quoted = quote_posix(path);
    let chunks = bytes.div_ceil(EVIDENCE_CHUNK_BYTES).max(1) as usize;
    let mut got = Vec::with_capacity(bytes as usize);
    for index in 0..chunks {
        let script = format!(
            "dd if={quoted} bs={EVIDENCE_CHUNK_BYTES} skip={index} count=1 2>/dev/null | base64"
        );
        let out = run(backend, &script, session, None, QUICK_TIMEOUT).await?;
        if out.exit_code != Some(0) {
            return Err(CaptureError::CommandFailed {
                script,
                exit: out.exit_code,
                stderr: out.stderr.clone(),
            });
        }
        let cleaned: String = out.stdout.chars().filter(|c| !c.is_whitespace()).collect();
        let piece = base64::engine::general_purpose::STANDARD
            .decode(&cleaned)
            .map_err(|_| CaptureError::ShortRead {
                expected: bytes,
                got: got.len() as u64,
            })?;
        got.extend_from_slice(&piece);
    }
    if got.len() as u64 != bytes {
        return Err(CaptureError::ShortRead {
            expected: bytes,
            got: got.len() as u64,
        });
    }
    Ok(got)
}

/// One capture, in progress.
///
/// The struct exists because the operation has state that must not be lost between steps: the
/// staging path is only worth removing if it was ever written to, and a `&mut bool` threaded
/// through four free functions was how that got expressed the first time.
struct Job<'a> {
    backend: &'a Arc<dyn ExecutionBackend>,
    source: &'a Source,
    session: &'a str,
    dir: &'a Path,
    token: Option<&'a ApprovalToken>,
    budget: u64,
    nonce: String,
    stage: String,
    staged: bool,
}

/// Capture one source into `dir` on the host.
///
/// `backend` is normally the chain from [`host::chain`](super::chain), so staging a screenshot
/// is a creation under §4.6.4's own rules, and two useful things happen automatically: the gate
/// asks for the `android:fs:outside-app` grant, and the rollback ledger records `rm -f` as its
/// inverse. If a capture dies halfway, that entry is what stops a 4 MB screenshot sitting on the
/// user's phone.
pub async fn capture(
    backend: &Arc<dyn ExecutionBackend>,
    source: &Source,
    session: &str,
    dir: &Path,
    token: Option<&ApprovalToken>,
    budget: u64,
) -> Result<Artifact, CaptureError> {
    let nonce = next_nonce();
    let stage = format!("{EVIDENCE_STAGING_DIR}/.acowork-ev-{nonce}.bin");
    let mut job = Job {
        backend,
        source,
        session,
        dir,
        token,
        budget,
        nonce,
        stage,
        staged: false,
    };
    let outcome = job.run().await;
    // Every path out of here removes the staging file, including the error paths. A capture
    // that failed at chunk 7 of 29 has no reason to leave its bytes behind — and one that was
    // refused before it staged anything has no reason to run a command either.
    if job.staged {
        let _ = job.cleanup().await;
    }
    outcome
}

impl Job<'_> {
    async fn run(&mut self) -> Result<Artifact, CaptureError> {
        let path = self.resolve().await?;
        let (bytes, digest) = measure(self.backend, &path, self.session).await?;
        if bytes > self.budget {
            return Err(CaptureError::OverBudget {
                bytes,
                budget: self.budget,
            });
        }
        let got = read_chunks(self.backend, &path, bytes, self.session).await?;

        let mut hasher = Sha256::new();
        hasher.update(&got);
        let host_digest = hasher.finalize();
        let host_digest = host_digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        // The receipt, not a formality: the device hashed the bytes before they were encoded,
        // so this is the only place a lost chunk or a clipped tail becomes visible.
        if host_digest != digest {
            return Err(CaptureError::DigestMismatch {
                expected: digest,
                got: host_digest,
            });
        }

        std::fs::create_dir_all(self.dir).map_err(|e| CaptureError::Host(e.to_string()))?;
        let host_path = self.dir.join(format!(
            "{}-{}.{}",
            self.source.slug(),
            self.nonce,
            self.source.extension()
        ));
        std::fs::write(&host_path, &got).map_err(|e| CaptureError::Host(e.to_string()))?;
        Ok(Artifact {
            source: self.source.describe(),
            host_path,
            bytes,
            digest,
            reads: bytes.div_ceil(EVIDENCE_CHUNK_BYTES).max(1) as usize,
        })
    }

    /// Put the bytes on the device somewhere readable, and say where they ended up.
    async fn resolve(&mut self) -> Result<String, CaptureError> {
        let path = match self.source {
            Source::DeviceFile { path } => {
                let path = safe_name(path, "device path")?;
                if !path.starts_with('/') {
                    return Err(CaptureError::UnsafeName {
                        value: path.clone(),
                        what: "device path (must be absolute)".to_string(),
                    });
                }
                path
            }
            Source::Bugreport => {
                let out = run(
                    self.backend,
                    "bugreportz",
                    self.session,
                    self.token,
                    BUGREPORT_TIMEOUT,
                )
                .await?;
                if out.exit_code != Some(0) {
                    return Err(CaptureError::CommandFailed {
                        script: "bugreportz".to_string(),
                        exit: out.exit_code,
                        stderr: out.stderr.clone(),
                    });
                }
                // The protocol is a single line: `OK:/path`, or `FAILED:<code>`.
                out.stdout
                    .lines()
                    .find(|l| l.starts_with("OK:"))
                    .map(|l| l.trim_start_matches("OK:").trim().to_string())
                    .ok_or_else(|| {
                        CaptureError::NoReportPath(out.stdout.trim().chars().take(200).collect())
                    })?
            }
            other => {
                let script = other.stage_script(&self.stage)?;
                self.staged = true;
                let out = run(
                    self.backend,
                    &script,
                    self.session,
                    self.token,
                    other.timeout(),
                )
                .await?;
                if out.exit_code != Some(0) {
                    return Err(CaptureError::CommandFailed {
                        script,
                        exit: out.exit_code,
                        stderr: out.stderr.clone(),
                    });
                }
                self.stage.clone()
            }
        };
        Ok(path)
    }

    async fn cleanup(&self) -> Result<ExecRecord, CaptureError> {
        run(
            self.backend,
            &format!("rm -f {}", quote_posix(&self.stage)),
            self.session,
            None,
            QUICK_TIMEOUT,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{BackendError, ExecRecord, HostProfile, ShellDialect, probe::ProbeOutput};
    use std::collections::BTreeMap;

    /// A device with a filesystem, a permission model, and one deliberate fault injection.
    struct Device {
        profile: HostProfile,
        files: std::sync::Mutex<BTreeMap<String, Vec<u8>>>,
        unreadable: Vec<String>,
        /// Chunk index that comes back mangled instead of correct.
        corrupt_chunk: Option<usize>,
        seen: std::sync::Mutex<Vec<String>>,
    }

    impl Device {
        fn new() -> Device {
            Device {
                profile: HostProfile::assemble(&ProbeOutput::nothing_ran(), "com.example.agent"),
                files: std::sync::Mutex::new(BTreeMap::new()),
                unreadable: Vec::new(),
                corrupt_chunk: None,
                seen: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn with_unreadable(mut self, path: &str) -> Self {
            self.unreadable.push(path.to_string());
            self
        }

        fn put(&self, path: &str, bytes: &[u8]) {
            self.files
                .lock()
                .unwrap()
                .insert(path.to_string(), bytes.to_vec());
        }

        fn scripts(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }

        fn exists(&self, path: &str) -> bool {
            self.files.lock().unwrap().contains_key(path)
        }

        fn read(&self, path: &str) -> Option<Vec<u8>> {
            self.files.lock().unwrap().get(path).cloned()
        }
    }

    fn digest_of(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The redirect target of a script, when it has one.
    fn redirect_target(script: &str) -> Option<String> {
        script
            .rsplit_once("> ")
            .map(|(_, rest)| rest.trim().trim_matches('\'').to_string())
    }

    #[async_trait::async_trait]
    impl ExecutionBackend for Device {
        fn name(&self) -> &'static str {
            "fake(shell)"
        }

        fn dialect(&self) -> Option<ShellDialect> {
            Some(ShellDialect::MkSh)
        }

        fn profile(&self) -> &HostProfile {
            &self.profile
        }

        async fn exec(&self, request: ExecRequest) -> Result<ExecRecord, BackendError> {
            let script = request.script.clone();
            self.seen.lock().unwrap().push(script.clone());
            let record = |stdout: String, code: i32, stderr: String| ExecRecord {
                stdout,
                stderr,
                exit_code: Some(code),
                selinux_denials: Vec::new(),
                uid: Some(2000),
                context: Some("u:r:shell:s0".to_string()),
                duration_ms: 1,
                truncated: false,
                timed_out: false,
            };

            if let Some(target) = redirect_target(&script) {
                // Whatever is being staged, the fake device produces deterministic bytes for it.
                let body = format!("artifact for {target}");
                self.put(&target, body.as_bytes());
                return Ok(record(String::new(), 0, String::new()));
            }
            if let Some(rest) = script.strip_prefix("wc -c < ") {
                let path = rest.trim().trim_matches('\'');
                if self.unreadable.iter().any(|p| p == path) {
                    return Ok(record(
                        String::new(),
                        1,
                        format!("wc: {path}: Permission denied"),
                    ));
                }
                return match self.read(path) {
                    Some(bytes) => Ok(record(format!("{}\n", bytes.len()), 0, String::new())),
                    None => Ok(record(String::new(), 1, "No such file or directory".into())),
                };
            }
            if let Some(rest) = script.strip_prefix("sha256sum < ") {
                let path = rest.trim().trim_matches('\'');
                if self.unreadable.iter().any(|p| p == path) {
                    return Ok(record(
                        String::new(),
                        1,
                        format!("sha256sum: {path}: Permission denied"),
                    ));
                }
                return match self.read(path) {
                    Some(bytes) => Ok(record(format!("{}\n", digest_of(&bytes)), 0, String::new())),
                    None => Ok(record(String::new(), 1, "No such file or directory".into())),
                };
            }
            if script.starts_with("dd if=") && script.ends_with("| base64") {
                // `dd if='p' bs=<chunk> skip=<i> count=1 2>/dev/null | base64`
                let path = script
                    .trim_start_matches("dd if=")
                    .split(" bs=")
                    .next()
                    .unwrap_or("")
                    .trim_matches('\'')
                    .to_string();
                let skip: usize = script
                    .split(" skip=")
                    .nth(1)
                    .and_then(|s| s.split(' ').next())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let bytes = self.read(&path).unwrap_or_default();
                let start = skip * EVIDENCE_CHUNK_BYTES as usize;
                let end = (start + EVIDENCE_CHUNK_BYTES as usize).min(bytes.len());
                let mut piece = bytes[start..end].to_vec();
                if self.corrupt_chunk == Some(skip) {
                    piece.truncate(piece.len() / 2);
                }
                let encoded = base64::engine::general_purpose::STANDARD.encode(&piece);
                return Ok(record(encoded, 0, String::new()));
            }
            if let Some(rest) = script.strip_prefix("rm -f ") {
                let path = rest.trim().trim_matches('\'');
                self.files.lock().unwrap().remove(path);
                return Ok(record(String::new(), 0, String::new()));
            }
            if script == "bugreportz" {
                let path = "/data/user_de/0/com.android.shell/files/bugreports/report.zip";
                self.put(path, b"PK\x03\x04 a whole bugreport");
                return Ok(record(format!("OK:{path}\n"), 0, String::new()));
            }
            Ok(record(String::new(), 0, String::new()))
        }
    }

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("acowork-evidence-{tag}"));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn device() -> Arc<Device> {
        Arc::new(Device::new())
    }

    async fn capture_on(
        device: &Arc<Device>,
        source: &Source,
        session: &str,
        dir: &Path,
        budget: u64,
    ) -> Result<Artifact, CaptureError> {
        let inner = Arc::clone(device) as Arc<dyn ExecutionBackend>;
        capture(&inner, source, session, dir, None, budget).await
    }

    #[tokio::test]
    async fn an_artifact_arrives_as_the_bytes_the_device_wrote() {
        let device = device();
        let dir = dir("roundtrip");
        let artifact = capture_on(
            &device,
            &Source::Screenshot,
            "s-1",
            &dir,
            DEFAULT_EVIDENCE_BUDGET,
        )
        .await
        .unwrap();

        let on_host = std::fs::read(&artifact.host_path).unwrap();
        assert_eq!(artifact.source, "screencap -p");
        assert_eq!(on_host.len() as u64, artifact.bytes);
        assert_eq!(digest_of(&on_host), artifact.digest);
        assert!(artifact.host_path.to_string_lossy().ends_with(".png"));
        assert_eq!(
            device
                .scripts()
                .iter()
                .filter(|s| s.starts_with("rm -f"))
                .count(),
            1,
            "staging is removed exactly once"
        );
        let staged = device
            .scripts()
            .iter()
            .find_map(|s| redirect_target(s))
            .expect("a staging path was written");
        assert!(!device.exists(&staged), "{staged} outlived the capture");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The reason the digest check exists: chunk arithmetic that looks fine and is not.
    #[tokio::test]
    async fn a_mangled_chunk_is_a_failure_not_a_short_artifact() {
        let mut raw = Device::new();
        raw.corrupt_chunk = Some(0);
        let device = Arc::new(raw);
        let dir = dir("corrupt");
        let err = capture_on(
            &device,
            &Source::Screenshot,
            "s-2",
            &dir,
            DEFAULT_EVIDENCE_BUDGET,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                CaptureError::DigestMismatch { .. } | CaptureError::ShortRead { .. }
            ),
            "{err}"
        );
        assert!(
            std::fs::read_dir(&dir)
                .map(|mut r| r.next().is_none())
                .unwrap_or(true),
            "nothing half-written is left behind for someone to open"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// §4.6 item 6 measured this exact case on hardware: names are listable, bytes are not.
    #[tokio::test]
    async fn a_file_the_device_will_not_open_is_refused_with_its_own_words() {
        let device = Arc::new(Device::new().with_unreadable("/data/anr/trace_00"));
        let err = capture_on(
            &device,
            &Source::DeviceFile {
                path: "/data/anr/trace_00".to_string(),
            },
            "s-3",
            &dir("anr"),
            DEFAULT_EVIDENCE_BUDGET,
        )
        .await
        .unwrap_err();
        match err {
            CaptureError::Unreadable { path, reason } => {
                assert_eq!(path, "/data/anr/trace_00");
                assert!(reason.contains("Permission denied"), "{reason}");
            }
            other => panic!("{other}"),
        }
    }

    #[tokio::test]
    async fn an_artifact_over_the_budget_is_not_brought_back() {
        let device = device();
        device.put("/data/local/tmp/big.bin", &vec![7u8; 1200]);
        let err = capture_on(
            &device,
            &Source::DeviceFile {
                path: "/data/local/tmp/big.bin".to_string(),
            },
            "s-4",
            &dir("budget"),
            1000,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, CaptureError::OverBudget { bytes: 1200, .. }),
            "{err}"
        );
        // It was read in place, so there is nothing of ours to clean up.
        assert!(device.exists("/data/local/tmp/big.bin"));
    }

    /// A service name arrives from a model, and it is pasted into a command line. The refusal
    /// happens here, before a script exists, rather than downstream in the classifier.
    #[tokio::test]
    async fn a_service_name_cannot_carry_a_second_command() {
        let device = device();
        let err = capture_on(
            &device,
            &Source::Dumpsys {
                service: "package; rm -rf <root>".to_string(),
            },
            "s-5",
            &dir("inject"),
            DEFAULT_EVIDENCE_BUDGET,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CaptureError::UnsafeName { .. }), "{err}");
        assert!(
            device.scripts().is_empty(),
            "refused before anything reached a device: {:?}",
            device.scripts()
        );
    }

    /// `bugreportz` does not write where we point it; it tells us where it wrote. It is also a
    /// write, so the capture asks for one.
    #[tokio::test]
    async fn a_bugreport_is_found_by_asking_it_where_it_put_itself() {
        let device = device();
        let dir = dir("bugreport");
        let artifact = capture_on(
            &device,
            &Source::Bugreport,
            "s-6",
            &dir,
            DEFAULT_EVIDENCE_BUDGET,
        )
        .await
        .unwrap();
        assert!(artifact.host_path.to_string_lossy().ends_with(".zip"));
        assert_eq!(artifact.source, "bugreportz");
        assert!(
            device
                .scripts()
                .iter()
                .any(|s| s.starts_with("dd if='/data/user_de/")),
            "read from the device's own path: {:?}",
            device.scripts()
        );
        assert!(
            !device
                .scripts()
                .iter()
                .any(|s| s.starts_with("rm -f /data/user_de")),
            "the report is the device's file, not our staging"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every script this module generates has to survive the real classifier at the tier it is
    /// claimed for, or the capture is a design document.
    #[test]
    fn generated_scripts_satisfy_the_command_guardrails() {
        use crate::host::Effect;
        let stage = "/data/local/tmp/.acowork-ev-n.bin";
        let reads = [
            format!("wc -c < {}", quote_posix(stage)),
            format!("sha256sum < {}", quote_posix(stage)),
            format!(
                "dd if={} bs={EVIDENCE_CHUNK_BYTES} skip=3 count=1 2>/dev/null | base64",
                quote_posix(stage)
            ),
        ];
        for script in reads {
            assert_eq!(
                classify_script(&script).strongest(),
                Effect::ReadOnly,
                "`{script}` must read, not write"
            );
        }
        // Staging is a write, and the module claims it as one rather than hiding it.
        let staged = format!("screencap -p > {}", quote_posix(stage));
        assert_eq!(
            classify_script(&staged).strongest(),
            Effect::FileWrite,
            "`{staged}` creates a file and must say so"
        );
        assert_eq!(
            classify_script(&format!("rm -f {}", quote_posix(stage))).strongest(),
            Effect::FileWrite
        );
        // `bugreportz` is not a read. It builds a 4 MB zip under /data/user_de before anyone
        // asks for its bytes, and the classifier has always known that — so a capture of it
        // needs the write tier and a token, and this module must not pretend otherwise.
        assert_eq!(
            classify_script("bugreportz").strongest(),
            Effect::ShellWrite,
            "the device writes a 4 MB report to produce it"
        );
    }

    #[test]
    fn the_multi_chunk_shape_is_the_one_the_transport_assumes() {
        // A 1.38 MB screenshot (the measured size) is 6 chunks at 256 KiB, and the last one is
        // partial — the arithmetic that silently truncates an artifact lives here.
        let bytes = 1_378_048u64;
        let chunks = bytes.div_ceil(EVIDENCE_CHUNK_BYTES);
        assert_eq!(chunks, 6);
        let tail = bytes - (chunks - 1) * EVIDENCE_CHUNK_BYTES;
        assert_eq!(tail, 67_328);
        // And its base64 still fits under one output cap, which is what sets the chunk size.
        let encoded = (tail as usize).div_ceil(3) * 4;
        assert!(encoded < crate::host::DEFAULT_OUTPUT_CAP);
    }
}
