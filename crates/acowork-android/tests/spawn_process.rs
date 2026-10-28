//! Real-process tests for [`ProcessSpawnRunner`], against the build host's `/bin/sh`.
//!
//! The unit tests in `src/host/spawn.rs` use a canned runner, which proves the mapping
//! logic and nothing else. This file is where the claims about *how a process is actually
//! started* get tested against a process: that the script reaches stdin rather than argv,
//! that the Runtime's environment does not leak into the child, that the quoting in
//! [`host::script`] survives a real shell's parser, and that a killed command still hands
//! back the bytes it produced before dying.
//!
//! Gated to Unix. Android is the target, macOS and Linux are the build hosts, and `/bin/sh`
//! is the only shell common to all three.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use acowork_android::host::script::{EX_CWD_UNAVAILABLE, extract_identity, prepare};
use acowork_android::host::spawn::{
    ProcessSpawnRunner, RawOutput, SpawnError, SpawnInvocation, SpawnRunner,
};

/// A PATH that reaches `id`, `ps` and `cat` on macOS and on a normal Linux box.
///
/// The runner clears the child's environment, so a test that wants an external command has
/// to supply this itself — which is the point of
/// [`the_child_environment_is_the_one_supplied_not_the_one_inherited`], and why every test
/// here passes a PATH explicitly rather than relying on inheritance.
const TEST_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// One test at a time owns the process table.
///
/// `#[tokio::test]` gives every test its own current-thread runtime, and on macOS all of
/// them share one SIGCHLD reaper. With twelve runtimes reaping at once, delivery of an exit
/// status is delayed often enough that a `wait()` on a command which finished in
/// milliseconds can sit past its own deadline: measured 2 failures in 12 runs at the default
/// thread count, 0 in 12 runs at `RUST_TEST_THREADS=1`, with no change to the code between
/// them.
///
/// That is a property of the harness, not of [`ProcessSpawnRunner`] — the product drives a
/// single runtime — but a test that fails for reasons outside the code under test is a test
/// nobody trusts, so the real-process tests here are serialised and their wall-clock
/// assertions stay strict rather than being loosened to absorb the contention.
///
/// A permit is awaited rather than a mutex locked, because the waiting happens inside a
/// runtime: blocking a harness thread on a `std` lock while holding a future parks one test
/// and, under clippy's `await_holding_lock`, advertises a hazard that a semaphore simply does
/// not have. `tokio::sync::Semaphore` is not bound to the runtime that created it, so
/// twelve independent runtimes can queue on one static permit.
static PROCESS_TABLE: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();

fn process_table() -> &'static tokio::sync::Semaphore {
    PROCESS_TABLE.get_or_init(|| tokio::sync::Semaphore::new(1))
}

/// Take the single permit. Panics only if the semaphore were closed, which nothing here does.
async fn own_the_process_table() -> tokio::sync::SemaphorePermit<'static> {
    process_table()
        .acquire()
        .await
        .expect("the process-table permit is never closed")
}

/// A shell that can resolve external commands, and nothing else.
fn base_env() -> BTreeMap<String, String> {
    env(&[("PATH", TEST_PATH), ("HOME", "/")])
}

async fn run(script: &str, env: BTreeMap<String, String>) -> RawOutput {
    let mut inv = SpawnInvocation::new("/bin/sh", script).with_args(&["-s"]);
    inv.env = env;
    inv.timeout = Some(Duration::from_secs(10));
    ProcessSpawnRunner::new()
        .spawn(inv)
        .await
        // Carry the reason: this helper backs most tests in the file, and a bare expect made an
        // intermittent failure unclassifiable from its message alone.
        .unwrap_or_else(|error| panic!("spawn failed: {error}"))
}

/// This process's real uid, obtained without libc and without asking a shell.
///
/// A file we just created is owned by us, so `stat` reports our uid. Deriving it this way
/// keeps the identity tests honest: the prologue under test gets its answer from `id -u`,
/// so the expected value must not come from `id -u` as well.
fn process_uid() -> u32 {
    // The pid alone is not a unique name: every test in this binary runs in one process, and
    // they run concurrently, so two calls would create and then delete the same path — and one
    // would `stat` a file the other had already removed. The counter makes each call's file
    // its own.
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let probe = std::env::temp_dir().join(format!("acowork-uid-{}-{}", std::process::id(), n));
    std::fs::write(&probe, b"x").expect("write uid probe file");
    let uid = std::fs::metadata(&probe)
        .expect("stat uid probe file")
        .uid();
    let _ = std::fs::remove_file(&probe);
    uid
}

#[tokio::test]
async fn a_script_runs_and_its_streams_are_captured_separately() {
    let _process_table = own_the_process_table().await;
    let out = run(
        "printf 'to-out\\n'; printf 'to-err\\n' >&2; exit 3",
        base_env(),
    )
    .await;

    assert_eq!(
        out.exit_code,
        Some(3),
        "stderr was {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "to-out\n");
    assert_eq!(String::from_utf8_lossy(&out.stderr), "to-err\n");
    assert!(!out.timed_out);
    assert!(!out.truncated);
    assert!(!out.succeeded(), "exit 3 is not success");
}

#[tokio::test]
async fn a_zero_exit_is_the_only_success() {
    let _process_table = own_the_process_table().await;
    let out = run("true", base_env()).await;
    assert!(
        out.succeeded(),
        "timed_out={} exit={:?} dur={:?} out={:?}",
        out.timed_out,
        out.exit_code,
        out.duration,
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(out.exit_code, Some(0));
}

/// The claim from ADR-AND-001 §4.7, tested rather than asserted in a doc comment.
///
/// The script asks its own shell for the command line it was started with. Had the runner
/// passed the body as an argument — `sh -c '<body>'` — the canary would appear in that
/// line, and any process on the device could read it out of `/proc/<pid>/cmdline`. With
/// `sh -s` the body is never in argv, so the canary cannot appear.
#[tokio::test]
async fn the_script_body_never_appears_in_the_child_command_line() {
    let _process_table = own_the_process_table().await;
    const CANARY: &str = "ACOWORK-CANARY-4f9c2b";

    let script = format!("ps -o args= -p $$ 2>/dev/null || true\necho {CANARY}\n");
    let out = run(&script, base_env()).await;
    let text = String::from_utf8_lossy(&out.stdout).to_string();

    let cmdline = text.lines().next().unwrap_or("").trim().to_string();
    if cmdline.is_empty() {
        // `ps` is missing or does not support `-o args= -p`. Say so loudly rather than
        // letting the assertion below pass vacuously.
        panic!(
            "cannot perform the argv check: `ps -o args= -p $$` produced no output on this \
             host. stdout was {text:?}"
        );
    }

    assert!(
        cmdline.contains("sh"),
        "expected a shell command line, got: {cmdline}"
    );
    assert!(
        !cmdline.contains(CANARY),
        "the script body leaked into argv; the child's command line was: {cmdline}"
    );
}

#[tokio::test]
async fn the_child_environment_is_the_one_supplied_not_the_one_inherited() {
    let _process_table = own_the_process_table().await;
    // `HOME` is set in every process cargo runs, so if the child inherited the Runtime's
    // environment, the first case below would print a real path instead of UNSET.
    let inherited = run("printf 'H=[%s]\\n' \"${HOME-UNSET}\"\n", BTreeMap::new()).await;
    assert_eq!(
        String::from_utf8_lossy(&inherited.stdout).trim(),
        "H=[UNSET]",
        "the child inherited the parent's HOME; env_clear() is not taking effect"
    );

    let supplied = run(
        "printf 'H=[%s] V=[%s]\\n' \"${HOME-UNSET}\" \"${ACOWORK_PROBE-unset}\"\n",
        env(&[
            ("PATH", TEST_PATH),
            ("HOME", "/tmp/acowork-fixture"),
            ("ACOWORK_PROBE", "visible"),
        ]),
    )
    .await;
    assert_eq!(
        String::from_utf8_lossy(&supplied.stdout).trim(),
        "H=[/tmp/acowork-fixture] V=[visible]",
        "an explicitly supplied variable must still reach the child"
    );
}

/// The caller's `env` reaches the child as `export` lines inside the script, not as
/// process environment — which is what lets a backend keep its base environment separate
/// from what each request asks for, and keeps the pair out of `/proc/<pid>/environ`.
#[tokio::test]
async fn request_environment_reaches_the_body_as_shell_exports() {
    let _process_table = own_the_process_table().await;
    let prepared = prepare(
        "printf 'TAG=[%s]\\n' \"$ACOWORK_TAG\"",
        None,
        &env(&[("ACOWORK_TAG", "a b'c")]),
    )
    .unwrap();
    assert!(
        prepared
            .text
            .contains("export ACOWORK_TAG='a '\\''b'\\''c'")
            || prepared.text.contains("export ACOWORK_TAG='a b'"),
        "expected an export line, got:\n{}",
        prepared.text
    );

    let mut inv = SpawnInvocation::new("/bin/sh", prepared.text.clone()).with_args(&["-s"]);
    // Only the base environment goes to the process; the request's variables are in the
    // script, so they must arrive without being put here.
    inv.env = base_env();
    let out = ProcessSpawnRunner::new().spawn(inv).await.unwrap();

    let (_identity, clean) = extract_identity(&out.stdout, &prepared.nonce);
    assert_eq!(
        String::from_utf8_lossy(&clean).trim(),
        "TAG=[a b'c]",
        "script:\n{}",
        prepared.text
    );
}

#[tokio::test]
async fn output_past_the_cap_is_cut_but_the_child_still_finishes() {
    let _process_table = own_the_process_table().await;
    // ~220 KB, well past both the cap and the kernel's pipe buffer. If the reader stopped
    // pulling once the cap was hit, the pipe would fill and this command would reach its
    // deadline for the wrong reason — reported as a timeout rather than as truncation.
    let script = "i=0; while [ $i -lt 20000 ]; do echo line-$i; i=$((i+1)); done";

    let mut inv = SpawnInvocation::new("/bin/sh", script).with_args(&["-s"]);
    inv.env = base_env();
    inv.output_cap = 512;
    inv.timeout = Some(Duration::from_secs(30));

    let out = ProcessSpawnRunner::new().spawn(inv).await.unwrap();

    assert_eq!(
        out.exit_code,
        Some(0),
        "a capped read must not fail the command"
    );
    assert!(out.truncated, "512 bytes cannot hold 20000 lines");
    assert!(
        out.stdout.len() <= 512,
        "kept {} bytes over a cap of 512",
        out.stdout.len()
    );
    assert_eq!(out.stderr.len(), 0);
}

#[tokio::test]
async fn a_deadline_kills_the_process_and_keeps_what_it_already_printed() {
    let _process_table = own_the_process_table().await;
    let script = "echo before-the-hang\nsleep 30\necho never\n";

    let mut inv = SpawnInvocation::new("/bin/sh", script).with_args(&["-s"]);
    inv.env = base_env();
    inv.timeout = Some(Duration::from_millis(400));

    let started = Instant::now();
    let out = ProcessSpawnRunner::new().spawn(inv).await.unwrap();
    let elapsed = started.elapsed();

    assert!(out.timed_out);
    assert_eq!(
        out.exit_code, None,
        "a killed process has no exit code, and that is not 0"
    );
    assert!(!out.succeeded());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "before-the-hang\n",
        "output produced before the kill must survive it"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "waited {elapsed:?} instead of killing at the deadline"
    );
}

/// The identity prologue is prepended rather than appended *because* of this case: a
/// command killed by its deadline still has to answer "who was running this".
#[tokio::test]
async fn a_timed_out_command_still_reports_the_identity_that_ran_it() {
    let _process_table = own_the_process_table().await;
    let prepared = prepare("sleep 30", None, &base_env()).unwrap();

    let mut inv = SpawnInvocation::new("/bin/sh", prepared.text.clone()).with_args(&["-s"]);
    inv.env = base_env();
    inv.timeout = Some(Duration::from_millis(600));

    let out = ProcessSpawnRunner::new().spawn(inv).await.unwrap();
    assert!(out.timed_out, "expected a timeout");

    let (identity, _rest) = extract_identity(&out.stdout, &prepared.nonce);
    assert_eq!(
        identity.uid,
        Some(process_uid()),
        "a killed command must still prove which uid ran it; stdout was {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// The end-to-end proof for `host::script`'s quoting.
///
/// That module's unit tests only compare generated text. A path containing a single quote
/// is exactly the case where wrapping an already-quoted literal in `'...'` double-wraps it,
/// so the shell reads an empty literal followed by bare words — a `cd` into the wrong place
/// and a `printf` whose format string has been pulled apart. Only a real shell settles it.
#[tokio::test]
async fn a_working_directory_survives_a_real_shell_parser() {
    let _process_table = own_the_process_table().await;
    let dir = fixture_dir_with_a_quote();
    std::fs::create_dir_all(&dir).expect("create fixture directory");

    let prepared = prepare(
        "printf 'PWD=%s\\nUID=%s\\n' \"$(pwd -P)\" \"$(id -u)\"",
        Some(&dir),
        &base_env(),
    )
    .unwrap();

    let mut inv = SpawnInvocation::new("/bin/sh", prepared.text.clone()).with_args(&["-s"]);
    inv.env = base_env();
    let out = ProcessSpawnRunner::new().spawn(inv).await.unwrap();

    assert_eq!(
        out.exit_code,
        Some(0),
        "stderr: {}\nscript:\n{}",
        String::from_utf8_lossy(&out.stderr),
        prepared.text
    );

    let (identity, clean) = extract_identity(&out.stdout, &prepared.nonce);
    let clean = String::from_utf8(clean).unwrap();

    assert_eq!(identity.uid, Some(process_uid()));
    assert!(
        !clean.contains(&prepared.nonce),
        "the marker must be stripped, got: {clean:?}"
    );

    // macOS resolves /var -> /private/var, so compare against the canonical path rather
    // than the string we asked for.
    let want = std::fs::canonicalize(&dir).unwrap();
    assert!(
        clean.contains(&format!("PWD={}\n", want.display())),
        "the quoted path did not survive; body saw: {clean:?}"
    );
    // Independent corroboration: the body's own `id -u` agrees with the prologue.
    assert!(
        clean.contains(&format!("UID={}\n", process_uid())),
        "the identity prologue and the body disagree; body said: {clean:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

fn fixture_dir_with_a_quote() -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("acowork it's here {}", std::process::id()));
    p
}

#[tokio::test]
async fn a_missing_working_directory_is_reported_not_silently_ignored() {
    let _process_table = own_the_process_table().await;
    let missing = Path::new("/acowork-definitely-not-here");
    let prepared = prepare("echo SHOULD-NOT-RUN", Some(missing), &base_env()).unwrap();

    let mut inv = SpawnInvocation::new("/bin/sh", prepared.text.clone()).with_args(&["-s"]);
    inv.env = base_env();
    let out = ProcessSpawnRunner::new().spawn(inv).await.unwrap();

    assert_eq!(
        out.exit_code,
        Some(EX_CWD_UNAVAILABLE),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // stdout is not empty: the identity prologue runs before the `cd`, which is the point —
    // a command that could not even start still has to say who tried it. So the assertion is
    // about the *body*, once the marker is stripped.
    let (identity, clean) = extract_identity(&out.stdout, &prepared.nonce);
    assert_eq!(
        identity.uid,
        Some(process_uid()),
        "the refusal still carries an identity"
    );
    assert!(
        clean.is_empty(),
        "the body must not run when the working directory is missing, got: {:?}",
        String::from_utf8_lossy(&clean)
    );

    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        err.contains("cannot enter working directory")
            && err.contains(&missing.display().to_string()),
        "the refusal must name the directory, got: {err}"
    );
}

/// Regression for a hang that the first version of this runner had.
///
/// `sleep` inherits the shell's stdout write end and outlives the shell, so "read the pipe
/// to EOF" waits for a process that has nothing to do with the command we were asked to run.
/// The bounded drain in [`Capture`]/`settle` is what stops it; without that test the runner
/// returned after 30 s with the right bytes and the wrong duration, which is the kind of bug
/// only a real process exposes.
#[tokio::test]
async fn a_grandchild_holding_the_pipes_does_not_delay_a_finished_command() {
    let _process_table = own_the_process_table().await;
    let script = "echo out-then-orphan\nsleep 20 &\n";

    let started = Instant::now();
    let out = run(script, base_env()).await;
    let elapsed = started.elapsed();

    assert_eq!(out.exit_code, Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "out-then-orphan\n");
    assert!(
        elapsed < Duration::from_secs(5),
        "waited {elapsed:?} for a grandchild that holds the pipe open; the drain is not \
         bounded — and on a phone that orphan is also a battery cost"
    );
}

#[tokio::test]
async fn a_program_that_is_not_there_is_unavailable_not_a_failing_command() {
    let _process_table = own_the_process_table().await;
    let err = ProcessSpawnRunner::new()
        .spawn(SpawnInvocation::new("/system/bin/su", "id -u"))
        .await
        .expect_err("no `su` at this path on a build host");

    match err {
        SpawnError::Unavailable { file, reason } => {
            assert_eq!(file, "/system/bin/su");
            assert!(
                !reason.is_empty(),
                "the OS reason must be carried, not swallowed"
            );
        }
        other => {
            panic!(
                "expected Unavailable, got {other:?} — a missing privileged helper must stay \
                 distinguishable from a command that ran and failed, because the first is a \
                 fact about the device and the second is a fact about the script"
            );
        }
    }
}
