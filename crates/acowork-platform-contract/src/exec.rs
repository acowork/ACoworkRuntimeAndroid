//! The execution contract: uniform rules, port-shaped mechanisms.
//!
//! # R10 — the request shape belongs to the port
//!
//! An earlier draft of this contract carried `ExecRequest { script, cwd, env }`.
//! That is a POSIX request: it assumes a shell to interpret `script`, a filesystem
//! with directories, and a process environment. An ESP32 has none of the three — it
//! has an RPC dispatch table and a fixed firmware image.
//!
//! So the contract does not define a request. [`ExecutionBackend::Request`] is an
//! associated type and each port fills it in: Android keeps a script, a working
//! directory and an environment; a microcontroller carries a service name, a method
//! and arguments. What the contract requires instead is [`GateView`] — three
//! accessors that let the gate do its job without knowing the shape.
//!
//! This is the difference between a uniform *scheme* and uniform *rules*. Forcing
//! every platform through one request struct would have produced a lowest-common-
//! denominator type that fits nothing well. Requiring every request to *answer* the
//! same three questions produces rules that hold everywhere.
//!
//! # R11 — one mutating action at a time
//!
//! A device is a single physical thing. Two sessions writing to it concurrently is
//! not a scheduling problem, it is a correctness problem, and the platform cannot
//! fix it for us. [`ResourceLock`] serialises mutating capabilities with a TTL and
//! **no queueing and no preemption**: a second caller is told to come back, not
//! parked. Queueing would mean an unattended node silently accumulating a backlog of
//! state changes against a device nobody is watching.
//!
//! The lock is driven by a caller-supplied timestamp rather than reading a clock,
//! because `no_std` targets have no wall clock and a lock that cannot be tested
//! deterministically is a lock nobody will test.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::future::Future;
// The lock below is the only part of this crate that needs target atomics, so the
// import is gated with it. See `ResourceLock` for why, and for what a port without
// atomics is expected to do instead.
#[cfg(target_has_atomic = "ptr")]
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;

use serde::{Deserialize, Serialize};

use crate::capability::HostCapability;

/// The three things the gate must be able to read off any request, whatever its
/// shape (R10).
///
/// A port implements this on its own request type. Nothing else about the request is
/// visible to the contract.
pub trait GateView {
    /// Which capability this invocation exercises. Drives every axis lookup.
    fn capability(&self) -> &HostCapability;

    /// The resource budget for this invocation.
    fn budget(&self) -> &Budget;

    /// How to undo it, when the capability is irreversible (R8).
    ///
    /// `None` is correct for reversible capabilities and is *rejected* for
    /// irreversible ones — the gate makes that call from the capability spec, so a
    /// port cannot forget it.
    fn rollback_plan(&self) -> Option<&str> {
        None
    }
}

/// Resource limits for one invocation.
///
/// Both fields are mandatory in practice: an unbounded timeout on an unattended node
/// is a hang, and an unbounded output cap is an OOM. The contract does not pick the
/// numbers — a phone and a microcontroller differ by orders of magnitude — but it
/// does require that there *are* numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    /// Wall-clock limit. `None` means "no limit", which a port should only use for
    /// provably bounded calls.
    pub timeout: Option<Duration>,
    /// Maximum bytes of combined output to retain. Output beyond this is dropped and
    /// [`ExecOutput::truncated`] is set, so a chatty command cannot exhaust memory.
    pub output_cap: usize,
}

impl Budget {
    /// A budget with no limits. Intended for tests and for provably bounded calls;
    /// a production port should state real numbers.
    pub fn unbounded() -> Budget {
        Budget {
            timeout: None,
            output_cap: usize::MAX,
        }
    }
}

/// How an invocation ended.
///
/// Deliberately not POSIX. There is no `Signal` variant, because signals are a Unix
/// concept; "the platform stopped it early" is the general idea and is what
/// [`ExitStatus::Terminated`] means, whether the cause was `SIGKILL`, a watchdog
/// reset or a radio timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExitStatus {
    /// A numeric completion code. A POSIX exit status on Android; an RPC result code
    /// on a microcontroller.
    Code(i32),
    /// The platform stopped the invocation before it completed.
    Terminated,
    /// This platform has no notion of a completion code.
    NotApplicable,
}

impl ExitStatus {
    /// True when the invocation ran to completion and reported success.
    ///
    /// `NotApplicable` counts as success: a platform without completion codes
    /// signals failure by returning [`ExecutionError`] instead.
    pub fn is_success(&self) -> bool {
        matches!(self, ExitStatus::Code(0) | ExitStatus::NotApplicable)
    }
}

/// One captured output stream.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ExecOutput {
    /// The retained bytes. Not assumed to be UTF-8: a shell's stdout can be binary
    /// and a radio's payload certainly is.
    pub bytes: Vec<u8>,
    /// True when [`Budget::output_cap`] cut this stream short.
    pub truncated: bool,
}

impl ExecOutput {
    /// The output as text, lossily. Convenience for ports whose output is textual.
    pub fn as_text(&self) -> alloc::string::String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }

    /// Append bytes, honouring the cap.
    ///
    /// Returns the number of bytes actually retained. A port calls this from its
    /// reader loop; the cap is enforced here rather than in each port so that no port
    /// can forget it.
    pub fn push(&mut self, chunk: &[u8], cap: usize) -> usize {
        let room = cap.saturating_sub(self.bytes.len());
        let take = room.min(chunk.len());
        self.bytes.extend_from_slice(&chunk[..take]);
        if take < chunk.len() {
            self.truncated = true;
        }
        take
    }
}

/// Why an invocation could not be carried out.
///
/// Distinct from a non-zero [`ExitStatus`]: this is the backend failing to run the
/// thing at all, not the thing failing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionError {
    /// The budget's timeout elapsed.
    TimedOut,
    /// The capability is not declared on this device, so there is no way to run it.
    CapabilityUnavailable(HostCapability),
    /// The backend itself could not be reached: helper missing, transport down.
    BackendUnavailable(String),
    /// The platform refused to start the invocation.
    Rejected(String),
}

impl core::fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The wording lives here, not inside `ExecOutcome::failed`, for two reasons. R9
        // requires a refusal to name the missing condition *and* the next step, and a port
        // that constructs `Err(error)` directly — keeping the partial output it did get —
        // would otherwise have no way to produce that text at all. And `failed` is not the
        // only path: the same reason has to read the same way wherever it surfaces.
        match self {
            // No next step is offered because there is none on the device: the caller's
            // options are to raise the budget or to stop the command, both of which are its
            // decision rather than this crate's.
            ExecutionError::TimedOut => f.write_str(
                "the invocation exceeded its time budget; the partial output is whatever the \
                 command managed before it was killed",
            ),
            // Not an identifier leak: the capability ID is already in the reported summary,
            // so the model is allowed to see it.
            ExecutionError::CapabilityUnavailable(cap) => f.write_fmt(format_args!(
                "capability `{cap}` is not available on this device; re-probe the host or pick \
                 a tool that does not need it",
            )),
            ExecutionError::BackendUnavailable(what) => {
                f.write_fmt(format_args!("execution backend unavailable: {what}"))
            }
            ExecutionError::Rejected(why) => {
                f.write_fmt(format_args!("the device refused this invocation: {why}"))
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ExecutionError {}

/// The result of one invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecOutcome {
    /// How it ended, or why it could not be run.
    pub result: Result<ExitStatus, ExecutionError>,
    /// Captured standard output, or the port's equivalent success channel.
    pub stdout: ExecOutput,
    /// Captured standard error, or the port's equivalent diagnostic channel.
    pub stderr: ExecOutput,
}

impl ExecOutcome {
    /// An outcome for a backend-level failure, with the reason as stderr text so the
    /// model sees something actionable (R9).
    pub fn failed(error: ExecutionError) -> ExecOutcome {
        let message = error.to_string();
        ExecOutcome {
            result: Err(error),
            stdout: ExecOutput::default(),
            stderr: ExecOutput {
                bytes: message.into_bytes(),
                truncated: false,
            },
        }
    }

    /// True when the invocation ran and reported success.
    pub fn succeeded(&self) -> bool {
        self.result.as_ref().is_ok_and(ExitStatus::is_success)
    }
}

/// What a platform port must provide to run things.
///
/// The associated `Request` type is the point (R10): the contract never sees its
/// fields, only its [`GateView`] answers. `ExecuteFuture` is an associated type
/// rather than a boxed trait object for the same reason — a multi-threaded host binds
/// it to a `Send` future, a single-threaded target does not have to, and neither is
/// forced to pay for the other's constraint.
pub trait ExecutionBackend {
    /// The port's own request shape.
    type Request: GateView;

    /// The port's own future type.
    type ExecuteFuture<'a>: Future<Output = ExecOutcome>
    where
        Self: 'a;

    /// Run one invocation.
    ///
    /// Implementations may assume the gate has already run; the contract's
    /// [`crate::gate`] is what calls this, and it does not call it on a refusal.
    fn execute(&self, request: Self::Request) -> Self::ExecuteFuture<'_>;
}

/// Outcome of a lock attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockOutcome {
    /// The caller holds the lock and must release it.
    Acquired,
    /// Someone else holds it. No queueing, no preemption (R11).
    Busy {
        /// How long the current holder has had it.
        held_for: Duration,
        /// How long until the TTL expires it, if the holder never releases.
        retry_after: Duration,
    },
}

/// A single-flight lock over the device's mutating capabilities.
///
/// Lock-free and clock-free: the caller passes `now`, so the same code runs on a
/// phone with a wall clock and on a target with only a tick counter, and tests can
/// move time by hand.
///
/// Held state is one atomic timestamp in milliseconds, `0` meaning free. A TTL is
/// required because an unattended node whose session died mid-write would otherwise
/// wedge the device permanently — and "permanently" on a device nobody is looking at
/// means until someone reboots it.
///
/// The timestamp is a `usize`, not a `u64`, because 32-bit targets — including the
/// ESP32-class boards this contract exists to admit — have no 64-bit atomic. That
/// makes the counter wrap (every ~49.7 days at millisecond resolution on a 32-bit
/// `usize`), so every comparison here goes through [`elapsed_since`], which uses
/// wrapping subtraction. Elapsed time stays correct across one wrap as long as it is
/// much shorter than the wrap period; a TTL measured in minutes satisfies that by
/// four orders of magnitude. On a 64-bit target the wrap is unreachable and the
/// arithmetic degenerates to ordinary subtraction.
///
/// # Availability
///
/// Gated on `target_has_atomic = "ptr"`: the compare-exchange in [`Self::try_acquire`]
/// is what makes two racing callers unable to both believe they won, and a target with
/// no atomics cannot express it. Such targets do exist — `riscv32imc-unknown-none-elf`
/// has no `a` extension, so `max_atomic_width` is 0 and this type does not compile
/// there.
///
/// That is a limitation of the *implementation*, not of R11. A target without atomics
/// is in practice a single-core target without preemptive threading, where mutual
/// exclusion is either trivial or belongs in a critical section the port already has.
/// Such a port still owes the R11 semantics — one mutating action at a time, no
/// queueing, no preemption, a TTL so a dead session cannot wedge the device — and
/// supplies its own mechanism. The contract states the rule; it does not claim that
/// this particular lock-free encoding is the only way to satisfy it.
#[cfg(target_has_atomic = "ptr")]
#[derive(Debug)]
pub struct ResourceLock {
    ttl: Duration,
    /// Acquisition time in ms since the caller's epoch, plus one; `0` means free.
    held_since_ms: AtomicUsize,
}

/// The sentinel for "not held".
///
/// A real acquisition is stored as `now_ms + 1`, so a timestamp of exactly zero is
/// unambiguous and the offset costs nothing but one `wrapping_sub` on read. Storing
/// the raw timestamp instead would make "acquired at t=0" indistinguishable from
/// "free", which is not a hypothetical: every test in this module starts at zero, and
/// so does a target whose clock begins at boot.
#[cfg(target_has_atomic = "ptr")]
const FREE: usize = 0;

/// Elapsed time between a stored acquisition and `now`.
///
/// Wrapping, not saturating: on a 32-bit target the caller's millisecond counter can
/// roll over while the lock is held, and saturating subtraction would report the hold
/// as zero-length — which would make it look expired and hand the lock to a second
/// writer. `held` must not be [`FREE`].
#[cfg(target_has_atomic = "ptr")]
fn elapsed_since(held: usize, now: Duration) -> Duration {
    let held_ms = held.wrapping_sub(1);
    let now_ms = now.as_millis() as usize;
    Duration::from_millis(now_ms.wrapping_sub(held_ms) as u64)
}

/// Encode an acquisition time for storage.
///
/// The `+1` offset is what makes [`FREE`] unambiguous, but it aliases exactly one
/// input — a counter reading of `usize::MAX` — back onto the sentinel. That case is
/// mapped to the largest representable hold instead. It then reads back one
/// millisecond earlier than the truth, which is benign; reading back as `FREE` would
/// admit a second writer, which is the one thing R11 forbids. The failure mode is
/// deliberately chosen to be "stays locked", never "opens".
///
/// On a 64-bit target the aliased instant is unreachable in practice. On a 32-bit one
/// it occurs for a single millisecond every ~49.7 days — rare, but a lock that fails
/// once a month on a device nobody is watching is not a lock.
#[cfg(target_has_atomic = "ptr")]
fn stored_for(now: Duration) -> usize {
    match (now.as_millis() as usize).wrapping_add(1) {
        FREE => usize::MAX,
        stored => stored,
    }
}

#[cfg(target_has_atomic = "ptr")]
impl ResourceLock {
    /// A lock whose hold expires after `ttl`.
    pub fn new(ttl: Duration) -> ResourceLock {
        ResourceLock {
            ttl,
            held_since_ms: AtomicUsize::new(FREE),
        }
    }

    /// The configured TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Try to take the lock at time `now`.
    ///
    /// On success the hold is identified by `now` itself: that is the value [`renew`] and
    /// [`release`] need back, and a port that discards it has no way to tell its own hold
    /// from one that replaced it after a TTL expiry.
    ///
    /// [`renew`]: ResourceLock::renew
    /// [`release`]: ResourceLock::release
    ///
    /// Three outcomes, and only three:
    /// - free → take it;
    /// - held within its TTL → [`LockOutcome::Busy`]. **No queueing, no preemption**
    ///   (R11): a live holder is never displaced, because two concurrent writers to
    ///   one physical device is a correctness bug the platform cannot fix for us;
    /// - held past its TTL → reclaim it. The previous holder is presumed dead, which
    ///   is the only assumption that stops a crashed session from wedging a device
    ///   nobody is watching.
    ///
    /// Implemented as a compare-exchange loop rather than a load-then-store: two
    /// callers racing must not both believe they won. Each retry means another caller
    /// changed the state, so the loop is lock-free — it always makes system-wide
    /// progress even though an individual caller may spin.
    pub fn try_acquire(&self, now: Duration) -> LockOutcome {
        let now_ms = stored_for(now);
        loop {
            let held = self.held_since_ms.load(Ordering::Acquire);

            if held == FREE {
                return match self.held_since_ms.compare_exchange(
                    FREE,
                    now_ms,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => LockOutcome::Acquired,
                    // Lost the race to another taker; re-read and take the Busy path.
                    Err(_) => continue,
                };
            }

            if !self.is_expired(held, now) {
                let held_for = elapsed_since(held, now);
                return LockOutcome::Busy {
                    held_for,
                    retry_after: self.ttl.saturating_sub(held_for),
                };
            }

            // Expired. Reclaim only if the value is still the one we read: if another
            // caller got there first, loop and report Busy against *their* hold.
            return match self.held_since_ms.compare_exchange(
                held,
                now_ms,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => LockOutcome::Acquired,
                Err(_) => continue,
            };
        }
    }

    /// Extend *this* hold, identified by the instant it was taken.
    ///
    /// Renewal is required by R11's own wording — a mutating command refreshes the TTL
    /// rather than reacquiring — and without a primitive for it a port has to improvise with
    /// `release()` followed by `try_acquire()`, which is how a stale holder ends up freeing
    /// whoever legitimately reclaimed the lock after it expired. This does not: the expected
    /// value is our own acquisition instant, so the compare-exchange fails the moment another
    /// caller's hold is standing.
    ///
    /// Renewal is **not** acquisition. A hold past its TTL is dead, and reviving it here would
    /// let a caller that stalled for longer than the TTL keep a device it was presumed to have
    /// stopped using. `false` means "you are not the holder any more"; the caller goes back
    /// through [`try_acquire`](ResourceLock::try_acquire), which is where the reclaim rule
    /// lives and where another caller's live hold is respected.
    ///
    /// Why the caller passes `at` at all: the lock carries no identity, because "session" is a
    /// port concept and R11 states a platform-neutral rule. The acquisition instant is the only
    /// thing that distinguishes our hold from whoever took it after we expired. It is not a
    /// unique token — two acquisitions at the same instant are the same hold — which is sound
    /// except when the TTL is zero, where every caller reclaims immediately and mutual
    /// exclusion was vacuous anyway.
    pub fn renew(&self, at: Duration, now: Duration) -> bool {
        let expected = stored_for(at);
        if expected == FREE || self.is_expired(expected, now) {
            return false;
        }
        self.held_since_ms
            .compare_exchange(
                expected,
                stored_for(now),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Release, if the hold still standing is the one taken at `at`. Returns whether it was.
    ///
    /// The unconditional store this replaced was documented as meaning "releasing something
    /// you no longer hold must not free someone else's lock" and did the opposite: a session
    /// whose TTL had passed, whose lock had meanwhile been reclaimed, could call `release()`
    /// on teardown and free the *new* holder's lock — two writers on one device, the one
    /// outcome R11 exists to prevent. The guarantee now lives in the code rather than in the
    /// sentence about it.
    ///
    /// Releasing a lock you never took returns `false` and changes nothing, so a double
    /// release is still harmless.
    pub fn release(&self, at: Duration) -> bool {
        self.held_since_ms
            .compare_exchange(stored_for(at), FREE, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Who holds the lock at time `now`, and for how long.
    pub fn holder(&self, now: Duration) -> Option<Duration> {
        let held = self.held_since_ms.load(Ordering::Acquire);
        if held == FREE || self.is_expired(held, now) {
            return None;
        }
        Some(elapsed_since(held, now))
    }

    /// True when nothing is held at `now`.
    pub fn is_free(&self, now: Duration) -> bool {
        self.holder(now).is_none()
    }

    /// True when a hold has outlived the TTL. Only meaningful for a non-`FREE` value.
    fn is_expired(&self, held: usize, now: Duration) -> bool {
        elapsed_since(held, now) >= self.ttl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn output_cap_is_enforced_and_truncation_is_reported() {
        let mut out = ExecOutput::default();
        assert_eq!(out.push(b"hello", 8), 5);
        assert!(!out.truncated);
        assert_eq!(out.push(b"world", 8), 3);
        assert!(
            out.truncated,
            "the caller must be able to tell output was cut"
        );
        assert_eq!(out.bytes, b"hellowor");
        // Once at the cap, nothing more is retained.
        assert_eq!(out.push(b"!", 8), 0);
        assert_eq!(out.bytes.len(), 8);
    }

    #[test]
    fn output_is_not_assumed_to_be_utf8() {
        let mut out = ExecOutput::default();
        out.push(&[0xff, 0xfe, 0x00], 16);
        assert_eq!(out.bytes, vec![0xff, 0xfe, 0x00]);
        // Lossy conversion must not panic on invalid UTF-8.
        assert!(!out.as_text().is_empty());
    }

    #[test]
    fn exit_status_success_covers_platforms_without_codes() {
        assert!(ExitStatus::Code(0).is_success());
        assert!(!ExitStatus::Code(1).is_success());
        assert!(!ExitStatus::Terminated.is_success());
        assert!(
            ExitStatus::NotApplicable.is_success(),
            "a platform with no completion codes signals failure via ExecutionError"
        );
    }

    #[test]
    fn a_failed_outcome_carries_an_actionable_message() {
        // R9: the model gets a reason, not a bare error.
        let cap = HostCapability::parse("android:shell:write").unwrap();
        let out = ExecOutcome::failed(ExecutionError::CapabilityUnavailable(cap));
        assert!(!out.succeeded());
        assert!(out.stderr.as_text().contains("android:shell:write"));
        assert!(out.stderr.as_text().contains("not available"));

        let out = ExecOutcome::failed(ExecutionError::TimedOut);
        assert!(out.stderr.as_text().contains("time budget"));
    }

    #[test]
    fn every_execution_error_reads_as_a_reason_and_a_next_step() {
        // R9 applied to the whole enum rather than to the two variants `failed` happened to
        // be tested with. The discipline is the one that found the `AttributionDenied` gap on
        // the Android side: iterate the variants, assert each one names what is missing *and*
        // what to do, and assert none of them degenerates to a bare discriminant.
        let cap = HostCapability::parse("esp32:gpio:write").unwrap();
        let cases = [
            (
                ExecutionError::TimedOut.to_string(),
                "time budget",
                "partial output",
            ),
            (
                ExecutionError::CapabilityUnavailable(cap).to_string(),
                "esp32:gpio:write",
                "re-probe",
            ),
            (
                ExecutionError::BackendUnavailable("no su binary".into()).to_string(),
                "no su binary",
                "backend unavailable",
            ),
            (
                ExecutionError::Rejected("approval missing".into()).to_string(),
                "approval missing",
                "refused",
            ),
        ];
        for (text, reason, next_step) in cases {
            assert!(text.contains(reason), "reason missing from: {text}");
            assert!(text.contains(next_step), "no {next_step:?} in: {text}");
            assert!(
                !text.starts_with("ExecutionError::"),
                "rendered as a debug discriminant, which is actionable for nobody: {text}"
            );
        }
    }

    // Everything below exercises `ResourceLock`, which exists only where the target
    // has atomics. The nested module keeps one gate instead of nine.
    #[cfg(target_has_atomic = "ptr")]
    mod resource_lock {
        use super::*;

        #[test]
        fn lock_is_single_flight() {
            let lock = ResourceLock::new(secs(600));
            assert_eq!(lock.try_acquire(secs(0)), LockOutcome::Acquired);
            assert!(matches!(
                lock.try_acquire(secs(1)),
                LockOutcome::Busy { .. }
            ));
            assert_eq!(lock.holder(secs(1)), Some(secs(1)));
        }

        #[test]
        fn lock_releases() {
            let lock = ResourceLock::new(secs(600));
            lock.try_acquire(secs(0));
            assert!(lock.release(secs(0)));
            assert!(lock.is_free(secs(1)));
            assert_eq!(lock.try_acquire(secs(1)), LockOutcome::Acquired);
        }

        #[test]
        fn release_is_idempotent() {
            let lock = ResourceLock::new(secs(600));
            assert!(!lock.release(secs(0)), "never taken at 0");
            lock.try_acquire(secs(3));
            assert!(
                !lock.release(secs(0)),
                "releasing a hold that is not ours must not free it"
            );
            assert!(lock.release(secs(3)));
            assert!(lock.is_free(secs(0)));
        }

        #[test]
        fn renew_extends_a_live_hold() {
            // R11's "a mutating command refreshes the hold" needs a primitive, because the
            // alternative — release then re-acquire — opens the device for the width of two
            // statements and frees it for whoever is holding it by then.
            let lock = ResourceLock::new(secs(100));
            assert_eq!(lock.try_acquire(secs(0)), LockOutcome::Acquired);
            assert!(
                lock.renew(secs(0), secs(60)),
                "the holder may extend its own hold"
            );
            // The hold now runs to 160, not to 100: measured from the renewal, not from the
            // original acquisition.
            assert_eq!(
                lock.try_acquire(secs(90)),
                LockOutcome::Busy {
                    held_for: secs(30),
                    retry_after: secs(70),
                },
                "a renewal that did not move the deadline would not be worth this API"
            );
        }

        #[test]
        fn a_renewal_does_not_resurrect_an_expired_hold() {
            // Renewal is not acquisition. A caller that stalled past the TTL was presumed dead;
            // letting it revive its own hold by touching it would make the TTL a suggestion and
            // the reclaim rule decorative.
            let lock = ResourceLock::new(secs(100));
            assert_eq!(lock.try_acquire(secs(0)), LockOutcome::Acquired);
            assert!(
                !lock.renew(secs(0), secs(150)),
                "expired: not ours to extend"
            );
            assert_eq!(
                lock.try_acquire(secs(150)),
                LockOutcome::Acquired,
                "the way back is the ordinary reclaim, which is also how a new caller wins"
            );
        }

        #[test]
        fn a_stale_holder_cannot_touch_a_live_one() {
            // The steal, pinned without threads. A expires, B legitimately reclaims, and A
            // comes back believing it still holds. Neither renewal nor release may act on B's
            // hold: the acquisition instant is the only identity this lock has, and it no
            // longer matches.
            let lock = ResourceLock::new(secs(100));
            assert_eq!(lock.try_acquire(secs(0)), LockOutcome::Acquired);
            assert_eq!(
                lock.try_acquire(secs(200)),
                LockOutcome::Acquired,
                "B reclaims a hold presumed dead"
            );
            assert!(
                !lock.renew(secs(0), secs(210)),
                "A's instant is not standing"
            );
            assert!(
                !lock.release(secs(0)),
                "and A's release must not free B — the guarantee the old unconditional store \
                 documented and did not provide"
            );
            assert_eq!(lock.holder(secs(210)), Some(secs(10)), "B still holds");
            assert!(lock.release(secs(200)), "B may release its own");
        }

        #[test]
        fn an_expired_hold_is_reclaimed() {
            // R11: a session that died mid-write must not wedge the device forever.
            let lock = ResourceLock::new(secs(600));
            assert_eq!(lock.try_acquire(secs(0)), LockOutcome::Acquired);
            assert!(
                lock.is_free(secs(601)),
                "past the TTL the hold is presumed dead"
            );
            assert_eq!(lock.try_acquire(secs(601)), LockOutcome::Acquired);
        }

        #[test]
        fn a_hold_within_ttl_is_not_reclaimed() {
            let lock = ResourceLock::new(secs(600));
            lock.try_acquire(secs(0));
            assert!(matches!(
                lock.try_acquire(secs(599)),
                LockOutcome::Busy { .. }
            ));
        }

        #[test]
        fn busy_reports_how_long_to_wait() {
            // No queueing: the caller is told to come back, not parked.
            let lock = ResourceLock::new(secs(600));
            lock.try_acquire(secs(0));
            match lock.try_acquire(secs(100)) {
                LockOutcome::Busy {
                    held_for,
                    retry_after,
                } => {
                    assert_eq!(held_for, secs(100));
                    assert_eq!(retry_after, secs(500));
                }
                other => panic!("expected Busy, got {other:?}"),
            }
        }

        #[test]
        fn concurrent_acquisition_admits_exactly_one_holder() {
            // The compare-exchange, not a load-then-store, is what makes this hold.
            use std::sync::Arc;
            use std::thread;

            let lock = Arc::new(ResourceLock::new(secs(600)));
            let winners = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();
            for _ in 0..16 {
                let lock = Arc::clone(&lock);
                let winners = Arc::clone(&winners);
                handles.push(thread::spawn(move || {
                    if lock.try_acquire(secs(0)) == LockOutcome::Acquired {
                        winners.fetch_add(1, Ordering::SeqCst);
                    }
                }));
            }
            for h in handles {
                h.join().unwrap();
            }
            assert_eq!(winners.load(Ordering::SeqCst), 1);
        }

        #[test]
        fn acquisition_at_the_counter_maximum_still_locks() {
            // Regression: the `+1` offset aliases `usize::MAX` onto the `FREE` sentinel.
            // Before `stored_for` handled it, an acquisition on that one millisecond stored
            // "not held" and the next caller walked straight in — two writers on one device,
            // which is the exact failure R11 exists to prevent. On a 32-bit target that
            // millisecond comes around every ~49.7 days.
            let at_max = Duration::from_millis(usize::MAX as u64);
            let lock = ResourceLock::new(secs(600));

            assert_eq!(lock.try_acquire(at_max), LockOutcome::Acquired);
            // The point of the test: still held, so a second taker is refused.
            assert!(matches!(lock.try_acquire(at_max), LockOutcome::Busy { .. }));
            assert!(lock.holder(at_max).is_some());
            assert!(!lock.is_free(at_max));
        }

        #[test]
        fn elapsed_time_survives_a_counter_wrap() {
            // A hold that spans the counter's wrap boundary must not read as zero-length
            // (which would look expired) or as enormous (which would wedge the device).
            // Wrapping subtraction gets it right; saturating subtraction got it wrong.
            let before = usize::MAX - 500; // 500 ms short of the wrap
            let lock = ResourceLock::new(secs(600));
            assert_eq!(
                lock.try_acquire(Duration::from_millis(before as u64)),
                LockOutcome::Acquired
            );

            // 60 s later, i.e. past the wrap.
            let after = before.wrapping_add(60_000);
            assert!(
                after < before,
                "test premise: the counter must have wrapped"
            );

            match lock.try_acquire(Duration::from_millis(after as u64)) {
                LockOutcome::Busy {
                    held_for,
                    retry_after,
                } => {
                    assert_eq!(held_for, Duration::from_secs(60));
                    assert_eq!(retry_after, secs(600) - Duration::from_secs(60));
                }
                other => panic!("a live hold must not be reclaimed across a wrap: {other:?}"),
            }
            assert_eq!(
                lock.holder(Duration::from_millis(after as u64)),
                Some(Duration::from_secs(60))
            );
        }
    }

    #[test]
    fn budget_unbounded_is_explicit() {
        let b = Budget::unbounded();
        assert_eq!(b.timeout, None);
        assert_eq!(b.output_cap, usize::MAX);
    }
}
