//! Per-node serial install scheduler.
//!
//! This is the reusable middleware between the install data model
//! ([`super`]) and whichever host executes the install: the Node's
//! install gate today, the Gateway's coordinator next. It owns three
//! responsibilities and nothing else:
//!
//! 1. **Serialization** — at most one ticket is in flight. This is a
//!    structural property, not a convention: [`InstallScheduler::take_next`]
//!    refuses to hand out work while a ticket is running.
//! 2. **Instance identity** — a job is identified by the `instance_id`
//!    it will create; re-submitting that id is the same install and is
//!    merged into the accepted job, so no two jobs can ever target the
//!    same landing directory.
//! 3. **Ordering** — tickets dequeue in admission order (plain FIFO).
//!
//! Deliberately *not* here: package-level uniqueness. Two different
//! instance ids for the same `agent_id` are both admitted and both run
//! (ADR-073 multi-instance is a legal state). The only package-scoped
//! question this module answers is the [`InstallKind::Ensure`]
//! existence precondition, and it is answered by the host at execution
//! time — not by the queue's identity rule.
//!
//! The scheduler is synchronous and I/O-free so it can be unit-tested
//! without a runtime or a filesystem; the host drives
//! `take_next()` → execute → `finish()`.

use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

use super::{InstallKind, InstallOutcome, InstallPhase, InstallRequest, InstallTicket};
use crate::agent_instance_id::AgentInstanceId;
use crate::operation::OperationId;

/// Completion handle shared by a queued install and every caller that
/// was coalesced into it.
///
/// Held by the scheduler entry; clones are handed to waiters so a
/// duplicate request observes the *same* terminal result as the
/// original instead of starting a second install.
#[derive(Debug, Default)]
pub struct InstallCompletion {
    state: Mutex<Option<InstallOutcome>>,
    notify: Notify,
}

impl InstallCompletion {
    /// A handle that is not yet resolved.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A handle that is already resolved (used for no-op paths).
    pub fn completed(outcome: InstallOutcome) -> Arc<Self> {
        let handle = Self::default();
        *handle.state.lock().expect("completion mutex poisoned") = Some(outcome);
        Arc::new(handle)
    }

    /// Record the terminal outcome. Late waiters observe it
    /// immediately; the first outcome wins (terminal states are sticky,
    /// mirroring `OperationStore`).
    pub fn complete(&self, outcome: InstallOutcome) {
        {
            let mut state = self.state.lock().expect("completion mutex poisoned");
            if state.is_some() {
                return;
            }
            *state = Some(outcome);
        }
        self.notify.notify_waiters();
    }

    /// The outcome if it has already been recorded.
    pub fn outcome(&self) -> Option<InstallOutcome> {
        self.state.lock().expect("completion mutex poisoned").clone()
    }

    /// Wait until the install reaches a terminal state.
    pub async fn wait(&self) -> InstallOutcome {
        loop {
            // Register before re-checking so a `complete()` racing this
            // loop cannot be lost between the check and the await.
            let notified = self.notify.notified();
            if let Some(outcome) = self.outcome() {
                return outcome;
            }
            notified.await;
        }
    }
}

/// Result of admitting a request into the queue.
#[derive(Debug)]
pub enum AdmitOutcome {
    /// A new queue slot was created; nothing has executed yet.
    Accepted {
        /// Snapshot with [`InstallPhase::Queued`].
        ticket: InstallTicket,
        /// Handle resolving when the job reaches a terminal state.
        completion: Arc<InstallCompletion>,
    },
    /// This instance is already queued or running — the request was
    /// merged into that job and no second install will start.
    Coalesced {
        /// Snapshot of the job this request was merged into.
        ticket: InstallTicket,
        /// That job's completion handle.
        completion: Arc<InstallCompletion>,
    },
    /// A declarative request whose precondition already held; nothing
    /// was queued.
    AlreadySatisfied {
        /// The instance that already satisfies the request.
        instance_id: AgentInstanceId,
    },
}

impl AdmitOutcome {
    /// Operation id this request resolves through (the merged job's id
    /// for a coalesced request).
    pub fn operation_id(&self) -> Option<&OperationId> {
        match self {
            Self::Accepted { ticket, .. } | Self::Coalesced { ticket, .. } => {
                Some(&ticket.operation_id)
            }
            Self::AlreadySatisfied { .. } => None,
        }
    }

    /// ADR-073 instance identity this request resolves to.
    pub fn instance_id(&self) -> &AgentInstanceId {
        match self {
            Self::Accepted { ticket, .. } | Self::Coalesced { ticket, .. } => &ticket.instance_id,
            Self::AlreadySatisfied { instance_id } => instance_id,
        }
    }

    /// The queue snapshot this request resolved to, when a job exists.
    pub fn ticket(&self) -> Option<&InstallTicket> {
        match self {
            Self::Accepted { ticket, .. } | Self::Coalesced { ticket, .. } => Some(ticket),
            Self::AlreadySatisfied { .. } => None,
        }
    }

    /// Whether the request was merged into an already-accepted job.
    pub fn is_coalesced(&self) -> bool {
        matches!(self, Self::Coalesced { .. })
    }

    /// Whether a queue slot was created.
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    /// The completion handle, for callers that need to await the result.
    pub fn completion(&self) -> Option<&Arc<InstallCompletion>> {
        match self {
            Self::Accepted { completion, .. } | Self::Coalesced { completion, .. } => {
                Some(completion)
            }
            Self::AlreadySatisfied { .. } => None,
        }
    }
}

/// One queued installation.
///
/// The job's identity is the instance it will create — see
/// [`InstallScheduler::admit`].
#[derive(Debug)]
struct Entry {
    seq: u64,
    request: InstallRequest,
    completion: Arc<InstallCompletion>,
}

impl Entry {
    fn ticket(&self, phase: InstallPhase) -> InstallTicket {
        InstallTicket {
            operation_id: self.request.operation_id.clone(),
            agent_id: self.request.agent_id.clone(),
            instance_id: self.request.instance_id.clone(),
            kind: self.request.kind,
            source: self.request.source.clone(),
            dev_mode: self.request.dev_mode,
            phase,
        }
    }
}

/// Serial install queue for **one node**.
///
/// Scope is per node on purpose: a device installs one package at a
/// time (the Android `PackageManagerService` model), so hosts holding
/// several nodes keep one scheduler per node rather than a global lock.
#[derive(Debug, Default)]
pub struct InstallScheduler {
    /// Admission order; used as the FIFO tiebreak within a lane.
    next_seq: u64,
    /// Queued, not yet handed out. Scanned linearly: the queue depth is
    /// bounded by how many installs a single device can be asked to do
    /// at once (a handful), so a scan is cheaper to read and maintain
    /// than a heap plus the index bookkeeping a removal needs.
    pending: Vec<Entry>,
    /// The single running job, if any.
    inflight: Option<Entry>,
}

impl InstallScheduler {
    /// An idle scheduler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit a request, applying the identity rule.
    ///
    /// Admission never executes anything and never inspects the
    /// filesystem: it decides *whether a new job is needed*, which is
    /// the check that must be atomic with queue insertion.
    ///
    /// A job is identified by the instance it will create, so this is
    /// the only deduplication rule:
    ///
    /// - same `instance_id` already queued or running → the request is
    ///   the same install (replay / retry / a second caller); it is
    ///   merged and no second job, and therefore no second write to the
    ///   landing directory, can happen;
    /// - different `instance_id` → a new job, **even for the same
    ///   package** (ADR-073 multi-instance is legal);
    /// - `Ensure` whose existence precondition already holds → no job.
    pub fn admit(&mut self, request: InstallRequest) -> AdmitOutcome {
        // 1. The same instance is already accepted → merge into it.
        //    Checked before the "already installed" shortcut so a
        //    duplicate caller lands on the live job (and thus on its
        //    result) rather than on a stale snapshot.
        if let Some(entry) = self.find(&request.instance_id) {
            return AdmitOutcome::Coalesced {
                ticket: entry.ticket(entry_phase(&self.inflight, entry)),
                completion: entry.completion.clone(),
            };
        }

        // 2. Declarative request whose precondition already holds → no
        //    job at all. Explicit installs skip this: "it exists" is
        //    not a reason to refuse another copy (ADR-073).
        if request.kind == InstallKind::Ensure
            && let Some(existing) = request.already_installed.clone()
        {
            return AdmitOutcome::AlreadySatisfied {
                instance_id: existing,
            };
        }

        // 3. New job.
        let entry = Entry {
            seq: self.next_seq,
            request,
            completion: InstallCompletion::new(),
        };
        self.next_seq += 1;
        let ticket = entry.ticket(InstallPhase::Queued);
        let completion = entry.completion.clone();
        self.pending.push(entry);
        AdmitOutcome::Accepted { ticket, completion }
    }

    /// Take the next ticket, or `None` when the queue is empty **or a
    /// ticket is already in flight**.
    ///
    /// The second condition is the serialization invariant: a host that
    /// respects this API cannot run two installs concurrently for the
    /// same node, even if it calls `take_next()` in a loop.
    pub fn take_next(&mut self) -> Option<InstallTicket> {
        if self.inflight.is_some() {
            return None;
        }
        let idx = self
            .pending
            .iter()
            .enumerate()
            .min_by_key(|(_, entry)| entry.seq)
            .map(|(idx, _)| idx)?;
        let entry = self.pending.swap_remove(idx);
        let ticket = entry.ticket(InstallPhase::Running);
        self.inflight = Some(entry);
        Some(ticket)
    }

    /// Resolve the in-flight ticket and free the install slot.
    ///
    /// Returns `false` when `operation_id` is not the running ticket —
    /// a stale or foreign completion must not release the slot held by
    /// a different job.
    pub fn finish(&mut self, operation_id: &OperationId, outcome: InstallOutcome) -> bool {
        let matches = self
            .inflight
            .as_ref()
            .is_some_and(|entry| &entry.request.operation_id == operation_id);
        if !matches {
            return false;
        }
        let entry = self.inflight.take().expect("checked above");
        entry.completion.complete(outcome);
        true
    }

    /// The running ticket's operation id, if any.
    pub fn inflight_operation_id(&self) -> Option<&OperationId> {
        self.inflight
            .as_ref()
            .map(|entry| &entry.request.operation_id)
    }

    /// Number of queued (not yet handed out) installs.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Whether nothing is queued and nothing is running.
    pub fn is_idle(&self) -> bool {
        self.inflight.is_none() && self.pending.is_empty()
    }

    /// Whether work is available for a worker that is free to take it.
    pub fn has_work(&self) -> bool {
        self.inflight.is_none() && !self.pending.is_empty()
    }

    /// Find an accepted job (queued or running) by the instance it will
    /// create.
    fn find(&self, instance_id: &AgentInstanceId) -> Option<&Entry> {
        let matches = |entry: &Entry| &entry.request.instance_id == instance_id;
        self.pending
            .iter()
            .find(|entry| matches(entry))
            .or_else(|| self.inflight.as_ref().filter(|entry| matches(entry)))
    }
}

/// Phase reported for a coalesced snapshot: the merged job may already
/// be running, and reporting `Queued` for it would mislead the caller.
fn entry_phase(inflight: &Option<Entry>, entry: &Entry) -> InstallPhase {
    match inflight {
        Some(running) if running.seq == entry.seq => InstallPhase::Running,
        _ => InstallPhase::Queued,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::{InstallOutcome, InstallSource};

    const AGENT: &str = "com.test.agent";

    /// Payload origin shared by scheduler tests — the scheduler never
    /// interprets it, it only has to survive the trip into the ticket.
    fn test_source() -> InstallSource {
        InstallSource::registry("http://127.0.0.1:19876/pkg/com.test.agent")
    }

    fn request(kind: InstallKind, instance: AgentInstanceId) -> InstallRequest {
        let op = OperationId::new();
        match kind {
            InstallKind::Install => {
                InstallRequest::install(op, AGENT, instance, test_source())
            }
            InstallKind::Ensure => {
                InstallRequest::ensure(op, AGENT, instance, test_source())
            }
        }
    }

    /// A request for a fixed instance — i.e. a replay of an existing
    /// install, however the caller learned the instance id.
    fn same_instance_request(kind: InstallKind, instance: &AgentInstanceId) -> InstallRequest {
        request(kind, instance.clone())
    }

    fn ready(ticket: &InstallTicket) -> InstallOutcome {
        InstallOutcome::Ready {
            instance_id: ticket.instance_id.clone(),
        }
    }

    #[test]
    fn resubmitted_instance_is_coalesced_while_queued() {
        // The queue's identity rule: one job per instance, so a repeated
        // request for the same instance can never queue a second job
        // (and therefore can never race for the same landing directory).
        let mut sched = InstallScheduler::new();
        let instance = AgentInstanceId::new();
        let first = sched.admit(request(InstallKind::Ensure, instance.clone()));
        let second = sched.admit(same_instance_request(InstallKind::Ensure, &instance));

        assert!(first.is_accepted());
        assert!(second.is_coalesced());
        assert_eq!(second.operation_id(), first.operation_id());
        assert_eq!(second.instance_id(), first.instance_id());
        assert_eq!(sched.pending_len(), 1);
    }

    #[test]
    fn resubmitted_instance_is_coalesced_while_running() {
        let mut sched = InstallScheduler::new();
        let instance = AgentInstanceId::new();
        let first = sched.admit(request(InstallKind::Ensure, instance.clone()));
        let running = sched.take_next().expect("one ticket");

        let retry = sched.admit(same_instance_request(InstallKind::Ensure, &instance));
        assert!(retry.is_coalesced());
        assert_eq!(retry.operation_id(), first.operation_id());
        // A coalesced caller observes the live phase, not `Queued`.
        match retry {
            AdmitOutcome::Coalesced { ticket, .. } => {
                assert_eq!(ticket.phase, InstallPhase::Running);
                assert_eq!(ticket.operation_id, running.operation_id);
            }
            other => panic!("expected Coalesced, got {other:?}"),
        }
    }

    #[test]
    fn distinct_instances_of_one_package_are_never_merged() {
        // ADR-073: multiple instances of one package are legal. Two
        // different instance ids must produce two jobs — for `Install`
        // *and* for `Ensure`, since dedup is per instance, not per
        // package.
        for kind in [InstallKind::Install, InstallKind::Ensure] {
            let mut sched = InstallScheduler::new();
            let first = sched.admit(request(kind, AgentInstanceId::new()));
            let second = sched.admit(request(kind, AgentInstanceId::new()));

            assert!(first.is_accepted(), "{kind:?}");
            assert!(second.is_accepted(), "{kind:?}");
            assert_ne!(first.operation_id(), second.operation_id(), "{kind:?}");
            assert_ne!(first.instance_id(), second.instance_id(), "{kind:?}");
            assert_eq!(sched.pending_len(), 2, "{kind:?}");
        }
    }

    #[test]
    fn ensure_with_known_instance_is_not_queued() {
        let mut sched = InstallScheduler::new();
        let existing = AgentInstanceId::new();
        let request = request(InstallKind::Ensure, AgentInstanceId::new())
            .with_already_installed(existing.clone());

        let outcome = sched.admit(request);
        assert!(matches!(
            outcome,
            AdmitOutcome::AlreadySatisfied { ref instance_id } if instance_id == &existing
        ));
        assert_eq!(sched.pending_len(), 0);
        assert!(sched.is_idle());
    }

    #[test]
    fn explicit_install_ignores_the_installed_shortcut() {
        // "It is already installed" is not a reason to refuse another
        // copy, so the caller-provided hint must not suppress an
        // explicit install.
        let mut sched = InstallScheduler::new();
        let outcome = sched.admit(
            request(InstallKind::Install, AgentInstanceId::new())
                .with_already_installed(AgentInstanceId::new()),
        );
        assert!(outcome.is_accepted());
        assert_eq!(sched.pending_len(), 1);
    }

    #[test]
    fn only_one_ticket_is_ever_in_flight() {
        let mut sched = InstallScheduler::new();
        sched.admit(request(InstallKind::Install, AgentInstanceId::new()));
        sched.admit(request(InstallKind::Install, AgentInstanceId::new()));

        let running = sched.take_next().expect("first ticket");
        assert_eq!(sched.inflight_operation_id(), Some(&running.operation_id));
        // Serialization is structural: no second hand-out is possible.
        assert!(sched.take_next().is_none());
        assert!(!sched.has_work());

        assert!(sched.finish(&running.operation_id, ready(&running)));
        let next = sched.take_next().expect("second ticket after finish");
        assert_ne!(next.operation_id, running.operation_id);
        assert_eq!(next.phase, InstallPhase::Running);
    }

    #[test]
    fn tickets_dequeue_in_admission_order() {
        let mut sched = InstallScheduler::new();
        for id in ["com.test.a", "com.test.b", "com.test.c"] {
            sched.admit(InstallRequest::install(
                OperationId::new(),
                id,
                AgentInstanceId::new(),
                test_source(),
            ));
        }

        let mut order = Vec::new();
        for _ in 0..3 {
            let ticket = sched.take_next().expect("queued ticket");
            order.push(ticket.agent_id.clone());
            assert!(sched.finish(&ticket.operation_id, ready(&ticket)));
        }
        assert_eq!(order, ["com.test.a", "com.test.b", "com.test.c"]);
        assert!(sched.is_idle());
    }

    #[test]
    fn stale_finish_does_not_release_the_slot() {
        let mut sched = InstallScheduler::new();
        sched.admit(request(InstallKind::Install, AgentInstanceId::new()));
        let running = sched.take_next().expect("ticket");

        // A completion for an unrelated operation must not free the slot.
        let foreign = OperationId::new();
        assert!(!sched.finish(&foreign, InstallOutcome::Failed { message: "x".into() }));
        assert_eq!(sched.inflight_operation_id(), Some(&running.operation_id));
        assert!(sched.take_next().is_none());
    }

    #[test]
    fn a_completed_instance_can_be_admitted_again() {
        // Admission only sees accepted jobs: once a job is terminal the
        // queue is free again. Whether a *new* install is wanted is the
        // caller's decision (and, for `Ensure`, the execution-time
        // precondition's).
        let mut sched = InstallScheduler::new();
        let instance = AgentInstanceId::new();
        sched.admit(request(InstallKind::Ensure, instance.clone()));
        let running = sched.take_next().expect("ticket");
        assert!(sched.finish(&running.operation_id, ready(&running)));

        let again = sched.admit(same_instance_request(InstallKind::Ensure, &instance));
        assert!(again.is_accepted());
    }

    #[tokio::test]
    async fn completion_handles_are_shared_with_coalesced_callers() {
        let mut sched = InstallScheduler::new();
        let instance = AgentInstanceId::new();
        let first = sched.admit(request(InstallKind::Ensure, instance.clone()));
        let second = sched.admit(same_instance_request(InstallKind::Ensure, &instance));

        let first_handle = first.completion().expect("handle").clone();
        let second_handle = second.completion().expect("handle").clone();
        assert!(Arc::ptr_eq(&first_handle, &second_handle));

        let running = sched.take_next().expect("ticket");
        assert!(sched.finish(&running.operation_id, ready(&running)));

        let outcome = second_handle.wait().await;
        assert!(outcome.is_satisfied());
        assert_eq!(outcome.instance_id(), Some(&running.instance_id));
    }

    #[tokio::test]
    async fn already_resolved_completion_returns_immediately() {
        let id = AgentInstanceId::new();
        let handle = InstallCompletion::completed(InstallOutcome::AlreadySatisfied {
            instance_id: id.clone(),
        });
        let outcome = handle.wait().await;
        assert_eq!(outcome.phase(), InstallPhase::AlreadySatisfied);
        assert_eq!(outcome.instance_id(), Some(&id));
    }
}
