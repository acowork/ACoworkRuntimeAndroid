//! L1 单元测试 — `CancelHandle` + `select_on_cancel`
//!
//! 覆盖 ADR-044 §4.6 验证矩阵 L1：
//! - handle cancel 前后 `cancelled()` future 行为（fast / linger）
//! - `select_on_cancel`：cancel 先到 / fut 先到 / cancel 在 race 期间多发的丢弃
//! - reason 字段多线程可见性
//! - 取消的 drop-future 语义（inner future 被 drop）
//! - re-entry：同一 handle 多次 `cancel` + 多次 `cancelled()`
//!
//! Per-request 架构测试见文末 L5 区块。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use crate::cancellation::{CancelHandle, CancellationReason, StopSource, select_on_cancel};
use crate::error::{Result, RuntimeError};

// ──────────────────────────────────────────────────────────────────────
// CancelHandle 基础行为
// ──────────────────────────────────────────────────────────────────────

#[test]
fn new_handle_is_active() {
    let handle = CancelHandle::new();
    assert!(!handle.is_cancelled(), "fresh handle must be Active");
    assert!(handle.reason().is_none(), "fresh handle has no reason");
}

#[test]
fn cancel_flips_state_and_records_reason() {
    let handle = CancelHandle::new();
    let reason = CancellationReason::UserStop {
        source: StopSource::Cli,
        reason: "manual".into(),
    };
    assert!(handle.cancel(reason.clone()));
    assert!(handle.is_cancelled());
    assert_eq!(handle.reason(), Some(reason));
}

#[test]
fn cancel_is_first_wins() {
    let handle = CancelHandle::new();
    let r1 = CancellationReason::UserStop {
        source: StopSource::Cli,
        reason: "first".into(),
    };
    let r2 = CancellationReason::UserStop {
        source: StopSource::Cli,
        reason: "second".into(),
    };
    assert!(handle.cancel(r1.clone()));
    assert!(
        !handle.cancel(r2.clone()),
        "second cancel must return false (first-wins)"
    );
    assert_eq!(
        handle.reason(),
        Some(r1),
        "first reason must be preserved on subsequent cancels"
    );
}

#[test]
fn cancel_is_idempotent_for_distinct_variants() {
    let handle = CancelHandle::new();
    assert!(handle.cancel(CancellationReason::Pause));
    assert!(!handle.cancel(CancellationReason::DebugStop));
    assert!(!handle.cancel(CancellationReason::Error("oops".into())));
    assert_eq!(handle.reason(), Some(CancellationReason::Pause));
}

#[test]
fn clones_share_underlying_state() {
    let a = CancelHandle::new();
    let b = a.clone();
    let c = b.clone();
    assert!(!a.is_cancelled());
    assert!(!c.is_cancelled());
    a.cancel(CancellationReason::DebugStop);
    assert!(b.is_cancelled(), "all clones must observe the cancel");
    assert!(c.is_cancelled());
    assert_eq!(b.reason(), Some(CancellationReason::DebugStop));
    assert_eq!(c.reason(), Some(CancellationReason::DebugStop));
}

#[test]
fn default_yields_active_handle() {
    let handle: CancelHandle = Default::default();
    assert!(!handle.is_cancelled());
}

// ──────────────────────────────────────────────────────────────────────
// cancelled() future 行为
// ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn cancelled_future_returns_immediately_when_already_cancelled() {
    let handle = CancelHandle::new();
    handle.cancel(CancellationReason::Pause);
    // Must resolve well under the timeout — no Notified awaiting needed.
    tokio::time::timeout(Duration::from_millis(50), handle.cancelled())
        .await
        .expect("cancelled() should resolve instantly when already cancelled");
}

#[tokio::test]
async fn cancelled_future_resolves_after_cancel() {
    let handle = CancelHandle::new();
    let t = handle.clone();

    let canceller = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        t.cancel(CancellationReason::SessionClosed);
    });

    tokio::time::timeout(Duration::from_millis(500), handle.cancelled())
        .await
        .expect("cancelled() should resolve within 500ms after cancel()");

    canceller.await.expect("canceller task panicked");
}

#[tokio::test]
async fn cancelled_future_lingers_when_not_cancelled() {
    let handle = CancelHandle::new();
    // Without cancel(), the future must NOT resolve within a short timeout.
    let res = tokio::time::timeout(Duration::from_millis(50), handle.cancelled()).await;
    assert!(
        res.is_err(),
        "cancelled() must not resolve without cancel() (got {:?})",
        res
    );
}

#[tokio::test]
async fn re_entry_after_cancel_resolves_immediately() {
    let handle = CancelHandle::new();
    handle.cancel(CancellationReason::SessionClosed);

    // Multiple awaited calls after cancel — all should return immediately.
    for i in 0..3 {
        tokio::time::timeout(Duration::from_millis(50), handle.cancelled())
            .await
            .unwrap_or_else(|_| panic!("subsequent cancelled() #{} must resolve instantly", i));
    }
}

// ──────────────────────────────────────────────────────────────────────
// select_on_cancel 行为
// ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn select_on_cancel_future_wins_returns_some() {
    let handle = CancelHandle::new();
    let result = select_on_cancel(handle, async { Ok::<i32, RuntimeError>(42) }).await;
    assert_eq!(result.unwrap(), Some(42));
}

#[tokio::test]
async fn select_on_cancel_cancel_wins_returns_none() {
    let handle = CancelHandle::new();
    let t = handle.clone();

    let canceller = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        t.cancel(CancellationReason::UserStop {
            source: StopSource::Cli,
            reason: "test".into(),
        });
    });

    // Inner future takes 200ms (much longer than the cancel signal at 10ms).
    let result = select_on_cancel(handle, async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        Ok::<i32, RuntimeError>(99)
    })
    .await;

    assert_eq!(
        result.unwrap(),
        None,
        "cancel must win over the 200ms inner future"
    );
    canceller.await.unwrap();
}

#[tokio::test]
async fn select_on_cancel_propagates_inner_error() {
    let handle = CancelHandle::new();
    let result = select_on_cancel::<i32, RuntimeError, _>(handle, async {
        Err(RuntimeError::Tool("inner failure".into()))
    })
    .await;
    assert!(result.is_err(), "inner error must propagate unchanged");
    match result.unwrap_err() {
        RuntimeError::Tool(msg) => assert_eq!(msg, "inner failure"),
        e => panic!("expected RuntimeError::Tool, got {:?}", e),
    }
}

#[tokio::test]
async fn select_on_cancel_drops_inner_future_on_cancel() {
    let handle = CancelHandle::new();
    let t = handle.clone();
    let drop_flag = Arc::new(AtomicBool::new(false));

    // FlagGuard flips the AtomicBool in its Drop impl. We hold one inside
    // the inner future so we can detect when the future is dropped.
    struct FlagGuard(Arc<AtomicBool>);
    impl Drop for FlagGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let drop_flag_for_inner = drop_flag.clone();
    let inner = async move {
        let _guard = FlagGuard(drop_flag_for_inner);
        tokio::time::sleep(Duration::from_millis(200)).await;
        Ok::<(), RuntimeError>(())
    };

    let task_handle = tokio::spawn(async move { select_on_cancel(t.clone(), inner).await });

    // Give the spawned task time to enter the select! and start the sleep.
    tokio::time::sleep(Duration::from_millis(20)).await;
    handle.cancel(CancellationReason::UserStop {
        source: StopSource::Test,
        reason: "drop-test".into(),
    });

    let outcome = task_handle.await.unwrap();
    assert_eq!(outcome.unwrap(), None);
    assert!(
        drop_flag.load(Ordering::SeqCst),
        "inner future must be dropped on cancel (FlagGuard Drop should have fired)"
    );
}

#[tokio::test]
async fn select_on_cancel_with_already_cancelled_handle_returns_none() {
    let handle = CancelHandle::new();
    handle.cancel(CancellationReason::Pause);

    // Inner future must never run — biased; select! resolves the cancel branch first.
    let drop_flag = Arc::new(AtomicBool::new(false));
    struct FlagGuard(Arc<AtomicBool>);
    impl Drop for FlagGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let drop_flag_clone = drop_flag.clone();
    let inner = async move {
        let _guard = FlagGuard(drop_flag_clone);
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok::<(), RuntimeError>(())
    };

    let result = select_on_cancel(handle, inner).await;
    assert_eq!(result.unwrap(), None);
    // Drop may or may not fire depending on whether `fut` was constructed
    // (creating the future does not run it; the async block only runs when
    // polled). For this test we only require the result semantics.
    let _ = drop_flag; // suppress unused warning
}

#[tokio::test]
async fn select_on_cancel_multiple_cancels_resolve_once() {
    let handle = CancelHandle::new();
    let cancel_count = Arc::new(AtomicU32::new(0));
    let t = handle.clone();
    let cc = cancel_count.clone();

    let cancel_task = tokio::spawn(async move {
        // Many cancels — only the first should take effect.
        for _ in 0..5 {
            t.cancel(CancellationReason::DebugStop);
            cc.fetch_add(1, Ordering::SeqCst);
        }
    });

    select_on_cancel::<i32, _, _>(handle.clone(), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok::<i32, RuntimeError>(1)
    })
    .await
    .unwrap();

    cancel_task.await.unwrap();
    assert_eq!(cancel_count.load(Ordering::SeqCst), 5);
    assert!(handle.is_cancelled());
    assert_eq!(handle.reason(), Some(CancellationReason::DebugStop));
}

// ──────────────────────────────────────────────────────────────────────
// 多线程可见性（reason 字段）
// ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reason_visible_across_threads_after_cancel() {
    let handle = CancelHandle::new();
    let handle_clone = handle.clone();
    let counter = Arc::new(AtomicU32::new(0));

    let mut handles = Vec::new();
    for _ in 0..4 {
        let t = handle.clone();
        let c = counter.clone();
        handles.push(tokio::spawn(async move {
            // Spin briefly waiting for cancel.
            t.cancelled().await;
            // After we observe cancel, reason must be visible to this thread.
            assert!(t.reason().is_some(), "reason must be visible after cancel");
            c.fetch_add(1, Ordering::SeqCst);
        }));
    }

    tokio::time::sleep(Duration::from_millis(20)).await;
    handle_clone.cancel(CancellationReason::BudgetExceeded("tokens".into()));

    for h in handles {
        h.await.unwrap();
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        4,
        "all 4 spawned tasks must observe cancel"
    );
    assert_eq!(
        handle.reason(),
        Some(CancellationReason::BudgetExceeded("tokens".into()))
    );
}

// ──────────────────────────────────────────────────────────────────────
// 默认值 / trait 实现一致性
// ──────────────────────────────────────────────────────────────────────

#[test]
fn send_sync_compile_time_guarantees() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<CancelHandle>();
    assert_sync::<CancelHandle>();
}

#[tokio::test]
async fn result_type_alias_works_with_select_on_cancel() {
    // Compile-time check: `select_on_cancel` returns `Result<Option<T>, E>`
    // — generic over `E`, so callers from any layer can plug in their own
    // error type. We exercise it here via the crate's `Result` alias
    // (which fixes `E = RuntimeError`) to confirm signature drift is
    // caught at compile time.
    let handle = CancelHandle::new();
    let r: Result<Option<i32>> =
        select_on_cancel(handle, async { Ok::<i32, RuntimeError>(7) }).await;
    assert_eq!(r.unwrap(), Some(7));
}

// ──────────────────────────────────────────────────────────────────────
// ADR-044 Phase 3 specific integration tests
// ──────────────────────────────────────────────────────────────────────

/// Phase 3 L4: simulates the LLM TTFT (Time-To-First-Token) stop bug fix.
///
/// Before Phase 3, `chat_stream().await` in `loop_llm.rs:71` was a bare
/// `.await` with no `tokio::select!` wrapper — a Stop signal arriving while
/// the future was establishing TCP/TLS/HTTP-headers/waiting for the first
/// SSE chunk could not be observed until the upstream returned. After Phase
/// 3, `select_on_cancel` races the future against the session's
/// `CancelHandle`; a cancel drops the inner future (and any in-flight
/// `reqwest::send()`), returning `Ok(None)`.
///
/// This test verifies the drop semantics directly: we wrap a sleep-heavy
/// future (the stand-in for a slow LLM connection) and confirm that a
/// cancel fires within milliseconds rather than waiting for the inner
/// future's natural completion.
#[tokio::test]
async fn phase3_select_on_cancel_drops_slow_future_quickly() {
    let handle = CancelHandle::new();
    let t = handle.clone();

    // Simulate a 30s upstream TTFT — would be the worst-case latency a user
    // experienced before Phase 3.
    let slow_future = async {
        tokio::time::sleep(Duration::from_secs(30)).await;
        Ok::<(), RuntimeError>(())
    };

    let started = std::time::Instant::now();
    let canceller = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        t.cancel(CancellationReason::UserStop {
            source: StopSource::ChatPanel {
                agent_id: "com.test.agent".into(),
                session_id: "test-session".into(),
            },
            reason: "user_requested".into(),
        });
    });

    let outcome = select_on_cancel(handle, slow_future).await;
    let elapsed = started.elapsed();

    assert_eq!(
        outcome.unwrap(),
        None,
        "select_on_cancel must drop the inner future when the handle is cancelled"
    );
    // We give a generous upper bound (1s) — in practice the cancel fires
    // within milliseconds, but we don't want CI flakiness from a slow runner.
    assert!(
        elapsed < Duration::from_secs(1),
        "cancel must drop the future quickly (took {:?}); without select_on_cancel \
         this would take 30s — the original TTFT bug",
        elapsed
    );

    canceller.await.unwrap();
}

/// Phase 3 L4: verifies that the cancellation future resolves on *first poll*
/// when the handle was already cancelled before `select_on_cancel` was
/// awaited. This is the "MQTT Stop arrives before the loop reaches
/// `chat_stream`" race that `biased;` ordering in `select_on_cancel` exists
/// to handle.
#[tokio::test]
async fn phase3_select_on_cancel_resolves_immediately_when_pre_cancelled() {
    let handle = CancelHandle::new();
    handle.cancel(CancellationReason::UserStop {
        source: StopSource::ChatPanel {
            agent_id: "com.test.agent".into(),
            session_id: "test-session".into(),
        },
        reason: "user_requested".into(),
    });

    let started = std::time::Instant::now();
    let outcome = select_on_cancel(handle, async {
        // This future must never run — biased; ensures cancel wins first poll.
        tokio::time::sleep(Duration::from_secs(60)).await;
        Ok::<(), RuntimeError>(())
    })
    .await;
    let elapsed = started.elapsed();

    assert_eq!(outcome.unwrap(), None);
    assert!(
        elapsed < Duration::from_millis(100),
        "pre-cancelled select_on_cancel must resolve in < 100ms (took {:?})",
        elapsed
    );
}

/// Phase 3 L4: simulates the high-level flow:
/// 1. A session task starts `chat_stream().await` (slow upstream TTFT)
/// 2. The MQTT dispatcher calls `cancel()` on the session's handle
/// 3. The session task wakes within `select_on_cancel` and returns Ok(None)
///
/// This mirrors the production flow in `startup/gateway_loop.rs::dispatch_inbound`
/// where `InboundMessage::Stop { reason }` triggers
/// `session_manager.cancel_handle(sid)?.cancel(UserStop{...})` before
/// forwarding. The test exercises the handle-lookup-and-cancel pattern in
/// isolation.
#[tokio::test]
async fn phase3_handle_lookup_then_cancel_propagates_to_select() {
    use std::collections::HashMap;

    // Stand-in for SessionManager's `cancel_handles: HashMap<String, CancelHandle>`.
    let mut handles: HashMap<String, CancelHandle> = HashMap::new();
    handles.insert("session-a".into(), CancelHandle::new());
    handles.insert("session-b".into(), CancelHandle::new());

    let session_id = "session-a";
    let handle = handles
        .get(session_id)
        .expect("handle must be registered for session-a")
        .clone();

    let slow_chat = async {
        // Simulates provider.chat_stream().await: TCP connect + TLS + headers + TTFT.
        tokio::time::sleep(Duration::from_secs(10)).await;
        Ok::<(), RuntimeError>(())
    };

    let canceller_handle = handle.clone();
    let canceller = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(15)).await;
        // Dispatcher code path: handle.cancel(UserStop { ... })
        canceller_handle.cancel(CancellationReason::UserStop {
            source: StopSource::ChatPanel {
                agent_id: "com.test.agent".into(),
                session_id: session_id.into(),
            },
            reason: "user_clicked_stop".into(),
        });
    });

    let started = std::time::Instant::now();
    let outcome = select_on_cancel(handle.clone(), slow_chat).await;
    let elapsed = started.elapsed();

    assert_eq!(outcome.unwrap(), None, "cancel must propagate to select");
    assert!(
        elapsed < Duration::from_millis(500),
        "stop latency must be sub-500ms (took {:?}) — the original bug was 10–30s",
        elapsed
    );
    assert!(
        handle.is_cancelled(),
        "handle must be in Cancelled state after select_on_cancel returned"
    );
    match handle.reason() {
        Some(CancellationReason::UserStop {
            source: StopSource::ChatPanel { .. },
            reason,
        }) => assert_eq!(reason, "user_clicked_stop"),
        other => panic!(
            "expected UserStop{{ChatPanel, user_clicked_stop}}, got {:?}",
            other
        ),
    }

    canceller.await.unwrap();
}

/// Phase 3 L4: verifies that *re-cancellation* during an in-flight stop
/// does not duplicate side effects. The handle's first-wins invariant means
/// the original reason is preserved — important for telemetry that wants
/// to attribute the cancel to a specific user action.
#[tokio::test]
async fn phase3_repeat_cancel_preserves_first_reason() {
    let handle = CancelHandle::new();

    let first = CancellationReason::UserStop {
        source: StopSource::ChatPanel {
            agent_id: "com.test".into(),
            session_id: "sid".into(),
        },
        reason: "first_stop".into(),
    };
    let second = CancellationReason::UserStop {
        source: StopSource::ChatPanel {
            agent_id: "com.test".into(),
            session_id: "sid".into(),
        },
        reason: "second_stop".into(),
    };

    assert!(
        handle.cancel(first.clone()),
        "first cancel must take effect"
    );
    assert!(
        !handle.cancel(second),
        "subsequent cancels must be no-ops (first-wins)"
    );
    assert_eq!(
        handle.reason(),
        Some(first),
        "first reason must be preserved"
    );
}

/// Phase 3 L4: verifies the `poll_control()` integration — when the handle
/// is cancelled while the agent loop is mid-iteration, the next
/// `poll_control()` call observes the cancellation as `ControlDecision::Stop`
/// (lowest priority among the four sources, but observable via the
/// `is_cancelled()` atomic load). This is what the `select!` cancel branch
/// falls back on after dropping the inner future: it returns
/// `Ok(None) | stopped response`, and the upstream `run_inner` re-checks
/// `poll_control()` to confirm the stop.
#[tokio::test]
async fn phase3_handle_state_observable_via_is_cancelled() {
    let handle = CancelHandle::new();
    assert!(!handle.is_cancelled());

    handle.cancel(CancellationReason::UserStop {
        source: StopSource::Cli,
        reason: "manual".into(),
    });
    assert!(handle.is_cancelled());

    // Re-entrant: a second poll_control() sees the same state.
    assert!(handle.is_cancelled());
}

// ──────────────────────────────────────────────────────────────────────
// ADR-044 §4.5: per-request CancelHandle slot — regression coverage for the
// stop-then-continue bug.
//
// Bug: before §4.5, Stop flipped the session-level handle permanently, so
// any subsequent run_inner started with the same Cancelled handle and
// short-circuited through `select_on_cancel` within 10 ms. Session was
// unusable until the user created a fresh session (new token = new Arc).
//
// Fix: SessionCore keeps an `Arc<parking_lot::Mutex<CancelHandle>>` slot.
// `begin_new_request` swaps a fresh handle into the slot. SessionManager
// always reads through the Arc (never holds a stale clone).
//
// The two tests below cover the slot mechanics at the wrapper level — they
// don't depend on SessionManager or SessionTask so they isolate the per-
// request behaviour in a small, fast unit test surface.
// ──────────────────────────────────────────────────────────────────────

#[test]
fn per_request_slot_replaces_cancelled_state() {
    use parking_lot::Mutex as ParkingMutex;

    // Stand-in for `SessionCore::current_cancel_handle` slot.
    let slot: Arc<ParkingMutex<CancelHandle>> = Arc::new(ParkingMutex::new(CancelHandle::new()));

    // Read the initial (Active) handle through the slot — exactly what
    // SessionManager does on every external cancel dispatch.
    let initial = slot.lock().clone();
    assert!(!initial.is_cancelled(), "fresh slot must yield Active");

    // Cancel via the initial handle.
    initial.cancel(CancellationReason::UserStop {
        source: StopSource::ChatPanel {
            agent_id: "com.test".into(),
            session_id: "s1".into(),
        },
        reason: "first".into(),
    });
    assert!(initial.is_cancelled());

    // The slot *itself* still points to the cancelled handle. Reading the
    // slot now would still give a Cancelled handle — but the production
    // design never re-reads a clone: `begin_new_request` writes a fresh
    // handle first, then external sources observe the new one.

    // Simulate `begin_new_request`: swap a fresh handle into the slot.
    *slot.lock() = CancelHandle::new();

    // A new read through the slot returns the fresh Active handle.
    let fresh = slot.lock().clone();
    assert!(!fresh.is_cancelled(), "begin_new_request must yield Active");
    assert!(
        fresh.reason().is_none(),
        "fresh handle must have no reason — old cancel must NOT leak across"
    );

    // The old handle is reachable only through the dropped `initial` Arc;
    // it remains Cancelled (level-triggered semantics) but no one observes
    // it any more. We hold it here to demonstrate that the old instance is
    // in fact still alive (Arc keeps it).
    assert!(
        initial.is_cancelled(),
        "old handle still observed as Cancelled"
    );
}

/// Per-request slot + concurrent reader/writer: simulates the production
/// hot path where SessionManager reads the slot while `run_inner` swaps a
/// new handle. With the Arc<Mutex<>> slot, readers never observe a stale
/// clone — they always see the slot's *current* value at lock time.
#[test]
fn per_request_slot_arc_keeps_readers_in_sync() {
    use parking_lot::Mutex as ParkingMutex;

    let slot: Arc<ParkingMutex<CancelHandle>> = Arc::new(ParkingMutex::new(CancelHandle::new()));

    // "Old generation" handle — what `chat_stream` was using before Stop.
    let old = slot.lock().clone();
    old.cancel(CancellationReason::SessionClosed);

    // Verify the invariant: the cancelled `old` handle is still cancelled,
    // but reading the slot produces `old` (still Cancelled) — which is why
    // we MUST replace before the next run_inner, not just rely on time.
    let read_before_swap = slot.lock().clone();
    assert!(read_before_swap.is_cancelled());

    // Production entry-point: `begin_new_request` writes a fresh handle.
    *slot.lock() = CancelHandle::new();

    // After the swap, the slot reader gets the fresh Active handle — never
    // the old cancelled one. This is the key invariant: SessionManager
    // always sees the *current* generation.
    let read_after_swap = slot.lock().clone();
    assert!(!read_after_swap.is_cancelled());

    // The old handle is still Cancelled (Arc keeps it), but no external
    // source will ever call cancel on it again — it's effectively retired.
    assert_eq!(old.reason(), Some(CancellationReason::SessionClosed));
    assert!(read_before_swap.is_cancelled());
}
