//! Shared output-size safety helpers for built-in tools.
//!
//! Every tool that can produce unbounded output (file_read, shell,
//! content_search, etc.) must guard against the entire response being fed
//! into the LLM context window, which can exhaust the token budget and
//! crash the session task.
//!
//! Constants and helpers defined here provide consistent, project-wide
//! truncation behaviour.  The underlying character-boundary-safe slice
//! logic is the project-wide [`crate::util::text::truncate_utf8`] helper;
//! the markers and append-policies specific to *tool output* stay here.

/// Default maximum bytes for a single tool output (32 KB).
///
/// Reduced from 512 KB → 256 KB → 128 KB → 32 KB. The 32 KB cap (~8K
/// tokens at the conventional ~4 chars/token ratio) is small enough that
/// even several concurrent tool results cannot single-handedly exhaust the
/// LLM context window — they need to be **accumulated** before compression
/// kicks in, which gives the agent loop time to react. Tools that are
/// particularly prone to blowing the budget (e.g. raw shell output) have
/// their own stricter head+tail truncation — see
/// [`MAX_SHELL_HEAD_BYTES`] / [`MAX_SHELL_TAIL_BYTES`].
///
/// Note: `doc_reader`'s plain-text fallback enforces this limit as a
/// hard "file too large" gate *before* opening the file, by design
/// (`doc_reader/text.rs`). Tools that produce meaningful local content
/// (e.g. `file_read`, `content_search`) must use `start_line`/`end_line`
/// paging to stay under the cap.
pub const MAX_OUTPUT_BYTES: usize = 32 * 1024; // 32 KB

/// Head budget for shell-like tools — first N bytes of stdout+stderr are
/// kept verbatim. See [`truncate_head_tail_output`].
///
/// 4 KB is enough for the typical "command echo + setup banner" preamble
/// of a shell result while staying well under any single-tool context
/// contribution. DeepSeek-style aggressive truncation.
pub const MAX_SHELL_HEAD_BYTES: usize = 4 * 1024; // 4 KB

/// Tail budget for shell-like tools — last N bytes of stdout+stderr are
/// kept verbatim. See [`truncate_head_tail_output`].
///
/// 1 KB is enough for the typical "exit reason / final error / last few
/// result lines" tail that the LLM actually needs to act on. Diagnostic
/// commands (cargo / pytest / npm) almost always put the actionable error
/// at the end; keeping the tail saves a retry round-trip.
pub const MAX_SHELL_TAIL_BYTES: usize = 1024; // 1 KB

/// Maximum bytes per *single matched line* when a tool emits line-level
/// output (e.g. content_search content mode).
///
/// A single line that is hundreds of KB (e.g. an inlined HTML tool_result
/// in a JSONL file) can dominate the output on its own.  Truncating
/// individual lines at 10 KB prevents this while still allowing most
/// real-world lines through unchanged.
pub const MAX_LINE_OUTPUT_BYTES: usize = 10 * 1024; // 10 KB

/// Appended when a line is truncated because it exceeded
/// [`MAX_LINE_OUTPUT_BYTES`].
pub const TRUNCATED_LINE_MARKER: &str = "...[truncated]";

/// Appended when an entire output is truncated because it exceeded
/// [`MAX_OUTPUT_BYTES`].  Provides the LLM with actionable guidance
/// so it knows to narrow the request rather than blindly retry.
pub const TRUNCATED_OUTPUT_MARKER: &str = "\
\n[OUTPUT TRUNCATED: exceeded tool-level output limit (32 KB). \
The full output was too large to fit in the LLM context window. \
SUGGESTION: re-run with more targeted parameters — narrower \
search patterns, file range limits (head/tail/Select-Object), \
or pagination across multiple calls.]";

/// Marker inserted between head and tail when [`truncate_head_tail_output`]
/// drops the middle of a tool output. Carries the concrete byte count of
/// what was dropped plus a concrete re-query command, rather than a vague
/// "narrow your parameters" hint.
///
/// `grep -n` is the recommended command — it is available on every Unix-like
/// shell (bash / sh / zsh / Git Bash / WSL / msys2). PowerShell users get
/// `Select-String` as the platform-native equivalent.
pub const OMITTED_MARKER_FMT: &str = "\
\n\n[... {omitted} bytes omitted from middle. \
Use 'grep -n PATTERN file' (or Select-String on PowerShell) \
to query the missing section.]\n\n";

/// Maximum number of results returned by collection tools (glob_search,
/// files_with_matches mode, etc.).  Prevents a tool from dumping tens of
/// thousands of paths into the output.
pub const MAX_RESULT_COUNT: usize = 1000;

/// Truncate a **single line** to [`MAX_LINE_OUTPUT_BYTES`], preserving
/// valid UTF-8 boundaries.  Returns the original string if it fits; otherwise
/// appends [`TRUNCATED_LINE_MARKER`].
pub fn truncate_line(line: &str) -> String {
    let truncated = crate::util::text::truncate_utf8(line, MAX_LINE_OUTPUT_BYTES);
    if truncated.len() == line.len() {
        return line.to_string();
    }
    let mut out = truncated.to_string();
    out.push_str(TRUNCATED_LINE_MARKER);
    out
}

/// Truncate a **full output string** to [`MAX_OUTPUT_BYTES`], preserving
/// valid UTF-8 boundaries.  Appends [`TRUNCATED_OUTPUT_MARKER`] when
/// truncation occurs.
///
/// Returns `(maybe_truncated_string, was_truncated_bool)`.
pub fn truncate_output(output: &str) -> (String, bool) {
    let truncated = crate::util::text::truncate_utf8(output, MAX_OUTPUT_BYTES);
    if truncated.len() == output.len() {
        return (output.to_string(), false);
    }
    let mut out = truncated.to_string();
    out.push_str(TRUNCATED_OUTPUT_MARKER);
    (out, true)
}

/// Truncate `input` to **head** `head_bytes` + **tail** `tail_bytes`, with
/// an omission marker (`_OMitted bytes omitted from middle. Use 'grep -n
/// PATTERN' (or Select-String on PowerShell) to query the missing section.`)
/// in between.  Returns `(maybe_truncated, was_truncated)`.
///
/// Designed for tools whose output is **unfiltered** (e.g. `shell`): a
/// naïve head-truncate would throw away the actionable error at the tail;
/// a naïve tail-truncate would throw away the command-echo header that
/// the LLM needs to remember what it ran. Head+tail is the cheapest way to
/// keep both ends.
///
/// - `input.len() <= head_bytes + tail_bytes`: returned verbatim, no marker.
/// - `head_bytes == 0`: degenerate to pure tail (`truncate_utf8` of `input[..0]` + tail).
/// - `tail_bytes == 0`: degenerate to pure head.
/// - UTF-8 safe: both slices land on char boundaries (`util::text::tail_slice_from`).
///
/// Total budget = `head_bytes + tail_bytes` (marker excluded). With the
/// project defaults (4 KB + 1 KB) this gives 5 KB of preserved content —
/// small enough to never single-handedly exhaust context, large enough to
/// cover the "echo + setup" head and the "final error / last result" tail
/// of a typical shell invocation.
pub fn truncate_head_tail_output(
    input: &str,
    head_bytes: usize,
    tail_bytes: usize,
) -> (String, bool) {
    let total = input.len();
    let budget = head_bytes.saturating_add(tail_bytes);

    if total <= budget {
        return (input.to_string(), false);
    }

    // HEAD: take from the front, floor to char boundary.
    let head = crate::util::text::truncate_utf8(input, head_bytes);

    // TAIL: take the last tail_bytes bytes, floor **down** to char boundary.
    // `&input[len - tail_bytes..]` would panic if that byte lands mid-char;
    // `tail_slice_from` walks back to the previous char boundary.
    let tail_start_raw = total.saturating_sub(tail_bytes);
    let tail = crate::util::text::tail_slice_from(input, tail_start_raw);

    let head_end = head.len();
    let omitted = total.saturating_sub(head_end).saturating_sub(tail.len());

    let marker = OMITTED_MARKER_FMT.replace("{omitted}", &omitted.to_string());

    let mut out = String::with_capacity(head_end + marker.len() + tail.len());
    out.push_str(head);
    out.push_str(&marker);
    out.push_str(tail);
    (out, true)
}

// Re-exported so older internal callers (none in mainline today, but
// possibly in plugins) keep working.  The single source of truth is
// [`crate::util::text::truncate_utf8`].
pub use crate::util::text::truncate_utf8;

#[cfg(test)]
mod tests {
    use super::*;

    // ── truncate_head_tail_output ─────────────────────────────────

    #[test]
    fn head_tail_under_budget_returns_verbatim() {
        // 不触发截断时，原样返回，不写 marker
        let (out, was_truncated) = truncate_head_tail_output("hello world", 100, 100);
        assert_eq!(out, "hello world");
        assert!(!was_truncated);
    }

    #[test]
    fn head_tail_exact_budget_returns_verbatim() {
        // 等于预算也算"未截断"
        let s = "x".repeat(20);
        let (out, was_truncated) = truncate_head_tail_output(&s, 10, 10);
        assert_eq!(out, s);
        assert!(!was_truncated);
    }

    #[test]
    fn head_tail_ascii_truncates_and_writes_marker() {
        // 30 ASCII 字节，head=8 tail=4 → 预算 12 → 应截断
        let s = "A".repeat(20) + &"B".repeat(10); // 30 bytes, head="A"*20, tail="B"*10
        let (out, was_truncated) = truncate_head_tail_output(&s, 8, 4);
        assert!(was_truncated);
        assert!(out.starts_with("A".repeat(8).as_str()));
        assert!(out.ends_with("B".repeat(4).as_str()));
        // marker 中应该写明省略了多少字节
        assert!(out.contains("18 bytes omitted from middle"), "got: {out}");
    }

    #[test]
    fn head_tail_marker_omitted_count_is_correct() {
        // head=10, tail=10, total=100 → omitted = 100 - 10 - 10 = 80
        let s = "x".repeat(100);
        let (out, _) = truncate_head_tail_output(&s, 10, 10);
        assert!(out.contains("80 bytes omitted from middle"), "got: {out}");
    }

    #[test]
    fn head_tail_marker_offers_re_query_commands() {
        // marker 必须包含重新查询的具体命令：grep -n（Unix 兼容）+ Select-String（PowerShell）
        let s = "x".repeat(10_000);
        let (out, _) = truncate_head_tail_output(&s, 100, 100);
        assert!(out.contains("grep -n PATTERN"), "got: {out}");
        assert!(out.contains("Select-String"), "got: {out}");
    }

    #[test]
    fn head_tail_cjk_boundaries_are_safe() {
        // 关键回归：CJK 字符不得切到字节中间
        // 100 个"中"字 × 3 bytes = 300 bytes
        let s = "中".repeat(100);
        let (out, was_truncated) = truncate_head_tail_output(&s, 12, 12); // 12 / 3 = 4 chars each
        assert!(was_truncated);
        // head: 前 12 字节 = "中中中中"（4 个汉字）
        assert!(
            out.starts_with("中中中中"),
            "got head bytes: {:?}",
            &out[..30]
        );
        // tail: 后 12 字节 = "中中中中"
        assert!(
            out.ends_with("中中中中"),
            "got tail bytes: {:?}",
            &out[out.len() - 30..]
        );
    }

    #[test]
    fn head_tail_tail_boundary_on_emoji_does_not_panic() {
        // tail 起点落在 4-byte emoji 中间 — 是 head+tail 截断的典型 panic 路径
        // 1 emoji (4 bytes) + 5 emoji (4 bytes each, total 20) + ASCII = 9 emoji total = 36 bytes
        // head=10, tail=10 → tail_start_raw = 36 - 10 = 26 → byte 26 落在第 7 个 emoji 中间
        // 应回退到第 7 个 emoji 起点 (24) → tail = "😀😀"（2 emoji，8 bytes）
        let s = "😀".repeat(9); // 36 bytes
        let (out, was_truncated) = truncate_head_tail_output(&s, 10, 10);
        assert!(was_truncated);
        // head 应该是前 8 字节（2 emoji，floor from 10）
        assert!(out.starts_with("😀😀"), "got head: {out}");
        // tail 应该是后 8 字节（2 emoji，floor from byte 26 → 24）
        assert!(out.ends_with("😀😀"), "got tail: {out}");
    }

    #[test]
    fn head_tail_head_zero_degenerates_to_pure_tail() {
        // head_bytes=0 → 只保留尾部
        let s = "x".repeat(100);
        let (out, was_truncated) = truncate_head_tail_output(&s, 0, 10);
        assert!(was_truncated);
        assert!(!out.starts_with('x') || out.len() < 20); // head 没有内容，输出很短
        assert!(out.ends_with(&"x".repeat(10)));
    }

    #[test]
    fn head_tail_tail_zero_degenerates_to_pure_head() {
        let s = "x".repeat(100);
        let (out, was_truncated) = truncate_head_tail_output(&s, 10, 0);
        assert!(was_truncated);
        assert!(out.starts_with(&"x".repeat(10)));
        assert!(!out.ends_with(&"x".repeat(10)));
    }

    #[test]
    fn head_tail_empty_input() {
        let (out, was_truncated) = truncate_head_tail_output("", 100, 100);
        assert_eq!(out, "");
        assert!(!was_truncated);
    }

    #[test]
    fn head_tail_max_output_bytes_constant_is_32k() {
        // 防止有人无意改回去
        assert_eq!(MAX_OUTPUT_BYTES, 32 * 1024);
    }

    #[test]
    fn head_tail_max_shell_constants_are_4k_plus_1k() {
        assert_eq!(MAX_SHELL_HEAD_BYTES, 4 * 1024);
        assert_eq!(MAX_SHELL_TAIL_BYTES, 1024);
    }

    #[test]
    fn truncated_output_marker_mentions_32_kb_not_256_kb() {
        // 防止文案再次脱节
        assert!(
            TRUNCATED_OUTPUT_MARKER.contains("32 KB"),
            "got: {TRUNCATED_OUTPUT_MARKER}"
        );
        assert!(
            !TRUNCATED_OUTPUT_MARKER.contains("256"),
            "got: {TRUNCATED_OUTPUT_MARKER}"
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn shell_budget_fits_within_one_tool_result() {
        // Cross-constraint invariant: a single shell result, after head+tail
        // truncation, must be small enough that even with the marker and
        // the "STDOUT:/STDERR:" wrapper bytes, it stays well under
        // MAX_OUTPUT_BYTES. Otherwise a single shell call alone could
        // blow past the per-tool cap and force compression.
        //
        // Budget = head + tail + marker (~300 bytes) + wrapper (~30 bytes)
        //       = 5_330 bytes ≪ 32 KB.
        let shell_budget = MAX_SHELL_HEAD_BYTES + MAX_SHELL_TAIL_BYTES;
        let worst_case = shell_budget + 400; // marker + STDOUT:/STDERR: wrapper
        assert!(
            worst_case < MAX_OUTPUT_BYTES,
            "shell worst-case ({} bytes) must fit under MAX_OUTPUT_BYTES ({} bytes); \
             otherwise a single shell result would single-handedly blow the cap",
            worst_case,
            MAX_OUTPUT_BYTES
        );
        // And the actual budget must be a small fraction (≤ 25%) of the
        // cap, leaving headroom for other context contributors.
        assert!(
            shell_budget * 4 < MAX_OUTPUT_BYTES,
            "shell budget ({} bytes) should be ≪ MAX_OUTPUT_BYTES ({} bytes) \
             to leave room for concurrent tool results",
            shell_budget,
            MAX_OUTPUT_BYTES
        );
    }

    #[test]
    fn ommitted_marker_format_uses_braces_for_substitution() {
        // The marker is built via `String::replace("{omitted}", ...)`.
        // If someone changes the template and forgets to keep the
        // placeholder, the marker would say literal "{omitted}" to the LLM.
        assert!(
            OMITTED_MARKER_FMT.contains("{omitted}"),
            "OMITTED_MARKER_FMT must keep the {{omitted}} placeholder"
        );
    }
}
