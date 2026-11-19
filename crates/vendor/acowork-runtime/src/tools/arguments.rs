//! 工具调用参数的解析与降级（统一抽象）
//!
//! ## 为什么需要这个模块
//!
//! 之前 `agent::loop_llm` 和 `agent::loop_tools` 各自手写 JSON 校验，逻辑分散，
//! 且当 LLM 返回的参数不是合法 JSON 时直接丢弃原始内容。
//!
//! 2026-08-24 线上 session 就是因此丢失合理信息：
//! - DeepSeek 流式返回 tool call 参数时混入中文自然语言（"全景 + P0 的单一文档，
//!   还是拆分成 2 个文档？"）
//! - 累积的 args 走 JSON 校验失败
//! - runtime 替换为 [`TOOL_CALL_INCOMPLETE`] marker，**原始内容丢失**
//! - LLM 下一轮既看不到自己的原始意图，也无法基于原文修复格式
//!
//! ## 架构
//!
//! 把 "tool call args 解析" 抽象为单一入口 [`resolve`]，产出 [`ResolvedArgs`]
//! 三态结果：
//!
//! - [`ResolvedArgs::Valid`] — 完整合法 JSON，直接用于工具执行。
//! - [`ResolvedArgs::Recovered`] — 从混排文本中提取出 JSON，但保留原始全文作为
//!   `hint`（透传给 LLM，让 LLM 下一轮能看到原始意图）。
//! - [`ResolvedArgs::Invalid`] — 完全无法解析，原始内容作为 `hint`，工具执行器
//!   会把 hint 作为错误消息的一部分返回给 LLM，让 LLM 重新格式化。
//!
//! 所有调用方（streaming assembler 的 [`crate::agent::loop_llm`] 和工具执行器的
//! [`crate::agent::loop_tools`]）都通过这一个解析器处理 args。原
//! `agent::loop_llm::make_incomplete_marker` 已迁移到此处的 [`make_incomplete_marker`]，
//! 消息体中携带原始 hint 而不是只报长度。
//!
//! ## 标记协议（wire-format 兼容）
//!
//! marker 仍是 `{"error": "TOOL_CALL_INCOMPLETE", "message": "..."}` —— `loop_tools`
//! 识别 `error == "TOOL_CALL_INCOMPLETE"` 后读取 `message` 返回给 LLM。改动只在
//! message 内容（增加 hint 透传），不影响识别逻辑。

use serde_json::Value;

// ── ResolvedArgs ─────────────────────────────────────────────────────────

/// 工具调用参数的解析结果。
///
/// 三态语义：
/// - [`ResolvedArgs::Valid`] — 输入就是合法 JSON，直接用 [`Self::value`]。
/// - [`ResolvedArgs::Recovered`] — 输入前半段有自然语言/噪声，从首个顶层 JSON
///   值中提取出可用的 JSON。`hint`（原始全文）仅供日志 / 审计，**不**透传给 LLM
///   —— 工具已正常执行（详见 variant 级文档）。
/// - [`ResolvedArgs::Invalid`] — 完全无法解析。原始内容作为 hint，工具执行器
///   应把 hint 透传给 LLM 作为错误消息的一部分。
#[derive(Debug, Clone)]
pub enum ResolvedArgs {
    /// 输入是完整合法的 JSON。
    Valid(Value),

    /// 从混排文本中提取出 JSON，并保留原始全文。
    ///
    /// 注意：`hint` 字段在 `Recovered` 状态下**仅供日志 / 审计使用**，不会透传给
    /// LLM —— 因为 JSON 已成功提取，工具会正常执行，原始自然语言前缀（如
    /// "全景 + P0 的单一文档，还是拆分成 2 个文档？"）是 LLM 的思考过程而非
    /// 需要回传的意图。只有 [`ResolvedArgs::Invalid`] 才会把原始内容作为 hint
    /// 写进 marker 消息返回给 LLM。
    Recovered { value: Value, hint: String },

    /// 完全无法解析。
    Invalid { raw: String, reason: String },
}

impl ResolvedArgs {
    /// 获取可用于工具执行的 JSON 值（`Valid` / `Recovered` 返回 `Some`）。
    pub fn value(&self) -> Option<&Value> {
        match self {
            Self::Valid(v) | Self::Recovered { value: v, .. } => Some(v),
            Self::Invalid { .. } => None,
        }
    }

    /// 获取原始内容 hint（`Recovered` / `Invalid` 返回 `Some`）。
    ///
    /// - `Invalid`：应透传给 LLM（写入 marker 消息，让 LLM 看到原始意图）。
    /// - `Recovered`：仅供日志 / 审计，不传回 LLM（工具已正常执行）。
    pub fn hint(&self) -> Option<&str> {
        match self {
            Self::Valid(_) => None,
            Self::Recovered { hint, .. } => Some(hint),
            Self::Invalid { raw, .. } => Some(raw),
        }
    }

    /// 是否可用于工具执行（`Valid` 或 `Recovered`）。
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Valid(_) | Self::Recovered { .. })
    }

    /// 是否应跳过工具执行（`Invalid` 状态）。对应 marker 模式。
    pub fn is_skip_marker(&self) -> bool {
        matches!(self, Self::Invalid { .. })
    }
}

// ── resolve ──────────────────────────────────────────────────────────────

/// 解析工具参数，按 1→2→3 顺序尝试多种恢复策略。
///
/// 1. 直接 [`serde_json::from_str`] — 严格合法 JSON。
/// 2. 找到首个顶层 `{...}` 或 `[...]` 子串并尝试解析 — 容忍自然语言前缀/噪声。
/// 3. 都失败 → [`ResolvedArgs::Invalid`]，携带原始内容和简短失败原因。
pub fn resolve(arguments: &str) -> ResolvedArgs {
    if arguments.is_empty() {
        return ResolvedArgs::Invalid {
            raw: arguments.to_string(),
            reason: "empty arguments string".to_string(),
        };
    }

    // 1. 直接解析
    if let Ok(value) = serde_json::from_str::<Value>(arguments) {
        return ResolvedArgs::Valid(value);
    }

    // 2. 提取首个顶层 JSON 值
    if let Some((start, end)) = find_top_level_json(arguments) {
        let candidate = &arguments[start..end];
        if let Ok(value) = serde_json::from_str::<Value>(candidate) {
            return ResolvedArgs::Recovered {
                value,
                hint: arguments.to_string(),
            };
        }
    }

    // 3. 完全失败
    ResolvedArgs::Invalid {
        raw: arguments.to_string(),
        reason: short_reason(arguments),
    }
}

/// 在字符串 `s` 中找到首个顶层 JSON object 或 array 的字节区间 `(start, end_exclusive)`。
///
/// 跳过字符串字面量内的括号、跳过 `\"` 转义。
fn find_top_level_json(s: &str) -> Option<(usize, usize)> {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        match bytes[i] {
            b'{' | b'[' => {
                let open = bytes[i];
                let close = if open == b'{' { b'}' } else { b']' };
                if let Some(end) = find_matching_close(s, i, open, close) {
                    return Some((i, end));
                }
                return None;
            }
            _ => i += 1,
        }
    }
    None
}

/// 从 `start` 开始找匹配的 close 括号（深度搜索），跳过字符串字面量。
fn find_matching_close(s: &str, start: usize, open: u8, close: u8) -> Option<usize> {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut depth: i32 = 0;
    let mut i = start;

    while i < len {
        let b = bytes[i];
        match b {
            b'"' => {
                // 跳过字符串字面量（含 \" 转义）
                i += 1;
                while i < len && bytes[i] != b'"' {
                    if bytes[i] == b'\\' && i + 1 < len {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                i += 1; // skip closing "
            }
            x if x == open => {
                depth += 1;
                i += 1;
            }
            x if x == close => {
                if depth == 0 {
                    // 闭括号出现在开括号之前 → 输入有结构性错误
                    return None;
                }
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => i += 1,
        }
    }
    None
}

fn short_reason(arguments: &str) -> String {
    // 字符安全截断，避免在错误信息中再次触发 UTF-8 panic
    let preview = crate::util::text::truncate_utf8(arguments, 80);
    format!("could not extract valid JSON (input starts with: {preview:?})")
}

// ── make_incomplete_marker ───────────────────────────────────────────────

/// 构造 `TOOL_CALL_INCOMPLETE` marker JSON 字符串。
///
/// 工具执行器识别 marker（`params.error == "TOOL_CALL_INCOMPLETE"`）后跳过实际
/// 调用并把 `message` 字段作为 LLM 可见的工具结果返回。
///
/// `hint` 应来自 [`ResolvedArgs::hint`]，这样 LLM 下一轮能看到原始意图。
///
/// **关键修复**：旧版本的 marker 仅报"received N bytes"，原始内容被完全丢弃，
/// LLM 无法基于原文修复格式。新版本在 message 中透传 hint（截到 200 字符预览），
/// 包含"raw arguments"段落。
pub fn make_incomplete_marker(tool_name: &str, hint: &str) -> String {
    let message = build_message(tool_name, hint);
    serde_json::json!({
        "error": "TOOL_CALL_INCOMPLETE",
        "message": message,
    })
    .to_string()
}

/// 构造 marker 时仅知道原始字节长度（不知道全文），用此便利函数生成 stub hint。
///
/// 保留旧 `loop_llm::make_incomplete_marker(name, raw_len)` 的语义兼容性，
/// 后续应替换为 [`make_incomplete_marker`] 并传入真实 hint。
pub fn make_incomplete_marker_with_len(tool_name: &str, raw_len: usize) -> String {
    let stub =
        format!("<raw arguments were {raw_len} bytes; original content not preserved by caller>");
    make_incomplete_marker(tool_name, &stub)
}

fn build_message(tool_name: &str, hint: &str) -> String {
    // 字符安全截断：hint 可能含中文/emoji，不能用 `&hint[..200]`
    let preview = crate::util::text::Preview::new(hint, 200);
    format!(
        "Tool '{tool_name}' arguments were not parseable as JSON. \
         This call was NOT executed — do NOT retry with the same arguments. \
         Your original raw arguments are preserved below for reference; \
         please regenerate a strict JSON object matching the tool's parameter schema.\n\n\
         --- raw arguments ---\n{preview}\n--- end ---"
    )
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Valid ──────────────────────────────────────────────────────

    #[test]
    fn resolve_valid_object() {
        let args = r#"{"path": "foo.rs", "content": "hello"}"#;
        match resolve(args) {
            ResolvedArgs::Valid(v) => {
                assert_eq!(v["path"], "foo.rs");
                assert_eq!(v["content"], "hello");
            }
            other => panic!("expected Valid, got {other:?}"),
        }
        assert!(resolve(args).is_usable());
        assert!(!resolve(args).is_skip_marker());
    }

    #[test]
    fn resolve_valid_array() {
        let args = r#"[{"title": "todo 1"}, {"title": "todo 2"}]"#;
        match resolve(args) {
            ResolvedArgs::Valid(v) => {
                assert!(v.is_array());
                assert_eq!(v.as_array().unwrap().len(), 2);
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    // ── Recovered ───────────────────────────────────────────────────

    #[test]
    fn resolve_with_chinese_natural_language_prefix() {
        // 2026-08-24 线上真实场景：DeepSeek 在 JSON 前混入中文表达
        let args = r#"全景 + P0 的单一文档，还是拆分成 2 个文档？{"title": "ADR-057 文档结构确认", "merge": false}"#;
        match resolve(args) {
            ResolvedArgs::Recovered { value, hint } => {
                assert_eq!(value["title"], "ADR-057 文档结构确认");
                assert_eq!(value["merge"], false);
                assert!(hint.contains("全景"));
                assert!(hint.contains("拆分"));
            }
            other => panic!("expected Recovered, got {other:?}"),
        }
        assert!(resolve(args).is_usable());
    }

    #[test]
    fn resolve_with_newline_prefix() {
        let args = "考虑下：\n{\"key\": \"value\"}";
        match resolve(args) {
            ResolvedArgs::Recovered { value, .. } => {
                assert_eq!(value["key"], "value");
            }
            other => panic!("expected Recovered, got {other:?}"),
        }
    }

    #[test]
    fn resolve_with_duplicate_json() {
        // DeepSeek 已知问题：后续 chunk 重复发送完整 JSON
        let args = r#"{"path": "."}{"path": "."}"#;
        match resolve(args) {
            ResolvedArgs::Recovered { value, hint } => {
                assert_eq!(value["path"], ".");
                assert!(hint.contains(r#"{"path": "."}{"path": "."}"#));
            }
            other => panic!("expected Recovered, got {other:?}"),
        }
    }

    // ── Invalid ────────────────────────────────────────────────────

    #[test]
    fn resolve_truncated_json() {
        let args = r#"{"message": "hel"#;
        match resolve(args) {
            ResolvedArgs::Invalid { raw, reason } => {
                assert!(raw.contains("hel"));
                assert!(!reason.is_empty());
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
        assert!(resolve(args).is_skip_marker());
    }

    #[test]
    fn resolve_garbage() {
        assert!(matches!(
            resolve("not even JSON"),
            ResolvedArgs::Invalid { .. }
        ));
    }

    #[test]
    fn resolve_empty() {
        assert!(matches!(resolve(""), ResolvedArgs::Invalid { .. }));
    }

    // ── Edge cases ─────────────────────────────────────────────────

    #[test]
    fn resolve_object_with_nested_string_braces() {
        // JSON 字符串里包含 { 和 } 不能误判为嵌套 object
        let args = r#"{"content": "function foo() { return 1; }"}"#;
        match resolve(args) {
            ResolvedArgs::Valid(v) => assert!(v["content"].as_str().unwrap().contains("function")),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn resolve_object_with_escaped_quotes() {
        let args = r#"{"msg": "He said \"hello\" {nested}"}"#;
        match resolve(args) {
            ResolvedArgs::Valid(v) => assert!(v["msg"].as_str().unwrap().contains("nested")),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn resolve_object_with_unicode_in_string() {
        let args = r#"{"content": "中文测试字符串"}"#;
        match resolve(args) {
            ResolvedArgs::Valid(v) => {
                assert_eq!(v["content"], "中文测试字符串");
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn hint_preserves_chinese_text() {
        let args = "我建议：{\"command\": \"ls\"}";
        let resolved = resolve(args);
        let hint = resolved.hint().unwrap();
        assert!(hint.contains("我建议"));
        assert!(hint.contains("ls"));
    }

    // ── find_top_level_json 异常输入 ─────────────────────────────

    #[test]
    fn find_top_level_json_unbalanced_brace_inside_string() {
        // 字符串字面量里的 { 不算结构开括号
        let s = r#"{"a": "b{c"}"#;
        let (start, end) = find_top_level_json(s).unwrap();
        assert_eq!(&s[start..end], r#"{"a": "b{c"}"#);
    }

    #[test]
    fn find_top_level_json_close_brace_inside_string() {
        let s = r#"{"a": "b}c"}"#;
        let (start, end) = find_top_level_json(s).unwrap();
        assert_eq!(&s[start..end], r#"{"a": "b}c"}"#);
    }

    #[test]
    fn find_top_level_json_unclosed_string_returns_none() {
        // 字符串未闭合 → 找不到匹配 close → None（不 panic）
        assert!(find_top_level_json(r#"{"a": "b"#).is_none());
        assert!(find_top_level_json(r#"{"a": "b\"#).is_none());
    }

    #[test]
    fn find_top_level_json_unclosed_brackets_return_none() {
        assert!(find_top_level_json("{").is_none());
        assert!(find_top_level_json("{{{").is_none());
        assert!(find_top_level_json("[[").is_none());
        assert!(find_top_level_json(r#"[{"a": "b"},"#).is_none());
    }

    #[test]
    fn find_top_level_json_deep_nesting_still_finds_range() {
        // 1000 层嵌套：find_top_level_json 必须找到完整区间
        // （即使 serde 有 recursion limit，本函数也要正确识别范围）
        let s = format!("{}{}", "{".repeat(1000), "}".repeat(1000));
        let (start, end) = find_top_level_json(&s).unwrap();
        assert_eq!(&s[start..end], s);
    }

    #[test]
    fn find_top_level_json_multibyte_and_escapes_inside_string() {
        // 中文 + 转义引号 + 未配对大括号，全部位于字符串字面量内
        let s = "{\"content\": \"中文\\\"{c}测试\"}";
        let (start, end) = find_top_level_json(s).unwrap();
        assert_eq!(&s[start..end], s);
    }

    #[test]
    fn resolve_with_prefix_and_unclosed_json_is_invalid() {
        // DeepSeek 场景恶化版：自然语言前缀 + 截断 JSON → Invalid，不 panic
        let args = "考虑一下：{\"title\": \"没写完";
        let r = resolve(args);
        assert!(matches!(r, ResolvedArgs::Invalid { .. }));
        assert!(r.is_skip_marker());
    }

    // ── make_incomplete_marker ────────────────────────────────────

    #[test]
    fn marker_contains_error_and_message_fields() {
        let marker = make_incomplete_marker("file_write", "全景 + P0");
        let parsed: Value = serde_json::from_str(&marker).unwrap();
        assert_eq!(parsed["error"], "TOOL_CALL_INCOMPLETE");
        let message = parsed["message"].as_str().unwrap();
        assert!(message.contains("file_write"));
        assert!(message.contains("全景"));
        assert!(message.contains("NOT executed"));
    }

    #[test]
    fn marker_truncates_long_hint_safely() {
        // 关键回归：超长中文 hint 不能在 message 中再次触发 UTF-8 切片 panic
        let long_hint = "全景 + P0 的单一文档，还是拆分成 2 个文档？".repeat(5000);
        let marker = make_incomplete_marker("file_write", &long_hint);
        let parsed: Value = serde_json::from_str(&marker).unwrap();
        let message = parsed["message"].as_str().unwrap();
        // 必须是合法 UTF-8
        assert!(message.is_char_boundary(message.len()));
        assert!(message.contains("truncated"));
    }

    #[test]
    fn marker_with_len_legacy_compat() {
        let m = make_incomplete_marker_with_len("echo", 1234);
        let parsed: Value = serde_json::from_str(&m).unwrap();
        assert_eq!(parsed["error"], "TOOL_CALL_INCOMPLETE");
        let message = parsed["message"].as_str().unwrap();
        assert!(message.contains("echo"));
        assert!(message.contains("1234"));
        assert!(message.contains("NOT executed"));
    }

    #[test]
    fn marker_with_emoji_hint_does_not_panic() {
        let hint = "😀😁😂 + 中文 + ascii: hello world";
        let marker = make_incomplete_marker("file_write", hint);
        let parsed: Value = serde_json::from_str(&marker).unwrap();
        let message = parsed["message"].as_str().unwrap();
        assert!(message.contains("😀"));
    }
}
