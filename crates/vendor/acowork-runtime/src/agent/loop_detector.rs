//! Loop detection (Exact Repeat / Ping-Pong / No Progress / Same-Tool Flood)
//!
//! Four detection modes + three-level progressive response.
//! Adapted from ZeroClaw agent/loop_detector.rs
//! ACowork deviation: uses acowork-core ToolCall types; result includes
//! recommended action level.
//! SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::{HashMap, VecDeque};

/// Normalize tool parameters to ensure consistent comparison across platforms.
///
/// - Parses and re-serializes JSON to remove whitespace differences.
/// - Falls back to normalizing path separators (`\` → `/`).
fn normalize_params(params: &str) -> String {
    // Try to normalize JSON
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(params)
        && let Ok(normalized) = serde_json::to_string(&json)
    {
        return normalized;
    }
    // Fallback: normalize path separators
    params.replace('\\', "/")
}

/// Loop detection result
#[derive(Debug, Clone)]
pub enum LoopDetectionResult {
    /// No loop detected
    NoLoop,
    /// Loop detected with a specific response level
    LoopDetected {
        /// Which pattern was detected
        pattern: LoopPattern,
        /// Response level (Warning / Block / Break)
        level: ResponseLevel,
        /// Count of consecutive hits
        count: u32,
        /// Human-readable message
        message: String,
    },
}

/// Loop pattern type
#[derive(Debug, Clone)]
pub enum LoopPattern {
    /// Same (tool_name, params) called consecutively
    ExactRepeat,
    /// Two tools alternating A→B→A→B
    PingPong,
    /// Same tool, different params, but same result hash
    NoProgress,
    /// Same tool called repeatedly within a window
    SameToolFlood,
}

/// Progressive response level
#[derive(Debug, Clone, PartialEq)]
pub enum ResponseLevel {
    /// First hit: inject warning, continue
    Warning,
    /// Second hit: block the tool call, continue
    Block,
    /// Third hit: break the loop, terminate iteration
    Break,
}

/// Configuration for loop detection thresholds
#[derive(Debug, Clone)]
pub struct LoopDetectionConfig {
    /// Exact Repeat: consecutive identical calls threshold
    pub exact_repeat_threshold: u32,
    /// Ping-Pong: alternating cycle threshold
    pub ping_pong_threshold: u32,
    /// No Progress: same result hash threshold
    pub no_progress_threshold: u32,
    /// Whether No Progress detection is enabled
    pub no_progress_enabled: bool,
    /// Same-Tool Flood: number of same-tool calls in window to trigger
    pub same_tool_flood_threshold: u32,
    /// Same-Tool Flood: window size for counting tool calls
    pub same_tool_flood_window: u32,
}

impl Default for LoopDetectionConfig {
    fn default() -> Self {
        Self {
            exact_repeat_threshold: 3,
            ping_pong_threshold: 4,
            no_progress_threshold: 5,
            no_progress_enabled: true,
            same_tool_flood_threshold: 8,
            same_tool_flood_window: 12,
        }
    }
}

/// Loop detector
pub struct LoopDetector {
    config: LoopDetectionConfig,
    /// Track consecutive identical (tool_name, params) calls
    exact_repeat_state: ExactRepeatState,
    /// Track alternating A→B pattern
    ping_pong_state: PingPongState,
    /// Track same tool + same result hash
    no_progress_state: NoProgressState,
    /// Recent tool call window for Same-Tool Flood detection
    tool_call_window: VecDeque<String>,
    /// Per-pattern hit count (for progressive response)
    hit_counts: HashMap<String, u32>,
}

#[derive(Default)]
struct ExactRepeatState {
    last_signature: Option<String>,
    count: u32,
}

#[derive(Default)]
struct PingPongState {
    history: Vec<String>, // last N tool names
}

#[derive(Default)]
struct NoProgressState {
    tool_name: Option<String>,
    result_hashes: Vec<u64>,
    consecutive_same: u32,
}

impl LoopDetector {
    /// Create new loop detector with configuration
    pub fn new(config: LoopDetectionConfig) -> Self {
        Self {
            config,
            exact_repeat_state: ExactRepeatState::default(),
            ping_pong_state: PingPongState::default(),
            no_progress_state: NoProgressState::default(),
            tool_call_window: VecDeque::new(),
            hit_counts: HashMap::new(),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(LoopDetectionConfig::default())
    }

    /// Peek-check whether the next tool call would trigger a loop without modifying state.
    ///
    /// Used for pre-execution blocking: if this returns `Block` or `Break`,
    /// the caller should skip execution and return an error result instead.
    pub fn peek_check(&self, tool_name: &str, params: &str) -> LoopDetectionResult {
        self.peek_exact_repeat(tool_name, params)
            .or_else(|| self.peek_ping_pong(tool_name))
            .unwrap_or(LoopDetectionResult::NoLoop)
    }

    /// Check the latest tool call for loop patterns
    /// Call this after step ⑥ (append to history)
    pub fn check(
        &mut self,
        tool_name: &str,
        params: &str,
        result_content: &str,
    ) -> LoopDetectionResult {
        // Check Exact Repeat
        if let Some(result) = self.check_exact_repeat(tool_name, params) {
            return result;
        }

        // Check Ping-Pong
        if let Some(result) = self.check_ping_pong(tool_name) {
            return result;
        }

        // Check No Progress
        if self.config.no_progress_enabled
            && let Some(result) = self.check_no_progress(tool_name, result_content)
        {
            return result;
        }

        // Same-Tool Flood detection is disabled by design decision:
        // max_iterations + user continue button serves as the safety net.
        // The check_same_tool_flood() method is retained for potential future use.

        // Reset hit counters if no loop detected (different tool used successfully)
        // Only reset for patterns not currently being tracked

        LoopDetectionResult::NoLoop
    }

    /// Peek exact-repeat detection without modifying state.
    fn peek_exact_repeat(&self, tool_name: &str, params: &str) -> Option<LoopDetectionResult> {
        let params = normalize_params(params);
        let signature = format!("{tool_name}:{params}");

        if self.exact_repeat_state.last_signature.as_ref() == Some(&signature)
            && self.exact_repeat_state.count >= self.config.exact_repeat_threshold
        {
            let key = "exact_repeat";
            let hit_val = self.hit_counts.get(key).copied().unwrap_or(0) + 1;
            let level = self.response_level(hit_val);
            let message = format!(
                "Detected repeated call to [{tool_name}] with same parameters ({hit_val} consecutive hits)"
            );

            return Some(LoopDetectionResult::LoopDetected {
                pattern: LoopPattern::ExactRepeat,
                level,
                count: self.exact_repeat_state.count,
                message,
            });
        }

        None
    }

    /// Peek ping-pong detection without modifying state.
    fn peek_ping_pong(&self, tool_name: &str) -> Option<LoopDetectionResult> {
        // Simulate adding the current tool name
        let mut simulated_history = self.ping_pong_state.history.clone();
        simulated_history.push(tool_name.to_string());

        let max_len = (self.config.ping_pong_threshold * 2) as usize;
        if simulated_history.len() > max_len {
            let drain_count = simulated_history.len() - max_len;
            simulated_history.drain(0..drain_count);
        }

        if simulated_history.len() >= 4 {
            let len = simulated_history.len();
            let a = &simulated_history[len - 4];
            let b = &simulated_history[len - 3];
            let c = &simulated_history[len - 2];
            let d = &simulated_history[len - 1];

            if a == c && b == d && a != b {
                let cycles = self.count_ping_pong_cycles(&simulated_history);
                if cycles >= self.config.ping_pong_threshold {
                    let key = "ping_pong";
                    let hit_val = self.hit_counts.get(key).copied().unwrap_or(0) + 1;
                    let level = self.response_level(hit_val);
                    let message =
                        format!("Detected ping-pong between [{a}] and [{b}] ({cycles} cycles)");

                    return Some(LoopDetectionResult::LoopDetected {
                        pattern: LoopPattern::PingPong,
                        level,
                        count: cycles,
                        message,
                    });
                }
            }
        }

        None
    }

    fn check_exact_repeat(&mut self, tool_name: &str, params: &str) -> Option<LoopDetectionResult> {
        let params = normalize_params(params);
        let signature = format!("{tool_name}:{params}");

        if self.exact_repeat_state.last_signature.as_ref() == Some(&signature) {
            self.exact_repeat_state.count += 1;
        } else {
            self.exact_repeat_state.last_signature = Some(signature.clone());
            self.exact_repeat_state.count = 1;
        }

        if self.exact_repeat_state.count >= self.config.exact_repeat_threshold {
            let key = "exact_repeat";
            let hit_val = {
                let hit_count = self.hit_counts.entry(key.to_string()).or_insert(0);
                *hit_count += 1;
                *hit_count
            };

            let level = self.response_level(hit_val);
            let message = format!(
                "Detected repeated call to [{tool_name}] with same parameters ({hit_val} consecutive hits)"
            );

            // Do NOT reset count and signature — escalation should continue
            // on subsequent identical calls. Only increment hit_counts.

            return Some(LoopDetectionResult::LoopDetected {
                pattern: LoopPattern::ExactRepeat,
                level,
                count: self.exact_repeat_state.count,
                message,
            });
        }

        None
    }

    fn check_ping_pong(&mut self, tool_name: &str) -> Option<LoopDetectionResult> {
        self.ping_pong_state.history.push(tool_name.to_string());

        // Keep only last N entries (2 * threshold)
        let max_len = (self.config.ping_pong_threshold * 2) as usize;
        if self.ping_pong_state.history.len() > max_len {
            let drain_count = self.ping_pong_state.history.len() - max_len;
            self.ping_pong_state.history.drain(0..drain_count);
        }

        // Check for A→B→A→B pattern
        let history = &self.ping_pong_state.history;
        if history.len() >= 4 {
            let len = history.len();
            let a = &history[len - 4];
            let b = &history[len - 3];
            let c = &history[len - 2];
            let d = &history[len - 1];

            // A==C, B==D, A!=B
            if a == c && b == d && a != b {
                // Count complete cycles
                let cycles = self.count_ping_pong_cycles(history);
                if cycles >= self.config.ping_pong_threshold {
                    let key = "ping_pong";
                    let hit_val = {
                        let hit_count = self.hit_counts.entry(key.to_string()).or_insert(0);
                        *hit_count += 1;
                        *hit_count
                    };

                    let level = self.response_level(hit_val);
                    let message =
                        format!("Detected ping-pong between [{a}] and [{b}] ({cycles} cycles)");

                    self.ping_pong_state.history.clear();

                    return Some(LoopDetectionResult::LoopDetected {
                        pattern: LoopPattern::PingPong,
                        level,
                        count: cycles,
                        message,
                    });
                }
            }
        }

        None
    }

    fn count_ping_pong_cycles(&self, history: &[String]) -> u32 {
        if history.len() < 2 {
            return 0;
        }

        let mut cycles = 0u32;
        let mut i = 0;
        while i + 1 < history.len() {
            if i + 2 < history.len() && history[i] == history[i + 2] {
                cycles += 1;
                i += 2;
            } else {
                break;
            }
        }
        cycles
    }

    fn check_no_progress(
        &mut self,
        tool_name: &str,
        result_content: &str,
    ) -> Option<LoopDetectionResult> {
        let result_hash = self.simple_hash(result_content);

        match &self.no_progress_state.tool_name {
            Some(name) if name == tool_name => {
                // Same tool — check if result hash is same
                if let Some(&last_hash) = self.no_progress_state.result_hashes.last() {
                    if last_hash == result_hash {
                        self.no_progress_state.consecutive_same += 1;
                    } else {
                        self.no_progress_state.consecutive_same = 0;
                    }
                }
                self.no_progress_state.result_hashes.push(result_hash);

                if self.no_progress_state.consecutive_same >= self.config.no_progress_threshold {
                    let key = "no_progress";
                    let hit_val = {
                        let hit_count = self.hit_counts.entry(key.to_string()).or_insert(0);
                        *hit_count += 1;
                        *hit_count
                    };

                    let level = self.response_level(hit_val);
                    let message = format!(
                        "Detected no progress: [{tool_name}] returns same result repeatedly ({hit_val} hits)"
                    );

                    self.no_progress_state = NoProgressState::default();

                    return Some(LoopDetectionResult::LoopDetected {
                        pattern: LoopPattern::NoProgress,
                        level,
                        count: self.no_progress_state.consecutive_same,
                        message,
                    });
                }
            }
            _ => {
                // Different tool — reset
                self.no_progress_state = NoProgressState {
                    tool_name: Some(tool_name.to_string()),
                    result_hashes: vec![result_hash],
                    consecutive_same: 0,
                };
            }
        }

        None
    }

    /// Peek same-tool flood detection without modifying state.
    #[allow(dead_code)]
    fn peek_same_tool_flood(&self, tool_name: &str) -> Option<LoopDetectionResult> {
        let mut simulated_window = self.tool_call_window.clone();
        simulated_window.push_back(tool_name.to_string());
        let window_size = self.config.same_tool_flood_window as usize;
        while simulated_window.len() > window_size {
            simulated_window.pop_front();
        }

        let count = simulated_window.iter().filter(|t| *t == tool_name).count() as u32;

        if count >= self.config.same_tool_flood_threshold {
            let level = if count >= self.config.same_tool_flood_threshold + 2 {
                ResponseLevel::Block
            } else {
                ResponseLevel::Warning
            };
            let message = format!(
                "Detected same-tool flood: [{tool_name}] called {count} times in last {} calls",
                simulated_window.len()
            );

            return Some(LoopDetectionResult::LoopDetected {
                pattern: LoopPattern::SameToolFlood,
                level,
                count,
                message,
            });
        }

        None
    }

    /// Check same-tool flood detection.
    #[allow(dead_code)]
    fn check_same_tool_flood(&mut self, tool_name: &str) -> Option<LoopDetectionResult> {
        self.tool_call_window.push_back(tool_name.to_string());
        let window_size = self.config.same_tool_flood_window as usize;
        while self.tool_call_window.len() > window_size {
            self.tool_call_window.pop_front();
        }

        let count = self
            .tool_call_window
            .iter()
            .filter(|t| *t == tool_name)
            .count() as u32;

        if count >= self.config.same_tool_flood_threshold {
            let level = if count >= self.config.same_tool_flood_threshold + 2 {
                ResponseLevel::Block
            } else {
                ResponseLevel::Warning
            };
            let message = format!(
                "Detected same-tool flood: [{tool_name}] called {count} times in last {} calls",
                self.tool_call_window.len()
            );

            return Some(LoopDetectionResult::LoopDetected {
                pattern: LoopPattern::SameToolFlood,
                level,
                count,
                message,
            });
        }

        None
    }

    /// Determine response level based on hit count
    fn response_level(&self, hit_count: u32) -> ResponseLevel {
        match hit_count {
            1 => ResponseLevel::Warning,
            2 => ResponseLevel::Block,
            _ => ResponseLevel::Break,
        }
    }

    /// Simple hash for result content (FNV-like)
    fn simple_hash(&self, s: &str) -> u64 {
        // Use first 256 chars + length for hash
        let content: String = s.chars().take(256).collect();
        let mut hash: u64 = 14695981039346656037; // FNV offset basis
        for byte in content.bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(1099511628211); // FNV prime
        }
        hash ^= s.len() as u64;
        hash
    }

    /// Reset all detection state (e.g., when conversation starts)
    pub fn reset(&mut self) {
        self.exact_repeat_state = ExactRepeatState::default();
        self.ping_pong_state = PingPongState::default();
        self.no_progress_state = NoProgressState::default();
        self.tool_call_window.clear();
        self.hit_counts.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_repeat_warning() {
        let mut detector = LoopDetector::with_defaults();

        // 3 identical calls (threshold = 3)
        let result1 = detector.check("weather", "{city:Shanghai}", "Sunny");
        assert!(matches!(result1, LoopDetectionResult::NoLoop));

        let result2 = detector.check("weather", "{city:Shanghai}", "Sunny");
        assert!(matches!(result2, LoopDetectionResult::NoLoop));

        let result3 = detector.check("weather", "{city:Shanghai}", "Sunny");
        if let LoopDetectionResult::LoopDetected { level, pattern, .. } = &result3 {
            assert!(matches!(pattern, LoopPattern::ExactRepeat));
            assert_eq!(*level, ResponseLevel::Warning); // First hit = Warning
        } else {
            panic!("Expected LoopDetected, got {result3:?}");
        }
    }

    #[test]
    fn test_exact_repeat_escalation() {
        let mut detector = LoopDetector::with_defaults();

        // First detection
        for _ in 0..3 {
            detector.check("weather", "{city:Shanghai}", "Sunny");
        }
        // Reset state between detections (simulates different iterations)
        // Second detection
        for _ in 0..3 {
            detector.check("weather", "{city:Shanghai}", "Sunny");
        }
        let _result = detector.check("weather", "{city:Shanghai}", "Sunny");
        let _result = detector.check("weather", "{city:Shanghai}", "Sunny");
        let result = detector.check("weather", "{city:Shanghai}", "Sunny");
        if let LoopDetectionResult::LoopDetected { level, .. } = &result {
            assert_eq!(*level, ResponseLevel::Break); // Third hit = Break
        }
    }

    #[test]
    fn test_no_loop_different_tools() {
        let mut detector = LoopDetector::with_defaults();

        let result = detector.check("weather", "{city:Shanghai}", "Sunny");
        assert!(matches!(result, LoopDetectionResult::NoLoop));

        let result = detector.check("calculator", "{expr:2+2}", "4");
        assert!(matches!(result, LoopDetectionResult::NoLoop));
    }

    #[test]
    fn test_simple_hash_deterministic() {
        let detector = LoopDetector::with_defaults();
        let h1 = detector.simple_hash("hello world");
        let h2 = detector.simple_hash("hello world");
        assert_eq!(h1, h2);

        let h3 = detector.simple_hash("hello earth");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_reset() {
        let mut detector = LoopDetector::with_defaults();
        detector.check("weather", "{city:Shanghai}", "Sunny");
        detector.reset();
        // After reset, should not trigger
        let result = detector.check("weather", "{city:Shanghai}", "Sunny");
        assert!(matches!(result, LoopDetectionResult::NoLoop));
    }

    #[test]
    #[ignore = "Same-Tool Flood detection is disabled by design decision"]
    fn test_same_tool_flood_detection() {
        let mut detector = LoopDetector::with_defaults();

        // Use different parameters to avoid triggering Exact Repeat
        // First 7 calls: count < threshold (8) -> NoLoop
        for i in 1..=7 {
            let result = detector.check("flood_tool", &format!("p{i}"), &format!("r{i}"));
            assert!(
                matches!(result, LoopDetectionResult::NoLoop),
                "Expected NoLoop at call {i}, got {result:?}"
            );
        }

        // 8th call: count == threshold (8) -> Warning
        let result = detector.check("flood_tool", "p8", "r8");
        if let LoopDetectionResult::LoopDetected { level, pattern, .. } = &result {
            assert!(matches!(pattern, LoopPattern::SameToolFlood));
            assert_eq!(*level, ResponseLevel::Warning);
        } else {
            panic!("Expected SameToolFlood Warning, got {result:?}");
        }

        // 9th call: count == 9 -> still Warning (9 < 8 + 2)
        let result = detector.check("flood_tool", "p9", "r9");
        if let LoopDetectionResult::LoopDetected { level, pattern, .. } = &result {
            assert!(matches!(pattern, LoopPattern::SameToolFlood));
            assert_eq!(*level, ResponseLevel::Warning);
        } else {
            panic!("Expected SameToolFlood Warning, got {result:?}");
        }

        // 10th call: count == 10 -> Block (10 >= 8 + 2)
        let result = detector.check("flood_tool", "p10", "r10");
        if let LoopDetectionResult::LoopDetected { level, pattern, .. } = &result {
            assert!(matches!(pattern, LoopPattern::SameToolFlood));
            assert_eq!(*level, ResponseLevel::Block);
        } else {
            panic!("Expected SameToolFlood Block, got {result:?}");
        }
    }

    #[test]
    #[ignore = "Same-Tool Flood detection is disabled by design decision"]
    fn test_same_tool_flood_below_threshold() {
        let mut detector = LoopDetector::with_defaults();

        // 7 calls, threshold is 8 -> no trigger
        for i in 1..=7 {
            let result = detector.check("tool", &format!("p{i}"), &format!("r{i}"));
            assert!(
                matches!(result, LoopDetectionResult::NoLoop),
                "Expected NoLoop at call {i}, got {result:?}"
            );
        }
    }

    #[test]
    #[ignore = "Same-Tool Flood detection is disabled by design decision"]
    fn test_same_tool_flood_mixed_tools() {
        let mut detector = LoopDetector::with_defaults();

        // Alternate between two tools for 6 calls
        for i in 0..6 {
            let tool = if i % 2 == 0 { "tool_a" } else { "tool_b" };
            let result = detector.check(tool, &format!("p{i}"), &format!("r{i}"));
            assert!(
                matches!(result, LoopDetectionResult::NoLoop),
                "Failed at iteration {i}: {result:?}"
            );
        }
    }

    #[test]
    fn test_no_progress_detection() {
        let mut detector = LoopDetector::with_defaults();

        // 1st call: initializes no-progress state
        let result = detector.check("tool", "p1", "same_result");
        assert!(matches!(result, LoopDetectionResult::NoLoop));

        // 2nd call: consecutive_same = 1
        let result = detector.check("tool", "p2", "same_result");
        assert!(matches!(result, LoopDetectionResult::NoLoop));

        // 3rd call: consecutive_same = 2
        let result = detector.check("tool", "p3", "same_result");
        assert!(matches!(result, LoopDetectionResult::NoLoop));

        // 4th call: consecutive_same = 3
        let result = detector.check("tool", "p4", "same_result");
        assert!(matches!(result, LoopDetectionResult::NoLoop));

        // 5th call: consecutive_same = 4
        let result = detector.check("tool", "p5", "same_result");
        assert!(matches!(result, LoopDetectionResult::NoLoop));

        // 6th call: consecutive_same = 5 >= threshold(5), triggers NoProgress
        let result = detector.check("tool", "p6", "same_result");
        if let LoopDetectionResult::LoopDetected { pattern, .. } = &result {
            assert!(matches!(pattern, LoopPattern::NoProgress));
        } else {
            panic!("Expected NoProgress at 6th call, got {result:?}");
        }
    }
}
