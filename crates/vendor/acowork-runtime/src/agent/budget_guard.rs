//! Local budget pre-check
//!
//! Checks local token budget before making LLM calls.
//! Prevents unnecessary API calls when budget is exhausted.

use acowork_core::Budget;

/// Budget guard for local token estimation
pub struct BudgetGuard {
    /// Configured budget limits
    budget: Budget,
    /// Current session token usage
    session_tokens: u64,
    /// Current session cost in USD
    session_cost_usd: f64,
}

impl BudgetGuard {
    /// Create new budget guard with the given budget configuration
    pub fn new(budget: Budget) -> Self {
        Self {
            budget,
            session_tokens: 0,
            session_cost_usd: 0.0,
        }
    }

    /// Create a budget guard with no limits (unlimited)
    pub fn unlimited() -> Self {
        Self {
            budget: Budget {
                daily_tokens: None,
                monthly_tokens: None,
                daily_cost_usd: None,
                monthly_cost_usd: None,
                exceeded_action: "warn".to_string(),
            },
            session_tokens: 0,
            session_cost_usd: 0.0,
        }
    }

    /// Check if budget allows a new request with the given estimated tokens
    pub fn check(&self, estimated_tokens: u64) -> BudgetCheckResult {
        // Check daily token limit
        if let Some(daily_limit) = self.budget.daily_tokens
            && self.session_tokens + estimated_tokens > daily_limit
        {
            return BudgetCheckResult::Exceeded {
                reason: format!(
                    "Daily token limit: used {} + estimated {} > limit {}",
                    self.session_tokens, estimated_tokens, daily_limit
                ),
                action: self.budget.exceeded_action.clone(),
            };
        }

        // Check monthly token limit
        if let Some(monthly_limit) = self.budget.monthly_tokens
            && self.session_tokens + estimated_tokens > monthly_limit
        {
            return BudgetCheckResult::Exceeded {
                reason: format!(
                    "Monthly token limit: used {} + estimated {} > limit {}",
                    self.session_tokens, estimated_tokens, monthly_limit
                ),
                action: self.budget.exceeded_action.clone(),
            };
        }

        // Check daily cost limit
        if let Some(daily_cost) = self.budget.daily_cost_usd
            && self.session_cost_usd >= daily_cost
        {
            return BudgetCheckResult::Exceeded {
                reason: format!(
                    "Daily cost limit: ${:.4} >= ${:.4}",
                    self.session_cost_usd, daily_cost
                ),
                action: self.budget.exceeded_action.clone(),
            };
        }

        BudgetCheckResult::Allowed
    }

    /// Update usage after an LLM call
    pub fn update_usage(&mut self, tokens: u64, cost_usd: f64) {
        self.session_tokens += tokens;
        self.session_cost_usd += cost_usd;
    }

    /// Get current session token usage
    pub fn session_tokens(&self) -> u64 {
        self.session_tokens
    }

    /// Get current session cost
    pub fn session_cost_usd(&self) -> f64 {
        self.session_cost_usd
    }
}

/// Result of budget check
#[derive(Debug, Clone)]
pub enum BudgetCheckResult {
    /// Budget allows the request
    Allowed,
    /// Budget exceeded
    Exceeded {
        /// Why the budget was exceeded
        reason: String,
        /// What action to take ("deny", "warn", "fallback")
        action: String,
    },
}

impl BudgetCheckResult {
    /// Check if the request is allowed
    pub fn is_allowed(&self) -> bool {
        matches!(self, BudgetCheckResult::Allowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limited_budget() -> Budget {
        Budget {
            daily_tokens: Some(1000),
            monthly_tokens: Some(10000),
            daily_cost_usd: Some(1.0),
            monthly_cost_usd: Some(10.0),
            exceeded_action: "deny".to_string(),
        }
    }

    #[test]
    fn test_check_allowed() {
        let guard = BudgetGuard::new(limited_budget());
        let result = guard.check(100);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_check_exceeded_tokens() {
        let mut guard = BudgetGuard::new(limited_budget());
        guard.update_usage(950, 0.0);
        let result = guard.check(100);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_unlimited_budget() {
        let guard = BudgetGuard::unlimited();
        let result = guard.check(1_000_000);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_update_usage() {
        let mut guard = BudgetGuard::new(limited_budget());
        guard.update_usage(100, 0.05);
        assert_eq!(guard.session_tokens(), 100);
        assert!((guard.session_cost_usd() - 0.05).abs() < 0.001);
    }
}
