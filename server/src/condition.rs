use crate::protocol::{LocalVar, RegValue};

// ---------------------------------------------------------------------------
// Condition types
// ---------------------------------------------------------------------------

/// Action to take when a breakpoint fires (used for intercept hooks).
#[derive(Debug, Clone)]
pub enum BreakpointAction {
    /// Log the hit and auto-continue without pausing.
    LogAndContinue,
    /// ForceEarlyReturn with value and auto-continue. -1 = void.
    ForceReturn(i32),
}

pub const FORCE_RETURN_VOID: i32 = -1;
/// Sentinel: auto-detect return value from method signature at hit time.
pub const FORCE_RETURN_AUTO: i32 = -2;

/// Pick a neutral return value based on the JNI method signature.
/// Returns FORCE_RETURN_VOID for V, 0 (false/zero/null) for everything else.
pub fn neutral_return_for_sig(sig: &str) -> i32 {
    let ret_char = sig.find(')').and_then(|i| sig[i + 1..].chars().next());
    match ret_char {
        Some('V') => FORCE_RETURN_VOID,
        _ => 0,
    }
}

/// Parse an action string into a BreakpointAction.
pub fn parse_action(s: &str) -> Option<BreakpointAction> {
    match s {
        "log-continue" | "log" => Some(BreakpointAction::LogAndContinue),
        "force-return-void" | "frv" => Some(BreakpointAction::ForceReturn(FORCE_RETURN_VOID)),
        "force-return-0" | "fr0" => Some(BreakpointAction::ForceReturn(0)),
        "force-return-1" | "fr1" => Some(BreakpointAction::ForceReturn(1)),
        _ => None,
    }
}

/// A breakpoint condition attached to a breakpoint.
#[derive(Debug, Clone)]
pub struct BreakpointCondition {
    pub hit_condition: Option<HitCondition>,
    pub var_condition: Option<CondExpr>,
    pub hit_count: u32,
    pub action: Option<BreakpointAction>,
}

#[derive(Debug, Clone)]
pub enum HitCondition {
    /// Break on exactly the Nth hit.
    Count(u32),
    /// Break every Nth hit.
    Every(u32),
}

#[derive(Debug, Clone)]
pub struct CondExpr {
    pub lhs: CondOperand,
    pub op: CondOp,
    pub rhs: CondOperand,
}

#[derive(Debug, Clone)]
pub enum CondOperand {
    /// Named local variable (e.g. "algo", "this", "arg0").
    VarName(String),
    /// Register slot (e.g. v0, v2).
    RegSlot(i32),
    /// String literal (e.g. "AES").
    StringLit(String),
    /// Integer literal (e.g. 42).
    IntLit(i64),
    /// null keyword.
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CondOp {
    Eq,       // ==
    Ne,       // !=
    Contains, // ~
    Lt,       // <
    Gt,       // >
    Le,       // <=
    Ge,       // >=
}

impl BreakpointCondition {
    pub fn new(hit: Option<HitCondition>, var: Option<CondExpr>) -> Self {
        Self {
            hit_condition: hit,
            var_condition: var,
            hit_count: 0,
            action: None,
        }
    }

    pub fn for_action(action: BreakpointAction) -> Self {
        Self {
            hit_condition: None,
            var_condition: None,
            hit_count: 0,
            action: Some(action),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.hit_condition.is_none() && self.var_condition.is_none() && self.action.is_none()
    }

}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

impl std::fmt::Display for HitCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HitCondition::Count(n) => write!(f, "hits={}", n),
            HitCondition::Every(n) => write!(f, "every={}", n),
        }
    }
}

impl std::fmt::Display for BreakpointCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        match &self.hit_condition {
            Some(HitCondition::Count(n)) => parts.push(format!("hits={}", n)),
            Some(HitCondition::Every(n)) => parts.push(format!("every={}", n)),
            None => {}
        }
        if let Some(expr) = &self.var_condition {
            parts.push(format!("when {}", expr));
        }
        if let Some(action) = &self.action {
            parts.push(format!("action={}", action));
        }
        write!(f, "{}", parts.join(" "))
    }
}

impl std::fmt::Display for BreakpointAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BreakpointAction::LogAndContinue => write!(f, "log-continue"),
            BreakpointAction::ForceReturn(FORCE_RETURN_VOID) => write!(f, "force-return-void"),
            BreakpointAction::ForceReturn(v) => write!(f, "force-return-{}", v),
        }
    }
}

impl std::fmt::Display for CondExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.lhs, self.op, self.rhs)
    }
}

impl std::fmt::Display for CondOperand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CondOperand::VarName(s) => write!(f, "{}", s),
            CondOperand::RegSlot(n) => write!(f, "v{}", n),
            CondOperand::StringLit(s) => write!(f, "\"{}\"", s),
            CondOperand::IntLit(n) => write!(f, "{}", n),
            CondOperand::Null => write!(f, "null"),
        }
    }
}

impl std::fmt::Display for CondOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CondOp::Eq => write!(f, "=="),
            CondOp::Ne => write!(f, "!="),
            CondOp::Contains => write!(f, "~"),
            CondOp::Lt => write!(f, "<"),
            CondOp::Gt => write!(f, ">"),
            CondOp::Le => write!(f, "<="),
            CondOp::Ge => write!(f, ">="),
        }
    }
}

// ---------------------------------------------------------------------------
// Parser: extract --hits N, --every N, --when "expr" from argument list
// ---------------------------------------------------------------------------

/// Parse condition flags from an argument string.
/// Returns (cleaned_args_without_flags, Option<BreakpointCondition>).
/// The cleaned args can be passed to parse_command() for bp_set.
pub fn parse_condition_flags(args: &str) -> Result<(String, Option<BreakpointCondition>), String> {
    let mut hit_cond: Option<HitCondition> = None;
    let mut var_cond: Option<CondExpr> = None;
    let mut action: Option<BreakpointAction> = None;
    let mut clean_parts: Vec<&str> = Vec::new();

    let parts: Vec<&str> = args.split_whitespace().collect();
    let mut i = 0;
    while i < parts.len() {
        match parts[i] {
            "--hits" => {
                i += 1;
                if i >= parts.len() {
                    return Err("--hits requires a number".into());
                }
                let n: u32 = parts[i].parse().map_err(|_| "--hits value must be a positive integer")?;
                if n == 0 {
                    return Err("--hits value must be >= 1".into());
                }
                hit_cond = Some(HitCondition::Count(n));
            }
            "--every" => {
                i += 1;
                if i >= parts.len() {
                    return Err("--every requires a number".into());
                }
                let n: u32 = parts[i].parse().map_err(|_| "--every value must be a positive integer")?;
                if n == 0 {
                    return Err("--every value must be >= 1".into());
                }
                hit_cond = Some(HitCondition::Every(n));
            }
            "--when" => {
                i += 1;
                if i >= parts.len() {
                    return Err("--when requires an expression".into());
                }
                // Collect the rest as the expression (it may contain spaces in quotes)
                let expr_str = collect_when_expr(&parts[i..]);
                var_cond = Some(parse_cond_expr(&expr_str)?);
                // Skip all tokens consumed by the expression
                break; // --when consumes the rest
            }
            "--action" => {
                i += 1;
                if i >= parts.len() {
                    return Err("--action requires a value (log-continue, force-return-void, force-return-0, force-return-1)".into());
                }
                action = Some(parse_action(parts[i]).ok_or_else(|| {
                    format!("unknown --action '{}'. Use: log-continue, force-return-void, force-return-0, force-return-1", parts[i])
                })?);
            }
            _ => {
                clean_parts.push(parts[i]);
            }
        }
        i += 1;
    }

    let clean = clean_parts.join(" ");
    if hit_cond.is_none() && var_cond.is_none() && action.is_none() {
        Ok((clean, None))
    } else {
        let mut cond = BreakpointCondition::new(hit_cond, var_cond);
        cond.action = action;
        Ok((clean, Some(cond)))
    }
}

/// Collect all remaining tokens as the --when expression string.
/// The user typically writes `--when "expr"`, so split_whitespace breaks
/// the quoted expr across tokens (e.g. `["\"v0", "==", "1\""]`).
/// We join them back and strip the outer quotes.
fn collect_when_expr(tokens: &[&str]) -> String {
    let joined = tokens.join(" ");
    // Strip outer double-quotes (may be literal or escaped)
    let trimmed = joined.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        return trimmed[1..trimmed.len() - 1].to_string();
    }
    if trimmed.starts_with("\\\"") && trimmed.ends_with("\\\"") && trimmed.len() >= 4 {
        return trimmed[2..trimmed.len() - 2].to_string();
    }
    joined
}

/// Parse a condition expression like: name == "AES", v0 > 5, arg0 ~ "evil"
pub fn parse_cond_expr(expr: &str) -> Result<CondExpr, String> {
    let expr = expr.trim();
    if expr.is_empty() {
        return Err("empty condition expression".into());
    }

    // Find operator position  - try two-char ops first, then single-char
    let (lhs_str, op, rhs_str) = split_expr(expr)?;

    let lhs = parse_operand(lhs_str.trim())?;
    let rhs = parse_operand(rhs_str.trim())?;

    Ok(CondExpr { lhs, op, rhs })
}

/// Split expression on operator.
fn split_expr(expr: &str) -> Result<(&str, CondOp, &str), String> {
    // Try two-char operators first
    for (pat, op) in &[("==", CondOp::Eq), ("!=", CondOp::Ne), ("<=", CondOp::Le), (">=", CondOp::Ge)] {
        if let Some(pos) = expr.find(pat) {
            let lhs = &expr[..pos];
            let rhs = &expr[pos + pat.len()..];
            if !lhs.trim().is_empty() && !rhs.trim().is_empty() {
                return Ok((lhs, *op, rhs));
            }
        }
    }

    // Single-char operators (but not inside quotes)
    for (ch, op) in &[('~', CondOp::Contains), ('<', CondOp::Lt), ('>', CondOp::Gt)] {
        // Find the operator outside of quotes (double or single)
        let mut in_quote = false;
        let mut quote_char = '"';
        for (i, c) in expr.char_indices() {
            if !in_quote && (c == '"' || c == '\'') {
                in_quote = true;
                quote_char = c;
            } else if in_quote && c == quote_char {
                in_quote = false;
            } else if c == *ch && !in_quote {
                let lhs = &expr[..i];
                let rhs = &expr[i + 1..];
                if !lhs.trim().is_empty() && !rhs.trim().is_empty() {
                    return Ok((lhs, *op, rhs));
                }
            }
        }
    }

    Err(format!("no operator found in expression: {}. Use ==, !=, ~, <, >, <=, >=", expr))
}

/// Parse an operand: variable name, register slot, string literal, integer, or null.
fn parse_operand(s: &str) -> Result<CondOperand, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty operand".into());
    }

    // null
    if s == "null" {
        return Ok(CondOperand::Null);
    }

    // String literal: "...", '...', or escaped \"...\"
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        let inner = &s[1..s.len() - 1];
        return Ok(CondOperand::StringLit(inner.to_string()));
    }
    if s.starts_with("\\\"") && s.ends_with("\\\"") && s.len() >= 4 {
        let inner = &s[2..s.len() - 2];
        return Ok(CondOperand::StringLit(inner.to_string()));
    }

    // Register slot: v0, v1, ...
    if s.starts_with('v') && s.len() > 1 && s[1..].chars().all(|c| c.is_ascii_digit()) {
        let n: i32 = s[1..].parse().map_err(|_| format!("invalid register: {}", s))?;
        return Ok(CondOperand::RegSlot(n));
    }

    // Integer literal (including negative)
    if let Ok(n) = s.parse::<i64>() {
        return Ok(CondOperand::IntLit(n));
    }

    // Variable name (any remaining identifier)
    if s.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Ok(CondOperand::VarName(s.to_string()));
    }

    Err(format!("invalid operand: {}", s))
}

// ---------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------

/// Evaluate a hit condition. Returns true if the breakpoint should fire.
pub fn evaluate_hit_condition(cond: &HitCondition, hit_count: u32) -> bool {
    match cond {
        HitCondition::Count(n) => hit_count == *n,
        HitCondition::Every(n) => *n > 0 && hit_count % *n == 0,
    }
}

/// Evaluate a variable condition against locals and registers.
/// Returns true if the condition is satisfied.
pub fn evaluate_var_condition(expr: &CondExpr, locals: &[LocalVar], regs: &[RegValue]) -> bool {
    let lhs_val = resolve_operand(&expr.lhs, locals, regs);
    let rhs_val = resolve_operand(&expr.rhs, locals, regs);

    match (&lhs_val, &rhs_val) {
        (ResolvedValue::String(a), ResolvedValue::String(b)) => match expr.op {
            CondOp::Eq => a == b,
            CondOp::Ne => a != b,
            CondOp::Contains => a.contains(b.as_str()),
            CondOp::Lt => a < b,
            CondOp::Gt => a > b,
            CondOp::Le => a <= b,
            CondOp::Ge => a >= b,
        },
        (ResolvedValue::Int(a), ResolvedValue::Int(b)) => match expr.op {
            CondOp::Eq => a == b,
            CondOp::Ne => a != b,
            CondOp::Lt => a < b,
            CondOp::Gt => a > b,
            CondOp::Le => a <= b,
            CondOp::Ge => a >= b,
            CondOp::Contains => false,
        },
        (ResolvedValue::Null, ResolvedValue::Null) => match expr.op {
            CondOp::Eq => true,
            CondOp::Ne => false,
            _ => false,
        },
        (_, ResolvedValue::Null) | (ResolvedValue::Null, _) => match expr.op {
            CondOp::Eq => false,
            CondOp::Ne => true,
            _ => false,
        },
        // String vs Int: try parsing string as int for comparison
        (ResolvedValue::String(s), ResolvedValue::Int(n)) => {
            if let Ok(sn) = s.parse::<i64>() {
                eval_int_op(sn, *n, expr.op)
            } else {
                // String contains for int: check if string contains the int as text
                match expr.op {
                    CondOp::Contains => s.contains(&n.to_string()),
                    CondOp::Eq => false,
                    CondOp::Ne => true,
                    _ => false,
                }
            }
        }
        (ResolvedValue::Int(n), ResolvedValue::String(s)) => {
            if let Ok(sn) = s.parse::<i64>() {
                eval_int_op(*n, sn, expr.op)
            } else {
                match expr.op {
                    CondOp::Eq => false,
                    CondOp::Ne => true,
                    _ => false,
                }
            }
        }
        (ResolvedValue::Unknown, _) | (_, ResolvedValue::Unknown) => {
            // Can't resolve operand  - default to not matching
            false
        }
    }
}

fn eval_int_op(a: i64, b: i64, op: CondOp) -> bool {
    match op {
        CondOp::Eq => a == b,
        CondOp::Ne => a != b,
        CondOp::Lt => a < b,
        CondOp::Gt => a > b,
        CondOp::Le => a <= b,
        CondOp::Ge => a >= b,
        CondOp::Contains => false,
    }
}

// ---------------------------------------------------------------------------
// Operand resolution
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum ResolvedValue {
    String(String),
    Int(i64),
    Null,
    Unknown,
}

/// Resolve an operand to a concrete value using locals and registers.
fn resolve_operand(op: &CondOperand, locals: &[LocalVar], regs: &[RegValue]) -> ResolvedValue {
    match op {
        CondOperand::StringLit(s) => ResolvedValue::String(s.clone()),
        CondOperand::IntLit(n) => ResolvedValue::Int(*n),
        CondOperand::Null => ResolvedValue::Null,
        CondOperand::RegSlot(slot) => {
            if let Some(rv) = regs.iter().find(|r| r.slot == *slot) {
                ResolvedValue::Int(rv.value)
            } else {
                ResolvedValue::Unknown
            }
        }
        CondOperand::VarName(name) => {
            // Search locals for a matching name
            if let Some(lv) = locals.iter().find(|l| l.name == *name) {
                let val = &lv.value;
                if val == "null" {
                    ResolvedValue::Null
                } else if let Ok(n) = val.parse::<i64>() {
                    ResolvedValue::Int(n)
                } else {
                    // Strip surrounding quotes if present (agent sends strings quoted)
                    let stripped = val.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(val);
                    ResolvedValue::String(stripped.to_string())
                }
            } else {
                // Not a local variable  - treat as string literal so bare words
                // like `algo == AES` work (AES becomes the string "AES")
                ResolvedValue::String(name.clone())
            }
        }
    }
}
