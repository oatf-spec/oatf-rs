//! Evaluation module per SDK spec §4.1–§4.5 and §6.1–§6.3.
//!
//! Provides indicator evaluation, CEL expression evaluation, semantic matching,
//! and attack-level verdict computation.

use crate::enums::*;
use crate::error::*;
use crate::primitives::{evaluate_condition, resolve_simple_path, resolve_wildcard_path};
use crate::types::*;
use serde_json::Value;
use std::collections::HashMap;

// ─── §6.1 CelEvaluator ─────────────────────────────────────────────────────

/// Extension point for CEL expression evaluation.
///
/// SDKs SHOULD ship a default implementation when a production-quality
/// CEL library is available. See [`DefaultCelEvaluator`] (requires `cel-eval` feature).
pub trait CelEvaluator {
    /// Evaluates a CEL expression against a context of named variables.
    ///
    /// `context` is a JSON object where each key is a variable name available
    /// in the CEL expression. Returns the expression result or an error.
    fn evaluate(&self, expression: &str, context: &Value) -> Result<Value, EvaluationError>;
}

// ─── §6.2 SemanticEvaluator ─────────────────────────────────────────────────

/// Extension point for semantic/intent-based matching.
///
/// SDKs MUST NOT ship a default implementation (SDK spec §6.2).
/// Semantic evaluation is model-dependent and deployment-specific.
pub trait SemanticEvaluator {
    /// Evaluates semantic similarity between observed text and an intent.
    ///
    /// Returns a confidence score between 0.0 and 1.0.
    fn evaluate(
        &self,
        text: &str,
        intent: &str,
        intent_class: Option<&SemanticIntentClass>,
        threshold: Option<f64>,
        examples: Option<&SemanticExamples>,
    ) -> Result<f64, EvaluationError>;
}

// ─── §6.3 GenerationProvider ────────────────────────────────────────────────

/// Extension point for LLM-based content generation.
///
/// SDKs MUST NOT ship a default implementation (SDK spec §6.3).
/// Used by adversarial tools to execute `synthesize` blocks.
pub trait GenerationProvider {
    /// Generates adversarial content from a prompt for the given protocol.
    fn generate(
        &self,
        prompt: &str,
        protocol: &str,
        response_context: &Value,
    ) -> Result<Value, GenerationError>;
}

// ─── Default CEL Evaluator (behind `cel-eval` feature) ──────────────────────

/// Default CEL evaluator backed by the `cel` crate.
///
/// Supports: `size`, `contains`, `startsWith`, `endsWith`, `matches`,
/// `exists`, `all`, `filter`, `map`.
///
/// Limitations: The `cel` crate (cel-rust) does not support the `matches`
/// function from the CEL standard without the `regex` feature. The crate's
/// regex support may differ from RE2 semantics in edge cases.
///
/// # Resource Limits
///
/// This evaluator does **not** impose execution time or memory limits.
/// Callers processing untrusted OATF documents should wrap evaluation
/// in a timeout or provide a custom [`CelEvaluator`] with resource controls.
#[cfg(feature = "cel-eval")]
pub struct DefaultCelEvaluator;

/// Convenience constructor for [`DefaultCelEvaluator`].
#[cfg(feature = "cel-eval")]
pub fn default_cel_evaluator() -> DefaultCelEvaluator {
    DefaultCelEvaluator
}

#[cfg(feature = "cel-eval")]
impl CelEvaluator for DefaultCelEvaluator {
    fn evaluate(&self, expression: &str, context: &Value) -> Result<Value, EvaluationError> {
        let program = cel::Program::compile(expression).map_err(|e| EvaluationError {
            kind: EvaluationErrorKind::CelError,
            message: format!("CEL compile error: {}", e),
            indicator_id: None,
        })?;

        let mut cel_ctx = cel::Context::default();

        if let Value::Object(map) = context {
            for (key, value) in map {
                let cel_value = json_to_cel(value);
                cel_ctx.add_variable_from_value(key.as_str(), cel_value);
            }
        }

        match program.execute(&cel_ctx) {
            Ok(result) => Ok(cel_to_json(&result)),
            Err(cel::ExecutionError::NoSuchKey(ref key)) => Err(EvaluationError {
                kind: EvaluationErrorKind::CelError,
                message: format!("CEL missing field: {}", key),
                indicator_id: None,
            }),
            Err(cel::ExecutionError::UndeclaredReference(ref name)) => Err(EvaluationError {
                kind: EvaluationErrorKind::CelError,
                message: format!("CEL undeclared reference: {}", name),
                indicator_id: None,
            }),
            Err(ref e @ cel::ExecutionError::NotSupportedAsMethod { .. }) => Err(EvaluationError {
                kind: EvaluationErrorKind::UnsupportedMethod,
                message: format!("CEL unsupported method: {}", e),
                indicator_id: None,
            }),
            Err(e) => Err(EvaluationError {
                kind: EvaluationErrorKind::CelError,
                message: format!("CEL execution error: {}", e),
                indicator_id: None,
            }),
        }
    }
}

const MAX_VALUE_DEPTH: usize = 128;

/// Convert serde_json::Value → cel::Value.
#[cfg(feature = "cel-eval")]
fn json_to_cel(value: &Value) -> cel::Value {
    json_to_cel_inner(value, 0)
}

#[cfg(feature = "cel-eval")]
fn json_to_cel_inner(value: &Value, depth: usize) -> cel::Value {
    use std::sync::Arc;

    if depth > MAX_VALUE_DEPTH {
        return cel::Value::Null;
    }
    match value {
        Value::Null => cel::Value::Null,
        Value::Bool(b) => cel::Value::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                cel::Value::Int(i)
            } else if let Some(u) = n.as_u64() {
                cel::Value::UInt(u)
            } else if let Some(f) = n.as_f64() {
                cel::Value::Float(f)
            } else {
                cel::Value::Null
            }
        }
        Value::String(s) => cel::Value::String(Arc::new(s.clone())),
        Value::Array(arr) => {
            let items: Vec<cel::Value> = arr
                .iter()
                .map(|v| json_to_cel_inner(v, depth + 1))
                .collect();
            cel::Value::List(Arc::new(items))
        }
        Value::Object(map) => {
            let entries: HashMap<String, cel::Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), json_to_cel_inner(v, depth + 1)))
                .collect();
            entries.into()
        }
    }
}

/// Convert cel::Value → serde_json::Value.
#[cfg(feature = "cel-eval")]
fn cel_to_json(value: &cel::Value) -> Value {
    cel_to_json_inner(value, 0)
}

#[cfg(feature = "cel-eval")]
fn cel_to_json_inner(value: &cel::Value, depth: usize) -> Value {
    if depth > MAX_VALUE_DEPTH {
        return Value::Null;
    }
    match value {
        cel::Value::Null => Value::Null,
        cel::Value::Bool(b) => Value::Bool(*b),
        cel::Value::Int(i) => Value::Number((*i).into()),
        cel::Value::UInt(u) => Value::Number((*u).into()),
        cel::Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        cel::Value::String(s) => Value::String(s.to_string()),
        cel::Value::List(l) => {
            Value::Array(l.iter().map(|v| cel_to_json_inner(v, depth + 1)).collect())
        }
        cel::Value::Map(m) => {
            let mut obj = serde_json::Map::new();
            for (key, val) in m.map.iter() {
                let k = match key {
                    cel::objects::Key::String(s) => s.to_string(),
                    cel::objects::Key::Int(i) => i.to_string(),
                    cel::objects::Key::Uint(u) => u.to_string(),
                    cel::objects::Key::Bool(b) => b.to_string(),
                };
                obj.insert(k, cel_to_json_inner(val, depth + 1));
            }
            Value::Object(obj)
        }
        // Bytes, Duration, Timestamp, Function, Opaque → null
        _ => Value::Null,
    }
}

/// Returns the current time as an ISO 8601 / RFC 3339 UTC string.
fn now_iso8601() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    // Decompose into date/time components (UTC)
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Civil date from day count (algorithm from Howard Hinnant)
    let z = days as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hours, minutes, seconds
    )
}

fn make_verdict(id: String, result: IndicatorResult, evidence: Option<String>) -> IndicatorVerdict {
    IndicatorVerdict {
        indicator_id: id,
        result,
        timestamp: Some(now_iso8601()),
        evidence,
        source: None,
    }
}

fn build_attack_verdict(
    attack_id: Option<String>,
    result: AttackResult,
    indicator_verdicts: Vec<IndicatorVerdict>,
    evaluation_summary: EvaluationSummary,
) -> AttackVerdict {
    AttackVerdict {
        attack_id,
        result,
        indicator_verdicts,
        evaluation_summary,
        timestamp: Some(now_iso8601()),
        source: None,
    }
}

// ─── §4.2 evaluate_pattern ──────────────────────────────────────────────────

/// Evaluates a pattern indicator against a protocol message.
///
/// Precondition: `pattern` is in normalized standard form (explicit `condition`,
/// resolved `target`).
///
/// Returns `Ok(true)` if any resolved value matches the condition.
/// Returns `Ok(false)` if no values match or if the target resolves to nothing.
///
/// The `exists` operator is handled at the pattern level (not by `evaluate_condition`,
/// per §5.3), mirroring the path-resolution semantics of `evaluate_predicate` (§5.4).
pub fn evaluate_pattern(pattern: &PatternMatch, message: &Value) -> Result<bool, EvaluationError> {
    let target = pattern.target.as_deref().unwrap_or("");
    let condition = match &pattern.condition {
        Some(c) => c,
        None => return Ok(false),
    };

    let resolved = resolve_wildcard_path(target, message);

    // Handle `exists` at the pattern level. Per §5.3, `exists` is evaluated
    // during path resolution, not by `evaluate_condition`.
    if let Condition::Operators(cond) = condition
        && cond.exists == Some(false)
    {
        // exists: false + other operators → always false (AND with false)
        let has_other_ops = cond.contains.is_some()
            || cond.starts_with.is_some()
            || cond.ends_with.is_some()
            || cond.regex.is_some()
            || cond.any_of.is_some()
            || cond.gt.is_some()
            || cond.lt.is_some()
            || cond.gte.is_some()
            || cond.lte.is_some();
        if has_other_ops {
            return Ok(false);
        }
        return Ok(resolved.is_empty());
    }

    if resolved.is_empty() {
        return Ok(false);
    }

    for value in &resolved {
        if evaluate_condition(condition, value) {
            return Ok(true);
        }
    }

    Ok(false)
}

// ─── §4.3 evaluate_expression ───────────────────────────────────────────────

/// Evaluates a CEL expression indicator against a protocol message.
///
/// Builds the CEL context by binding `message` and any declared variables,
/// then delegates to the provided `CelEvaluator`.
///
/// When `cel_evaluator` is `None`, returns `Err(EvaluationError)` indicating
/// that CEL evaluation is not available.
///
/// Non-boolean results produce `EvaluationError { kind: type_error }`.
pub fn evaluate_expression(
    expression: &ExpressionMatch,
    message: &Value,
    cel_evaluator: Option<&dyn CelEvaluator>,
) -> Result<bool, EvaluationError> {
    let cel_evaluator = cel_evaluator.ok_or_else(|| EvaluationError {
        kind: EvaluationErrorKind::CelError,
        message: "CEL evaluator not available".to_string(),
        indicator_id: None,
    })?;

    // Build CEL context
    let mut context = serde_json::Map::new();
    context.insert("message".to_string(), message.clone());

    // Resolve variables
    if let Some(vars) = &expression.variables {
        for (name, path) in vars {
            let resolved = resolve_simple_path(path, message).unwrap_or(Value::Null);
            context.insert(name.clone(), resolved);
        }
    }

    let result = cel_evaluator.evaluate(&expression.cel, &Value::Object(context))?;

    match result {
        Value::Bool(b) => Ok(b),
        _ => Err(EvaluationError {
            kind: EvaluationErrorKind::TypeError,
            message: format!(
                "CEL expression returned non-boolean result: {}",
                serde_json::to_string(&result).unwrap_or_else(|_| "<unserializable>".to_string())
            ),
            indicator_id: None,
        }),
    }
}

// ─── §4.4 evaluate_indicator ────────────────────────────────────────────────

/// Top-level indicator evaluation. Dispatches to the appropriate evaluator
/// and wraps the result in an [`IndicatorVerdict`].
pub fn evaluate_indicator(
    indicator: &Indicator,
    message: &Value,
    cel_evaluator: Option<&dyn CelEvaluator>,
    semantic_evaluator: Option<&dyn SemanticEvaluator>,
) -> IndicatorVerdict {
    let indicator_id = match &indicator.id {
        Some(id) => id.clone(),
        None => {
            return make_verdict(
                "<missing-id>".to_string(),
                IndicatorResult::Error,
                Some(
                    "indicator has no id; document must be normalized before evaluation"
                        .to_string(),
                ),
            );
        }
    };

    if let Some(ref pattern) = indicator.pattern {
        match evaluate_pattern(pattern, message) {
            Ok(true) => make_verdict(indicator_id, IndicatorResult::Matched, None),
            Ok(false) => make_verdict(indicator_id, IndicatorResult::NotMatched, None),
            Err(e) => make_verdict(indicator_id, IndicatorResult::Error, Some(e.message)),
        }
    } else if let Some(ref expr) = indicator.expression {
        if cel_evaluator.is_none() {
            return make_verdict(
                indicator_id,
                IndicatorResult::Skipped,
                Some("CEL evaluator not available".to_string()),
            );
        }
        match evaluate_expression(expr, message, cel_evaluator) {
            Ok(true) => make_verdict(indicator_id, IndicatorResult::Matched, None),
            Ok(false) => make_verdict(indicator_id, IndicatorResult::NotMatched, None),
            Err(e) => make_verdict(indicator_id, IndicatorResult::Error, Some(e.message)),
        }
    } else if let Some(ref semantic) = indicator.semantic {
        match semantic_evaluator {
            None => make_verdict(
                indicator_id,
                IndicatorResult::Skipped,
                Some("Semantic evaluator not available".to_string()),
            ),
            Some(sem_eval) => evaluate_semantic(semantic, message, sem_eval, &indicator_id),
        }
    } else {
        make_verdict(
            indicator_id,
            IndicatorResult::Error,
            Some("No detection key (pattern/expression/semantic) present".to_string()),
        )
    }
}

/// Semantic indicator evaluation per §4.4.
fn evaluate_semantic(
    semantic: &SemanticMatch,
    message: &Value,
    evaluator: &dyn SemanticEvaluator,
    indicator_id: &str,
) -> IndicatorVerdict {
    let target = semantic.target.as_deref().unwrap_or("");
    let resolved = resolve_wildcard_path(target, message);

    if resolved.is_empty() {
        return make_verdict(indicator_id.to_string(), IndicatorResult::NotMatched, None);
    }

    let threshold = semantic.threshold.unwrap_or(0.7);
    let mut highest_score: f64 = 0.0;

    for value in &resolved {
        let text = value_to_text(value);
        match evaluator.evaluate(
            &text,
            &semantic.intent,
            semantic.intent_class.as_ref(),
            semantic.threshold,
            semantic.examples.as_ref(),
        ) {
            Ok(score) => {
                if score > highest_score {
                    highest_score = score;
                }
            }
            Err(e) => {
                return make_verdict(
                    indicator_id.to_string(),
                    IndicatorResult::Error,
                    Some(e.message),
                );
            }
        }
    }

    let result = if highest_score >= threshold {
        IndicatorResult::Matched
    } else {
        IndicatorResult::NotMatched
    };
    make_verdict(
        indicator_id.to_string(),
        result,
        Some(format!("{:.2}", highest_score)),
    )
}

/// Serialize a value to text for semantic evaluation.
fn value_to_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        _ => serde_json::to_string(value).unwrap_or_else(|_| "<unserializable>".to_string()),
    }
}

// ─── §4.5 compute_verdict ───────────────────────────────────────────────────

/// Computes the attack-level verdict from indicator verdicts.
///
/// Uses the attack's `correlation.logic` to determine the overall result:
/// - `any` (default): error > any matched=exploited > not_exploited
/// - `all`: error > all matched=exploited > mixed=partial > not_exploited
///
/// Skipped verdicts are treated as not_matched for verdict computation.
pub fn compute_verdict(
    attack: &Attack,
    indicator_verdicts: &HashMap<String, IndicatorVerdict>,
) -> AttackVerdict {
    let indicators = match &attack.indicators {
        Some(inds) => inds,
        None => {
            return build_attack_verdict(
                attack.id.clone(),
                AttackResult::Error,
                vec![],
                EvaluationSummary {
                    matched: 0,
                    not_matched: 0,
                    error: 0,
                    skipped: 0,
                },
            );
        }
    };

    let logic = attack
        .correlation
        .as_ref()
        .and_then(|c| c.logic.as_ref())
        .unwrap_or(&CorrelationLogic::Any);

    let mut matched: i64 = 0;
    let mut not_matched: i64 = 0;
    let mut error: i64 = 0;
    let mut skipped: i64 = 0;
    let mut collected_verdicts = Vec::new();

    for indicator in indicators {
        let ind_id = indicator.id.as_deref().unwrap_or("");
        let verdict = indicator_verdicts.get(ind_id);

        match verdict {
            Some(v) => {
                match v.result {
                    IndicatorResult::Matched => matched += 1,
                    IndicatorResult::NotMatched => not_matched += 1,
                    IndicatorResult::Error => error += 1,
                    IndicatorResult::Skipped => skipped += 1,
                }
                collected_verdicts.push(v.clone());
            }
            None => {
                skipped += 1;
                collected_verdicts.push(make_verdict(
                    ind_id.to_string(),
                    IndicatorResult::Skipped,
                    Some("No evaluation result provided".to_string()),
                ));
            }
        }
    }

    // All-skipped → error: no evaluation occurred (§4.5)
    if skipped > 0 && matched == 0 && not_matched == 0 && error == 0 {
        return build_attack_verdict(
            attack.id.clone(),
            AttackResult::Error,
            collected_verdicts,
            EvaluationSummary {
                matched,
                not_matched,
                error,
                skipped,
            },
        );
    }

    let result = match logic {
        CorrelationLogic::Any => {
            if error > 0 {
                AttackResult::Error
            } else if matched > 0 {
                AttackResult::Exploited
            } else {
                AttackResult::NotExploited
            }
        }
        CorrelationLogic::All => {
            if error > 0 {
                AttackResult::Error
            } else if matched > 0 && not_matched == 0 && skipped == 0 {
                AttackResult::Exploited
            } else if matched > 0 {
                AttackResult::Partial
            } else {
                AttackResult::NotExploited
            }
        }
    };

    build_attack_verdict(
        attack.id.clone(),
        result,
        collected_verdicts,
        EvaluationSummary {
            matched,
            not_matched,
            error,
            skipped,
        },
    )
}
