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
            Err(cel::ExecutionError::NoSuchKey(_)) => {
                // Missing fields produce not_matched per §4.1
                Ok(Value::Bool(false))
            }
            Err(cel::ExecutionError::UndeclaredReference(_)) => {
                // Undeclared references treated as missing → not_matched
                Ok(Value::Bool(false))
            }
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

/// Convert serde_json::Value → cel::Value.
#[cfg(feature = "cel-eval")]
fn json_to_cel(value: &Value) -> cel::Value {
    use std::sync::Arc;

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
            let items: Vec<cel::Value> = arr.iter().map(json_to_cel).collect();
            cel::Value::List(Arc::new(items))
        }
        Value::Object(map) => {
            let entries: HashMap<String, cel::Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), json_to_cel(v)))
                .collect();
            entries.into()
        }
    }
}

/// Convert cel::Value → serde_json::Value.
#[cfg(feature = "cel-eval")]
fn cel_to_json(value: &cel::Value) -> Value {
    match value {
        cel::Value::Null => Value::Null,
        cel::Value::Bool(b) => Value::Bool(*b),
        cel::Value::Int(i) => Value::Number((*i).into()),
        cel::Value::UInt(u) => Value::Number((*u).into()),
        cel::Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        cel::Value::String(s) => Value::String(s.to_string()),
        cel::Value::List(l) => Value::Array(l.iter().map(cel_to_json).collect()),
        cel::Value::Map(m) => {
            let mut obj = serde_json::Map::new();
            for (key, val) in m.map.iter() {
                let k = match key {
                    cel::objects::Key::String(s) => s.to_string(),
                    cel::objects::Key::Int(i) => i.to_string(),
                    cel::objects::Key::Uint(u) => u.to_string(),
                    cel::objects::Key::Bool(b) => b.to_string(),
                };
                obj.insert(k, cel_to_json(val));
            }
            Value::Object(obj)
        }
        // Bytes, Duration, Timestamp, Function, Opaque → null
        _ => Value::Null,
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
pub fn evaluate_pattern(pattern: &PatternMatch, message: &Value) -> Result<bool, EvaluationError> {
    let target = pattern.target.as_deref().unwrap_or("");
    let condition = match &pattern.condition {
        Some(c) => c,
        None => return Ok(false),
    };

    let resolved = resolve_wildcard_path(target, message);
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
/// Non-boolean results produce `EvaluationError { kind: type_error }`.
pub fn evaluate_expression(
    expression: &ExpressionMatch,
    message: &Value,
    cel_evaluator: &dyn CelEvaluator,
) -> Result<bool, EvaluationError> {
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
                serde_json::to_string(&result).unwrap_or_default()
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
    let indicator_id = indicator.id.clone().unwrap_or_default();

    if let Some(ref pattern) = indicator.pattern {
        // Pattern dispatch
        match evaluate_pattern(pattern, message) {
            Ok(true) => IndicatorVerdict {
                indicator_id,
                result: IndicatorResult::Matched,
                timestamp: None,
                evidence: None,
                source: None,
            },
            Ok(false) => IndicatorVerdict {
                indicator_id,
                result: IndicatorResult::NotMatched,
                timestamp: None,
                evidence: None,
                source: None,
            },
            Err(e) => IndicatorVerdict {
                indicator_id,
                result: IndicatorResult::Error,
                timestamp: None,
                evidence: Some(e.message),
                source: None,
            },
        }
    } else if let Some(ref expr) = indicator.expression {
        // Expression dispatch
        match cel_evaluator {
            None => IndicatorVerdict {
                indicator_id,
                result: IndicatorResult::Skipped,
                timestamp: None,
                evidence: Some("CEL evaluator not available".to_string()),
                source: None,
            },
            Some(cel_eval) => match evaluate_expression(expr, message, cel_eval) {
                Ok(true) => IndicatorVerdict {
                    indicator_id,
                    result: IndicatorResult::Matched,
                    timestamp: None,
                    evidence: None,
                    source: None,
                },
                Ok(false) => IndicatorVerdict {
                    indicator_id,
                    result: IndicatorResult::NotMatched,
                    timestamp: None,
                    evidence: None,
                    source: None,
                },
                Err(e) => IndicatorVerdict {
                    indicator_id,
                    result: IndicatorResult::Error,
                    timestamp: None,
                    evidence: Some(e.message),
                    source: None,
                },
            },
        }
    } else if let Some(ref semantic) = indicator.semantic {
        // Semantic dispatch
        match semantic_evaluator {
            None => IndicatorVerdict {
                indicator_id,
                result: IndicatorResult::Skipped,
                timestamp: None,
                evidence: Some("Semantic evaluator not available".to_string()),
                source: None,
            },
            Some(sem_eval) => evaluate_semantic(semantic, message, sem_eval, &indicator_id),
        }
    } else {
        // No detection key present
        IndicatorVerdict {
            indicator_id,
            result: IndicatorResult::Error,
            timestamp: None,
            evidence: Some("No detection key (pattern/expression/semantic) present".to_string()),
            source: None,
        }
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
        return IndicatorVerdict {
            indicator_id: indicator_id.to_string(),
            result: IndicatorResult::NotMatched,
            timestamp: None,
            evidence: None,
            source: None,
        };
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
                return IndicatorVerdict {
                    indicator_id: indicator_id.to_string(),
                    result: IndicatorResult::Error,
                    timestamp: None,
                    evidence: Some(e.message),
                    source: None,
                };
            }
        }
    }

    if highest_score >= threshold {
        IndicatorVerdict {
            indicator_id: indicator_id.to_string(),
            result: IndicatorResult::Matched,
            timestamp: None,
            evidence: Some(format!("{:.2}", highest_score)),
            source: None,
        }
    } else {
        IndicatorVerdict {
            indicator_id: indicator_id.to_string(),
            result: IndicatorResult::NotMatched,
            timestamp: None,
            evidence: Some(format!("{:.2}", highest_score)),
            source: None,
        }
    }
}

/// Serialize a value to text for semantic evaluation.
fn value_to_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        _ => serde_json::to_string(value).unwrap_or_default(),
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
            return AttackVerdict {
                attack_id: attack.id.clone(),
                result: AttackResult::Error,
                indicator_verdicts: vec![],
                evaluation_summary: EvaluationSummary {
                    matched: 0,
                    not_matched: 0,
                    error: 0,
                    skipped: 0,
                },
                timestamp: None,
                source: None,
            };
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
                // Missing entry → treated as skipped
                skipped += 1;
                collected_verdicts.push(IndicatorVerdict {
                    indicator_id: ind_id.to_string(),
                    result: IndicatorResult::Skipped,
                    timestamp: None,
                    evidence: Some("No evaluation result provided".to_string()),
                    source: None,
                });
            }
        }
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

    AttackVerdict {
        attack_id: attack.id.clone(),
        result,
        indicator_verdicts: collected_verdicts,
        evaluation_summary: EvaluationSummary {
            matched,
            not_matched,
            error,
            skipped,
        },
        timestamp: None,
        source: None,
    }
}
