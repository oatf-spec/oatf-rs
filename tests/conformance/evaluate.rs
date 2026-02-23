use oatf::enums::*;
use oatf::evaluate;
use oatf::types::*;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

fn conformance_dir() -> PathBuf {
    std::env::var("OATF_CONFORMANCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("spec/conformance"))
}

// ─── evaluate_pattern ───────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct PatternCase {
    name: String,
    id: String,
    input: PatternInput,
    expected: String,
}

#[derive(Debug, serde::Deserialize)]
struct PatternInput {
    indicator: PatternIndicatorDef,
    message: Value,
}

#[derive(Debug, serde::Deserialize)]
struct PatternIndicatorDef {
    surface: String,
    pattern: Value,
}

#[test]
fn evaluate_pattern_suite() {
    let path = conformance_dir().join("evaluate/pattern.yaml");
    if !path.exists() {
        eprintln!("Skipping evaluate_pattern tests: {:?} not found", path);
        return;
    }

    let content = std::fs::read_to_string(&path).unwrap();
    let cases: Vec<PatternCase> = serde_saphyr::from_str(&content).unwrap();

    let mut passed = 0;
    let mut failed = 0;

    for case in &cases {
        let pattern = parse_pattern_match(&case.input.indicator.pattern);
        let indicator = Indicator {
            id: Some(case.id.clone()),
            protocol: None,
            surface: case.input.indicator.surface.clone(),
            description: None,
            pattern: Some(pattern),
            expression: None,
            semantic: None,
            confidence: None,
            severity: None,
            false_positives: None,
            extensions: HashMap::new(),
        };

        let verdict = evaluate::evaluate_indicator(&indicator, &case.input.message, None, None);

        let result_str = match verdict.result {
            IndicatorResult::Matched => "matched",
            IndicatorResult::NotMatched => "not_matched",
            IndicatorResult::Error => "error",
            IndicatorResult::Skipped => "skipped",
        };

        if result_str == case.expected {
            passed += 1;
        } else {
            eprintln!(
                "  FAIL [{}] {}: expected {}, got {}",
                case.id, case.name, case.expected, result_str
            );
            failed += 1;
        }
    }

    eprintln!(
        "\nevaluate_pattern: {} passed, {} failed out of {} total",
        passed,
        failed,
        cases.len()
    );
    assert_eq!(failed, 0, "{} evaluate_pattern tests failed", failed);
}

fn parse_pattern_match(value: &Value) -> PatternMatch {
    serde_json::from_value(value.clone()).unwrap()
}

// ─── evaluate_expression (via evaluate_indicator) ───────────────────────────

#[derive(Debug, serde::Deserialize)]
struct ExpressionCase {
    name: String,
    id: String,
    input: ExpressionInput,
    expected: String,
    #[serde(default)]
    #[allow(dead_code)]
    expected_error_kind: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ExpressionInput {
    indicator: ExpressionIndicatorDef,
    message: Value,
    cel_evaluator: String,
}

#[derive(Debug, serde::Deserialize)]
struct ExpressionIndicatorDef {
    surface: String,
    expression: ExpressionMatchDef,
}

#[derive(Debug, serde::Deserialize)]
struct ExpressionMatchDef {
    cel: String,
    variables: Option<HashMap<String, String>>,
}

#[test]
fn evaluate_expression_suite() {
    let path = conformance_dir().join("evaluate/expression.yaml");
    if !path.exists() {
        eprintln!("Skipping evaluate_expression tests: {:?} not found", path);
        return;
    }

    let content = std::fs::read_to_string(&path).unwrap();
    let cases: Vec<ExpressionCase> = serde_saphyr::from_str(&content).unwrap();

    #[cfg(feature = "cel-eval")]
    let cel_evaluator = evaluate::DefaultCelEvaluator;

    let mut passed = 0;
    let mut failed = 0;
    #[allow(unused_mut)]
    let mut skipped = 0;

    for case in &cases {
        let expr = ExpressionMatch {
            cel: case.input.indicator.expression.cel.clone(),
            variables: case.input.indicator.expression.variables.clone(),
        };

        let indicator = Indicator {
            id: Some(case.id.clone()),
            protocol: None,
            surface: case.input.indicator.surface.clone(),
            description: None,
            pattern: None,
            expression: Some(expr),
            semantic: None,
            confidence: None,
            severity: None,
            false_positives: None,
            extensions: HashMap::new(),
        };

        // When cel-eval feature is disabled, skip tests that require a present evaluator
        #[cfg(not(feature = "cel-eval"))]
        if case.input.cel_evaluator == "present" {
            eprintln!(
                "  SKIP [{}] {}: cel-eval feature disabled",
                case.id, case.name
            );
            skipped += 1;
            continue;
        }

        let cel_eval_opt: Option<&dyn evaluate::CelEvaluator> =
            if case.input.cel_evaluator == "present" {
                #[cfg(feature = "cel-eval")]
                {
                    Some(&cel_evaluator)
                }
                #[cfg(not(feature = "cel-eval"))]
                {
                    unreachable!()
                }
            } else {
                None
            };

        let verdict =
            evaluate::evaluate_indicator(&indicator, &case.input.message, cel_eval_opt, None);

        let result_str = match verdict.result {
            IndicatorResult::Matched => "matched",
            IndicatorResult::NotMatched => "not_matched",
            IndicatorResult::Error => "error",
            IndicatorResult::Skipped => "skipped",
        };

        if result_str == case.expected {
            passed += 1;
        } else {
            eprintln!(
                "  FAIL [{}] {}: expected {}, got {} (evidence: {:?})",
                case.id, case.name, case.expected, result_str, verdict.evidence
            );
            failed += 1;
        }
    }

    eprintln!(
        "\nevaluate_expression: {} passed, {} failed, {} skipped out of {} total",
        passed,
        failed,
        skipped,
        cases.len()
    );
    assert_eq!(failed, 0, "{} evaluate_expression tests failed", failed);
}

// ─── evaluate_indicator semantic ────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct SemanticCase {
    name: String,
    id: String,
    input: SemanticInput,
    expected: String,
}

#[derive(Debug, serde::Deserialize)]
struct SemanticInput {
    indicator: SemanticIndicatorDef,
    message: Value,
    semantic_evaluator: SemanticEvaluatorConfig,
}

#[derive(Debug, serde::Deserialize)]
struct SemanticIndicatorDef {
    surface: String,
    semantic: SemanticMatchDef,
}

#[derive(Debug, serde::Deserialize)]
struct SemanticMatchDef {
    target: Option<String>,
    intent: String,
    intent_class: Option<SemanticIntentClass>,
    threshold: Option<f64>,
    examples: Option<SemanticExamples>,
}

#[derive(Debug, serde::Deserialize)]
struct SemanticEvaluatorConfig {
    present: bool,
    #[serde(default)]
    mock_score: Option<f64>,
}

/// Mock semantic evaluator that returns a predetermined score.
struct MockSemanticEvaluator {
    score: f64,
}

impl evaluate::SemanticEvaluator for MockSemanticEvaluator {
    fn evaluate(
        &self,
        _text: &str,
        _intent: &str,
        _intent_class: Option<&SemanticIntentClass>,
        _threshold: Option<f64>,
        _examples: Option<&SemanticExamples>,
    ) -> Result<f64, oatf::error::EvaluationError> {
        Ok(self.score)
    }
}

#[test]
fn evaluate_semantic_suite() {
    let path = conformance_dir().join("evaluate/semantic.yaml");
    if !path.exists() {
        eprintln!("Skipping evaluate_semantic tests: {:?} not found", path);
        return;
    }

    let content = std::fs::read_to_string(&path).unwrap();
    let cases: Vec<SemanticCase> = serde_saphyr::from_str(&content).unwrap();

    let mut passed = 0;
    let mut failed = 0;

    for case in &cases {
        let semantic = SemanticMatch {
            target: case.input.indicator.semantic.target.clone(),
            intent: case.input.indicator.semantic.intent.clone(),
            intent_class: case.input.indicator.semantic.intent_class.clone(),
            threshold: case.input.indicator.semantic.threshold,
            examples: case.input.indicator.semantic.examples.clone(),
        };

        let indicator = Indicator {
            id: Some(case.id.clone()),
            protocol: None,
            surface: case.input.indicator.surface.clone(),
            description: None,
            pattern: None,
            expression: None,
            semantic: Some(semantic),
            confidence: None,
            severity: None,
            false_positives: None,
            extensions: HashMap::new(),
        };

        let mock_evaluator = case
            .input
            .semantic_evaluator
            .mock_score
            .map(|score| MockSemanticEvaluator { score });

        let sem_eval_opt: Option<&dyn evaluate::SemanticEvaluator> =
            if case.input.semantic_evaluator.present {
                mock_evaluator
                    .as_ref()
                    .map(|e| e as &dyn evaluate::SemanticEvaluator)
            } else {
                None
            };

        let verdict =
            evaluate::evaluate_indicator(&indicator, &case.input.message, None, sem_eval_opt);

        let result_str = match verdict.result {
            IndicatorResult::Matched => "matched",
            IndicatorResult::NotMatched => "not_matched",
            IndicatorResult::Error => "error",
            IndicatorResult::Skipped => "skipped",
        };

        if result_str == case.expected {
            passed += 1;
        } else {
            eprintln!(
                "  FAIL [{}] {}: expected {}, got {} (evidence: {:?})",
                case.id, case.name, case.expected, result_str, verdict.evidence
            );
            failed += 1;
        }
    }

    eprintln!(
        "\nevaluate_semantic: {} passed, {} failed out of {} total",
        passed,
        failed,
        cases.len()
    );
    assert_eq!(failed, 0, "{} evaluate_semantic tests failed", failed);
}
