use oatf::primitives;
use oatf::types::*;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::PathBuf;

fn conformance_dir() -> PathBuf {
    std::env::var("OATF_CONFORMANCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("spec/conformance"))
}

// --- resolve_simple_path -----------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct SimplePathCase {
    name: String,
    id: String,
    input: SimplePathInput,
    expected: Value,
}

#[derive(Debug, serde::Deserialize)]
struct SimplePathInput {
    path: String,
    value: Value,
}

#[test]
fn resolve_simple_path_suite() {
    let path = conformance_dir().join("primitives/resolve-simple-path.yaml");
    assert!(
        path.exists(),
        "Conformance fixture not found: {:?}. Is the spec submodule initialized?",
        path
    );

    let content = std::fs::read_to_string(&path).unwrap();
    let cases: Vec<SimplePathCase> = serde_saphyr::from_str(&content).unwrap();

    let mut passed = 0;
    let mut failed = 0;

    for case in &cases {
        let result = primitives::resolve_simple_path(&case.input.path, &case.input.value);

        // Handle the special PATH-010 format: {found: true, value: null}
        let matches = if case.expected.is_object()
            && case.expected.get("found").is_some()
            && case.expected.get("value").is_some()
        {
            let found = case.expected["found"].as_bool().unwrap_or(false);
            if found {
                result
                    .as_ref()
                    .map(|v| *v == case.expected["value"])
                    .unwrap_or(false)
            } else {
                result.is_none()
            }
        } else if case.expected.is_null() {
            result.is_none()
        } else {
            result
                .as_ref()
                .map(|v| *v == case.expected)
                .unwrap_or(false)
        };

        if matches {
            passed += 1;
        } else {
            eprintln!(
                "  FAIL [{}] {}: expected {:?}, got {:?}",
                case.id, case.name, case.expected, result
            );
            failed += 1;
        }
    }

    eprintln!(
        "\nresolve_simple_path: {} passed, {} failed out of {} total",
        passed,
        failed,
        cases.len()
    );
    assert_eq!(failed, 0, "{} resolve_simple_path tests failed", failed);
}

// --- resolve_wildcard_path ---------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct WildcardPathCase {
    name: String,
    id: String,
    input: WildcardPathInput,
    expected: WildcardPathExpected,
}

#[derive(Debug, serde::Deserialize)]
struct WildcardPathInput {
    path: String,
    value: Value,
}

#[derive(Debug, serde::Deserialize)]
struct WildcardPathExpected {
    values: Vec<Value>,
}

#[test]
fn resolve_wildcard_path_suite() {
    let path = conformance_dir().join("primitives/resolve-wildcard-path.yaml");
    assert!(
        path.exists(),
        "Conformance fixture not found: {:?}. Is the spec submodule initialized?",
        path
    );

    let content = std::fs::read_to_string(&path).unwrap();
    let cases: Vec<WildcardPathCase> = serde_saphyr::from_str(&content).unwrap();

    let mut passed = 0;
    let mut failed = 0;

    for case in &cases {
        let result = primitives::resolve_wildcard_path(&case.input.path, &case.input.value);

        if result == case.expected.values {
            passed += 1;
        } else {
            eprintln!(
                "  FAIL [{}] {}: expected {:?}, got {:?}",
                case.id, case.name, case.expected.values, result
            );
            failed += 1;
        }
    }

    eprintln!(
        "\nresolve_wildcard_path: {} passed, {} failed out of {} total",
        passed,
        failed,
        cases.len()
    );
    assert_eq!(failed, 0, "{} resolve_wildcard_path tests failed", failed);
}

// --- parse_duration ----------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct DurationCase {
    name: String,
    id: String,
    input: String,
    expected: DurationExpected,
}

#[derive(Debug, serde::Deserialize)]
struct DurationExpected {
    #[serde(default)]
    seconds: Option<u64>,
    #[serde(default)]
    error: Option<bool>,
}

#[test]
fn parse_duration_suite() {
    let path = conformance_dir().join("primitives/parse-duration.yaml");
    assert!(
        path.exists(),
        "Conformance fixture not found: {:?}. Is the spec submodule initialized?",
        path
    );

    let content = std::fs::read_to_string(&path).unwrap();
    let cases: Vec<DurationCase> = serde_saphyr::from_str(&content).unwrap();

    let mut passed = 0;
    let mut failed = 0;

    for case in &cases {
        let result = primitives::parse_duration(&case.input);

        if case.expected.error == Some(true) {
            if result.is_err() {
                passed += 1;
            } else {
                eprintln!(
                    "  FAIL [{}] {}: expected error, got {:?}",
                    case.id,
                    case.name,
                    result.unwrap()
                );
                failed += 1;
            }
        } else if let Some(expected_secs) = case.expected.seconds {
            match result {
                Ok(dur) => {
                    if dur.as_secs() == expected_secs {
                        passed += 1;
                    } else {
                        eprintln!(
                            "  FAIL [{}] {}: expected {}s, got {}s",
                            case.id,
                            case.name,
                            expected_secs,
                            dur.as_secs()
                        );
                        failed += 1;
                    }
                }
                Err(e) => {
                    eprintln!(
                        "  FAIL [{}] {}: expected {}s, got error: {}",
                        case.id, case.name, expected_secs, e
                    );
                    failed += 1;
                }
            }
        }
    }

    eprintln!(
        "\nparse_duration: {} passed, {} failed out of {} total",
        passed,
        failed,
        cases.len()
    );
    assert_eq!(failed, 0, "{} parse_duration tests failed", failed);
}

// --- evaluate_condition ------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct ConditionCase {
    name: String,
    id: String,
    input: ConditionInput,
    expected: bool,
}

#[derive(Debug, serde::Deserialize)]
struct ConditionInput {
    condition: Value,
    value: Value,
}

#[test]
fn evaluate_condition_suite() {
    let path = conformance_dir().join("primitives/evaluate-condition.yaml");
    assert!(
        path.exists(),
        "Conformance fixture not found: {:?}. Is the spec submodule initialized?",
        path
    );

    let content = std::fs::read_to_string(&path).unwrap();
    let cases: Vec<ConditionCase> = serde_saphyr::from_str(&content).unwrap();

    let mut passed = 0;
    let mut failed = 0;

    for case in &cases {
        let condition = parse_condition(&case.input.condition);
        let result = primitives::evaluate_condition(&condition, &case.input.value);

        if result == case.expected {
            passed += 1;
        } else {
            eprintln!(
                "  FAIL [{}] {}: expected {}, got {}",
                case.id, case.name, case.expected, result
            );
            failed += 1;
        }
    }

    eprintln!(
        "\nevaluate_condition: {} passed, {} failed out of {} total",
        passed,
        failed,
        cases.len()
    );
    assert_eq!(failed, 0, "{} evaluate_condition tests failed", failed);
}

/// Parse a condition from a raw JSON value (same logic as Condition::from_value
/// but for test input which can be a bare scalar or an operator object).
fn parse_condition(value: &Value) -> Condition {
    Condition::from_value(value.clone())
}

// --- evaluate_predicate ------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct PredicateCase {
    name: String,
    id: String,
    input: PredicateInput,
    expected: bool,
}

#[derive(Debug, serde::Deserialize)]
struct PredicateInput {
    predicate: Value,
    value: Value,
}

#[test]
fn evaluate_predicate_suite() {
    let path = conformance_dir().join("primitives/evaluate-predicate.yaml");
    assert!(
        path.exists(),
        "Conformance fixture not found: {:?}. Is the spec submodule initialized?",
        path
    );

    let content = std::fs::read_to_string(&path).unwrap();
    let cases: Vec<PredicateCase> = serde_saphyr::from_str(&content).unwrap();

    let mut passed = 0;
    let mut failed = 0;

    for case in &cases {
        let predicate = parse_match_predicate(&case.input.predicate);
        let result = primitives::evaluate_predicate(&predicate, &case.input.value);

        if result == case.expected {
            passed += 1;
        } else {
            eprintln!(
                "  FAIL [{}] {}: expected {}, got {}",
                case.id, case.name, case.expected, result
            );
            failed += 1;
        }
    }

    eprintln!(
        "\nevaluate_predicate: {} passed, {} failed out of {} total",
        passed,
        failed,
        cases.len()
    );
    assert_eq!(failed, 0, "{} evaluate_predicate tests failed", failed);
}

/// Parse a MatchPredicate from a raw JSON value.
fn parse_match_predicate(value: &Value) -> MatchPredicate {
    let obj = value.as_object().unwrap();
    let mut predicate = MatchPredicate::new();

    for (key, val) in obj {
        let entry = parse_match_entry(val);
        predicate.insert(key.clone(), entry);
    }

    predicate
}

fn parse_match_entry(value: &Value) -> MatchEntry {
    match value {
        Value::Object(map) => {
            let operator_keys = [
                "contains",
                "starts_with",
                "ends_with",
                "regex",
                "any_of",
                "gt",
                "lt",
                "gte",
                "lte",
                "exists",
            ];
            if map.keys().any(|k| operator_keys.contains(&k.as_str())) {
                let cond: MatchCondition = serde_json::from_value(value.clone()).unwrap();
                MatchEntry::Condition(cond)
            } else {
                MatchEntry::Scalar(value.clone())
            }
        }
        _ => MatchEntry::Scalar(value.clone()),
    }
}

// --- interpolate_template ----------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct TemplateCase {
    name: String,
    id: String,
    input: TemplateInput,
    expected: String,
}

#[derive(Debug, serde::Deserialize)]
struct TemplateInput {
    template: String,
    #[serde(default)]
    extractors: std::collections::HashMap<String, String>,
    #[serde(default)]
    request: Option<Value>,
    #[serde(default)]
    response: Option<Value>,
}

#[test]
fn interpolate_template_suite() {
    let path = conformance_dir().join("primitives/interpolate-template.yaml");
    assert!(
        path.exists(),
        "Conformance fixture not found: {:?}. Is the spec submodule initialized?",
        path
    );

    let content = std::fs::read_to_string(&path).unwrap();
    let cases: Vec<TemplateCase> = serde_saphyr::from_str(&content).unwrap();

    let mut passed = 0;
    let mut failed = 0;

    for case in &cases {
        let (result, _diagnostics) = primitives::interpolate_template(
            &case.input.template,
            &case.input.extractors,
            case.input.request.as_ref(),
            case.input.response.as_ref(),
        );

        if result == case.expected {
            passed += 1;
        } else {
            eprintln!(
                "  FAIL [{}] {}: expected {:?}, got {:?}",
                case.id, case.name, case.expected, result
            );
            failed += 1;
        }
    }

    eprintln!(
        "\ninterpolate_template: {} passed, {} failed out of {} total",
        passed,
        failed,
        cases.len()
    );
    assert_eq!(failed, 0, "{} interpolate_template tests failed", failed);
}

// --- evaluate_extractor ------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct ExtractorCase {
    name: String,
    id: String,
    input: ExtractorInput,
    expected: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ExtractorInput {
    extractor: ExtractorDef,
    message: Value,
    #[serde(default)]
    direction: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ExtractorDef {
    name: String,
    source: String,
    #[serde(rename = "type")]
    extractor_type: String,
    selector: String,
}

#[test]
fn evaluate_extractor_suite() {
    let path = conformance_dir().join("primitives/evaluate-extractor.yaml");
    assert!(
        path.exists(),
        "Conformance fixture not found: {:?}. Is the spec submodule initialized?",
        path
    );

    let content = std::fs::read_to_string(&path).unwrap();
    let cases: Vec<ExtractorCase> = serde_saphyr::from_str(&content).unwrap();

    let mut passed = 0;
    let mut failed = 0;

    for case in &cases {
        let ext_type = match case.input.extractor.extractor_type.as_str() {
            "json_path" => oatf::enums::ExtractorType::JsonPath,
            "regex" => oatf::enums::ExtractorType::Regex,
            other => {
                eprintln!(
                    "  SKIP [{}] {}: unknown extractor type: {}",
                    case.id, case.name, other
                );
                continue;
            }
        };
        let source = match case.input.extractor.source.as_str() {
            "request" => oatf::enums::ExtractorSource::Request,
            "response" => oatf::enums::ExtractorSource::Response,
            other => {
                eprintln!(
                    "  SKIP [{}] {}: unknown source: {}",
                    case.id, case.name, other
                );
                continue;
            }
        };

        // Use fixture `direction` if present, otherwise default to extractor source
        let direction = match case.input.direction.as_deref() {
            Some("request") => oatf::enums::ExtractorSource::Request,
            Some("response") => oatf::enums::ExtractorSource::Response,
            _ => source.clone(),
        };
        let extractor = Extractor {
            name: case.input.extractor.name.clone(),
            source,
            extractor_type: ext_type,
            selector: case.input.extractor.selector.clone(),
        };

        let result = primitives::evaluate_extractor(&extractor, &case.input.message, direction);

        if result == case.expected {
            passed += 1;
        } else {
            eprintln!(
                "  FAIL [{}] {}: expected {:?}, got {:?}",
                case.id, case.name, case.expected, result
            );
            failed += 1;
        }
    }

    eprintln!(
        "\nevaluate_extractor: {} passed, {} failed out of {} total",
        passed,
        failed,
        cases.len()
    );
    assert_eq!(failed, 0, "{} evaluate_extractor tests failed", failed);
}

// --- compute_effective_state -------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct EffectiveStateCase {
    name: String,
    id: String,
    input: EffectiveStateInput,
    expected: Value,
}

#[derive(Debug, serde::Deserialize)]
struct EffectiveStateInput {
    phases: Vec<PhaseInput>,
    phase_index: usize,
}

#[derive(Debug, serde::Deserialize)]
struct PhaseInput {
    name: String,
    #[serde(default)]
    state: Option<Value>,
}

#[test]
fn compute_effective_state_suite() {
    let path = conformance_dir().join("primitives/compute-effective-state.yaml");
    assert!(
        path.exists(),
        "Conformance fixture not found: {:?}. Is the spec submodule initialized?",
        path
    );

    let content = std::fs::read_to_string(&path).unwrap();
    let cases: Vec<EffectiveStateCase> = serde_saphyr::from_str(&content).unwrap();

    let mut passed = 0;
    let mut failed = 0;

    for case in &cases {
        // Build Phase structs from test input
        let phases: Vec<Phase> = case
            .input
            .phases
            .iter()
            .map(|p| Phase {
                name: Some(p.name.clone()),
                description: None,
                mode: None,
                state: p.state.clone(),
                extractors: None,
                on_enter: None,
                trigger: None,
                extensions: std::collections::HashMap::new(),
            })
            .collect();

        let result = primitives::compute_effective_state(&phases, case.input.phase_index);

        if result == case.expected {
            passed += 1;
        } else {
            eprintln!(
                "  FAIL [{}] {}: expected {:?}, got {:?}",
                case.id, case.name, case.expected, result
            );
            failed += 1;
        }
    }

    eprintln!(
        "\ncompute_effective_state: {} passed, {} failed out of {} total",
        passed,
        failed,
        cases.len()
    );
    assert_eq!(failed, 0, "{} compute_effective_state tests failed", failed);
}

// --- resolve_event_qualifier -------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct QualifierCase {
    name: String,
    id: String,
    input: QualifierInput,
    expected: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct QualifierInput {
    protocol: String,
    base_event: String,
    content: Value,
}

#[test]
fn resolve_event_qualifier_suite() {
    let path = conformance_dir().join("primitives/resolve-event-qualifier.yaml");
    assert!(
        path.exists(),
        "Conformance fixture not found: {:?}. Is the spec submodule initialized?",
        path
    );

    let content = std::fs::read_to_string(&path).unwrap();
    let cases: Vec<QualifierCase> = serde_saphyr::from_str(&content).unwrap();

    let mut passed = 0;
    let mut failed = 0;

    for case in &cases {
        let result = primitives::resolve_event_qualifier(
            &case.input.protocol,
            &case.input.base_event,
            &case.input.content,
        );

        if result == case.expected {
            passed += 1;
        } else {
            eprintln!(
                "  FAIL [{}] {}: expected {:?}, got {:?}",
                case.id, case.name, case.expected, result
            );
            failed += 1;
        }
    }

    eprintln!(
        "\nresolve_event_qualifier: {} passed, {} failed out of {} total",
        passed,
        failed,
        cases.len()
    );
    assert_eq!(failed, 0, "{} resolve_event_qualifier tests failed", failed);
}

// --- evaluate_trigger --------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct TriggerCase {
    name: String,
    id: String,
    input: TriggerInput,
    expected: TriggerExpected,
}

#[derive(Debug, serde::Deserialize)]
struct TriggerInput {
    trigger: TriggerDef,
    event: Option<TriggerEventDef>,
    elapsed: String,
    state: TriggerStateDef,
    protocol: String,
}

#[derive(Debug, serde::Deserialize)]
struct TriggerDef {
    #[serde(default)]
    event: Option<String>,
    #[serde(default)]
    count: Option<i64>,
    #[serde(default)]
    after: Option<String>,
    #[serde(default, rename = "match")]
    match_predicate: Option<Value>,
}

#[derive(Debug, serde::Deserialize)]
struct TriggerEventDef {
    event_type: String,
    #[serde(default)]
    qualifier: Option<String>,
    content: Value,
}

#[derive(Debug, serde::Deserialize)]
struct TriggerStateDef {
    event_count: u64,
}

#[derive(Debug, serde::Deserialize)]
struct TriggerExpected {
    result: String,
    #[serde(default)]
    reason: Option<String>,
    state: TriggerStateDef,
}

#[test]
fn evaluate_trigger_suite() {
    let path = conformance_dir().join("primitives/evaluate-trigger.yaml");
    assert!(
        path.exists(),
        "Conformance fixture not found: {:?}. Is the spec submodule initialized?",
        path
    );

    let content = std::fs::read_to_string(&path).unwrap();
    let cases: Vec<TriggerCase> = serde_saphyr::from_str(&content).unwrap();

    let mut passed = 0;
    let mut failed = 0;

    for case in &cases {
        let trigger = Trigger {
            event: case.input.trigger.event.clone(),
            count: case.input.trigger.count,
            after: case.input.trigger.after.clone(),
            match_predicate: case
                .input
                .trigger
                .match_predicate
                .as_ref()
                .map(|v| parse_match_predicate(v)),
        };

        let event = case.input.event.as_ref().map(|e| ProtocolEvent {
            event_type: e.event_type.clone(),
            qualifier: e.qualifier.clone(),
            content: e.content.clone(),
        });

        let elapsed = primitives::parse_duration(&case.input.elapsed).unwrap();
        let mut state = TriggerState {
            event_count: case.input.state.event_count,
        };

        let result = primitives::evaluate_trigger(
            &trigger,
            event.as_ref(),
            elapsed,
            &mut state,
            &case.input.protocol,
        );

        let (result_str, reason_str) = match &result {
            TriggerResult::Advanced { reason } => {
                let r = match reason {
                    oatf::enums::AdvanceReason::Timeout => "timeout",
                    oatf::enums::AdvanceReason::EventMatched => "event_matched",
                };
                ("advanced", Some(r))
            }
            TriggerResult::NotAdvanced => ("not_advanced", None),
        };

        let result_ok = result_str == case.expected.result;
        let reason_ok = match (&case.expected.reason, reason_str) {
            (Some(expected), Some(actual)) => expected == actual,
            (None, _) => true,
            (Some(_), None) => false,
        };
        let state_ok = state.event_count == case.expected.state.event_count;

        if result_ok && reason_ok && state_ok {
            passed += 1;
        } else {
            eprintln!(
                "  FAIL [{}] {}: expected result={} reason={:?} state.event_count={}, got result={} reason={:?} state.event_count={}",
                case.id,
                case.name,
                case.expected.result,
                case.expected.reason,
                case.expected.state.event_count,
                result_str,
                reason_str,
                state.event_count,
            );
            failed += 1;
        }
    }

    eprintln!(
        "\nevaluate_trigger: {} passed, {} failed out of {} total",
        passed,
        failed,
        cases.len()
    );
    assert_eq!(failed, 0, "{} evaluate_trigger tests failed", failed);
}

// --- interpolate_value -------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct InterpolateValueCase {
    name: String,
    id: String,
    input: InterpolateValueInput,
    expected: Value,
}

#[derive(Debug, serde::Deserialize)]
struct InterpolateValueInput {
    value: Value,
    #[serde(default)]
    extractors: HashMap<String, String>,
    #[serde(default)]
    request: Option<Value>,
    #[serde(default)]
    response: Option<Value>,
}

#[test]
fn interpolate_value_suite() {
    let path = conformance_dir().join("primitives/interpolate-value.yaml");
    assert!(
        path.exists(),
        "Conformance fixture not found: {:?}. Is the spec submodule initialized?",
        path
    );

    let content = std::fs::read_to_string(&path).unwrap();
    let cases: Vec<InterpolateValueCase> = serde_saphyr::from_str(&content).unwrap();

    let mut passed = 0;
    let mut failed = 0;

    for case in &cases {
        let (result, _diagnostics) = primitives::interpolate_value(
            &case.input.value,
            &case.input.extractors,
            case.input.request.as_ref(),
            case.input.response.as_ref(),
        );

        if result == case.expected {
            passed += 1;
        } else {
            eprintln!(
                "  FAIL [{}] {}: expected {:?}, got {:?}",
                case.id, case.name, case.expected, result
            );
            failed += 1;
        }
    }

    eprintln!(
        "\ninterpolate_value: {} passed, {} failed out of {} total",
        passed,
        failed,
        cases.len()
    );
    assert_eq!(failed, 0, "{} interpolate_value tests failed", failed);
}

// --- evaluate_extractor direction tests (supplementary) ----------------------

#[test]
fn extractor_direction_mismatch_request() {
    let extractor = Extractor {
        name: "x".to_string(),
        source: oatf::enums::ExtractorSource::Request,
        extractor_type: oatf::enums::ExtractorType::JsonPath,
        selector: "$.name".to_string(),
    };
    let result = primitives::evaluate_extractor(
        &extractor,
        &json!({"name": "test"}),
        oatf::enums::ExtractorSource::Response,
    );
    assert_eq!(result, None);
}

#[test]
fn extractor_direction_mismatch_response() {
    let extractor = Extractor {
        name: "x".to_string(),
        source: oatf::enums::ExtractorSource::Response,
        extractor_type: oatf::enums::ExtractorType::JsonPath,
        selector: "$.name".to_string(),
    };
    let result = primitives::evaluate_extractor(
        &extractor,
        &json!({"name": "test"}),
        oatf::enums::ExtractorSource::Request,
    );
    assert_eq!(result, None);
}

#[test]
fn extractor_direction_match_extracts() {
    let extractor = Extractor {
        name: "x".to_string(),
        source: oatf::enums::ExtractorSource::Response,
        extractor_type: oatf::enums::ExtractorType::JsonPath,
        selector: "$.name".to_string(),
    };
    let result = primitives::evaluate_extractor(
        &extractor,
        &json!({"name": "test"}),
        oatf::enums::ExtractorSource::Response,
    );
    assert_eq!(result, Some("test".to_string()));
}
