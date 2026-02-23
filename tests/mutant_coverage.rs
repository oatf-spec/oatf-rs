//! Tests targeting gaps identified by mutation testing.

use oatf::enums::*;
use oatf::error::*;
use oatf::evaluate::{SemanticEvaluator, compute_verdict};
use oatf::types::*;
use serde_json::json;
use std::collections::HashMap;

// ─── 1. load() must reject documents with validation errors ──────────────────

#[test]
fn load_rejects_invalid_document() {
    // Missing required `execution` field — should fail validation.
    let yaml = r#"
oatf: "0.1"
attack:
  indicators:
    - surface: tool_description
      pattern:
        contains: test
"#;
    let result = oatf::load(yaml);
    assert!(
        result.is_err(),
        "load() must return Err for invalid documents"
    );
}

#[test]
fn load_returns_ok_for_valid_document() {
    let yaml = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    phases:
      - name: exploit
        state:
          tools:
            - name: test-tool
              description: "desc"
              inputSchema:
                type: object
        trigger:
          event: tools/call
      - name: terminal
  indicators:
    - surface: tool_description
      pattern:
        contains: test
"#;
    let result = oatf::load(yaml);
    assert!(result.is_ok(), "load() must return Ok for valid documents");
}

// ─── 2. ValidationResult::is_valid ───────────────────────────────────────────

#[test]
fn is_valid_returns_true_when_no_errors() {
    let result = ValidationResult::default();
    assert!(result.is_valid());
}

#[test]
fn is_valid_returns_false_when_errors_present() {
    let result = ValidationResult {
        errors: vec![ValidationError {
            rule: "V-001".to_string(),
            path: "attack".to_string(),
            message: "test error".to_string(),
        }],
        warnings: vec![],
    };
    assert!(!result.is_valid());
}

// ─── 3. evaluate_semantic threshold boundary (>= not >) ─────────────────────

/// Mock semantic evaluator that returns a fixed score.
struct FixedScoreEvaluator(f64);

impl SemanticEvaluator for FixedScoreEvaluator {
    fn evaluate(
        &self,
        _text: &str,
        _intent: &str,
        _intent_class: Option<&SemanticIntentClass>,
        _threshold: Option<f64>,
        _examples: Option<&SemanticExamples>,
    ) -> Result<f64, EvaluationError> {
        Ok(self.0)
    }
}

fn make_semantic_indicator(id: &str, threshold: f64) -> Indicator {
    Indicator {
        id: Some(id.to_string()),
        protocol: None,
        surface: "tool_description".to_string(),
        description: None,
        pattern: None,
        expression: None,
        semantic: Some(SemanticMatch {
            target: None,
            intent: "malicious".to_string(),
            intent_class: None,
            threshold: Some(threshold),
            examples: None,
        }),
        confidence: None,
        severity: None,
        false_positives: None,
        extensions: HashMap::new(),
    }
}

#[test]
fn semantic_score_exactly_at_threshold_matches() {
    use oatf::evaluate::evaluate_indicator;

    let indicator = make_semantic_indicator("sem-1", 0.8);
    // Score == threshold → should match (>= semantics)
    let evaluator = FixedScoreEvaluator(0.8);
    let message = json!("some suspicious text");

    let verdict = evaluate_indicator(&indicator, &message, None, Some(&evaluator));
    assert_eq!(
        verdict.result,
        IndicatorResult::Matched,
        "score == threshold must match"
    );
}

#[test]
fn semantic_score_just_below_threshold_does_not_match() {
    use oatf::evaluate::evaluate_indicator;

    let indicator = make_semantic_indicator("sem-2", 0.8);
    let evaluator = FixedScoreEvaluator(0.79);
    let message = json!("some text");

    let verdict = evaluate_indicator(&indicator, &message, None, Some(&evaluator));
    assert_eq!(
        verdict.result,
        IndicatorResult::NotMatched,
        "score < threshold must not match"
    );
}

// ─── 4. compute_verdict counting ─────────────────────────────────────────────

fn make_attack(indicator_ids: &[&str], logic: CorrelationLogic) -> Attack {
    let indicators: Vec<Indicator> = indicator_ids
        .iter()
        .map(|id| Indicator {
            id: Some(id.to_string()),
            protocol: None,
            surface: "tool_description".to_string(),
            description: None,
            pattern: None,
            expression: None,
            semantic: None,
            confidence: None,
            severity: None,
            false_positives: None,
            extensions: HashMap::new(),
        })
        .collect();

    Attack {
        id: Some("ATK-001".to_string()),
        name: None,
        version: None,
        status: None,
        created: None,
        modified: None,
        author: None,
        description: None,
        grace_period: None,
        severity: None,
        impact: None,
        classification: None,
        references: None,
        execution: Execution {
            mode: Some("mcp_server".to_string()),
            state: None,
            phases: None,
            actors: None,
            extensions: HashMap::new(),
        },
        indicators: Some(indicators),
        correlation: Some(Correlation { logic: Some(logic) }),
        extensions: HashMap::new(),
    }
}

fn make_verdict(id: &str, result: IndicatorResult) -> IndicatorVerdict {
    IndicatorVerdict {
        indicator_id: id.to_string(),
        result,
        timestamp: None,
        evidence: None,
        source: None,
    }
}

#[test]
fn verdict_any_counts_matched_correctly() {
    let attack = make_attack(&["i1", "i2", "i3"], CorrelationLogic::Any);
    let mut verdicts = HashMap::new();
    verdicts.insert(
        "i1".to_string(),
        make_verdict("i1", IndicatorResult::Matched),
    );
    verdicts.insert(
        "i2".to_string(),
        make_verdict("i2", IndicatorResult::NotMatched),
    );
    verdicts.insert(
        "i3".to_string(),
        make_verdict("i3", IndicatorResult::NotMatched),
    );

    let result = compute_verdict(&attack, &verdicts);
    assert_eq!(result.result, AttackResult::Exploited);
    assert_eq!(result.evaluation_summary.matched, 1);
    assert_eq!(result.evaluation_summary.not_matched, 2);
    assert_eq!(result.evaluation_summary.error, 0);
    assert_eq!(result.evaluation_summary.skipped, 0);
}

#[test]
fn verdict_all_partial_when_mixed() {
    let attack = make_attack(&["i1", "i2"], CorrelationLogic::All);
    let mut verdicts = HashMap::new();
    verdicts.insert(
        "i1".to_string(),
        make_verdict("i1", IndicatorResult::Matched),
    );
    verdicts.insert(
        "i2".to_string(),
        make_verdict("i2", IndicatorResult::NotMatched),
    );

    let result = compute_verdict(&attack, &verdicts);
    assert_eq!(result.result, AttackResult::Partial);
    assert_eq!(result.evaluation_summary.matched, 1);
    assert_eq!(result.evaluation_summary.not_matched, 1);
}

#[test]
fn verdict_all_exploited_when_all_matched() {
    let attack = make_attack(&["i1", "i2"], CorrelationLogic::All);
    let mut verdicts = HashMap::new();
    verdicts.insert(
        "i1".to_string(),
        make_verdict("i1", IndicatorResult::Matched),
    );
    verdicts.insert(
        "i2".to_string(),
        make_verdict("i2", IndicatorResult::Matched),
    );

    let result = compute_verdict(&attack, &verdicts);
    assert_eq!(result.result, AttackResult::Exploited);
    assert_eq!(result.evaluation_summary.matched, 2);
    assert_eq!(result.evaluation_summary.not_matched, 0);
}

#[test]
fn verdict_skipped_counted_correctly() {
    let attack = make_attack(&["i1", "i2"], CorrelationLogic::Any);
    let mut verdicts = HashMap::new();
    verdicts.insert(
        "i1".to_string(),
        make_verdict("i1", IndicatorResult::Skipped),
    );
    // i2 has no verdict entry → treated as skipped

    let result = compute_verdict(&attack, &verdicts);
    assert_eq!(result.result, AttackResult::NotExploited);
    assert_eq!(result.evaluation_summary.skipped, 2);
    assert_eq!(result.evaluation_summary.matched, 0);
}

#[test]
fn verdict_error_takes_priority() {
    let attack = make_attack(&["i1", "i2"], CorrelationLogic::Any);
    let mut verdicts = HashMap::new();
    verdicts.insert(
        "i1".to_string(),
        make_verdict("i1", IndicatorResult::Matched),
    );
    verdicts.insert("i2".to_string(), make_verdict("i2", IndicatorResult::Error));

    let result = compute_verdict(&attack, &verdicts);
    assert_eq!(result.result, AttackResult::Error);
    assert_eq!(result.evaluation_summary.error, 1);
    assert_eq!(result.evaluation_summary.matched, 1);
}

// ─── 5. N-006/N-007: normalization form guards ──────────────────────────────

#[test]
fn n006_only_fires_for_single_phase_form() {
    // Multi-phase form (phases present) should NOT be converted by N-006.
    let yaml = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    phases:
      - name: phase1
        state:
          tools:
            - name: t1
              description: "d"
              inputSchema:
                type: object
        trigger:
          event: tools/call
      - name: terminal
  indicators:
    - surface: tool_description
      pattern:
        contains: test
"#;
    let doc = oatf::parse(yaml).unwrap();
    assert!(doc.attack.execution.phases.is_some());
    assert!(doc.attack.execution.state.is_none());
    assert!(doc.attack.execution.actors.is_none());

    let normalized = oatf::normalize(doc);
    // N-007 should handle this, producing actors
    let actors = normalized.attack.execution.actors.unwrap();
    assert_eq!(actors.len(), 1);
    assert_eq!(actors[0].name, "default");
    assert_eq!(actors[0].phases.len(), 2);
}

#[test]
fn n007_does_not_fire_when_actors_present() {
    // If actors already present, N-007 should not modify them.
    let yaml = r#"
oatf: "0.1"
attack:
  execution:
    actors:
      - name: actor1
        mode: mcp_server
        phases:
          - name: p1
            state:
              tools:
                - name: t1
                  description: "d"
                  inputSchema:
                    type: object
            trigger:
              event: tools/call
          - name: terminal
  indicators:
    - surface: tool_description
      pattern:
        contains: test
"#;
    let doc = oatf::parse(yaml).unwrap();
    assert!(doc.attack.execution.actors.is_some());

    let normalized = oatf::normalize(doc);
    let actors = normalized.attack.execution.actors.unwrap();
    assert_eq!(actors.len(), 1);
    assert_eq!(actors[0].name, "actor1");
}

#[test]
fn n006_fires_for_single_phase_form() {
    // Single-phase form: execution.state present, no phases, no actors.
    let yaml = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    state:
      tools:
        - name: t1
          description: "d"
          inputSchema:
            type: object
  indicators:
    - surface: tool_description
      pattern:
        contains: test
"#;
    let doc = oatf::parse(yaml).unwrap();
    assert!(doc.attack.execution.state.is_some());
    assert!(doc.attack.execution.phases.is_none());
    assert!(doc.attack.execution.actors.is_none());

    let normalized = oatf::normalize(doc);
    // N-006 should convert to actors form
    assert!(normalized.attack.execution.state.is_none());
    assert!(normalized.attack.execution.actors.is_some());
    let actors = normalized.attack.execution.actors.unwrap();
    assert_eq!(actors.len(), 1);
    assert_eq!(actors[0].name, "default");
    assert_eq!(actors[0].mode, "mcp_server");
}
