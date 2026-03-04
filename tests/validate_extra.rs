use oatf::parse::parse;
use oatf::validate::validate;

/// Helper: parse then validate, return errors matching a specific rule.
fn errors_for(input: &str, rule: &str) -> Vec<String> {
    let doc = parse(input).expect("parse should succeed");
    let result = validate(&doc);
    result
        .errors
        .iter()
        .filter(|e| e.rule == rule)
        .map(|e| e.path.clone())
        .collect()
}

/// Helper: parse then validate, assert error with specific rule.
fn assert_has_error(input: &str, rule: &str) {
    let doc = parse(input).expect("parse should succeed");
    let result = validate(&doc);
    assert!(
        result.errors.iter().any(|e| e.rule == rule),
        "expected error {}, got: {:?}",
        rule,
        result.errors
    );
}

/// Helper: parse then validate, return warnings matching a specific code.
fn warnings_for(input: &str, code: &str) -> Vec<String> {
    let doc = parse(input).expect("parse should succeed");
    let result = validate(&doc);
    result
        .warnings
        .iter()
        .filter(|w| w.code == code)
        .map(|w| w.message.clone())
        .collect()
}

// ─── V-021: Wildcard dot-path syntax ────────────────────────────────────────

#[test]
fn v021_valid_wildcard_paths() {
    let cases = [
        r#"tools[*].description"#,
        r#"content[*]"#,
        r#"arguments"#,
        r#"skills[*].description"#,
        r#"messages[*].content"#,
    ];
    for target in &cases {
        let input = format!(
            r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    state:
      tools: []
  indicators:
    - surface: tool_description
      pattern:
        target: "{}"
        condition:
          contains: "test"
"#,
            target
        );
        let errs = errors_for(&input, "V-021");
        assert!(
            errs.is_empty(),
            "target '{}' should be valid but got: {:?}",
            target,
            errs
        );
    }
}

#[test]
fn v021_rejects_numeric_index() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    state:
      tools: []
  indicators:
    - surface: tool_description
      pattern:
        target: "tools[0].description"
        condition:
          contains: "test"
"#;
    assert_has_error(input, "V-021");
}

#[test]
fn v021_rejects_double_dot() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    state:
      tools: []
  indicators:
    - surface: tool_description
      pattern:
        target: "tools..name"
        condition:
          contains: "test"
"#;
    assert_has_error(input, "V-021");
}

// ─── V-022: Semantic threshold ──────────────────────────────────────────────

#[test]
fn v022_threshold_out_of_range() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    state:
      tools: []
  indicators:
    - surface: tool_description
      semantic:
        intent: "exfiltrate data"
        threshold: 1.5
"#;
    assert_has_error(input, "V-022");
}

#[test]
fn v022_threshold_valid() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    state:
      tools: []
  indicators:
    - surface: tool_description
      semantic:
        intent: "exfiltrate data"
        threshold: 0.8
"#;
    let errs = errors_for(input, "V-022");
    assert!(
        errs.is_empty(),
        "valid threshold should not error: {:?}",
        errs
    );
}

// ─── V-023: Attack ID format ────────────────────────────────────────────────

#[test]
fn v023_valid_attack_id() {
    let input = r#"
oatf: "0.1"
attack:
  id: OATF-TOOL-001
  execution:
    mode: mcp_server
    state:
      tools: []
  indicators:
    - surface: tool_description
      pattern:
        contains: "test"
"#;
    let errs = errors_for(input, "V-023");
    assert!(
        errs.is_empty(),
        "valid attack ID should not error: {:?}",
        errs
    );
}

// ─── V-024: Indicator ID format ─────────────────────────────────────────────

#[test]
fn v024_valid_indicator_id() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    state:
      tools: []
  indicators:
    - id: OATF-001-01
      surface: tool_description
      pattern:
        contains: "test"
"#;
    let errs = errors_for(input, "V-024");
    assert!(
        errs.is_empty(),
        "valid indicator ID should not error: {:?}",
        errs
    );
}

// ─── V-025: Indicator confidence range ──────────────────────────────────────

#[test]
fn v025_confidence_out_of_range() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    state:
      tools: []
  indicators:
    - surface: tool_description
      confidence: 150
      pattern:
        contains: "test"
"#;
    assert_has_error(input, "V-025");
}

// ─── V-029: Event-mode validity ─────────────────────────────────────────────

#[test]
fn v029_valid_event_for_mode() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    phases:
      - name: phase-1
        state:
          tools: []
        trigger:
          event: tools/call
      - name: phase-2
        description: "Terminal phase."
  indicators:
    - surface: tool_description
      pattern:
        contains: "test"
"#;
    let errs = errors_for(input, "V-029");
    assert!(errs.is_empty(), "valid event should not error: {:?}", errs);
}

// ─── V-030: Mutual exclusion (state/phases/actors) ──────────────────────────

#[test]
fn v030_state_and_phases_both_present() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    state:
      tools: []
    phases:
      - name: phase-1
        state:
          tools: []
  indicators:
    - surface: tool_description
      pattern:
        contains: "test"
"#;
    assert_has_error(input, "V-030");
}

// ─── V-031: Multi-actor constraints ─────────────────────────────────────────

#[test]
fn v031_actors_must_have_unique_names() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    actors:
      - name: attacker
        mode: mcp_server
        phases:
          - name: phase-1
            state:
              tools: []
      - name: attacker
        mode: a2a_server
        phases:
          - name: phase-1
            state:
              agent_card:
                name: "Agent"
                description: "Agent"
                url: "https://example.com"
                skills: []
  indicators:
    - surface: tool_description
      pattern:
        contains: "test"
"#;
    assert_has_error(input, "V-031");
}

// ─── V-037: Version must be positive integer ────────────────────────────────

#[test]
fn v037_zero_version() {
    let input = r#"
oatf: "0.1"
attack:
  version: 0
  execution:
    mode: mcp_server
    state:
      tools: []
  indicators:
    - surface: tool_description
      pattern:
        contains: "test"
"#;
    assert_has_error(input, "V-037");
}

#[test]
fn v037_negative_version() {
    let input = r#"
oatf: "0.1"
attack:
  version: -1
  execution:
    mode: mcp_server
    state:
      tools: []
  indicators:
    - surface: tool_description
      pattern:
        contains: "test"
"#;
    assert_has_error(input, "V-037");
}

// ─── V-038: Trigger after duration format ───────────────────────────────────

#[test]
fn v038_valid_duration() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    phases:
      - name: wait
        state:
          tools: []
        trigger:
          after: "30s"
      - name: exploit
        description: "Terminal phase."
  indicators:
    - surface: tool_description
      pattern:
        contains: "test"
"#;
    let errs = errors_for(input, "V-038");
    assert!(
        errs.is_empty(),
        "valid duration should not error: {:?}",
        errs
    );
}

#[test]
fn v038_invalid_duration() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    phases:
      - name: wait
        state:
          tools: []
        trigger:
          after: "invalid"
      - name: exploit
        description: "Terminal phase."
  indicators:
    - surface: tool_description
      pattern:
        contains: "test"
"#;
    assert_has_error(input, "V-038");
}

// ─── V-039: Extractor name pattern ──────────────────────────────────────────

#[test]
fn v039_valid_extractor_name() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    phases:
      - name: phase-1
        state:
          tools: []
        extractors:
          - name: user_input
            source: request
            type: json_path
            selector: "$.arguments.a"
        trigger:
          event: tools/call
      - name: phase-2
        description: "Terminal."
  indicators:
    - surface: tool_description
      pattern:
        contains: "test"
"#;
    let errs = errors_for(input, "V-039");
    assert!(
        errs.is_empty(),
        "valid extractor name should not error: {:?}",
        errs
    );
}

// ─── V-040: Extractors non-empty ────────────────────────────────────────────

#[test]
fn v040_empty_extractors_array() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    phases:
      - name: phase-1
        state:
          tools: []
        extractors: []
        trigger:
          event: tools/call
      - name: phase-2
        description: "Terminal."
  indicators:
    - surface: tool_description
      pattern:
        contains: "test"
"#;
    assert_has_error(input, "V-040");
}

// ─── V-042: Trigger must have event or after ────────────────────────────────

#[test]
fn v042_trigger_with_only_count() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    phases:
      - name: phase-1
        state:
          tools: []
        trigger:
          count: 3
      - name: phase-2
        description: "Terminal."
  indicators:
    - surface: tool_description
      pattern:
        contains: "test"
"#;
    assert_has_error(input, "V-042");
}

// ─── V-043: Binding-specific action keys ────────────────────────────────────

#[test]
fn v043_valid_known_action() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    phases:
      - name: phase-1
        state:
          tools: []
        on_enter:
          - log:
              message: "Phase entered"
              level: info
        trigger:
          event: tools/call
      - name: phase-2
        description: "Terminal."
  indicators:
    - surface: tool_description
      pattern:
        contains: "test"
"#;
    let errs = errors_for(input, "V-043");
    assert!(errs.is_empty(), "valid action should not error: {:?}", errs);
}

// ─── V-010: Unique indicator IDs ────────────────────────────────────────────

#[test]
fn v010_duplicate_indicator_ids() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    state:
      tools: []
  indicators:
    - id: dup-01
      surface: tool_description
      pattern:
        contains: "test"
    - id: dup-01
      surface: tool_name
      pattern:
        contains: "evil"
"#;
    assert_has_error(input, "V-010");
}

// ─── V-012: Exactly one detection key per indicator ─────────────────────────

#[test]
fn v012_no_detection_key() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    state:
      tools: []
  indicators:
    - surface: tool_description
"#;
    assert_has_error(input, "V-012");
}

#[test]
fn v012_two_detection_keys() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    state:
      tools: []
  indicators:
    - surface: tool_description
      pattern:
        contains: "test"
      semantic:
        intent: "exfiltrate"
"#;
    assert_has_error(input, "V-012");
}

// ─── V-013: Regex must compile ──────────────────────────────────────────────

#[test]
fn v013_invalid_regex() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    state:
      tools: []
  indicators:
    - surface: tool_description
      pattern:
        regex: "[unclosed"
"#;
    assert_has_error(input, "V-013");
}

#[test]
fn v013_valid_regex() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    state:
      tools: []
  indicators:
    - surface: tool_description
      pattern:
        regex: "(passwd|shadow|id_rsa)"
"#;
    let errs = errors_for(input, "V-013");
    assert!(errs.is_empty(), "valid regex should not error: {:?}", errs);
}

// ─── V-006: Indicators non-empty ────────────────────────────────────────────

#[test]
fn v006_empty_indicators() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    state:
      tools: []
  indicators: []
"#;
    assert_has_error(input, "V-006");
}

// ─── V-007: Phases non-empty ────────────────────────────────────────────────

#[test]
fn v007_empty_phases() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    phases: []
  indicators:
    - surface: tool_description
      pattern:
        contains: "test"
"#;
    assert_has_error(input, "V-007");
}

// ─── V-019: Trigger count constraints ───────────────────────────────────────

#[test]
fn v019_trigger_count_zero_rejected() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    phases:
      - name: phase-1
        state:
          tools: []
        trigger:
          event: tools/call
          count: 0
      - name: phase-2
        description: "Terminal."
  indicators:
    - surface: tool_description
      pattern:
        contains: "test"
"#;
    assert_has_error(input, "V-019");
}

#[test]
fn v019_trigger_count_negative_rejected() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    phases:
      - name: phase-1
        state:
          tools: []
        trigger:
          event: tools/call
          count: -1
      - name: phase-2
        description: "Terminal."
  indicators:
    - surface: tool_description
      pattern:
        contains: "test"
"#;
    assert_has_error(input, "V-019");
}

// ─── V-016: Template syntax in on_enter ─────────────────────────────────────

#[test]
fn v016_unclosed_template_in_on_enter_rejected() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    phases:
      - name: phase-1
        state:
          tools: []
        on_enter:
          - log:
              message: "started {{unclosed"
        trigger:
          event: tools/call
      - name: phase-2
        description: "Terminal."
  indicators:
    - surface: tool_description
      pattern:
        contains: "test"
"#;
    assert_has_error(input, "V-016");
}

// ─── V-032 / W-004: Single-phase template reference checks ──────────────────

#[test]
fn v032_single_phase_unknown_actor_reference_rejected() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    state:
      tools:
        - name: t1
          description: "use {{ghost.extractor}}"
  indicators:
    - surface: tool_description
      pattern:
        contains: "test"
"#;
    assert_has_error(input, "V-032");
}

#[test]
fn w004_single_phase_undeclared_extractor_warns() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    state:
      tools:
        - name: t1
          description: "use {{missing_extractor}}"
  indicators:
    - surface: tool_description
      pattern:
        contains: "test"
"#;
    let warnings = warnings_for(input, "W-004");
    assert!(
        !warnings.is_empty(),
        "undeclared extractor in single-phase state should emit W-004"
    );
}

// ─── V-044: Regex extractor capture group ───────────────────────────────────

#[test]
fn v044_regex_with_literal_parenthesis_and_no_group_rejected() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    phases:
      - name: phase-1
        state:
          tools: []
        extractors:
          - name: lit
            source: request
            type: regex
            selector: "[(]"
        trigger:
          event: tools/call
      - name: phase-2
        description: "Terminal."
  indicators:
    - surface: tool_description
      pattern:
        contains: "test"
"#;
    assert_has_error(input, "V-044");
}

// ─── Parse strictness: malformed pattern operator types ─────────────────────

#[test]
fn parse_rejects_shorthand_pattern_wrong_type() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    state:
      tools: []
  indicators:
    - surface: tool_description
      pattern:
        contains: 123
"#;
    assert!(parse(input).is_err(), "contains:number must fail parse");
}

#[test]
fn parse_rejects_condition_operator_wrong_type() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    state:
      tools: []
  indicators:
    - surface: tool_description
      pattern:
        condition:
          contains: 123
"#;
    assert!(
        parse(input).is_err(),
        "pattern.condition.contains:number must fail parse"
    );
}
