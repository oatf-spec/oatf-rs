use oatf::normalize::normalize;
use oatf::parse::parse;
use oatf::serialize::serialize;
use proptest::prelude::*;

/// Strategy for valid mode strings.
fn arb_mode() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("mcp_server".to_string()),
        Just("mcp_client".to_string()),
        Just("a2a_server".to_string()),
        Just("a2a_client".to_string()),
    ]
}

/// Strategy for valid severity levels.
fn arb_severity() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("informational"),
        Just("low"),
        Just("medium"),
        Just("high"),
        Just("critical"),
    ]
    .prop_map(|s| s.to_string())
}

/// Strategy for valid surface names.
fn arb_surface() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("tool_description"),
        Just("tool_output"),
        Just("tool_input"),
        Just("prompt_text"),
        Just("resource_content"),
    ]
    .prop_map(|s| s.to_string())
}

/// Build a minimal single-phase (state) form document.
fn build_single_phase_doc(mode: &str, tool_name: &str) -> String {
    format!(
        r#"oatf: "0.1"
attack:
  execution:
    mode: {mode}
    state:
      tools:
        - name: {tool_name}
          description: "A test tool"
          inputSchema:
            type: object"#,
    )
}

/// Build a minimal multi-phase form document.
fn build_multi_phase_doc(mode: &str, tool_name: &str) -> String {
    format!(
        r#"oatf: "0.1"
attack:
  execution:
    mode: {mode}
    phases:
      - name: exploit
        state:
          tools:
            - name: {tool_name}
              description: "A test tool"
              inputSchema:
                type: object
        trigger:
          event: tools/call
      - name: terminal"#,
    )
}

/// Build a minimal multi-actor form document.
fn build_multi_actor_doc(mode: &str, tool_name: &str) -> String {
    format!(
        r#"oatf: "0.1"
attack:
  execution:
    actors:
      - name: default
        mode: {mode}
        phases:
          - name: exploit
            state:
              tools:
                - name: {tool_name}
                  description: "A test tool"
                  inputSchema:
                    type: object
            trigger:
              event: tools/call
          - name: terminal"#,
    )
}

/// Build a document with indicators and severity.
fn build_doc_with_indicators(mode: &str, surface: &str, severity: &str) -> String {
    format!(
        r#"oatf: "0.1"
attack:
  severity: {severity}
  execution:
    mode: {mode}
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
    - surface: {surface}
      pattern:
        contains: malicious"#,
    )
}

/// Compare two documents structurally via their serialized JSON form.
fn docs_equal(a: &oatf::types::Document, b: &oatf::types::Document) -> bool {
    let a_json = serde_json::to_value(a).unwrap();
    let b_json = serde_json::to_value(b).unwrap();
    a_json == b_json
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    // Normalization is idempotent: normalize(normalize(doc)) == normalize(doc)
    #[test]
    fn single_phase_idempotent(
        mode in arb_mode(),
        tool_name in "[a-z]{2,8}",
    ) {
        let yaml = build_single_phase_doc(&mode, &tool_name);
        let doc = parse(&yaml).expect("parse should succeed");
        let n1 = normalize(doc);
        let n2 = normalize(n1.clone());
        prop_assert!(docs_equal(&n1, &n2),
            "normalize not idempotent for single-phase form with mode={}", mode);
    }

    #[test]
    fn multi_phase_idempotent(
        mode in arb_mode(),
        tool_name in "[a-z]{2,8}",
    ) {
        let yaml = build_multi_phase_doc(&mode, &tool_name);
        let doc = parse(&yaml).expect("parse should succeed");
        let n1 = normalize(doc);
        let n2 = normalize(n1.clone());
        prop_assert!(docs_equal(&n1, &n2),
            "normalize not idempotent for multi-phase form with mode={}", mode);
    }

    #[test]
    fn multi_actor_idempotent(
        mode in arb_mode(),
        tool_name in "[a-z]{2,8}",
    ) {
        let yaml = build_multi_actor_doc(&mode, &tool_name);
        let doc = parse(&yaml).expect("parse should succeed");
        let n1 = normalize(doc);
        let n2 = normalize(n1.clone());
        prop_assert!(docs_equal(&n1, &n2),
            "normalize not idempotent for multi-actor form with mode={}", mode);
    }

    // After normalization, single-phase/multi-phase forms are converted to actors form
    #[test]
    fn single_phase_becomes_actors(
        mode in arb_mode(),
        tool_name in "[a-z]{2,8}",
    ) {
        let yaml = build_single_phase_doc(&mode, &tool_name);
        let doc = parse(&yaml).expect("parse should succeed");
        let normalized = normalize(doc);
        prop_assert!(normalized.attack.execution.actors.is_some(),
            "single-phase should normalize to actors form");
        prop_assert!(normalized.attack.execution.state.is_none(),
            "single-phase state should be cleared after normalization");
    }

    #[test]
    fn multi_phase_becomes_actors(
        mode in arb_mode(),
        tool_name in "[a-z]{2,8}",
    ) {
        let yaml = build_multi_phase_doc(&mode, &tool_name);
        let doc = parse(&yaml).expect("parse should succeed");
        let normalized = normalize(doc);
        prop_assert!(normalized.attack.execution.actors.is_some(),
            "multi-phase should normalize to actors form");
        prop_assert!(normalized.attack.execution.phases.is_none(),
            "multi-phase phases should be cleared after normalization");
    }

    // N-001 defaults are applied
    #[test]
    fn defaults_applied(
        mode in arb_mode(),
        tool_name in "[a-z]{2,8}",
    ) {
        let yaml = build_multi_phase_doc(&mode, &tool_name);
        let doc = parse(&yaml).expect("parse should succeed");
        let normalized = normalize(doc);
        prop_assert_eq!(normalized.attack.name.as_deref(), Some("Untitled"));
        prop_assert_eq!(normalized.attack.version, Some(1));
        prop_assert_eq!(normalized.attack.status, Some(oatf::enums::Status::Draft));
    }

    // N-002 severity scalar → object expansion
    #[test]
    fn severity_expanded(
        mode in arb_mode(),
        severity in arb_severity(),
        surface in arb_surface(),
    ) {
        let yaml = build_doc_with_indicators(&mode, &surface, &severity);
        let doc = parse(&yaml).expect("parse should succeed");
        let normalized = normalize(doc);
        if let Some(ref sev) = normalized.attack.severity {
            match sev {
                oatf::types::Severity::Object { confidence, .. } => {
                    prop_assert_eq!(*confidence, Some(50),
                        "severity.confidence should default to 50");
                }
                oatf::types::Severity::Scalar(_) => {
                    prop_assert!(false, "severity should be expanded to object form");
                }
            }
        }
    }

    // N-003 indicator IDs auto-generated
    #[test]
    fn indicator_ids_generated(
        mode in arb_mode(),
        surface in arb_surface(),
        severity in arb_severity(),
    ) {
        let yaml = build_doc_with_indicators(&mode, &surface, &severity);
        let doc = parse(&yaml).expect("parse should succeed");
        let normalized = normalize(doc);
        if let Some(indicators) = &normalized.attack.indicators {
            for ind in indicators {
                prop_assert!(ind.id.is_some(), "indicator should have auto-generated id");
            }
        }
    }

    // Serialized normalized doc can be re-parsed
    #[test]
    fn normalized_is_reparseable(
        mode in arb_mode(),
        tool_name in "[a-z]{2,8}",
    ) {
        let yaml = build_multi_phase_doc(&mode, &tool_name);
        let doc = parse(&yaml).expect("parse should succeed");
        let normalized = normalize(doc);
        let serialized = serialize(&normalized).expect("serialize should succeed");
        let reparsed = parse(&serialized);
        prop_assert!(reparsed.is_ok(),
            "re-parsing normalized document failed: {:?}", reparsed.err());
    }
}
