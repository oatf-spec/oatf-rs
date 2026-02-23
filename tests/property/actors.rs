use oatf::parse::parse;
use oatf::validate::validate;
use proptest::prelude::*;

/// Strategy for valid mode strings matching `[a-z][a-z0-9_]*_(server|client)`.
fn arb_mode() -> impl Strategy<Value = String> {
    prop_oneof!["[a-z][a-z0-9]{0,6}_server", "[a-z][a-z0-9]{0,6}_client",]
}

/// Strategy for valid actor names matching `[a-z][a-z0-9_]*`.
fn arb_actor_name() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{0,8}"
}

/// Build a single actor YAML block with given name, mode, and a minimal terminal phase.
/// Names are quoted to prevent YAML boolean parsing (`y` → `true`).
fn actor_yaml(name: &str, mode: &str) -> String {
    format!(
        r#"      - name: "{name}"
        mode: {mode}
        phases:
          - name: terminal"#,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    // Valid single actor with valid mode should pass V-005 (mode pattern)
    #[test]
    fn single_actor_valid_mode(
        name in arb_actor_name(),
        mode in arb_mode(),
    ) {
        let yaml = format!(
            r#"oatf: "0.1"
attack:
  execution:
    actors:
{}"#,
            actor_yaml(&name, &mode),
        );
        let doc = parse(&yaml);
        prop_assert!(doc.is_ok(), "parse failed for name={:?} mode={:?}: {:?}", name, mode, doc.err());
        let result = validate(&doc.unwrap());
        let mode_errors: Vec<_> = result.errors.iter()
            .filter(|e| e.rule == "V-005" && e.message.contains("mode"))
            .collect();
        prop_assert!(mode_errors.is_empty(),
            "V-005 mode errors for valid mode {}: {:?}", mode, mode_errors);
    }

    // Duplicate actor names should trigger V-031 (unique actor names)
    #[test]
    fn duplicate_actor_names_rejected(
        name in arb_actor_name(),
        mode in arb_mode(),
    ) {
        let actor1 = actor_yaml(&name, &mode);
        let actor2 = actor_yaml(&name, &mode);
        let yaml = format!(
            r#"oatf: "0.1"
attack:
  execution:
    actors:
{}
{}"#,
            actor1, actor2,
        );
        let doc = parse(&yaml);
        if let Ok(doc) = doc {
            let result = validate(&doc);
            let dup_errors: Vec<_> = result.errors.iter()
                .filter(|e| e.rule == "V-031" && e.message.contains("duplicate actor name"))
                .collect();
            prop_assert!(!dup_errors.is_empty(),
                "Expected V-031 for duplicate actor name {:?}, got errors: {:?}",
                name, result.errors);
        }
    }

    // Actor with phases where first has state should pass V-009
    #[test]
    fn first_phase_with_state_passes_v009(
        name in arb_actor_name(),
        mode in arb_mode(),
        tool_name in "[a-z]{2,6}",
    ) {
        let yaml = format!(
            r#"oatf: "0.1"
attack:
  execution:
    actors:
      - name: "{name}"
        mode: {mode}
        phases:
          - name: exploit
            state:
              tools:
                - name: {tool_name}
                  description: "test"
                  inputSchema:
                    type: object
            trigger:
              event: tools/call
          - name: terminal"#,
        );
        let doc = parse(&yaml);
        prop_assert!(doc.is_ok(), "parse failed: {:?}", doc.err());
        let result = validate(&doc.unwrap());
        let v009_errors: Vec<_> = result.errors.iter()
            .filter(|e| e.rule == "V-009")
            .collect();
        prop_assert!(v009_errors.is_empty(),
            "Expected no V-009 errors but got: {:?}", v009_errors);
    }

    // Actor name as arbitrary string never panics parse/validate
    #[test]
    fn arbitrary_actor_name_never_panics(
        name in "\\PC{1,20}",
        mode in arb_mode(),
    ) {
        // Escape YAML special characters
        let safe_name = name.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', " ")
            .replace('\r', " ");
        let yaml = format!(
            r#"oatf: "0.1"
attack:
  execution:
    actors:
      - name: "{safe_name}"
        mode: {mode}
        phases:
          - name: terminal"#,
        );
        let _ = parse(&yaml);
    }
}
