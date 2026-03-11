//! Stress tests for resource limits and large/complex documents.

use oatf::{parse, validate};

#[test]
fn stress_oversized_input_rejected() {
    // Input > 10 MB should be rejected early by parse()
    let big = "a".repeat(10 * 1024 * 1024 + 1);
    let err = parse(&big).unwrap_err();
    assert!(
        err.message.contains("exceeds maximum"),
        "expected size-limit error, got: {}",
        err.message
    );
}

#[test]
fn stress_deeply_nested_state() {
    // Build a document with 64 levels of nesting in the state field.
    // Deep enough to exercise depth limits without blowing serde_json's stack.
    let mut nested = "null".to_string();
    for i in (0..64).rev() {
        nested = format!("{{\"level{}\": {}}}", i, nested);
    }

    let yaml = format!(
        r#"oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    phases:
      - name: exploit
        state: {}
        trigger:
          event: tools/call
      - name: terminal
  indicators:
    - surface: tools/list
      target: "tools[*].description"
      pattern:
        contains: test
"#,
        nested
    );

    let doc = parse(&yaml).expect("should parse deeply nested doc");
    // Validation should complete without hanging or stack overflow
    let result = validate(&doc);
    // We don't expect specific errors from nesting — just that it finishes
    let _ = result;
}

#[test]
fn stress_many_indicators() {
    // Document with 500 indicators, each with a pattern.
    // Should validate in reasonable time.
    let mut indicators = String::new();
    for i in 0..500 {
        indicators.push_str(&format!(
            "    - surface: tools/list\n      target: \"tools[*].description\"\n      pattern:\n        contains: \"test-{}\"\n",
            i
        ));
    }

    let yaml = format!(
        r#"oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    phases:
      - name: exploit
        state:
          tools:
            - name: t
              description: test
              inputSchema:
                type: object
        trigger:
          event: tools/call
      - name: terminal
  indicators:
{}
"#,
        indicators
    );

    let doc = parse(&yaml).expect("should parse many indicators");
    let result = validate(&doc);
    assert!(
        result.errors.is_empty(),
        "unexpected errors: {:?}",
        result.errors
    );
}

#[test]
fn stress_many_phases() {
    // Document with 100 phases.
    // Should normalize and validate without issues.
    let mut phases = String::new();
    for i in 0..100 {
        if i < 99 {
            phases.push_str(&format!(
                "      - name: phase-{}\n        state:\n          tools:\n            - name: tool-{}\n              description: t\n              inputSchema:\n                type: object\n        trigger:\n          event: tools/call\n",
                i, i
            ));
        } else {
            // Last phase is terminal (no trigger)
            phases.push_str(&format!("      - name: phase-{}\n", i));
        }
    }

    let yaml = format!(
        r#"oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    phases:
{}  indicators:
    - surface: tools/list
      target: "tools[*].description"
      pattern:
        contains: t
"#,
        phases
    );

    let doc = parse(&yaml).expect("should parse many phases");
    let result = validate(&doc);
    assert!(
        result.errors.is_empty(),
        "unexpected errors: {:?}",
        result.errors
    );
}

#[test]
fn stress_large_state_object() {
    // State with 200 tool entries.
    // Should validate all rules without excessive time.
    let mut tools = String::new();
    for i in 0..200 {
        tools.push_str(&format!(
            "            - name: tool-{}\n              description: \"Tool number {}\"\n              inputSchema:\n                type: object\n",
            i, i
        ));
    }

    let yaml = format!(
        r#"oatf: "0.1"
attack:
  execution:
    mode: mcp_server
    phases:
      - name: exploit
        state:
          tools:
{}        trigger:
          event: tools/call
      - name: terminal
  indicators:
    - surface: tools/list
      target: "tools[*].description"
      pattern:
        contains: Tool
"#,
        tools
    );

    let doc = parse(&yaml).expect("should parse large state");
    let result = validate(&doc);
    assert!(
        result.errors.is_empty(),
        "unexpected errors: {:?}",
        result.errors
    );
}

#[test]
fn stress_regex_size_limit() {
    // Document with a regex pattern that would produce a huge compiled regex.
    // Should fail validation gracefully, not OOM.
    // Large repetition counts blow up the compiled NFA beyond the 1MB limit.
    let huge_pattern = format!("[a-z]{{1,10000}}{}", r"(\d+[a-z]+){1,1000}".repeat(50));
    // Use single-quoted YAML to avoid backslash escape interpretation.
    let yaml = format!(
        "oatf: '0.1'\n\
         attack:\n\
         \x20 execution:\n\
         \x20   mode: mcp_server\n\
         \x20   phases:\n\
         \x20     - name: exploit\n\
         \x20       state:\n\
         \x20         tools:\n\
         \x20           - name: t\n\
         \x20             description: test\n\
         \x20             inputSchema:\n\
         \x20               type: object\n\
         \x20       trigger:\n\
         \x20         event: tools/call\n\
         \x20     - name: terminal\n\
         \x20 indicators:\n\
         \x20   - surface: tools/list\n\
         \x20     target: 'tools[*].description'\n\
         \x20     pattern:\n\
         \x20       regex: '{}'\n",
        huge_pattern
    );

    let doc = parse(&yaml).expect("should parse doc with huge regex");
    let result = validate(&doc);
    // The oversized regex should be caught by V-013
    assert!(
        result.errors.iter().any(|e| e.rule == "V-013"),
        "expected V-013 error for oversized regex, got: {:?}",
        result.errors
    );
}
