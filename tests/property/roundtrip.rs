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

/// Compare two documents structurally via their serialized JSON form.
fn docs_equal(a: &oatf::types::Document, b: &oatf::types::Document) -> bool {
    let a_json = serde_json::to_value(a).unwrap();
    let b_json = serde_json::to_value(b).unwrap();
    a_json == b_json
}

/// Build a multi-phase document with variable parts.
fn build_doc(mode: &str, tool_name: &str, tool_desc: &str) -> String {
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
              description: "{tool_desc}"
              inputSchema:
                type: object
        trigger:
          event: tools/call
      - name: terminal
  indicators:
    - surface: tool_description
      pattern:
        contains: test"#,
    )
}

/// Build a document with multiple indicators and severity.
fn build_rich_doc(mode: &str, tool_name: &str, severity: &str) -> String {
    format!(
        r#"oatf: "0.1"
attack:
  name: Test Attack
  severity: {severity}
  execution:
    mode: {mode}
    phases:
      - name: exploit
        state:
          tools:
            - name: {tool_name}
              description: "test tool"
              inputSchema:
                type: object
        trigger:
          event: tools/call
      - name: terminal
  indicators:
    - surface: tool_description
      pattern:
        contains: test
    - surface: tool_output
      pattern:
        regex: "secret.*"
  classification:
    category: capability_poisoning
    tags:
      - mcp
      - tool-injection"#,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    // roundtrip stability: parse → normalize → serialize → parse → normalize
    // produces structurally equivalent document
    #[test]
    fn roundtrip_stable(
        mode in arb_mode(),
        tool_name in "[a-z]{2,8}",
        tool_desc in "[a-zA-Z][a-zA-Z ]{0,18}[a-zA-Z]",
    ) {
        let yaml = build_doc(&mode, &tool_name, &tool_desc);
        let doc1 = parse(&yaml).expect("parse should succeed");
        let norm1 = normalize(doc1);
        let yaml2 = serialize(&norm1).expect("serialize should succeed");
        let doc2 = parse(&yaml2).expect("re-parse should succeed");
        let norm2 = normalize(doc2);

        prop_assert!(docs_equal(&norm1, &norm2),
            "roundtrip not stable for mode={}, tool={}", mode, tool_name);
    }

    // Rich document roundtrip
    #[test]
    fn rich_doc_roundtrip(
        mode in arb_mode(),
        tool_name in "[a-z]{2,8}",
        severity in prop_oneof![
            Just("informational"),
            Just("low"),
            Just("medium"),
            Just("high"),
            Just("critical"),
        ],
    ) {
        let yaml = build_rich_doc(&mode, &tool_name, severity);
        let doc1 = parse(&yaml).expect("parse should succeed");
        let norm1 = normalize(doc1);
        let yaml2 = serialize(&norm1).expect("serialize should succeed");
        let doc2 = parse(&yaml2).expect("re-parse should succeed");
        let norm2 = normalize(doc2);

        prop_assert!(docs_equal(&norm1, &norm2),
            "rich doc roundtrip not stable for mode={}", mode);
    }

    // serialize(normalize(doc)) produces valid YAML (re-parseable)
    #[test]
    fn serialized_is_valid_yaml(
        mode in arb_mode(),
        tool_name in "[a-z]{2,8}",
        tool_desc in "[a-zA-Z][a-zA-Z ]{0,18}[a-zA-Z]",
    ) {
        let yaml = build_doc(&mode, &tool_name, &tool_desc);
        let doc = parse(&yaml).expect("parse should succeed");
        let norm = normalize(doc);
        let serialized = serialize(&norm).expect("serialize should succeed");
        // Should be valid YAML
        let reparsed = parse(&serialized);
        prop_assert!(reparsed.is_ok(),
            "serialized normalized doc is not valid YAML:\n{}\nerror: {:?}",
            serialized, reparsed.err());
    }

    // Single-phase form roundtrip
    #[test]
    fn single_phase_roundtrip(
        mode in arb_mode(),
        tool_name in "[a-z]{2,8}",
    ) {
        let yaml = format!(
            r#"oatf: "0.1"
attack:
  execution:
    mode: {mode}
    state:
      tools:
        - name: {tool_name}
          description: "test"
          inputSchema:
            type: object"#,
        );
        let doc1 = parse(&yaml).expect("parse should succeed");
        let norm1 = normalize(doc1);
        let yaml2 = serialize(&norm1).expect("serialize should succeed");
        let doc2 = parse(&yaml2).expect("re-parse should succeed");
        let norm2 = normalize(doc2);

        prop_assert!(docs_equal(&norm1, &norm2),
            "single-phase roundtrip not stable");
    }

    // Multi-actor form roundtrip
    #[test]
    fn multi_actor_roundtrip(
        mode in arb_mode(),
        tool_name in "[a-z]{2,8}",
    ) {
        let yaml = format!(
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
                  description: "test"
                  inputSchema:
                    type: object
            trigger:
              event: tools/call
          - name: terminal"#,
        );
        let doc1 = parse(&yaml).expect("parse should succeed");
        let norm1 = normalize(doc1);
        let yaml2 = serialize(&norm1).expect("serialize should succeed");
        let doc2 = parse(&yaml2).expect("re-parse should succeed");
        let norm2 = normalize(doc2);

        prop_assert!(docs_equal(&norm1, &norm2),
            "multi-actor roundtrip not stable");
    }
}
