use oatf::parse::parse;

#[test]
fn action_deserialization_picks_correct_variant() {
    // Verify that oatf's Action deserializer picks the correct variant
    // based on the first non-extension key in the YAML map.
    let yaml = r#"
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
    let doc = parse(yaml).expect("parse should succeed");
    let actors = doc.attack.execution.phases.unwrap();
    let actions = actors[0].on_enter.as_ref().unwrap();
    assert_eq!(actions.len(), 1);

    let action_json = serde_json::to_value(&actions[0]).unwrap();
    assert!(
        action_json.get("log").is_some(),
        "Expected 'log' action variant, got: {}",
        action_json
    );
}
