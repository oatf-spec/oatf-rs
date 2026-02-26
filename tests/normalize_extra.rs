use oatf::normalize::normalize;
use oatf::parse::parse;
use oatf::types::Severity;

/// N-002: severity object without confidence gets default confidence 50.
#[test]
fn n002_severity_object_without_confidence_gets_default() {
    let input = r#"
oatf: "0.1"
attack:
  severity:
    level: high
  execution:
    mode: mcp_server
    state:
      tools: []
  indicators:
    - surface: tool_description
      pattern:
        contains: malicious
"#;

    let doc = parse(input).expect("parse should succeed");
    let doc = normalize(doc);

    match &doc.attack.severity {
        Some(Severity::Object { level, confidence }) => {
            assert_eq!(format!("{:?}", level), "High");
            assert_eq!(*confidence, Some(50), "confidence should be defaulted to 50");
        }
        other => panic!("expected Severity::Object, got {:?}", other),
    }
}

/// N-006: when actors are already present, normalize should not alter them.
#[test]
fn n006_noop_when_actors_already_present() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    actors:
      - name: attacker
        mode: mcp_server
        phases:
          - name: exploit
            state:
              tools:
                - name: evil
                  description: pwned
                  inputSchema:
                    type: object
            trigger:
              event: tools/call
          - name: terminal
"#;

    let doc = parse(input).expect("parse should succeed");
    let doc = normalize(doc);

    let actors = doc.attack.execution.actors.as_ref().expect("actors should exist");
    assert_eq!(actors.len(), 1);
    assert_eq!(actors[0].name, "attacker");
}

/// N-007: when both phases and actors are present, actors take precedence (already normalized).
#[test]
fn n007_noop_when_actors_already_present() {
    let input = r#"
oatf: "0.1"
attack:
  execution:
    phases:
      - name: phase-x
        state:
          tools: []
    actors:
      - name: custom-actor
        mode: mcp_server
        phases:
          - name: phase-x
            state:
              tools: []
          - name: terminal
"#;

    let doc = parse(input).expect("parse should succeed");
    let doc = normalize(doc);

    let actors = doc.attack.execution.actors.as_ref().expect("actors should exist");
    assert_eq!(actors.len(), 1);
    assert_eq!(actors[0].name, "custom-actor");
}
