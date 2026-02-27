use oatf::enums::*;
use oatf::evaluate;
use oatf::types::*;
use std::collections::HashMap;

/// Build a minimal Attack with the given correlation logic and indicator count.
fn attack_with_indicators(logic: CorrelationLogic, indicator_ids: &[&str]) -> Attack {
    let indicators = indicator_ids
        .iter()
        .map(|id| Indicator {
            id: Some(id.to_string()),
            protocol: None,
            surface: "test".to_string(),
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
        id: None,
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
            mode: None,
            state: None,
            phases: None,
            actors: Some(vec![]),
            extensions: HashMap::new(),
        },
        indicators: Some(indicators),
        correlation: Some(Correlation {
            logic: Some(logic),
        }),
        extensions: HashMap::new(),
    }
}

/// Zero indicators with Any correlation should yield NotExploited, not Error.
///
/// Kills mutant: `src/evaluate.rs:506` (`>` → `>=` would make 0 skipped trigger Error)
#[test]
fn zero_indicators_any_returns_not_exploited() {
    let attack = attack_with_indicators(CorrelationLogic::Any, &[]);
    let verdicts: HashMap<String, IndicatorVerdict> = HashMap::new();

    let result = evaluate::compute_verdict(&attack, &verdicts);
    assert_eq!(
        format!("{:?}", result.result),
        "NotExploited",
        "zero indicators with Any should be NotExploited"
    );
}

/// Zero indicators with All correlation should yield NotExploited, not Exploited.
///
/// Kills mutant: `src/evaluate.rs:535` (`>` → `>=` would make 0 matched trigger Exploited)
#[test]
fn zero_indicators_all_returns_not_exploited() {
    let attack = attack_with_indicators(CorrelationLogic::All, &[]);
    let verdicts: HashMap<String, IndicatorVerdict> = HashMap::new();

    let result = evaluate::compute_verdict(&attack, &verdicts);
    assert_eq!(
        format!("{:?}", result.result),
        "NotExploited",
        "zero indicators with All should be NotExploited"
    );
}
