use oatf::enums::*;
use oatf::evaluate;
use oatf::types::*;
use std::collections::HashMap;
use std::path::PathBuf;

fn conformance_dir() -> PathBuf {
    std::env::var("OATF_CONFORMANCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("spec/conformance"))
}

#[derive(Debug, serde::Deserialize)]
struct VerdictCase {
    name: String,
    id: String,
    input: VerdictInput,
    expected: VerdictExpected,
}

#[derive(Debug, serde::Deserialize)]
struct VerdictInput {
    correlation_logic: String,
    indicators: Vec<VerdictIndicator>,
    verdicts: Vec<VerdictEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct VerdictIndicator {
    id: String,
}

#[derive(Debug, serde::Deserialize)]
struct VerdictEntry {
    indicator_id: String,
    result: String,
    timestamp: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct VerdictExpected {
    result: String,
}

fn run_verdict_suite(filename: &str) {
    let path = conformance_dir().join(format!("verdict/{}", filename));
    if !path.exists() {
        eprintln!("Skipping verdict tests: {:?} not found", path);
        return;
    }

    let content = std::fs::read_to_string(&path).unwrap();
    let cases: Vec<VerdictCase> = serde_saphyr::from_str(&content).unwrap();

    let mut passed = 0;
    let mut failed = 0;

    for case in &cases {
        let logic = match case.input.correlation_logic.as_str() {
            "any" => CorrelationLogic::Any,
            "all" => CorrelationLogic::All,
            other => {
                eprintln!("  SKIP [{}] {}: unknown logic: {}", case.id, case.name, other);
                continue;
            }
        };

        // Build minimal Attack with indicators and correlation
        let indicators: Vec<Indicator> = case
            .input
            .indicators
            .iter()
            .map(|i| Indicator {
                id: Some(i.id.clone()),
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

        let attack = Attack {
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
        };

        // Build indicator verdicts map
        let mut indicator_verdicts: HashMap<String, IndicatorVerdict> = HashMap::new();
        for entry in &case.input.verdicts {
            let result = match entry.result.as_str() {
                "matched" => IndicatorResult::Matched,
                "not_matched" => IndicatorResult::NotMatched,
                "error" => IndicatorResult::Error,
                "skipped" => IndicatorResult::Skipped,
                other => {
                    eprintln!(
                        "  SKIP [{}] {}: unknown indicator result: {}",
                        case.id, case.name, other
                    );
                    continue;
                }
            };

            indicator_verdicts.insert(
                entry.indicator_id.clone(),
                IndicatorVerdict {
                    indicator_id: entry.indicator_id.clone(),
                    result,
                    timestamp: entry.timestamp.clone(),
                    evidence: None,
                    source: None,
                },
            );
        }

        let verdict = evaluate::compute_verdict(&attack, &indicator_verdicts);

        let result_str = match verdict.result {
            AttackResult::Exploited => "exploited",
            AttackResult::NotExploited => "not_exploited",
            AttackResult::Partial => "partial",
            AttackResult::Error => "error",
        };

        if result_str == case.expected.result {
            passed += 1;
        } else {
            eprintln!(
                "  FAIL [{}] {}: expected {}, got {} (summary: matched={}, not_matched={}, error={}, skipped={})",
                case.id, case.name, case.expected.result, result_str,
                verdict.evaluation_summary.matched,
                verdict.evaluation_summary.not_matched,
                verdict.evaluation_summary.error,
                verdict.evaluation_summary.skipped,
            );
            failed += 1;
        }
    }

    eprintln!(
        "\nverdict/{}: {} passed, {} failed out of {} total",
        filename,
        passed,
        failed,
        cases.len()
    );
    assert_eq!(
        failed, 0,
        "{} verdict/{} tests failed",
        failed, filename
    );
}

#[test]
fn verdict_any_suite() {
    run_verdict_suite("any.yaml");
}

#[test]
fn verdict_all_suite() {
    run_verdict_suite("all.yaml");
}
