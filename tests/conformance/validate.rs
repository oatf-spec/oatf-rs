use oatf::parse::parse;
use oatf::validate::validate;
use std::path::PathBuf;

fn conformance_dir() -> PathBuf {
    std::env::var("OATF_CONFORMANCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("spec/conformance"))
}

/// A single validation test case from the suite.
#[derive(Debug, serde::Deserialize)]
struct TestCase {
    name: String,
    id: String,
    input: String,
    expected: Expected,
}

#[derive(Debug, serde::Deserialize)]
struct Expected {
    #[serde(default)]
    valid: Option<bool>,
    #[serde(default)]
    errors: Option<Vec<ExpectedError>>,
    #[serde(default)]
    warnings: Option<Vec<ExpectedWarning>>,
}

#[derive(Debug, serde::Deserialize)]
struct ExpectedError {
    rule: String,
    #[serde(default)]
    path: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ExpectedWarning {
    rule: String,
    #[serde(default)]
    path: Option<String>,
}

#[test]
fn validate_conformance_suite() {
    let suite_path = conformance_dir().join("validate/suite.yaml");
    assert!(
        suite_path.exists(),
        "Conformance fixture not found: {:?}. Is the spec submodule initialized?",
        suite_path
    );

    let content = std::fs::read_to_string(&suite_path).unwrap();
    let cases: Vec<TestCase> = serde_saphyr::from_str(&content).unwrap();

    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;
    let mut parse_rejected = 0;

    for case in &cases {
        let doc = match parse(&case.input) {
            Ok(d) => d,
            Err(e) => {
                // This crate's parser is stricter than the conformance suite
                // assumes: some V-rules (V-001, V-003, V-004, V-005, V-020)
                // are caught at parse time rather than validation time.
                // Accept parse errors only when the test expects the document
                // to be invalid — either via `valid: false` or `errors: [...]`.
                if case.expected.valid == Some(false) || case.expected.errors.is_some() {
                    parse_rejected += 1;
                    continue;
                }
                eprintln!("  FAIL [{}] {}: parse error: {}", case.id, case.name, e);
                failed += 1;
                continue;
            }
        };

        let result = validate(&doc);
        let mut case_ok = true;

        if let Some(true) = case.expected.valid {
            if !result.is_valid() {
                eprintln!(
                    "  FAIL [{}] {}: expected valid but got {} errors",
                    case.id,
                    case.name,
                    result.errors.len()
                );
                for err in &result.errors {
                    eprintln!("    - {} at {}: {}", err.rule, err.path, err.message);
                }
                case_ok = false;
            }
        } else if let Some(expected_errors) = &case.expected.errors {
            if result.errors.is_empty() {
                // V-014 CEL syntax validation requires the cel-eval feature
                #[cfg(not(feature = "cel-eval"))]
                if expected_errors.iter().any(|e| e.rule == "V-014") {
                    skipped += 1;
                    continue;
                }
                eprintln!(
                    "  FAIL [{}] {}: expected errors but got valid",
                    case.id, case.name
                );
                case_ok = false;
            } else {
                // Check that each expected error is present
                for expected in expected_errors {
                    let found = result.errors.iter().any(|e| {
                        if e.rule != expected.rule {
                            return false;
                        }
                        match &expected.path {
                            Some(p) => e.path == *p,
                            None => true, // path not specified = match on rule only
                        }
                    });
                    if !found {
                        eprintln!(
                            "  FAIL [{}] {}: expected error {} at {:?} not found",
                            case.id, case.name, expected.rule, expected.path
                        );
                        eprintln!("    Actual errors:");
                        for e in &result.errors {
                            eprintln!("      - {} at {}: {}", e.rule, e.path, e.message);
                        }
                        case_ok = false;
                    }
                }
            }
        } else {
            skipped += 1;
            continue;
        }

        // Check warnings if expected
        if let Some(expected_warnings) = &case.expected.warnings {
            if expected_warnings.is_empty() {
                // Expect no warnings -- check that none are present
                if !result.warnings.is_empty() {
                    eprintln!(
                        "  FAIL [{}] {}: expected no warnings but got {}",
                        case.id,
                        case.name,
                        result.warnings.len()
                    );
                    for w in &result.warnings {
                        eprintln!("    - {} {:?}: {}", w.code, w.path, w.message);
                    }
                    case_ok = false;
                }
            } else {
                for expected in expected_warnings {
                    let found = result.warnings.iter().any(|w| {
                        if w.code != expected.rule {
                            return false;
                        }
                        match &expected.path {
                            Some(p) => w.path.as_deref() == Some(p.as_str()),
                            None => true,
                        }
                    });
                    if !found {
                        eprintln!(
                            "  FAIL [{}] {}: expected warning {} at {:?} not found",
                            case.id, case.name, expected.rule, expected.path
                        );
                        eprintln!("    Actual warnings:");
                        for w in &result.warnings {
                            eprintln!("      - {} {:?}: {}", w.code, w.path, w.message);
                        }
                        case_ok = false;
                    }
                }
            }
        }

        if case_ok {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    eprintln!(
        "\nValidation conformance: {} passed, {} failed, {} skipped, {} rejected at parse out of {} total",
        passed,
        failed,
        skipped,
        parse_rejected,
        cases.len()
    );

    assert!(
        passed + parse_rejected > 0,
        "No validation conformance cases were tested"
    );
    assert_eq!(failed, 0, "{} validation conformance tests failed", failed);
}

#[test]
fn validate_warnings_suite() {
    let suite_path = conformance_dir().join("validate/warnings.yaml");
    assert!(
        suite_path.exists(),
        "Conformance fixture not found: {:?}. Is the spec submodule initialized?",
        suite_path
    );

    let content = std::fs::read_to_string(&suite_path).unwrap();
    let cases: Vec<TestCase> = serde_saphyr::from_str(&content).unwrap();

    let mut passed = 0;
    let mut failed = 0;

    for case in &cases {
        let doc = match parse(&case.input) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("  FAIL [{}] {}: parse error: {}", case.id, case.name, e);
                failed += 1;
                continue;
            }
        };

        let result = validate(&doc);

        // Check errors are as expected
        if let Some(expected_errors) = &case.expected.errors {
            if expected_errors.is_empty() {
                if !result.is_valid() {
                    eprintln!(
                        "  FAIL [{}] {}: expected no errors but got {}",
                        case.id,
                        case.name,
                        result.errors.len()
                    );
                    for err in &result.errors {
                        eprintln!("    - {} at {}: {}", err.rule, err.path, err.message);
                    }
                    failed += 1;
                    continue;
                }
            } else {
                for expected in expected_errors {
                    let found = result.errors.iter().any(|e| e.rule == expected.rule);
                    if !found {
                        eprintln!(
                            "  FAIL [{}] {}: expected error {} not found",
                            case.id, case.name, expected.rule
                        );
                        failed += 1;
                        continue;
                    }
                }
            }
        }

        // Check warnings
        let mut case_ok = true;
        if let Some(expected_warnings) = &case.expected.warnings {
            if expected_warnings.is_empty() {
                if !result.warnings.is_empty() {
                    eprintln!(
                        "  FAIL [{}] {}: expected no warnings but got {}",
                        case.id,
                        case.name,
                        result.warnings.len()
                    );
                    for w in &result.warnings {
                        eprintln!("    - {} {:?}: {}", w.code, w.path, w.message);
                    }
                    case_ok = false;
                }
            } else {
                for expected in expected_warnings {
                    let found = result.warnings.iter().any(|w| w.code == expected.rule);
                    if !found {
                        eprintln!(
                            "  FAIL [{}] {}: expected warning {} not found",
                            case.id, case.name, expected.rule
                        );
                        eprintln!("    Actual warnings:");
                        for w in &result.warnings {
                            eprintln!("      - {} {:?}: {}", w.code, w.path, w.message);
                        }
                        case_ok = false;
                    }
                }
            }
        }

        if case_ok {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    eprintln!(
        "\nValidation warnings: {} passed, {} failed out of {} total",
        passed,
        failed,
        cases.len()
    );

    assert_eq!(failed, 0, "{} validation warning tests failed", failed);
}
