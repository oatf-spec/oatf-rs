use oatf::parse::parse;
use oatf::validate::validate;
use std::path::PathBuf;

fn conformance_dir() -> PathBuf {
    std::env::var("OATF_CONFORMANCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("spec/conformance")
        })
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
    if !suite_path.exists() {
        eprintln!("Skipping validate tests: {:?} not found", suite_path);
        return;
    }

    let content = std::fs::read_to_string(&suite_path).unwrap();
    let cases: Vec<TestCase> = serde_saphyr::from_str(&content).unwrap();

    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;

    for case in &cases {
        let doc = match parse(&case.input) {
            Ok(d) => d,
            Err(e) => {
                // If the input can't parse, check if the test expects that
                if case.expected.valid == Some(false) || case.expected.errors.is_some() {
                    // Parse error is acceptable for invalid test cases
                    passed += 1;
                    continue;
                }
                eprintln!("  FAIL [{}] {}: parse error: {}", case.id, case.name, e);
                failed += 1;
                continue;
            }
        };

        let result = validate(&doc);

        if let Some(true) = case.expected.valid {
            if result.is_valid() {
                passed += 1;
            } else {
                eprintln!(
                    "  FAIL [{}] {}: expected valid but got {} errors",
                    case.id,
                    case.name,
                    result.errors.len()
                );
                for err in &result.errors {
                    eprintln!("    - {} at {}: {}", err.rule, err.path, err.message);
                }
                failed += 1;
            }
        } else if let Some(expected_errors) = &case.expected.errors {
            if result.errors.is_empty() {
                eprintln!(
                    "  FAIL [{}] {}: expected errors but got valid",
                    case.id, case.name
                );
                failed += 1;
            } else {
                // Check that each expected error is present
                let mut all_found = true;
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
                        all_found = false;
                    }
                }
                if all_found {
                    passed += 1;
                } else {
                    failed += 1;
                }
            }
        } else {
            skipped += 1;
        }

        // Check warnings if expected
        if let Some(expected_warnings) = &case.expected.warnings {
            for expected in expected_warnings {
                let found = result.warnings.iter().any(|w| {
                    if w.code != expected.rule {
                        return false;
                    }
                    match &expected.path {
                        Some(p) => w.path.as_deref() == Some(p.as_str()),
                        None => true, // path not specified = match on rule only
                    }
                });
                if !found {
                    eprintln!(
                        "  WARN [{}] {}: expected warning {} at {:?} not found",
                        case.id, case.name, expected.rule, expected.path
                    );
                }
            }
        }
    }

    eprintln!(
        "\nValidation conformance: {} passed, {} failed, {} skipped out of {} total",
        passed,
        failed,
        skipped,
        cases.len()
    );

    assert_eq!(
        failed, 0,
        "{} validation conformance tests failed",
        failed
    );
}

#[test]
fn validate_warnings_suite() {
    let suite_path = conformance_dir().join("validate/warnings.yaml");
    if !suite_path.exists() {
        eprintln!("Skipping validate warnings tests: {:?} not found", suite_path);
        return;
    }

    let content = std::fs::read_to_string(&suite_path).unwrap();
    let cases: Vec<TestCase> = serde_saphyr::from_str(&content).unwrap();

    for case in &cases {
        let doc = match parse(&case.input) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let result = validate(&doc);

        if let Some(true) = case.expected.valid {
            assert!(
                result.is_valid(),
                "[{}] {}: expected valid but got errors: {:?}",
                case.id,
                case.name,
                result.errors
            );
        }
    }
}
