use super::common::values_structurally_equal;
use oatf::normalize::normalize;
use oatf::parse::parse;
use std::path::PathBuf;

fn conformance_dir() -> PathBuf {
    std::env::var("OATF_CONFORMANCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("spec/conformance")
        })
}

#[derive(Debug, serde::Deserialize)]
struct TestCase {
    name: String,
    id: String,
    input: String,
    expected: String,
}

#[test]
fn normalize_conformance_suite() {
    let suite_path = conformance_dir().join("normalize/suite.yaml");
    if !suite_path.exists() {
        eprintln!("Skipping normalize tests: {:?} not found", suite_path);
        return;
    }

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

        let normalized = normalize(doc);

        // Parse the expected output
        let expected_value: serde_json::Value =
            serde_saphyr::from_str(&case.expected).unwrap();

        // Convert normalized document to serde_json::Value for comparison
        let actual_value = serde_json::to_value(&normalized).unwrap();

        // Compare structurally
        if values_structurally_equal(&actual_value, &expected_value) {
            passed += 1;
        } else {
            eprintln!("  FAIL [{}] {}", case.id, case.name);
            eprintln!("    Expected: {}", serde_json::to_string_pretty(&expected_value).unwrap());
            eprintln!("    Actual:   {}", serde_json::to_string_pretty(&actual_value).unwrap());
            failed += 1;
        }
    }

    eprintln!(
        "\nNormalize conformance: {} passed, {} failed out of {} total",
        passed,
        failed,
        cases.len()
    );

    assert_eq!(
        failed, 0,
        "{} normalize conformance tests failed",
        failed
    );
}
