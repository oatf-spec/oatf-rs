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

/// Structural equality: ignore field ordering, compare values deeply.
/// Treat missing optional fields as equivalent to null.
fn values_structurally_equal(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    use serde_json::Value;
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Number(a), Value::Number(b)) => {
            // Compare numerically
            if let (Some(a), Some(b)) = (a.as_f64(), b.as_f64()) {
                (a - b).abs() < f64::EPSILON
            } else {
                a == b
            }
        }
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len()
                && a.iter()
                    .zip(b.iter())
                    .all(|(a, b)| values_structurally_equal(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            // Check all keys in expected are present and equal in actual
            // Skip keys in actual that are null and not in expected (optional fields)
            for (key, val_b) in b {
                match a.get(key) {
                    Some(val_a) => {
                        if !values_structurally_equal(val_a, val_b) {
                            return false;
                        }
                    }
                    None => {
                        if !val_b.is_null() {
                            return false;
                        }
                    }
                }
            }
            // Check for keys in actual that are not in expected and not null
            for (key, val_a) in a {
                if !b.contains_key(key) && !val_a.is_null() {
                    return false;
                }
            }
            true
        }
        _ => false,
    }
}
