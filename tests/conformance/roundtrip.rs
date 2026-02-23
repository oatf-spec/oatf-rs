use super::common::values_structurally_equal;
use oatf::normalize::normalize;
use oatf::parse::parse;
use oatf::serialize::serialize;
use std::path::PathBuf;

fn conformance_dir() -> PathBuf {
    std::env::var("OATF_CONFORMANCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("spec/conformance"))
}

#[derive(Debug, serde::Deserialize)]
struct TestCase {
    name: String,
    id: String,
    input: String,
    expected: Expected,
}

#[derive(Debug, serde::Deserialize)]
struct Expected {
    identical: bool,
}

#[test]
fn roundtrip_conformance_suite() {
    let suite_path = conformance_dir().join("roundtrip/suite.yaml");
    if !suite_path.exists() {
        eprintln!("Skipping roundtrip tests: {:?} not found", suite_path);
        return;
    }

    let content = std::fs::read_to_string(&suite_path).unwrap();
    let cases: Vec<TestCase> = serde_saphyr::from_str(&content).unwrap();

    let mut passed = 0;
    let mut failed = 0;

    for case in &cases {
        if !case.expected.identical {
            // Skip cases that are not expected to be identical
            continue;
        }

        // Step 1: parse → normalize
        let doc1 = match parse(&case.input) {
            Ok(d) => d,
            Err(e) => {
                eprintln!(
                    "  FAIL [{}] {}: initial parse error: {}",
                    case.id, case.name, e
                );
                failed += 1;
                continue;
            }
        };
        let norm1 = normalize(doc1);

        // Step 2: serialize
        let yaml1 = match serialize(&norm1) {
            Ok(y) => y,
            Err(e) => {
                eprintln!("  FAIL [{}] {}: serialize error: {}", case.id, case.name, e);
                failed += 1;
                continue;
            }
        };

        // Step 3: parse again → normalize again
        let doc2 = match parse(&yaml1) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("  FAIL [{}] {}: re-parse error: {}", case.id, case.name, e);
                eprintln!("    Serialized YAML:\n{}", yaml1);
                failed += 1;
                continue;
            }
        };
        let norm2 = normalize(doc2);

        // Step 4: compare structurally
        let val1 = serde_json::to_value(&norm1).unwrap();
        let val2 = serde_json::to_value(&norm2).unwrap();

        if values_structurally_equal(&val1, &val2) {
            passed += 1;
        } else {
            eprintln!("  FAIL [{}] {}: round-trip mismatch", case.id, case.name);
            eprintln!(
                "    First normalize:  {}",
                serde_json::to_string_pretty(&val1).unwrap()
            );
            eprintln!(
                "    Second normalize: {}",
                serde_json::to_string_pretty(&val2).unwrap()
            );
            failed += 1;
        }
    }

    eprintln!(
        "\nRound-trip conformance: {} passed, {} failed out of {} total",
        passed,
        failed,
        cases.len()
    );

    assert_eq!(failed, 0, "{} round-trip conformance tests failed", failed);
}
