use oatf::parse::parse;
use std::fs;
use std::path::PathBuf;

fn conformance_dir() -> PathBuf {
    std::env::var("OATF_CONFORMANCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("spec/conformance"))
}

#[test]
fn parse_valid_fixtures() {
    let valid_dir = conformance_dir().join("parse/valid");
    assert!(
        valid_dir.exists(),
        "Conformance fixture directory not found: {:?}. Is the spec submodule initialized?",
        valid_dir
    );

    let mut count = 0;
    for entry in fs::read_dir(&valid_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        if path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains(".meta.")
        {
            continue;
        }

        let content = fs::read_to_string(&path).unwrap();
        let result = parse(&content);
        assert!(
            result.is_ok(),
            "Expected valid parse for {:?}, got error: {:?}",
            path.file_name().unwrap(),
            result.err()
        );
        count += 1;
    }
    assert!(
        count > 0,
        "No valid parse fixtures found in {:?}",
        valid_dir
    );
}

#[test]
fn parse_invalid_fixtures() {
    let invalid_dir = conformance_dir().join("parse/invalid");
    assert!(
        invalid_dir.exists(),
        "Conformance fixture directory not found: {:?}. Is the spec submodule initialized?",
        invalid_dir
    );

    let mut count = 0;
    for entry in fs::read_dir(&invalid_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        if path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains(".meta.")
        {
            continue;
        }

        let content = fs::read_to_string(&path).unwrap();
        let result = parse(&content);
        assert!(
            result.is_err(),
            "Expected parse error for {:?}, but parsed successfully",
            path.file_name().unwrap(),
        );
        count += 1;
    }
    assert!(
        count > 0,
        "No invalid parse fixtures found in {:?}",
        invalid_dir
    );
}
